"""Fenced Proxmox token HTTPS and independently credentialed Linux JSON reads.

Read fences and direct SSH draining were informed by nautobot-testsuite's
transport_proxmox.py, proxmox_paths.py and transport_ssh.py (Apache-2.0).
This standalone transport narrows those surfaces and requires verified SSH keys.
No login API, write API, guest execution, shell interpolation or PTY is exposed.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
import threading
import time
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from .proxmox_sources import READ_COMMANDS

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_JSON_NODES = 131072
MAX_JSON_DEPTH = 64
MAX_STDERR_BYTES = 256 * 1024
_NODE = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}"
_VMID = r"[1-9][0-9]{2,8}"
_TOKEN_ID = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+\Z")
_SECRET_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "cipassword",
        "secret",
        "token",
        "token_secret",
        "api_token",
        "authorization",
        "sshkeys",
        "private_key",
    }
)


class ProxmoxError(RuntimeError):
    """Operator-safe failure; no remote body, headers or credential text."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _host_for_url(host):
    if not isinstance(host, str) or not host:
        raise ValueError("Proxmox host must be an IP address or DNS name")
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        address = ipaddress.ip_address(bare)
        return f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ValueError("Proxmox host must be an IP address or DNS name") from None
        return host


def _bounded_number(value, minimum, maximum, label, *, integer=False):
    types = (int,) if integer else (int, float)
    if (
        isinstance(value, bool)
        or not isinstance(value, types)
        or not math.isfinite(value)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"Invalid Proxmox {label}")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProxmoxError("Structured source returned duplicate JSON fields")
        result[key] = value
    return result


def _constant(_value):
    raise ProxmoxError("Structured source returned a non-finite JSON value")


def _json(body):
    if len(body) > MAX_JSON_BYTES:
        raise ProxmoxError("Structured JSON source exceeded the byte limit")
    try:
        result = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ProxmoxError("Structured source returned invalid complete UTF-8 JSON") from None
    pending = [(result, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ProxmoxError("Structured JSON source exceeded the structure limit")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str) and len(value) > 65536:
            raise ProxmoxError("Structured JSON string exceeded the value limit")
        elif isinstance(value, float) and not math.isfinite(value):
            raise ProxmoxError("Structured source returned a non-finite JSON value")
    return result


def fence_path(path, params=None):
    """Validate exact reviewed GETs before opening a connection."""
    if not isinstance(path, str) or len(path) > 256:
        raise ValueError("Proxmox API path is outside the reviewed GET surface")
    if re.fullmatch(r"/(?:version|cluster/status|access/permissions|storage)", path):
        match = None
    else:
        match = re.fullmatch(
            rf"/nodes/({_NODE})/(version|status|network|storage|qemu|lxc)"
            rf"(?:/({_VMID})/(config|pending|status/current))?",
            path,
        )
        if not match or (match.group(3) and match.group(2) not in {"qemu", "lxc"}):
            raise ValueError("Proxmox API path is outside the reviewed GET surface")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("Proxmox query is outside the reviewed read shape")
    if path == "/access/permissions":
        if (
            set(params) != {"path"}
            or not isinstance(params["path"], str)
            or not re.fullmatch(
                rf"/(?:nodes/{_NODE}|vms(?:/{_VMID})?|storage/[A-Za-z0-9][A-Za-z0-9_.-]{{0,62}})?",
                params["path"],
            )
        ):
            raise ValueError("Proxmox permissions GET requires one reviewed exact scope")
    elif match and match.group(4) == "config":
        if params and (
            set(params) != {"current"}
            or type(params["current"]) not in (str, int)
            or params["current"] not in (0, 1, "0", "1")
        ):
            raise ValueError("Proxmox config GET only accepts current=0 or current=1")
    elif params:
        raise ValueError("Proxmox query is outside the reviewed read shape")
    return path, dict(params)


class ProxmoxClient:
    """One API-local host; guest reads are limited to IDs in its scoped lists."""

    def __init__(
        self,
        host,
        token_id,
        token_secret,
        ssh_username=None,
        ssh_password=None,
        *,
        port=8006,
        ssh_port=22,
        verify=True,
        timeout=30,
        host_key_sha256=None,
        ssh_key_filename=None,
        max_requests=1024,
        max_guests=4096,
    ):
        authority = _host_for_url(host)
        _bounded_number(port, 1, 65535, "HTTPS port", integer=True)
        _bounded_number(ssh_port, 1, 65535, "SSH port", integer=True)
        _bounded_number(timeout, 1, 120, "read timeout")
        _bounded_number(max_requests, 1, 4096, "request limit", integer=True)
        _bounded_number(max_guests, 1, 16384, "guest limit", integer=True)
        if not (
            type(verify) is bool
            or isinstance(verify, str)
            and verify
            and not any(ord(c) < 32 or ord(c) == 127 for c in verify)
        ):
            raise ValueError("TLS verification must be boolean or a CA trust path")
        if (
            not isinstance(token_id, str)
            or len(token_id) > 255
            or not _TOKEN_ID.fullmatch(token_id)
        ):
            raise ValueError("Proxmox HTTPS requires a full user@realm!token API token ID")
        if (
            not isinstance(token_secret, str)
            or not token_secret
            or len(token_secret) > 1024
            or any(ord(c) < 33 or ord(c) > 126 for c in token_secret)
        ):
            raise ValueError("Proxmox API token secret must be nonempty printable ASCII")
        if ssh_username is not None and (
            not isinstance(ssh_username, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", ssh_username)
        ):
            raise ValueError("Linux SSH requires independent host account credentials")
        if ssh_password is not None and (not isinstance(ssh_password, str) or not ssh_password):
            raise ValueError("Linux SSH password must be a nonempty string")
        if ssh_key_filename is not None and (
            not isinstance(ssh_key_filename, str)
            or not ssh_key_filename.startswith("/")
            or any(ord(c) < 32 or ord(c) == 127 for c in ssh_key_filename)
        ):
            raise ValueError("Linux SSH key filename must be an absolute file path")
        if host_key_sha256 is not None and (
            not isinstance(host_key_sha256, str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host_key_sha256)
        ):
            raise ValueError("SSH host-key pin must be a SHA256 fingerprint")
        self.host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        self.base = f"https://{authority}:{port}/api2/json"
        self.verify, self.timeout, self.ssh_port = verify, timeout, ssh_port
        self.max_requests, self.max_guests = max_requests, max_guests
        self.trace = []
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"PVEAPIToken={token_id}={token_secret}",
            }
        )
        self._ssh_username, self._ssh_password = ssh_username, ssh_password
        self._ssh_key_filename, self._host_key_sha256 = ssh_key_filename, host_key_sha256
        self._secret_values = tuple(
            value
            for value in (token_secret, token_id, ssh_password)
            if isinstance(value, str) and value
        )
        self._requests = self._bytes = 0
        self._local_node = None
        self._guests = {}
        self._ssh = None
        self._closed = self._http_expired = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self.close()
        except BaseException:
            if args[0] is None:
                raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        ssh, self._ssh = self._ssh, None
        try:
            if ssh is not None:
                try:
                    ssh.close()
                except Exception as error:
                    if type(error).__name__ == "SoftTimeLimitExceeded":
                        raise
        finally:
            try:
                self.session.close()
            except Exception as error:
                if type(error).__name__ == "SoftTimeLimitExceeded":
                    raise
            finally:
                self._ssh_password = None
                self._secret_values = ()
                self.session.headers.pop("Authorization", None)

    def _charge(self):
        if self._closed:
            raise ProxmoxError("Proxmox session is closed")
        if self._http_expired:
            raise ProxmoxError("Proxmox HTTPS session exceeded its deadline; open a new session")
        if self._requests >= self.max_requests:
            raise ProxmoxError("Proxmox read request budget exceeded")
        self._requests += 1

    def _add_bytes(self, size):
        self._bytes += size
        if self._bytes > MAX_TOTAL_BYTES:
            raise ProxmoxError("Proxmox aggregate source byte budget exceeded")

    def _scrub(self, value):
        if isinstance(value, dict):
            return {
                key: self._scrub(item)
                for key, item in value.items()
                if key.lower() not in _SECRET_FIELDS
            }
        if isinstance(value, list):
            return [self._scrub(item) for item in value]
        if isinstance(value, str):
            for secret in self._secret_values:
                value = value.replace(secret, "[redacted]")
        return value

    def _pin_scope(self, path):
        match = re.match(rf"/nodes/({_NODE})/", path)
        if match and (self._local_node is None or match.group(1) != self._local_node):
            raise ProxmoxError("Node GET requires the uniquely verified API-local node")
        guest = re.fullmatch(rf"/nodes/({_NODE})/(qemu|lxc)/({_VMID})/(.+)", path)
        if guest and int(guest.group(3)) not in self._guests.get(guest.group(2), set()):
            raise ProxmoxError("Guest GET requires an identity observed in the local scoped list")

    def _record_scope(self, path, data):
        if path == "/cluster/status":
            if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                raise ProxmoxError("Proxmox cluster status was not a structured list")
            local = [
                row
                for row in data
                if row.get("type") == "node"
                and type(row.get("local")) in (int, bool)
                and row["local"] == 1
            ]
            if (
                len(local) != 1
                or not isinstance(local[0].get("name"), str)
                or not re.fullmatch(_NODE, local[0]["name"])
            ):
                raise ProxmoxError("Proxmox endpoint did not identify exactly one API-local node")
            node = local[0]["name"]
            if self._local_node is not None and node != self._local_node:
                raise ProxmoxError("Proxmox API-local node identity changed during capture")
            self._local_node = node
        kind = path.rsplit("/", 1)[-1]
        if re.fullmatch(rf"/nodes/{_NODE}/(?:qemu|lxc)", path):
            if not isinstance(data, list) or len(data) > self.max_guests:
                raise ProxmoxError("Proxmox guest list exceeded its structured identity budget")
            identities = set()
            for row in data:
                if (
                    not isinstance(row, dict)
                    or type(row.get("vmid")) is not int
                    or not 100 <= row["vmid"] <= 999999999
                    or row["vmid"] in identities
                ):
                    raise ProxmoxError(
                        "Proxmox guest list has a missing, duplicate or invalid VMID"
                    )
                if "node" in row and row["node"] != self._local_node:
                    raise ProxmoxError("Proxmox guest list contains a foreign node identity")
                identities.add(row["vmid"])
            if (
                sum(len(ids) for key, ids in self._guests.items() if key != kind) + len(identities)
                > self.max_guests
            ):
                raise ProxmoxError("Proxmox combined guest identity budget exceeded")
            if any(identities & ids for key, ids in self._guests.items() if key != kind):
                raise ProxmoxError("Proxmox QEMU and LXC lists repeat the same VMID")
            self._guests[kind] = identities

    def get(self, path, params=None):
        return self.get_envelope(path, params=params)["data"]

    def get_envelope(self, path, params=None):
        path, params = fence_path(path, params)
        self._pin_scope(path)
        self._charge()
        record = {"transport": "https", "path": path, "outcome": "failed", "bytes": 0}
        self.trace.append(record)
        try:
            envelope = _json(self._http_read(path, params, record))
            if not isinstance(envelope, dict) or "data" not in envelope:
                raise ProxmoxError("Proxmox HTTPS source returned an invalid API envelope")
            if (
                envelope.get("success") in (0, False)
                or envelope.get("error")
                or envelope.get("errors")
            ):
                raise ProxmoxError("Proxmox API source reported a failure")
            self._record_scope(path, envelope["data"])
            record["outcome"] = "complete"
            return self._scrub(envelope)
        except requests.exceptions.SSLError:
            raise ProxmoxError(
                "Proxmox TLS verification failed; configure the CA trust path or "
                "select the explicit lab TLS exception"
            ) from None
        except requests.RequestException:
            raise ProxmoxError(
                "Proxmox HTTPS read failed; check endpoint reachability and TLS"
            ) from None

    def _http_read(self, path, params, record):
        """Bound the whole read, including a peer that continuously trickles bytes.

        Requests' socket read timeout alone is an inactivity timeout. A daemon
        worker bounds complete collection without accepting any partial JSON.
        A timed-out client refuses all further reads, limiting abandoned work to
        one request; that worker closes its response as soon as its read returns.
        """
        complete, abandoned = threading.Event(), threading.Event()
        results, errors = [], []

        def read():
            response = None
            try:
                with warnings.catch_warnings():
                    if self.verify is False:
                        warnings.simplefilter("ignore", InsecureRequestWarning)
                    response = self.session.get(
                        self.base + path,
                        params=params,
                        verify=self.verify,
                        timeout=(self.timeout, self.timeout),
                        stream=True,
                        allow_redirects=False,
                    )
                    if abandoned.is_set():
                        return
                    status = response.status_code
                    if type(status) is not int:
                        raise ProxmoxError("Proxmox HTTPS source returned an invalid HTTP status")
                    record["status"] = status
                    if not 200 <= status < 300:
                        hints = {
                            401: "check the independent API token credentials",
                            403: "check user and token grants at this exact source scope",
                            404: "verify this read is supported by the installed PVE release",
                        }
                        hint = hints.get(status, "verify the endpoint and installed API release")
                        raise ProxmoxError(
                            f"Proxmox HTTPS GET failed (HTTP {status}); {hint}", status
                        )
                    body = bytearray()
                    for chunk in response.iter_content(chunk_size=8192):
                        if abandoned.is_set():
                            return
                        if chunk:
                            if not isinstance(chunk, bytes):
                                raise ProxmoxError("Proxmox HTTPS source returned invalid bytes")
                            body.extend(chunk)
                            record["bytes"] = len(body)
                            self._add_bytes(len(chunk))
                            if len(body) > MAX_JSON_BYTES:
                                raise ProxmoxError("Proxmox HTTPS source exceeded the byte limit")
                    if not abandoned.is_set():
                        results.append(bytes(body))
            except BaseException as error:
                errors.append(error)
            finally:
                if response is not None:
                    try:
                        response.close()
                    except Exception as error:
                        if type(error).__name__ == "SoftTimeLimitExceeded" and not errors:
                            errors.append(error)
                complete.set()

        threading.Thread(target=read, daemon=True).start()
        try:
            if not complete.wait(self.timeout):
                self._http_expired = True
                raise ProxmoxError(
                    "Proxmox HTTPS source read deadline exceeded; partial JSON refused"
                )
        except BaseException:
            abandoned.set()
            self._http_expired = True
            raise
        if errors:
            error = errors[0]
            if not isinstance(error, Exception) or type(error).__name__ == "SoftTimeLimitExceeded":
                raise error
            if isinstance(error, (ProxmoxError, requests.RequestException)):
                raise error
            raise ProxmoxError(
                "Proxmox HTTPS source read failed; no partial JSON accepted"
            ) from None
        if len(results) != 1:
            raise ProxmoxError("Proxmox HTTPS source read did not complete")
        return results[0]

    def _open_ssh(self):
        if self._ssh is not None:
            return
        if self._ssh_username is None or not (self._ssh_password or self._ssh_key_filename):
            raise ProxmoxError("Linux JSON reads require separate SSH username and password or key")
        try:
            import paramiko
        except ImportError:
            raise ProxmoxError(
                "Linux JSON reads require Paramiko on the discovery worker"
            ) from None
        client = paramiko.SSHClient()
        if self._host_key_sha256 is None:
            try:
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            except BaseException as error:
                try:
                    client.close()
                except Exception:
                    pass
                if (
                    not isinstance(error, Exception)
                    or type(error).__name__ == "SoftTimeLimitExceeded"
                ):
                    raise
                raise ProxmoxError("Proxmox SSH known-host key store could not be loaded") from None
        else:
            expected = self._host_key_sha256

            class PinnedHostKey(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, _client, _hostname, key):
                    actual = "SHA256:" + base64.b64encode(
                        hashlib.sha256(key.asbytes()).digest()
                    ).decode("ascii").rstrip("=")
                    if not hmac.compare_digest(actual, expected):
                        raise ProxmoxError("Proxmox SSH host-key fingerprint did not match the pin")

            client.set_missing_host_key_policy(PinnedHostKey())
        try:
            client.connect(
                hostname=self.host,
                port=self.ssh_port,
                username=self._ssh_username,
                password=self._ssh_password,
                key_filename=self._ssh_key_filename,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except BaseException as error:
            try:
                client.close()
            except Exception:
                pass
            if not isinstance(error, Exception) or type(error).__name__ == "SoftTimeLimitExceeded":
                raise
            if isinstance(error, ProxmoxError):
                raise
            raise ProxmoxError(
                "Proxmox Linux SSH connection failed; verify separate credentials "
                "and the pinned or known host key"
            ) from None
        self._ssh = client

    def ssh_json(self, source):
        if not isinstance(source, str) or source not in READ_COMMANDS:
            raise ValueError("Linux SSH source is outside the fixed structured read allowlist")
        self._charge()
        record = {
            "transport": "ssh",
            "source": source,
            "outcome": "failed",
            "bytes": 0,
            "stderr_bytes": 0,
        }
        self.trace.append(record)
        self._open_ssh()
        stdout, stderr = self._ssh_read(READ_COMMANDS[source])
        record["bytes"], record["stderr_bytes"] = len(stdout), len(stderr)
        result = _json(stdout)
        if source in {"links", "addresses", "bridge_vlans"}:
            if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
                raise ProxmoxError(
                    "Linux netlink JSON source did not return a complete record list"
                )
        elif source == "host" and not isinstance(result, dict):
            raise ProxmoxError("Linux host JSON source did not return a structured object")
        elif source == "hardware" and not isinstance(result, (dict, list)):
            raise ProxmoxError("Linux lshw JSON source did not return structured hardware")
        record["outcome"] = "complete"
        return self._scrub(result)

    def _ssh_read(self, command):
        """Drain both streams through EOF and exit status; refuse partial reads."""
        if not isinstance(command, str) or command not in READ_COMMANDS.values():
            raise ValueError("Linux command is outside the exact structured read allowlist")
        deadline = time.monotonic() + self.timeout
        stdout, stderr = bytearray(), bytearray()
        channel = None
        try:
            transport = self._ssh.get_transport()
            if transport is None or not transport.is_active():
                raise ProxmoxError("Proxmox Linux SSH transport is not active")
            channel = transport.open_session(timeout=max(0.001, deadline - time.monotonic()))
            channel.settimeout(0.0)
            acknowledged = threading.Event()
            errors = []

            def request():
                try:
                    channel.exec_command(command)
                    channel.shutdown_write()
                except BaseException as error:
                    errors.append(error)
                finally:
                    acknowledged.set()

            threading.Thread(target=request, daemon=True).start()
            if not acknowledged.wait(max(0.0, deadline - time.monotonic())):
                raise ProxmoxError("Linux SSH deadline exceeded before exec acknowledgement")
            if errors:
                if (
                    not isinstance(errors[0], Exception)
                    or type(errors[0]).__name__ == "SoftTimeLimitExceeded"
                ):
                    raise errors[0]
                raise ProxmoxError("Linux SSH exec request failed; no partial source was accepted")
            while True:
                if time.monotonic() >= deadline:
                    raise ProxmoxError("Linux SSH deadline exceeded; partial JSON output refused")
                progressed = False
                if channel.recv_ready():
                    chunk = channel.recv(65536)
                    stdout.extend(chunk)
                    self._add_bytes(len(chunk))
                    progressed = True
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    stderr.extend(chunk)
                    self._add_bytes(len(chunk))
                    progressed = True
                if len(stdout) > MAX_JSON_BYTES or len(stderr) > MAX_STDERR_BYTES:
                    raise ProxmoxError("Linux SSH output exceeded the bounded source byte limit")
                if (
                    (channel.eof_received or channel.closed)
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                    and channel.exit_status_ready()
                ):
                    status = channel.recv_exit_status()
                    if type(status) is not int or status != 0:
                        raise ProxmoxError(
                            "Linux structured SSH read failed; check the exact source "
                            "tool and account permissions (nonzero exit status)"
                        )
                    break
                if not progressed:
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
            try:
                bytes(stdout).decode("utf-8", errors="strict")
                bytes(stderr).decode("utf-8", errors="strict")
            except UnicodeError:
                raise ProxmoxError("Linux SSH output was not complete valid UTF-8") from None
            return bytes(stdout), bytes(stderr)
        except ProxmoxError:
            raise
        except Exception as error:
            if type(error).__name__ == "SoftTimeLimitExceeded":
                raise
            raise ProxmoxError("Linux SSH source read failed; partial output refused") from None
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception as error:
                    if type(error).__name__ == "SoftTimeLimitExceeded":
                        raise
