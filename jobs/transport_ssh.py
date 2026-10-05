"""Small, fenced PAN-OS SSH/XML transport with sanitized diagnostics.

Adapted from nautobot-testsuite/jobs/transport_ssh.py at commit
7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9 (Apache-2.0). Modified to accept
only discovery's exact reads, load Netmiko lazily, and suppress secret-bearing
transport exceptions. Session preparation changes presentation only.
"""

import re
import time

SYSTEM_INFO = "show system info"
INTERFACES = "show interface all"
MANAGEMENT_INTERFACE = "show interface management"
VM_INTERFACES = "debug show vm-series interfaces all"
RUNNING_INTERFACES = "show config effective-running xpath devices/entry/network/interface"
HA_STATE = "show high-availability all"
RUNNING_HA = "show config effective-running xpath devices/entry/deviceconfig"
RUNNING_VPN = "show config effective-running xpath devices/entry/network"
RUNNING_VSYS = "show config effective-running xpath devices/entry/vsys"
IKE_SAS = "show vpn ike-sa"
IPSEC_SAS = "show vpn ipsec-sa"
VPN_FLOWS = "show vpn flow"
SESSION_PREP = ("set cli pager off", "set cli op-command-xml-output on")
PROMPT_PATTERN = r"(?m:^[A-Za-z0-9_.:@()/\-]+>[ \t]*\r?$)"
_PROMPT_LINE = re.compile(r"[A-Za-z0-9_.:@()/\-]+>")
HA_VPN_READ_COMMANDS = (
    RUNNING_HA,
    HA_STATE,
    RUNNING_VPN,
    IKE_SAS,
    IPSEC_SAS,
    VPN_FLOWS,
)
READ_COMMANDS = frozenset(
    (SYSTEM_INFO, INTERFACES, MANAGEMENT_INTERFACE, RUNNING_INTERFACES, VM_INTERFACES, RUNNING_VSYS)
    + HA_VPN_READ_COMMANDS
)
_FLOW_DETAIL = re.compile(r"show vpn flow tunnel-id ([1-9][0-9]{0,4})")


def vpn_flow_detail_command(tunnel_id):
    """Use an observed integer in the documented CLI range; never interpolate names."""
    if type(tunnel_id) is not int or not 1 <= tunnel_id <= 65535:
        raise ValueError("VPN flow tunnel ID must be an integer between 1 and 65535")
    return "show vpn flow tunnel-id %s" % tunnel_id


def is_read_command(command):
    if not isinstance(command, str):
        return False
    if command in READ_COMMANDS:
        return True
    match = _FLOW_DETAIL.fullmatch(command)
    return bool(match and int(match.group(1)) <= 65535)


class SshError(RuntimeError):
    """An operator-safe SSH failure; remote messages are never interpolated."""


def _cancel(exc):
    if type(exc).__name__ == "SoftTimeLimitExceeded":
        raise exc


def _panos_connection(params):
    """Keep driver connection/authentication behavior without implicit CLI reads.

    Netmiko's default Palo preparation issues an untraced system-info read and
    assumes text display markers. Only our fenced transport may issue commands;
    prompt acquisition itself sends one RETURN and accepts an operational prompt.
    The driver remains lazy so pure planning does not require Netmiko.
    """
    from netmiko.paloalto.paloalto_panos import PaloAltoPanosSSH

    class FencedPaloAltoSSH(PaloAltoPanosSSH):
        def session_preparation(self):
            self.ansi_escape_codes = True
            self.write_channel(self.RETURN)
            output = self.read_until_pattern(pattern=PROMPT_PATTERN, read_timeout=60)
            if not isinstance(output, str) or not output.strip():
                raise SshError("PAN-OS SSH did not provide a complete operational prompt")
            prompt = output.strip().splitlines()[-1]
            if _PROMPT_LINE.fullmatch(prompt) is None:
                raise SshError("PAN-OS SSH did not provide a complete operational prompt")
            self.base_prompt = prompt[:-1]

    return FencedPaloAltoSSH(**params)


class PanosSshClient:
    """One direct firewall session. No caller can submit an arbitrary command."""

    def __init__(self, host, username, password, *, port=22, ssh_strict=True):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        if type(ssh_strict) is not bool:
            raise ValueError("SSH host-key checking must be a Boolean")
        self._params = {
            "device_type": "paloalto_panos",
            "host": str(host),
            "username": username,
            "password": password,
            "port": port,
            "ssh_strict": ssh_strict,
            "system_host_keys": True,
            "conn_timeout": 15,
            "auth_timeout": 20,
            "banner_timeout": 20,
            "fast_cli": False,
            "allow_agent": False,
            "use_keys": False,
        }
        self.conn = None
        self.trace = []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def open(self):
        if self.conn is not None:
            return
        try:
            self.conn = _panos_connection(self._params)
            for command in SESSION_PREP:
                self._send(command, timeout=30, presentation=True)
        except ImportError:
            raise SshError("PAN-OS SSH requires Netmiko on the Nautobot worker") from None
        except Exception as exc:
            self.close()
            _cancel(exc)
            if isinstance(exc, SshError):
                raise
            raise SshError("PAN-OS SSH connection or session preparation failed") from None

    def _send(self, command, *, timeout, presentation=False):
        record = {"command": command, "presentation": presentation, "error": None}
        self.trace.append(record)
        start = time.monotonic()
        try:
            return self.conn.send_command(
                command,
                read_timeout=timeout,
                strip_prompt=True,
                strip_command=True,
                expect_string=PROMPT_PATTERN,
                auto_find_prompt=False,
            )
        except Exception as exc:
            _cancel(exc)
            record["error"] = "SSH read failed or timed out"
            raise SshError("PAN-OS SSH read failed or timed out: %s" % command) from None
        finally:
            record["elapsed_ms"] = int((time.monotonic() - start) * 1000)

    def run(self, command, *, timeout=60):
        if not is_read_command(command):
            raise ValueError("PAN-OS discovery command is not in the exact read allowlist")
        if type(timeout) not in (int, float) or not 1 <= timeout <= 120:
            raise ValueError("SSH read timeout must be between 1 and 120 seconds")
        self.open()
        return self._send(command, timeout=timeout)

    def close(self):
        if self.conn is not None:
            try:
                self.conn.disconnect()
            except Exception as exc:
                _cancel(exc)
            finally:
                self.conn = None
