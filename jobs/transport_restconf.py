"""GET-only RESTCONF JSON transport.

Adapted from nautobot-testsuite/jobs/transport_restconf.py (Apache-2.0),
with verified TLS by default, redirect rejection, and sanitized diagnostics.
"""

import ipaddress
import re
import ssl
import time
import warnings
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning


class RestconfError(RuntimeError):
    """An operator-safe transport failure, including an optional HTTP status."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class _LegacyTlsAdapter(HTTPAdapter):
    """Compatibility context mounted only when verification is explicitly off."""

    def init_poolmanager(self, *args, **kwargs):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass
        context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)


def _host_for_url(host):
    host = str(host).strip()
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        return "[%s]" % address if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ValueError("RESTCONF host must be an IP address or DNS name") from None
        return host


class RestconfClient:
    """One device session; no method can change the remote device."""

    def __init__(self, host, username, password, *, port=443, verify=True):
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("RESTCONF port must be between 1 and 65535")
        if not isinstance(verify, bool):
            raise ValueError("TLS verification must be a boolean")
        self.host = str(host)
        self.base = "https://%s:%s/restconf" % (_host_for_url(host), port)
        self.verify = verify
        self.tls_mode = "default"
        self.trace = []
        self.session = requests.Session()
        # Ignore proxy and netrc environment overrides for this authenticated
        # management connection. Authentication belongs only to this session.
        self.session.trust_env = False
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/yang-data+json"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.session.close()

    def enable_legacy_tls(self):
        if self.verify:
            raise ValueError("Legacy TLS requires explicitly disabled certificate verification")
        self.session.mount("https://", _LegacyTlsAdapter())
        self.tls_mode = "legacy"

    def _request(self, path, timeout):
        record = {"path": path, "status": None, "tls_mode": self.tls_mode, "error": None}
        start = time.monotonic()
        self.trace.append(record)
        try:
            # Limit warning suppression to the explicitly unverified request.
            with warnings.catch_warnings():
                if not self.verify:
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                response = self.session.get(
                    self.base + path,
                    verify=self.verify,
                    timeout=(10, timeout),
                    allow_redirects=False,
                )
            record["status"] = response.status_code
            return response, record
        except requests.exceptions.SSLError:
            record["error"] = "TLS handshake failed"
            raise
        except requests.RequestException:
            record["error"] = "Connection failed or timed out"
            raise RestconfError("GET %s: connection failed or timed out" % path) from None
        finally:
            record["elapsed_ms"] = int((time.monotonic() - start) * 1000)

    def get(self, path, *, timeout=60, ok_404=False):
        """Return a JSON object; record no response bodies or authentication data."""
        if not isinstance(path, str) or not path.startswith("/data/"):
            raise ValueError("RESTCONF GET requires a /data/ path")
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or "\\" in path or ".." in parsed.path:
            raise ValueError("Invalid RESTCONF data path")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 1 <= timeout <= 120
        ):
            raise ValueError("RESTCONF read timeout must be between 1 and 120 seconds")
        try:
            response, record = self._request(path, timeout)
        except requests.exceptions.SSLError:
            if self.verify:
                raise RestconfError(
                    "GET %s: TLS handshake or certificate verification failed with Verify TLS "
                    "enabled. Use a certificate trusted by the worker; for a lab with a "
                    "self-signed certificate, explicitly uncheck Verify TLS on this run." % path
                ) from None
            if self.tls_mode != "default":
                raise RestconfError("GET %s: TLS handshake failed" % path) from None
            self.enable_legacy_tls()
            try:
                response, record = self._request(path, timeout)
            except requests.exceptions.SSLError:
                raise RestconfError("GET %s: TLS handshake failed" % path) from None
        status = response.status_code
        if status == 404 and ok_404:
            return None
        if not 200 <= status < 300:
            record["error"] = "HTTP %s" % status
            raise RestconfError("GET %s: HTTP %s" % (path, status), status_code=status)
        if status == 204 or not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError:
            record["error"] = "Invalid JSON response"
            raise RestconfError("GET %s: response is not JSON" % path, status_code=status) from None
        if not isinstance(payload, dict):
            record["error"] = "JSON object required"
            raise RestconfError("GET %s: JSON object required" % path, status_code=status)
        return payload
