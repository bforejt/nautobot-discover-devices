"""Small, fenced PAN-OS SSH/XML transport with sanitized diagnostics.

Adapted from nautobot-testsuite/jobs/transport_ssh.py at commit
7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9 (Apache-2.0). Modified to accept
only discovery's exact reads, load Netmiko lazily, and suppress secret-bearing
transport exceptions. Session preparation changes presentation only.
"""

import time

SYSTEM_INFO = "show system info"
INTERFACES = "show interface all"
VM_INTERFACES = "debug show vm-series interfaces all"
RUNNING_INTERFACES = "show config effective-running xpath devices/entry/network/interface"
SESSION_PREP = ("set cli pager off", "set cli op-command-xml-output on")
READ_COMMANDS = frozenset((SYSTEM_INFO, INTERFACES, RUNNING_INTERFACES, VM_INTERFACES))


class SshError(RuntimeError):
    """An operator-safe SSH failure; remote messages are never interpolated."""


def _cancel(exc):
    if type(exc).__name__ == "SoftTimeLimitExceeded":
        raise exc


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
            from netmiko import ConnectHandler

            self.conn = ConnectHandler(**self._params)
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
                command, read_timeout=timeout, strip_prompt=True, strip_command=True
            )
        except Exception as exc:
            _cancel(exc)
            record["error"] = "SSH read failed or timed out"
            raise SshError("PAN-OS SSH read failed or timed out: %s" % command) from None
        finally:
            record["elapsed_ms"] = int((time.monotonic() - start) * 1000)

    def run(self, command, *, timeout=60):
        if command not in READ_COMMANDS:
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
