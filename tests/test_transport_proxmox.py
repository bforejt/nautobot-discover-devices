"""Synthetic Proxmox API/SSH boundary tests; no live lab credentials or reads."""

import base64
import hashlib
import io
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from tests._loader import load

transport = load("transport_proxmox")
sources = load("proxmox_sources")
TOKEN = "fixture-reader@pve!inventory"
SECRET = "fixture-api-secret-value"
SSH_SECRET = "fixture-linux-password"
NODE = "pve-fixture"


def response(data=None, *, body=None, status=200, **fields):
    result = Mock()
    result.status_code = status
    result.iter_content.return_value = [
        body if body is not None else json.dumps({"data": data, **fields}).encode()
    ]
    return result


def local():
    return [{"type": "node", "name": NODE, "local": 1}]


class Channel:
    def __init__(self, stdout=b"[]", stderr=b"", status=0, *, eof=True):
        self.stdout = [stdout] if stdout else []
        self.stderr = [stderr] if stderr else []
        self.status = status
        self.eof_received = eof
        self.closed = False
        self.commands = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def exec_command(self, command):
        self.commands.append(command)

    def shutdown_write(self):
        pass

    def recv_ready(self):
        return bool(self.stdout)

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv(self, _count):
        return self.stdout.pop(0)

    def recv_stderr(self, _count):
        return self.stderr.pop(0)

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.closed = True


class ProxmoxTransportTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.session.headers = {}
        session_patch = patch.object(transport.requests, "Session", return_value=self.session)
        session_patch.start()
        self.addCleanup(session_patch.stop)
        self.ssh = Mock()
        self.ssh_transport = Mock()
        self.ssh_transport.is_active.return_value = True
        self.ssh.get_transport.return_value = self.ssh_transport
        self.channel = Channel()
        self.ssh_transport.open_session.return_value = self.channel
        self.paramiko = SimpleNamespace(
            SSHClient=Mock(return_value=self.ssh),
            RejectPolicy=type("RejectPolicy", (), {}),
            MissingHostKeyPolicy=type("MissingHostKeyPolicy", (), {}),
        )
        self.paramiko_patch = patch.dict(sys.modules, {"paramiko": self.paramiko})
        self.paramiko_patch.start()
        self.addCleanup(self.paramiko_patch.stop)

    def client(self, **options):
        return transport.ProxmoxClient(
            "192.0.2.104", TOKEN, SECRET, "fixture-linux", SSH_SECRET, **options
        )

    def pin(self, client):
        self.session.get.return_value = response(local())
        client.get("/cluster/status")
        self.session.get.reset_mock()

    def guests(self, client, kind="qemu", vmids=(100,)):
        self.session.get.return_value = response([{"vmid": vmid} for vmid in vmids])
        client.get(f"/nodes/{NODE}/{kind}")
        self.session.get.reset_mock()

    def test_token_https_is_get_only_verified_and_no_environment_proxies(self):
        self.session.get.return_value = response({"version": "9.0.3"})
        with self.client() as client:
            self.assertEqual(client.get("/version"), {"version": "9.0.3"})
            self.assertEqual(self.session.headers["Authorization"], f"PVEAPIToken={TOKEN}={SECRET}")
            self.assertIs(self.session.trust_env, False)
            self.assertEqual(client.trace[0]["outcome"], "complete")
        call = self.session.get.call_args
        self.assertEqual(call.args[0], "https://192.0.2.104:8006/api2/json/version")
        self.assertIs(call.kwargs["verify"], True)
        self.assertIs(call.kwargs["allow_redirects"], False)
        self.assertIs(call.kwargs["stream"], True)
        self.session.post.assert_not_called()
        self.session.close.assert_called_once()
        self.assertNotIn("Authorization", self.session.headers)
        self.assertNotIn(SECRET, json.dumps(client.trace))

    def test_envelope_retains_pending_network_changes(self):
        client = self.client()
        self.pin(client)
        self.session.get.return_value = response([{"iface": "vmbr0"}], changes=True)
        self.assertEqual(client.get_envelope(f"/nodes/{NODE}/network")["changes"], True)
        self.assertEqual(client.get(f"/nodes/{NODE}/network"), [{"iface": "vmbr0"}])

    def test_exact_api_paths_and_query_shapes_refuse_shell_and_write_surfaces(self):
        bad = (
            ("/nodes/pve/reboot", None),
            ("/nodes/pve/qemu/100/status/start", None),
            ("/nodes/pve/qemu/100/agent/network-get-interfaces", None),
            ("/nodes/pve/qemu/100/config?current=1", None),
            ("/version", {"redirect": "https://elsewhere.example"}),
            ("/nodes/pve/status", {"current": 1}),
            ("/nodes/pve/qemu/100/config", {"current": True}),
            ("/nodes/pve/qemu/100/config", {"current": "01"}),
            ("/access/permissions", {"path": "/", "userid": TOKEN}),
            ("/access/permissions", {"path": "/nodes/../pve"}),
            ("/access/permissions", None),
            ("/cluster/status;reboot", None),
            ("https://foreign.example/version", None),
            ("/nodes/%2e%2e/status", None),
            ("/nodes/pve/status/100/config", None),
            (None, None),
        )
        client = self.client()
        for path, params in bad:
            with self.subTest(path=path, params=params), self.assertRaises(ValueError):
                client.get(path, params=params)
        self.session.get.assert_not_called()

    def test_permissions_and_current_config_queries_use_structured_params(self):
        client = self.client()
        self.pin(client)
        self.guests(client)
        for scope in ("/", "/vms", "/vms/100", f"/nodes/{NODE}", "/storage/local"):
            self.session.get.return_value = response({scope: {"VM.Audit": 0}})
            self.assertEqual(
                client.get("/access/permissions", {"path": scope}), {scope: {"VM.Audit": 0}}
            )
            self.assertEqual(self.session.get.call_args.kwargs["params"], {"path": scope})
        self.session.get.return_value = response({"name": "fixture-guest"})
        client.get(f"/nodes/{NODE}/qemu/100/config", {"current": 1})
        self.assertEqual(self.session.get.call_args.kwargs["params"], {"current": 1})

    def test_local_node_and_guest_identities_must_be_observed_before_detail_reads(self):
        client = self.client()
        for path in (f"/nodes/{NODE}/status", f"/nodes/{NODE}/qemu/100/config"):
            with self.assertRaisesRegex(transport.ProxmoxError, "API-local"):
                client.get(path)
        self.session.get.assert_not_called()
        self.pin(client)
        with self.assertRaisesRegex(transport.ProxmoxError, "API-local"):
            client.get("/nodes/foreign-node/status")
        with self.assertRaisesRegex(transport.ProxmoxError, "observed"):
            client.get(f"/nodes/{NODE}/qemu/100/config")
        self.session.get.assert_not_called()
        self.guests(client)
        self.session.get.return_value = response({"status": "stopped"})
        self.assertEqual(
            client.get(f"/nodes/{NODE}/qemu/100/status/current"), {"status": "stopped"}
        )
        with self.assertRaisesRegex(transport.ProxmoxError, "observed"):
            client.get(f"/nodes/{NODE}/lxc/100/config")

    def test_cluster_local_identity_missing_duplicate_or_changing_fails(self):
        for rows in (
            [],
            local() * 2,
            [{"name": NODE, "type": "node", "local": "1"}],
            [{"name": "pve/foreign", "type": "node", "local": 1}],
        ):
            with self.subTest(rows=rows):
                self.session.get.return_value = response(rows)
                with self.assertRaisesRegex(transport.ProxmoxError, "exactly one"):
                    self.client().get("/cluster/status")
        client = self.client()
        self.pin(client)
        self.session.get.return_value = response([{"type": "node", "name": "changed", "local": 1}])
        with self.assertRaisesRegex(transport.ProxmoxError, "changed"):
            client.get("/cluster/status")

    def test_guest_lists_refuse_invalid_duplicate_foreign_and_cross_kind_vmids(self):
        client = self.client(max_guests=2)
        self.pin(client)
        for rows in (
            [{"vmid": 100}] * 2,
            [{"vmid": "100"}],
            [{"vmid": True}],
            [{"vmid": 99}],
            [{"vmid": 100, "node": "foreign"}],
            [{"vmid": 100}, {"vmid": 101}, {"vmid": 102}],
        ):
            with self.subTest(rows=rows):
                self.session.get.return_value = response(rows)
                with self.assertRaises(transport.ProxmoxError):
                    client.get(f"/nodes/{NODE}/qemu")
        self.guests(client)
        self.session.get.return_value = response([{"vmid": 100}])
        with self.assertRaisesRegex(transport.ProxmoxError, "same VMID"):
            client.get(f"/nodes/{NODE}/lxc")

    def test_redirects_http_failures_and_server_faults_never_return_raw_bodies(self):
        for status in (301, 302, 401, 403, 404, 500):
            reply = response(body=SECRET.encode(), status=status)
            self.session.get.return_value = reply
            with self.subTest(status=status), self.assertRaises(transport.ProxmoxError) as raised:
                self.client().get("/version")
            self.assertEqual(raised.exception.status_code, status)
            self.assertNotIn(SECRET, str(raised.exception))
            reply.close.assert_called_once()
        for fault in ({"error": SECRET}, {"success": 0}, {"errors": {"token": SECRET}}):
            self.session.get.return_value = response({}, **fault)
            with self.assertRaises(transport.ProxmoxError) as raised:
                self.client().get("/version")
            self.assertNotIn(SECRET, str(raised.exception))

    def test_malformed_json_duplicate_keys_utf8_nonfinite_and_envelopes_fail_closed(self):
        for body in (
            b'{"data":{"field":1,"field":2}}',
            b'{"data":NaN}',
            b'{"data":Infinity}',
            b'{"data":1e999}',
            b'{"data":"\xff"}',
            b'{"data":',
            b"[]",
            b'{"unreviewed":[]}',
        ):
            with self.subTest(body=body):
                reply = response(body=body)
                self.session.get.return_value = reply
                with self.assertRaises(transport.ProxmoxError):
                    self.client().get("/version")
                reply.close.assert_called_once()

    def test_request_byte_aggregate_depth_and_node_budgets_are_bounded(self):
        client = self.client(max_requests=1)
        self.session.get.return_value = response({})
        client.get("/version")
        with self.assertRaisesRegex(transport.ProxmoxError, "request budget"):
            client.get("/version")
        self.assertEqual(self.session.get.call_count, 1)
        for setting, size in (
            ("MAX_JSON_BYTES", 4),
            ("MAX_TOTAL_BYTES", 4),
            ("MAX_JSON_NODES", 1),
            ("MAX_JSON_DEPTH", 0),
        ):
            with self.subTest(setting=setting), patch.object(transport, setting, size):
                self.session.get.return_value = response({"version": "9.0.3"})
                with self.assertRaisesRegex(transport.ProxmoxError, "limit|budget"):
                    self.client().get("/version")

    def test_connection_tls_and_stream_errors_are_sanitized_without_retry(self):
        for error in (requests.RequestException(SECRET), requests.exceptions.SSLError(SECRET)):
            self.session.get.side_effect = error
            with self.assertRaises(transport.ProxmoxError) as raised:
                self.client().get("/version")
            self.assertNotIn(SECRET, str(raised.exception))
        self.session.get.side_effect = None
        reply = response({})
        reply.iter_content.side_effect = requests.RequestException(SECRET)
        self.session.get.return_value = reply
        with self.assertRaises(transport.ProxmoxError) as raised:
            self.client().get("/version")
        self.assertNotIn(SECRET, str(raised.exception))
        reply.close.assert_called_once()
        self.session.mount.assert_not_called()

    def test_whole_https_read_deadline_refuses_partial_json_and_further_reads(self):
        release = transport.threading.Event()
        reply = response({})

        def slow_stream(**_kwargs):
            release.wait(0.3)
            yield b'{"data":{}}'

        reply.iter_content.side_effect = slow_stream
        self.session.get.return_value = reply
        client = self.client()
        client.timeout = 0.02
        try:
            with self.assertRaisesRegex(transport.ProxmoxError, "deadline"):
                client.get("/version")
            with self.assertRaisesRegex(transport.ProxmoxError, "new session"):
                client.get("/version")
            self.assertEqual(self.session.get.call_count, 1)
            self.assertEqual(client.trace[0]["outcome"], "failed")
        finally:
            release.set()

    def test_response_secrets_removed_and_full_envelope_retained(self):
        self.session.get.return_value = response(
            {
                "password": SECRET,
                "cipassword": SSH_SECRET,
                "sshkeys": "private data",
                "name": SECRET,
                "nested": {"Authorization": TOKEN},
            },
            changes=1,
        )
        result = self.client().get_envelope("/version")
        self.assertEqual(result, {"data": {"name": "[redacted]", "nested": {}}, "changes": 1})

    def test_ipv6_explicit_tls_exception_and_ca_path(self):
        self.session.get.return_value = response({})
        for verify in (False, "/etc/ssl/lab-ca.pem"):
            client = transport.ProxmoxClient("2001:db8::104", TOKEN, SECRET, verify=verify)
            client.get("/version")
            self.assertEqual(
                self.session.get.call_args.args[0], "https://[2001:db8::104]:8006/api2/json/version"
            )
            self.assertEqual(self.session.get.call_args.kwargs["verify"], verify)

    def test_invalid_arguments_do_not_open_connections(self):
        for host in ("https://host", "user@host", "host/path", "host?secret", "host\\path", "[x]"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                transport.ProxmoxClient(host, TOKEN, SECRET)
        for options in (
            {"verify": 1},
            {"verify": ""},
            {"port": True},
            {"ssh_port": 0},
            {"timeout": float("nan")},
            {"timeout": 0},
            {"max_requests": 0},
            {"max_guests": True},
            {"host_key_sha256": "SHA256:bad"},
            {"ssh_key_filename": "relative.key"},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.client(**options)
        for token in ("fixture-reader", "fixture-reader@pve", "reader@pve!token\nInjected"):
            with self.assertRaises(ValueError):
                transport.ProxmoxClient("192.0.2.1", token, SECRET)
        with self.assertRaises(ValueError):
            transport.ProxmoxClient("192.0.2.1", TOKEN, "secret\nInjected")
        with self.assertRaises(ValueError):
            transport.ProxmoxClient("192.0.2.1", TOKEN, SECRET, TOKEN, SECRET)
        self.session.get.assert_not_called()
        self.ssh.connect.assert_not_called()

    def test_ssh_uses_known_keys_independent_credentials_and_no_agent_pty_or_shell(self):
        with self.client() as client:
            self.assertEqual(client.ssh_json("links"), [])
        self.ssh.load_system_host_keys.assert_called_once_with()
        self.assertIsInstance(
            self.ssh.set_missing_host_key_policy.call_args.args[0], self.paramiko.RejectPolicy
        )
        params = self.ssh.connect.call_args.kwargs
        self.assertEqual(params["username"], "fixture-linux")
        self.assertEqual(params["password"], SSH_SECRET)
        self.assertIs(params["look_for_keys"], False)
        self.assertIs(params["allow_agent"], False)
        self.assertEqual(self.channel.commands, ["ip -j -s -d link show"])
        self.assertEqual(self.channel.timeout, 0.0)
        self.assertTrue(self.channel.closed)
        self.ssh.invoke_shell.assert_not_called()
        self.ssh.close.assert_called_once()

    def test_ssh_key_auth_is_explicit_and_pinned_host_key_policy_requires_match(self):
        key = Mock()
        key.asbytes.return_value = b"fixture-host-key-material"
        pin = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip(
            "="
        )
        client = self.client(host_key_sha256=pin, ssh_key_filename="/tmp/fixture-id")
        client.ssh_json("links")
        policy = self.ssh.set_missing_host_key_policy.call_args.args[0]
        policy.missing_host_key(self.ssh, "192.0.2.104", key)
        key.asbytes.return_value = b"foreign-key"
        with self.assertRaisesRegex(transport.ProxmoxError, "fingerprint"):
            policy.missing_host_key(self.ssh, "192.0.2.104", key)
        self.ssh.load_system_host_keys.assert_not_called()
        self.assertEqual(self.ssh.connect.call_args.kwargs["key_filename"], "/tmp/fixture-id")

    def test_ssh_sources_are_exact_before_any_connection(self):
        client = self.client()
        for source in ("lshw -json", "hardware;reboot", " hardware", "host\nreboot", None, []):
            with self.subTest(source=source), self.assertRaises(ValueError):
                client.ssh_json(source)
        self.ssh.connect.assert_not_called()
        for command in ("reboot", "lshw -json; reboot", "ip -j link show", None):
            with self.assertRaises(ValueError):
                client._ssh_read(command)
        self.ssh_transport.open_session.assert_not_called()
        self.assertEqual(
            set(sources.READ_COMMANDS), {"hardware", "links", "addresses", "bridge_vlans", "host"}
        )
        self.assertNotIn("/proc/cmdline", sources.HOST_SCRIPT)
        self.assertNotIn("/etc/network", sources.HOST_SCRIPT)
        self.assertNotIn("subprocess", sources.HOST_SCRIPT)
        compile(sources.HOST_SCRIPT, "fixed-reader", "exec")

    def test_fixed_host_reader_skips_network_class_control_files(self):
        opened = []

        def source_open(path, mode="r", **_options):
            opened.append(path)
            if path.startswith("/sys/class/net/bonding_masters"):
                raise NotADirectoryError
            return (
                io.BytesIO(b'{"version":1}')
                if path == "/etc/pve/.vmlist"
                else io.StringIO("fixture")
            )

        def source_glob(pattern):
            return (
                ["/sys/class/net/bonding_masters", "/sys/class/net/eno1"]
                if pattern == "/sys/class/net/*"
                else []
            )

        capture = io.StringIO()
        with (
            patch("builtins.open", source_open),
            patch("glob.glob", side_effect=source_glob),
            patch("os.path.isdir", side_effect=lambda path: path == "/sys/class/net/eno1"),
            patch("os.path.islink", return_value=False),
            patch("sys.stdout", capture),
        ):
            exec(sources.HOST_SCRIPT, {})
        result = json.loads(capture.getvalue())
        self.assertEqual(result["errors"], [])
        self.assertEqual([row["name"] for row in result["net"]], ["eno1"])
        self.assertFalse(any("bonding_masters" in path for path in opened))

    def test_fixed_registry_reader_rejects_duplicate_truncated_and_oversized_json(self):
        payloads = (
            b'{"version":1,"ids":{"100":{},"100":{"secret":"DO_NOT_PRINT"}}}',
            b'{"version":1,"version":2}',
            b'{"version":1',
            b'{"version":NaN}',
            b"\xff",
            b" " * (4 * 1024 * 1024 + 1),
        )
        for payload in payloads:

            def source_open(path, mode="r", _payload=payload, **_options):
                return (
                    io.BytesIO(_payload) if path == "/etc/pve/.vmlist" else io.StringIO("fixture")
                )

            capture = io.StringIO()
            with (
                self.subTest(payload=payload[:64]),
                patch("builtins.open", source_open),
                patch("glob.glob", return_value=[]),
                patch("sys.stdout", capture),
            ):
                exec(sources.HOST_SCRIPT, {})
            result = json.loads(capture.getvalue())
            self.assertIsNone(result["guest_registry"])
            self.assertTrue(result["errors"])
            self.assertNotIn("DO_NOT_PRINT", capture.getvalue())

    def test_fixed_registry_reader_returns_native_json_and_requires_the_file(self):
        registry = {"version": 1, "ids": {"100": {"node": NODE, "type": "qemu", "version": 1}}}

        def source_open(path, mode="r", **_options):
            return (
                io.BytesIO(json.dumps(registry).encode())
                if path == "/etc/pve/.vmlist"
                else io.StringIO("fixture")
            )

        capture = io.StringIO()
        with (
            patch("builtins.open", source_open),
            patch("glob.glob", return_value=[]),
            patch("sys.stdout", capture),
        ):
            exec(sources.HOST_SCRIPT, {})
        result = json.loads(capture.getvalue())
        self.assertEqual(result["guest_registry"], registry)
        self.assertEqual(result["errors"], [])
        capture = io.StringIO()
        with patch("builtins.open", side_effect=FileNotFoundError), patch("sys.stdout", capture):
            exec(sources.HOST_SCRIPT, {})
        self.assertIsNone(json.loads(capture.getvalue())["guest_registry"])
        self.assertTrue(json.loads(capture.getvalue())["errors"])

    def test_ssh_drains_stdout_and_stderr_through_eof_without_raw_diagnostics(self):
        self.channel = Channel(b'[{"ifname":"eno1"}]', SECRET.encode())
        self.ssh_transport.open_session.return_value = self.channel
        client = self.client()
        self.assertEqual(client.ssh_json("addresses"), [{"ifname": "eno1"}])
        self.assertEqual(client.trace[0]["stderr_bytes"], len(SECRET))
        self.assertNotIn(SECRET, json.dumps(client.trace))
        self.assertTrue(self.channel.closed)

    def test_ssh_nonzero_exit_invalid_utf8_invalid_json_and_wrong_shapes_fail(self):
        cases = (
            (Channel(b"[]", SECRET.encode(), status=1), "links"),
            (Channel(b"[]", b"\xff"), "links"),
            (Channel(b'{"a":1,"a":2}'), "host"),
            (Channel(b"{}"), "links"),
            (Channel(b"[]"), "host"),
            (Channel(b'"wrapped native text"'), "hardware"),
        )
        for channel, source in cases:
            with self.subTest(source=source):
                self.ssh_transport.open_session.return_value = channel
                with self.assertRaises(transport.ProxmoxError) as raised:
                    self.client().ssh_json(source)
                self.assertNotIn(SECRET, str(raised.exception))
                self.assertTrue(channel.closed)

    def test_ssh_stdout_and_stderr_size_budgets_refuse_truncation(self):
        for setting, channel in (
            ("MAX_JSON_BYTES", Channel(b"[]" * 100)),
            ("MAX_STDERR_BYTES", Channel(b"[]", b"x" * 100)),
        ):
            with self.subTest(setting=setting), patch.object(transport, setting, 64):
                self.ssh_transport.open_session.return_value = channel
                with self.assertRaisesRegex(transport.ProxmoxError, "byte limit"):
                    self.client().ssh_json("links")
                self.assertTrue(channel.closed)

    def test_ssh_partial_output_with_exit_status_without_eof_times_out(self):
        channel = Channel(b"[]", eof=False)
        self.ssh_transport.open_session.return_value = channel
        client = self.client()
        client.timeout = 0.03
        with self.assertRaisesRegex(transport.ProxmoxError, "partial JSON"):
            client.ssh_json("links")
        self.assertTrue(channel.closed)

    def test_ssh_exec_acknowledgement_is_bounded(self):
        event = transport.threading.Event()
        self.channel.exec_command = lambda _command: event.wait(0.2)
        client = self.client()
        client.timeout = 0.02
        with self.assertRaisesRegex(transport.ProxmoxError, "acknowledgement"):
            client.ssh_json("links")
        self.assertTrue(self.channel.closed)
        event.set()

    def test_missing_ssh_credentials_and_auth_failure_are_safe(self):
        client = transport.ProxmoxClient("192.0.2.104", TOKEN, SECRET)
        with self.assertRaisesRegex(transport.ProxmoxError, "separate SSH"):
            client.ssh_json("host")
        self.ssh.connect.assert_not_called()
        self.ssh.connect.side_effect = RuntimeError(SSH_SECRET)
        with self.assertRaises(transport.ProxmoxError) as raised:
            self.client().ssh_json("host")
        self.assertNotIn(SSH_SECRET, str(raised.exception))
        self.ssh.close.assert_called_once()

    def test_known_key_store_failure_and_cleanup_faults_do_not_expose_credentials(self):
        self.ssh.load_system_host_keys.side_effect = RuntimeError(SSH_SECRET)
        with self.assertRaises(transport.ProxmoxError) as raised:
            self.client().ssh_json("host")
        self.assertNotIn(SSH_SECRET, str(raised.exception))
        self.ssh.connect.assert_not_called()
        self.ssh.close.assert_called_once()
        self.session.close.side_effect = RuntimeError(SECRET)
        self.client().close()

    def test_ssh_connect_cancellation_closes_partial_client(self):
        self.ssh.connect.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.client().ssh_json("host")
        self.ssh.close.assert_called_once()

    def test_active_failure_survives_worker_cancellation_during_teardown(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        self.session.close.side_effect = SoftTimeLimitExceeded()
        with self.assertRaisesRegex(RuntimeError, "original failure"):
            with self.client():
                raise RuntimeError("original failure")

    def test_closed_client_refuses_api_and_ssh_and_close_is_idempotent(self):
        client = self.client()
        client.close()
        client.close()
        with self.assertRaisesRegex(transport.ProxmoxError, "closed"):
            client.get("/version")
        with self.assertRaisesRegex(transport.ProxmoxError, "closed"):
            client.ssh_json("host")
        self.session.close.assert_called_once()
        self.session.get.assert_not_called()
        self.ssh.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
