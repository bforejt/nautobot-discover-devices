"""SSH fencing, presentation setup, resource cleanup and error redaction."""

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests._loader import load

ssh = load("transport_ssh")


class SshTransportTests(unittest.TestCase):
    def setUp(self):
        self.conn = Mock()
        self.conn.send_command.return_value = '<response status="success"><result/></response>'
        self.connect = Mock(return_value=self.conn)
        self.patch = patch.dict(
            sys.modules, {"netmiko": SimpleNamespace(ConnectHandler=self.connect)}
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def client(self, **kwargs):
        return ssh.PanosSshClient("192.0.2.1", "example-user", "example-password", **kwargs)

    def test_setup_and_exact_reads_use_xml_over_ssh(self):
        with self.client() as client:
            client.run(ssh.SYSTEM_INFO)
        self.assertEqual(
            [c.args[0] for c in self.conn.send_command.call_args_list],
            list(ssh.SESSION_PREP) + [ssh.SYSTEM_INFO],
        )
        self.assertEqual(self.connect.call_args.kwargs["device_type"], "paloalto_panos")
        self.assertIs(self.connect.call_args.kwargs["ssh_strict"], True)
        self.assertIs(self.connect.call_args.kwargs["system_host_keys"], True)
        self.conn.disconnect.assert_called_once()

    def test_only_exact_vm_diagnostic_read_is_allowed_and_xml_session_is_prepared(self):
        self.assertEqual(ssh.VM_INTERFACES, "debug show vm-series interfaces all")
        self.assertEqual(
            ssh.READ_COMMANDS,
            frozenset(
                (ssh.SYSTEM_INFO, ssh.INTERFACES, ssh.RUNNING_INTERFACES, ssh.VM_INTERFACES)
                + ssh.HA_VPN_READ_COMMANDS
            ),
        )
        with self.client() as client:
            output = client.run(ssh.VM_INTERFACES)
            read = client.trace[-1]
        self.assertEqual(output, self.conn.send_command.return_value)
        self.assertEqual(
            [call.args[0] for call in self.conn.send_command.call_args_list],
            list(ssh.SESSION_PREP) + [ssh.VM_INTERFACES],
        )
        self.assertEqual(read["command"], ssh.VM_INTERFACES)
        self.assertIs(read["presentation"], False)
        self.assertIsNone(read["error"])
        self.conn.disconnect.assert_called_once()

    def test_commands_are_refused_before_opening_a_connection(self):
        for command in (
            "configure",
            "show system info; configure",
            "show interface all\ncommit",
            "show config candidate",
            "show config running",
            "request restart system",
            "set cli op-command-xml-output off",
            "debug show vm-series interfaces",
            "debug show vm-series interfaces all ",
            " debug show vm-series interfaces all",
            "Debug show vm-series interfaces all",
            "debug show vm-series interfaces all; request restart system",
            "debug show vm-series interfaces all\nconfigure",
            "debug show vm-series interfaces all | match eth1",
            "debug dataplane packet-diag set capture on",
            "show vpn flow name tunnel-a",
            "show vpn flow tunnel-id 0",
            "show vpn flow tunnel-id 65536",
            "show vpn flow tunnel-id 01",
            "show vpn flow tunnel-id +1",
            "show vpn flow tunnel-id 1; configure",
            "show vpn flow tunnel-id 1\ncommit",
            "show vpn flow tunnel-id 1 | match secret",
            "show vpn flow tunnel-id 1 ",
            " show vpn flow tunnel-id 1",
            None,
            [],
        ):
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.client().run(command)
        self.connect.assert_not_called()

    def test_numeric_flow_details_use_canonical_documented_range(self):
        with self.client() as client:
            for tunnel_id in (1, 27, 65535):
                command = ssh.vpn_flow_detail_command(tunnel_id)
                self.assertTrue(ssh.is_read_command(command))
                client.run(command)
        self.assertEqual(
            [call.args[0] for call in self.conn.send_command.call_args_list][-3:],
            [
                "show vpn flow tunnel-id 1",
                "show vpn flow tunnel-id 27",
                "show vpn flow tunnel-id 65535",
            ],
        )

    def test_numeric_flow_command_constructor_refuses_unobserved_types_and_ranges(self):
        for value in (True, False, "1", 1.0, None, 0, -1, 65536):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ssh.vpn_flow_detail_command(value)
        self.connect.assert_not_called()

    def test_auth_failure_is_sanitized(self):
        self.connect.side_effect = RuntimeError("example-user example-password raw error")
        client = self.client()
        with self.assertRaises(ssh.SshError) as raised:
            client.run(ssh.SYSTEM_INFO)
        self.assertNotIn("example-password", str(raised.exception))
        self.assertNotIn("example-user", str(raised.exception))
        self.assertIsNone(client.conn)

    def test_read_failure_trace_and_exceptions_are_sanitized(self):
        client = self.client()
        client.open()
        self.conn.send_command.side_effect = RuntimeError("example-password raw body")
        with self.assertRaises(ssh.SshError) as raised:
            client.run(ssh.INTERFACES)
        self.assertNotIn("example-password", str(raised.exception))
        self.assertNotIn("raw body", str(client.trace))
        client.close()
        self.conn.disconnect.assert_called_once()

    def test_preparation_failure_disconnects_partial_session(self):
        self.conn.send_command.side_effect = RuntimeError("secret")
        with self.assertRaises(ssh.SshError):
            self.client().open()
        self.conn.disconnect.assert_called_once()

    def test_port_timeout_and_host_key_policy_are_validated(self):
        for port in (True, 0, 65536, "22"):
            with self.assertRaises(ValueError):
                self.client(port=port)
        with self.assertRaises(ValueError):
            self.client(ssh_strict="false")
        for timeout in (True, 0, 121, "60"):
            with self.assertRaises(ValueError):
                self.client().run(ssh.SYSTEM_INFO, timeout=timeout)
        self.connect.assert_not_called()

    def test_disconnect_error_is_suppressed_without_secret_output(self):
        self.conn.disconnect.side_effect = RuntimeError("example-password")
        with self.client():
            pass


if __name__ == "__main__":
    unittest.main()
