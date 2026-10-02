"""Network-boundary regression tests using a mocked requests session."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from tests._loader import load

transport = load("transport_restconf")


def response(status=200, payload=None):
    return SimpleNamespace(status_code=status, content=b"{}", json=Mock(return_value=payload or {}))


class RestconfTransportTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.session.headers = {}
        self.session.get.return_value = response(payload={"example:leaf": "value"})
        self.session_patch = patch.object(transport.requests, "Session", return_value=self.session)
        self.session_patch.start()
        self.addCleanup(self.session_patch.stop)

    def test_only_get_json_is_requested_with_verified_tls(self):
        with transport.RestconfClient("192.0.2.1", "example-user", "example-password") as client:
            self.assertEqual(client.get("/data/example:leaf"), {"example:leaf": "value"})
        self.session.get.assert_called_once_with(
            "https://192.0.2.1:443/restconf/data/example:leaf",
            verify=True,
            timeout=(10, 60),
            allow_redirects=False,
        )
        self.assertEqual(self.session.headers["Accept"], "application/yang-data+json")
        self.assertFalse(self.session.trust_env)
        self.session.close.assert_called_once()
        self.session.post.assert_not_called()
        self.session.put.assert_not_called()
        self.session.patch.assert_not_called()
        self.session.delete.assert_not_called()

    def test_redirect_is_rejected_without_following_authenticated_connection(self):
        self.session.get.return_value = response(status=302)
        client = transport.RestconfClient("192.0.2.1", "example-user", "example-password")
        with self.assertRaises(transport.RestconfError) as raised:
            client.get("/data/example:leaf")
        self.assertEqual(raised.exception.status_code, 302)
        self.assertEqual(self.session.get.call_count, 1)
        self.assertFalse(self.session.get.call_args.kwargs["allow_redirects"])

    def test_non_json_and_non_object_payloads_do_not_masquerade_as_empty_data(self):
        client = transport.RestconfClient("192.0.2.1", "example-user", "example-password")
        self.session.get.return_value.json.side_effect = ValueError("sensitive body example")
        with self.assertRaises(transport.RestconfError) as raised:
            client.get("/data/example:leaf")
        self.assertNotIn("sensitive body example", str(raised.exception))
        self.session.get.return_value.json.side_effect = None
        self.session.get.return_value.json.return_value = ["unexpected", "array"]
        with self.assertRaises(transport.RestconfError):
            client.get("/data/example:leaf")

    def test_trace_and_transport_errors_do_not_include_credentials_or_body(self):
        self.session.get.side_effect = requests.RequestException("example-password raw body")
        client = transport.RestconfClient("192.0.2.1", "example-user", "example-password")
        with self.assertRaises(transport.RestconfError) as raised:
            client.get("/data/example:leaf")
        for text in (str(raised.exception), str(client.trace)):
            self.assertNotIn("example-password", text)
            self.assertNotIn("example-user", text)
            self.assertNotIn("raw body", text)

    def test_invalid_data_paths_do_not_send_requests(self):
        client = transport.RestconfClient("192.0.2.1", "example-user", "example-password")
        for path in (
            "https://example.com/data/example:leaf",
            "/operations/example:action",
            "/data/../operations/example:action",
            "/data/example:leaf#fragment",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                client.get(path)
        self.session.get.assert_not_called()

    def test_tls_failure_cannot_downgrade_verified_session(self):
        self.session.get.side_effect = requests.exceptions.SSLError("TLS failure")
        client = transport.RestconfClient("192.0.2.1", "example-user", "example-password")
        with self.assertRaises(transport.RestconfError) as raised:
            client.get("/data/example:leaf")
        self.assertIn("Verify TLS enabled", str(raised.exception))
        self.assertIn("explicitly uncheck Verify TLS on this run", str(raised.exception))
        self.assertEqual(self.session.get.call_count, 1)
        self.session.mount.assert_not_called()

    def test_explicit_unverified_session_can_retry_legacy_tls(self):
        self.session.get.side_effect = [
            requests.exceptions.SSLError("TLS failure"),
            response(payload={"example:leaf": "value"}),
        ]
        client = transport.RestconfClient(
            "192.0.2.1", "example-user", "example-password", verify=False
        )
        self.assertEqual(client.get("/data/example:leaf"), {"example:leaf": "value"})
        self.assertEqual(self.session.get.call_count, 2)
        self.assertEqual(client.tls_mode, "legacy")
        self.assertTrue(all(not call.kwargs["verify"] for call in self.session.get.call_args_list))

    def test_ipv6_management_address_is_bracketed(self):
        client = transport.RestconfClient("2001:db8::1", "example-user", "example-password")
        client.get("/data/example:leaf")
        self.assertEqual(
            self.session.get.call_args.args[0],
            "https://[2001:db8::1]:443/restconf/data/example:leaf",
        )


if __name__ == "__main__":
    unittest.main()
