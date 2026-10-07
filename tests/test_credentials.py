"""Secrets Group credential resolution without Nautobot or real secrets."""

import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from tests._loader import load

credentials = load("credentials")


class MissingAssociation(Exception):
    pass


class CredentialTests(unittest.TestCase):
    def setUp(self):
        choices = ModuleType("nautobot.extras.choices")
        choices.SecretsGroupAccessTypeChoices = SimpleNamespace(
            TYPE_HTTP="HTTP", TYPE_GENERIC="Generic"
        )
        choices.SecretsGroupSecretTypeChoices = SimpleNamespace(
            TYPE_USERNAME="Username", TYPE_PASSWORD="Password"
        )
        secrets = ModuleType("nautobot.extras.models.secrets")
        secrets.SecretsGroupAssociation = SimpleNamespace(DoesNotExist=MissingAssociation)
        self.modules = patch.dict(
            sys.modules,
            {"nautobot.extras.choices": choices, "nautobot.extras.models.secrets": secrets},
        )
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_generic_fallback_and_override_use_selected_device_context(self):
        def lookup(access_type, secret_type, obj):
            if access_type == "HTTP":
                raise MissingAssociation
            return {"Username": "example-user", "Password": "example-password"}[secret_type]

        override = SimpleNamespace(get_secret_value=Mock(side_effect=lookup))
        own_group = SimpleNamespace(get_secret_value=Mock())
        device = SimpleNamespace(secrets_group=own_group)
        self.assertEqual(
            credentials.resolve_credentials(device, override), ("example-user", "example-password")
        )
        own_group.get_secret_value.assert_not_called()
        self.assertTrue(
            all(call.kwargs["obj"] is device for call in override.get_secret_value.call_args_list)
        )

    def test_ssh_prefers_ssh_and_never_uses_http(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_SSH = "SSH"
        group = SimpleNamespace(
            get_secret_value=Mock(
                side_effect=lambda access_type, secret_type, obj: {
                    "Username": "example-ssh-user",
                    "Password": "example-ssh-password",
                }[secret_type]
            )
        )
        device = SimpleNamespace(secrets_group=group)
        self.assertEqual(
            credentials.resolve_credentials(device, transport="ssh"),
            ("example-ssh-user", "example-ssh-password"),
        )
        self.assertEqual(
            [call.kwargs["access_type"] for call in group.get_secret_value.call_args_list],
            ["SSH", "SSH"],
        )

    def test_ssh_generic_fallback_preserves_override_context(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_SSH = "SSH"

        def lookup(access_type, secret_type, obj):
            if access_type == "SSH":
                raise MissingAssociation
            self.assertEqual(access_type, "Generic")
            return {"Username": "example-user", "Password": "example-password"}[secret_type]

        override = SimpleNamespace(get_secret_value=Mock(side_effect=lookup))
        own_group = SimpleNamespace(get_secret_value=Mock())
        device = SimpleNamespace(secrets_group=own_group)
        self.assertEqual(
            credentials.resolve_credentials(device, override, transport="ssh"),
            ("example-user", "example-password"),
        )
        own_group.get_secret_value.assert_not_called()
        self.assertTrue(
            all(call.kwargs["obj"] is device for call in override.get_secret_value.call_args_list)
        )

    def test_restconf_precedence_is_unchanged_when_ssh_exists(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_SSH = "SSH"
        choices.TYPE_RESTCONF = "RESTCONF"
        choices.TYPE_REST = "REST"
        group = SimpleNamespace(get_secret_value=Mock(return_value="example-value"))
        credentials.resolve_credentials(SimpleNamespace(secrets_group=group))
        self.assertEqual(
            [call.kwargs["access_type"] for call in group.get_secret_value.call_args_list],
            ["RESTCONF", "RESTCONF"],
        )

    def test_ssh_provider_error_is_sanitized_without_fallback(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_SSH = "SSH"
        group = SimpleNamespace(get_secret_value=Mock(side_effect=RuntimeError("secret sentinel")))
        with self.assertRaises(credentials.CredentialsError) as raised:
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group), transport="ssh")
        self.assertNotIn("sentinel", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertEqual(group.get_secret_value.call_count, 1)

    def test_ssh_missing_credentials_name_only_eligible_access_types(self):
        group = SimpleNamespace(get_secret_value=Mock(side_effect=MissingAssociation))
        with self.assertRaises(credentials.CredentialsError) as raised:
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group), transport="ssh")
        self.assertIn("SSH or Generic", str(raised.exception))
        self.assertNotIn("HTTP", str(raised.exception))

    def test_unknown_transport_is_rejected_before_provider_lookup(self):
        group = SimpleNamespace(get_secret_value=Mock())
        with self.assertRaises(credentials.CredentialsError):
            credentials.resolve_credentials(
                SimpleNamespace(secrets_group=group), transport="telnet"
            )
        group.get_secret_value.assert_not_called()

    def test_provider_exception_text_is_suppressed(self):
        group = SimpleNamespace(
            get_secret_value=Mock(side_effect=RuntimeError("example-password provider dump"))
        )
        with self.assertRaises(credentials.CredentialsError) as raised:
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group))
        self.assertNotIn("example-password", str(raised.exception))
        self.assertNotIn("provider dump", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)

    def test_missing_group_or_empty_credential_is_explicit(self):
        with self.assertRaises(credentials.CredentialsError):
            credentials.resolve_credentials(SimpleNamespace(secrets_group=None))
        group = SimpleNamespace(get_secret_value=Mock(return_value=""))
        with self.assertRaises(credentials.CredentialsError):
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group))

    def test_esxi_http_pair_precedes_rest_and_generic_without_restconf_or_ssh(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_REST = "REST"
        choices.TYPE_RESTCONF = "RESTCONF"
        choices.TYPE_SSH = "SSH"
        group = SimpleNamespace(get_secret_value=Mock(return_value="example-value"))
        credentials.resolve_credentials(SimpleNamespace(secrets_group=group), transport="esxi")
        self.assertEqual(
            [call.kwargs["access_type"] for call in group.get_secret_value.call_args_list],
            ["HTTP", "HTTP"],
        )

    def test_esxi_partial_http_pair_falls_back_to_complete_rest_pair(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_REST = "REST"
        device = SimpleNamespace(secrets_group=None)

        def lookup(access_type, secret_type, obj):
            self.assertIs(obj, device)
            if access_type == "HTTP":
                if secret_type == "Password":
                    raise MissingAssociation
                return "wrong-http-user"
            self.assertEqual(access_type, "REST")
            return {"Username": "rest-user", "Password": "rest-password"}[secret_type]

        override = SimpleNamespace(get_secret_value=Mock(side_effect=lookup))
        self.assertEqual(
            credentials.resolve_credentials(device, override, transport="esxi"),
            ("rest-user", "rest-password"),
        )

    def test_esxi_never_combines_credentials_from_different_access_types(self):
        def lookup(access_type, secret_type, obj):
            if (access_type, secret_type) == ("HTTP", "Username"):
                return "http-user"
            if (access_type, secret_type) == ("Generic", "Password"):
                return "generic-password"
            raise MissingAssociation

        group = SimpleNamespace(get_secret_value=Mock(side_effect=lookup))
        with self.assertRaisesRegex(credentials.CredentialsError, "usable username/password pair"):
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group), transport="esxi")

    def test_esxi_empty_pair_can_fall_back_to_generic_pair(self):
        def lookup(access_type, secret_type, obj):
            if access_type == "HTTP":
                return " " if secret_type == "Username" else "http-password"
            return {"Username": "generic-user", "Password": "generic-password"}[secret_type]

        group = SimpleNamespace(get_secret_value=Mock(side_effect=lookup))
        self.assertEqual(
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group), transport="esxi"),
            ("generic-user", "generic-password"),
        )

    def test_esxi_provider_error_is_sanitized_without_fallback(self):
        group = SimpleNamespace(get_secret_value=Mock(side_effect=RuntimeError("secret sentinel")))
        with self.assertRaises(credentials.CredentialsError) as raised:
            credentials.resolve_credentials(SimpleNamespace(secrets_group=group), transport="esxi")
        self.assertNotIn("sentinel", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertEqual(group.get_secret_value.call_count, 1)

    def test_esxi_worker_cancellation_is_not_swallowed(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        exceptions = ModuleType("billiard.exceptions")
        exceptions.SoftTimeLimitExceeded = SoftTimeLimitExceeded
        group = SimpleNamespace(get_secret_value=Mock(side_effect=SoftTimeLimitExceeded("cancel")))
        with patch.dict(sys.modules, {"billiard.exceptions": exceptions}):
            with self.assertRaises(SoftTimeLimitExceeded):
                credentials.resolve_credentials(
                    SimpleNamespace(secrets_group=group), transport="esxi"
                )


class ProxmoxCredentialTests(unittest.TestCase):
    setUp = CredentialTests.setUp

    def test_http_token_and_linux_ssh_pairs_are_selected_independently(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_SSH = "SSH"
        choices.TYPE_RESTCONF = "RESTCONF"
        choices.TYPE_REST = "REST"
        values = {
            "HTTP": {"Username": "reader@pve!discovery", "Password": "api-token"},
            "SSH": {"Username": "linux-user", "Password": "linux-password"},
        }
        group = SimpleNamespace(
            get_secret_value=Mock(
                side_effect=lambda access_type, secret_type, obj: values[access_type][secret_type]
            )
        )
        device = SimpleNamespace(secrets_group=group)
        self.assertEqual(
            credentials.resolve_credentials(device, transport="proxmox"),
            ("reader@pve!discovery", "api-token"),
        )
        self.assertEqual(
            credentials.resolve_credentials(device, transport="proxmox_ssh"),
            ("linux-user", "linux-password"),
        )
        self.assertEqual(
            [call.kwargs["access_type"] for call in group.get_secret_value.call_args_list],
            ["HTTP", "HTTP", "SSH", "SSH"],
        )

    def test_partial_http_pair_cannot_borrow_rest_password(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_REST = "REST"

        def lookup(access_type, secret_type, obj):
            if access_type == "HTTP" and secret_type == "Username":
                return "partial@pve!token"
            if access_type == "HTTP":
                raise MissingAssociation
            return {"Username": "complete@pve!token", "Password": "paired-rest-secret"}[secret_type]

        group = SimpleNamespace(get_secret_value=Mock(side_effect=lookup))
        self.assertEqual(
            credentials.resolve_credentials(
                SimpleNamespace(secrets_group=group), transport="proxmox"
            ),
            ("complete@pve!token", "paired-rest-secret"),
        )

    def test_generic_or_api_password_is_never_an_ssh_fallback(self):
        choices = sys.modules["nautobot.extras.choices"].SecretsGroupAccessTypeChoices
        choices.TYPE_SSH = "SSH"
        group = SimpleNamespace(get_secret_value=Mock(side_effect=MissingAssociation))
        for transport in ("proxmox", "proxmox_ssh"):
            with self.assertRaises(credentials.CredentialsError):
                credentials.resolve_credentials(
                    SimpleNamespace(secrets_group=group), transport=transport
                )
        self.assertEqual(
            [call.kwargs["access_type"] for call in group.get_secret_value.call_args_list],
            ["HTTP", "SSH"],
        )

    def test_provider_error_remains_sanitized_without_trying_another_pair(self):
        group = SimpleNamespace(get_secret_value=Mock(side_effect=RuntimeError("private-token")))
        with self.assertRaises(credentials.CredentialsError) as raised:
            credentials.resolve_credentials(
                SimpleNamespace(secrets_group=group), transport="proxmox"
            )
        self.assertNotIn("private-token", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertEqual(group.get_secret_value.call_count, 1)


if __name__ == "__main__":
    unittest.main()
