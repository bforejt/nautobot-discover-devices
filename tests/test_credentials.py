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


if __name__ == "__main__":
    unittest.main()
