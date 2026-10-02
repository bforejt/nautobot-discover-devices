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
