"""Optional native VPN relationship detection without Django or database access."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests._loader import load

native = load("nautobot_panos_vpn")


def compatible_models():
    models = {}
    for name, names in native.FIELDS.items():
        fields = [SimpleNamespace(name=field) for field in names]
        if name == "VPNTunnelEndpoint":
            prefixes = next(field for field in fields if field.name == "protected_prefixes")
            prefixes.is_relation = True
            prefixes.many_to_many = True
            prefixes.auto_created = False
            prefixes.remote_field = SimpleNamespace(
                model=SimpleNamespace(_meta=SimpleNamespace(label_lower="ipam.prefix"))
            )
        models[name] = SimpleNamespace(_meta=SimpleNamespace(get_fields=lambda rows=fields: rows))
    return models


class PanosVpnCapabilitiesTests(unittest.TestCase):
    def test_forward_prefix_many_to_many_is_supported(self):
        capabilities = native._capabilities(compatible_models())
        self.assertIsNotNone(capabilities)
        self.assertIn("protected_prefixes", capabilities["VPNTunnelEndpoint"]["fields"])

    def test_missing_or_incompatible_prefix_relation_is_report_only(self):
        changes = (
            "missing",
            {"is_relation": False},
            {"many_to_many": False},
            {"auto_created": True},
            {
                "remote_field": SimpleNamespace(
                    model=SimpleNamespace(_meta=SimpleNamespace(label_lower="ipam.ipaddress"))
                )
            },
            {"remote_field": SimpleNamespace(model="ipam.Prefix")},
        )
        for change in changes:
            with self.subTest(change=change):
                models = compatible_models()
                fields = models["VPNTunnelEndpoint"]._meta.get_fields()
                prefixes = next(field for field in fields if field.name == "protected_prefixes")
                if change == "missing":
                    fields.remove(prefixes)
                else:
                    for name, value in change.items():
                        setattr(prefixes, name, value)
                self.assertIsNone(native._capabilities(models))
                with patch.object(native, "_models", return_value=models):
                    snapshot = native.snapshot_panos_vpn(
                        SimpleNamespace(), {"contract": "panos-vpn-policy-v1", "tunnels": []}
                    )
                self.assertFalse(snapshot["supported"])
                self.assertEqual(snapshot["catalog"], {})
                self.assertEqual(snapshot["prefixes"], [])

    def test_absent_optional_models_remain_report_only(self):
        self.assertIsNone(native._capabilities(None))
        with patch.object(native, "_models", return_value=None):
            snapshot = native.snapshot_panos_vpn(SimpleNamespace(), None)
        self.assertFalse(snapshot["supported"])
        self.assertFalse(snapshot["catalog"])


if __name__ == "__main__":
    unittest.main()
