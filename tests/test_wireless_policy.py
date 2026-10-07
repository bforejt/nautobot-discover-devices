"""Admission is explicit native configuration, including controller-scoped placement."""

import json
import unittest
from copy import deepcopy
from unittest.mock import Mock

from tests._loader import load

policy = load("wireless_policy")
CONTROLLER = "00000001-0000-4000-8000-000000000001"
TARGET = "00000002-0000-4000-8000-000000000002"
MAC = "00:11:22:33:44:55"


class WirelessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.resolver = Mock(
            side_effect=lambda kind, identifier: {
                "id": identifier,
                "name": "Cisco" if kind == "manufacturer" else kind,
                "controller_id": CONTROLLER,
                "serial": "",
                "interfaces": [{"mac_address": MAC}],
            }
        )

    def normalize(self, value):
        return policy.normalize_wireless_policy(value, self.resolver, controller_id=CONTROLLER)

    def test_partial_policy_requires_no_admission_defaults(self):
        for value in (None, "", " ", "{}", {}):
            self.assertEqual(
                self.normalize(value),
                {
                    "contract": "wireless-policy-v1",
                    "controller_id": CONTROLLER,
                    "locations": [],
                    "identity_bindings": [],
                },
            )
        self.resolver.assert_not_called()

    def test_explicit_native_targets_and_location_are_resolved(self):
        raw = {key: TARGET for key in policy.TARGETS}
        raw.update(
            naming="reported",
            ethernet_enabled=False,
            locations=[{"match": {"site_tag": "REMOTE", "floor_label": "2"}, "location": TARGET}],
        )
        result = self.normalize(json.dumps(raw))
        self.assertEqual(result["managed_group"]["controller_id"], CONTROLLER)
        self.assertIs(result["ethernet_enabled"], False)
        self.assertEqual(result["locations"][0]["match"]["floor_label"], "2")
        self.assertEqual(self.resolver.call_count, 6)

    def test_invalid_policy_shapes_do_not_lookup_native_records(self):
        for value in (
            False,
            [],
            "[]",
            "invalid",
            {"guess": True},
            {"ethernet_enabled": 1},
            {"naming": "random"},
            {"manufacturer": "Cisco"},
            {"locations": [{}]},
            {"locations": [{"match": {}, "location": TARGET}]},
            {"locations": [{"match": {"switch_name": "SW"}, "location": TARGET}]},
            {"identity_bindings": [{"serial": "AP", "device": "AP-name"}]},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.normalize(value)
        self.resolver.assert_not_called()

    def test_other_controller_group_is_rejected(self):
        self.resolver.return_value = None
        self.resolver.side_effect = lambda kind, identifier: {
            "id": identifier,
            "controller_id": TARGET,
        }
        with self.assertRaisesRegex(ValueError, "collecting Controller"):
            self.normalize({"managed_group": TARGET})

    def test_other_manufacturer_and_incompatible_platform_are_rejected(self):
        self.resolver.side_effect = lambda kind, identifier: {"id": identifier, "name": "Acme"}
        with self.assertRaisesRegex(ValueError, "Cisco"):
            self.normalize({"manufacturer": TARGET})
        self.resolver.side_effect = lambda kind, identifier: {
            "id": identifier,
            "name": "Cisco",
            "manufacturer_id": CONTROLLER,
        }
        with self.assertRaisesRegex(ValueError, "different Manufacturer"):
            self.normalize({"manufacturer": TARGET, "platform": TARGET})

    def test_multicast_and_malformed_mac_bindings_are_rejected(self):
        for value in ("01:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "0:01122334455", "000000000000"):
            self.assertIsNone(policy.canonical_mac(value))

    def test_missing_or_different_native_uuid_is_rejected(self):
        for row in (None, {"id": CONTROLLER}):
            self.resolver.side_effect = None
            self.resolver.return_value = row
            with self.assertRaises(ValueError):
                self.normalize({"platform": TARGET})

    def test_blank_serial_binding_requires_native_mac_corroboration(self):
        result = self.normalize(
            {
                "identity_bindings": [
                    {
                        "serial": "SERIAL1",
                        "device": TARGET,
                        "ethernet_mac": "0011.2233.4455",
                    }
                ]
            }
        )
        self.assertEqual(result["identity_bindings"][0]["ethernet_mac"], MAC)
        for mac in (None, "00:11:22:33:44:66"):
            row = {"serial": "SERIAL1", "device": TARGET}
            if mac:
                row["ethernet_mac"] = mac
            with self.subTest(mac=mac), self.assertRaisesRegex(ValueError, "independently"):
                self.normalize({"identity_bindings": [row]})

    def test_conflicting_populated_serial_cannot_be_bound(self):
        self.resolver.side_effect = lambda kind, identifier: {"id": identifier, "serial": "OTHER"}
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.normalize({"identity_bindings": [{"serial": "SERIAL1", "device": TARGET}]})

    def test_duplicate_bindings_fail_before_lookups(self):
        row = {"serial": "SERIAL1", "device": TARGET, "ethernet_mac": MAC}
        with self.assertRaises(ValueError):
            self.normalize({"identity_bindings": [row, deepcopy(row)]})
        self.resolver.assert_not_called()

    def test_policy_input_and_resolver_rows_are_not_mutated(self):
        raw = {"locations": [{"match": {"serial": "SERIAL1"}, "location": TARGET}]}
        original = deepcopy(raw)
        resolved = {"id": TARGET, "name": "Site"}
        self.resolver.side_effect = None
        self.resolver.return_value = resolved
        result = self.normalize(raw)
        result["locations"][0]["location"]["name"] = "Changed"
        self.assertEqual(raw, original)
        self.assertEqual(resolved["name"], "Site")


if __name__ == "__main__":
    unittest.main()
