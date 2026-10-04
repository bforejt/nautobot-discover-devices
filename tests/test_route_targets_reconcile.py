"""Literal policy projection, native identity and conservative fill-only semantics."""

import unittest
from copy import deepcopy

from tests._loader import load

route_targets = load("reconcile_route_targets")


def fixtures(name="BLUE"):
    discovery = {
        "ipam": {
            "vrfs": [
                {
                    "name": name,
                    "route_targets": {
                        "status": "available",
                        "import": ["65000:10"],
                        "export": ["65000:20"],
                        "source": {"complete": True},
                    },
                }
            ],
        },
    }
    existing = {
        "ipam_inventory": {
            "device": {"id": "device-1"},
            "route_targets": [],
            "vrfs": [],
            "vrf_device_assignments": [],
            "policy": {"local_vrf_names": ["Mgmt-vrf", "LOCAL"]},
        }
    }
    ipam = {
        "vrfs": [
            {"key": "vrf:blue", "id": None, "create": True, "namespace_id": "ns-1", "name": name}
        ],
        "vrf_device_assignments": [{"name": name, "vrf_key": "vrf:blue", "device_id": "device-1"}],
    }
    return discovery, existing, ipam


class LiteralTests(unittest.TestCase):
    def test_reviewed_encoding_widths_and_canonical_asdot(self):
        valid = {
            "065000:0007": "65000:7",
            "65535:4294967295": "65535:4294967295",
            "65536:65535": "65536:65535",
            "4294967295:65535": "4294967295:65535",
            "1.10:0007": "65546:7",
            "192.0.2.10:65535": "192.0.2.10:65535",
            "65000:0": "65000:0",
        }
        for value, expected in valid.items():
            with self.subTest(value=value):
                self.assertEqual(route_targets.canonical_route_target(value), expected)

    def test_invalid_auto_type_or_loss_of_wire_identity_deferred(self):
        for value in (
            None,
            65000,
            "auto",
            "65000:4294967296",
            "65536:65536",
            "0.10:7",
            "4294967296:7",
            "1.65536:7",
            "192.0.2.10:65536",
            "2001:db8::1:7",
            "224.0.0.1:7",
            "65000:-1",
            "65000:7.0",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                route_targets.canonical_route_target(value)


class RouteTargetPlanTests(unittest.TestCase):
    def plan(self, values):
        return route_targets.plan_route_targets(*values)

    def test_new_non_management_vrf_gets_two_native_directions_without_mutation(self):
        values = fixtures()
        before = deepcopy(values)
        plan = self.plan(values)
        self.assertEqual(values, before)
        self.assertEqual(plan["summary"]["route_targets_created"], 2)
        self.assertEqual(plan["summary"]["vrf_import_targets_added"], 1)
        self.assertEqual(plan["summary"]["vrf_export_targets_added"], 1)
        self.assertEqual(
            {row["direction"] for row in plan["vrf_route_targets"]}, {"import", "export"}
        )
        self.assertFalse(plan["errors"] or plan["unresolved"])

    def test_management_skipped_but_device_local_user_vrf_is_eligible(self):
        management = self.plan(fixtures("Mgmt-vrf"))
        local_user = self.plan(fixtures("LOCAL"))
        self.assertFalse(management["route_targets"] or management["vrf_route_targets"])
        self.assertEqual(local_user["summary"]["route_targets_created"], 2)

    def test_global_catalog_reuse_does_not_merge_namespace_vrf_identities(self):
        values = fixtures()
        values[1]["ipam_inventory"]["route_targets"] = [{"id": "target-1", "name": "65000:10"}]
        values[2]["vrfs"][0]["namespace_id"] = "separate-namespace"
        plan = self.plan(values)
        self.assertEqual(plan["summary"]["route_targets_created"], 1)
        self.assertEqual(plan["route_targets"][0]["id"], "target-1")
        self.assertTrue(
            all(row["namespace_id"] == "separate-namespace" for row in plan["vrf_route_targets"])
        )

    def existing(self, values, imports=None, exports=None):
        catalog = values[1]["ipam_inventory"]
        catalog["route_targets"] = [
            {"id": "target-1", "name": "65000:10"},
            {"id": "target-2", "name": "65000:20"},
            {"id": "operator-target", "name": "65000:99"},
        ]
        catalog["vrfs"] = [
            {
                "id": "vrf-1",
                "namespace_id": "ns-1",
                "import_target_ids": imports or [],
                "export_target_ids": exports or [],
            }
        ]
        values[2]["vrfs"][0].update(id="vrf-1", create=False)

    def test_populated_direction_preserved_entirely_and_empty_other_direction_filled(self):
        values = fixtures()
        self.existing(values, imports=["operator-target"])
        plan = self.plan(values)
        self.assertEqual(plan["summary"]["vrf_import_targets_added"], 0)
        self.assertEqual(plan["summary"]["vrf_export_targets_added"], 1)
        self.assertEqual(plan["conflicts"][0]["before"], ["65000:99"])
        values[1]["ipam_inventory"]["vrfs"][0]["import_target_ids"] = [
            "target-1",
            "operator-target",
        ]
        plan = self.plan(values)
        self.assertEqual(plan["summary"]["vrf_import_targets_added"], 0)
        self.assertEqual(len(plan["conflicts"]), 1)

    def test_matching_native_sets_are_idempotent(self):
        values = fixtures()
        self.existing(values, imports=["target-1"], exports=["target-2"])
        plan = self.plan(values)
        self.assertFalse(plan["route_targets"] or plan["vrf_route_targets"] or plan["conflicts"])
        self.assertEqual(plan["summary"]["route_targets_created"], 0)

    def test_empty_shared_native_vrf_deferred_until_all_endpoints_known(self):
        values = fixtures()
        self.existing(values)
        values[1]["ipam_inventory"]["vrf_device_assignments"] = [
            {"vrf_id": "vrf-1", "device_id": "another-device"}
        ]
        plan = self.plan(values)
        self.assertFalse(plan["route_targets"] or plan["vrf_route_targets"])
        self.assertEqual(len(plan["unresolved"]), 2)
        values[1]["ipam_inventory"]["vrfs"][0].update(
            import_target_ids=["target-1"], export_target_ids=["target-2"]
        )
        self.assertFalse(self.plan(values)["unresolved"])

    def test_optional_source_failures_do_not_block_ipam_and_blank_explicit_policy_is_valid(self):
        for status in ("unavailable", "unresolved"):
            values = fixtures()
            values[0]["ipam"]["vrfs"][0]["route_targets"].update(
                status=status, reason="AF policies differ"
            )
            plan = self.plan(values)
            self.assertFalse(plan["errors"] or plan["route_targets"])
            self.assertEqual(plan["unresolved"][0]["reason"], "AF policies differ")
        values = fixtures()
        values[0]["ipam"]["vrfs"][0]["route_targets"].update({"import": [], "export": []})
        plan = self.plan(values)
        self.assertFalse(plan["unresolved"] or plan["route_targets"])

    def test_missing_complete_evidence_and_invalid_literals_defer_scoped(self):
        for change in ({"source": {}}, {"import": ["auto"]}, {"export": "65000:1"}):
            values = fixtures()
            values[0]["ipam"]["vrfs"][0]["route_targets"].update(change)
            plan = self.plan(values)
            self.assertFalse(plan["errors"] or plan["route_targets"])
            self.assertTrue(plan["unresolved"])

    def test_missing_catalog_cross_scope_and_unresolved_vrf_are_not_guessed(self):
        for case in ("catalog", "device", "namespace", "vrf"):
            values = fixtures()
            if case == "catalog":
                del values[1]["ipam_inventory"]["route_targets"]
            elif case == "device":
                values[2]["vrf_device_assignments"][0]["device_id"] = "other-device"
            elif case == "namespace":
                self.existing(values)
                values[1]["ipam_inventory"]["vrfs"][0]["namespace_id"] = "other-namespace"
            else:
                values[2]["vrf_device_assignments"] = []
            plan = self.plan(values)
            self.assertFalse(plan["route_targets"] or plan["errors"])
            self.assertTrue(plan["unresolved"])

    def test_duplicate_catalog_semantics_are_ambiguous_without_renaming(self):
        values = fixtures()
        values[1]["ipam_inventory"]["route_targets"] = [
            {"id": "target-1", "name": "65000:10"},
            {"id": "target-2", "name": "065000:010"},
        ]
        plan = self.plan(values)
        self.assertEqual(plan["summary"]["vrf_import_targets_added"], 0)
        self.assertEqual(plan["summary"]["vrf_export_targets_added"], 1)

    def test_multiple_local_policies_on_same_native_vrf_are_not_unioned(self):
        values = fixtures()
        other = deepcopy(values[0]["ipam"]["vrfs"][0])
        other["name"] = "RED"
        other["route_targets"]["import"] = ["65000:30"]
        values[0]["ipam"]["vrfs"].append(other)
        values[2]["vrf_device_assignments"].append(
            {"name": "RED", "vrf_key": "vrf:blue", "device_id": "device-1"}
        )
        plan = self.plan(values)
        self.assertEqual(plan["summary"]["vrf_import_targets_added"], 0)
        self.assertEqual(plan["summary"]["vrf_export_targets_added"], 1)

    def test_new_endpoint_adoption_requires_confirmed_populated_canonical_policy(self):
        values = fixtures()
        self.existing(values, imports=["target-1"], exports=["target-2"])
        observation = values[0]["ipam"]["vrfs"][0]
        vrf = values[1]["ipam_inventory"]["vrfs"][0]
        catalog = values[1]["ipam_inventory"]["route_targets"]
        self.assertIsNone(route_targets.route_target_adoption_reason(observation, vrf, catalog))
        observation["route_targets"]["import"] = ["65000:99"]
        self.assertIn(
            "conflicting", route_targets.route_target_adoption_reason(observation, vrf, catalog)
        )
        observation["route_targets"].update(status="unavailable")
        self.assertIn(
            "unconfirmed", route_targets.route_target_adoption_reason(observation, vrf, catalog)
        )
        vrf.update(import_target_ids=[], export_target_ids=[])
        self.assertIsNone(route_targets.route_target_adoption_reason(observation, vrf, catalog))


if __name__ == "__main__":
    unittest.main()
