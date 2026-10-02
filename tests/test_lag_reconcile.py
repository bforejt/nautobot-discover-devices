"""Membership reconciliation preserves operators' assignments and resolves aliases."""

import unittest
from copy import deepcopy

from tests.test_reconcile import apply_to_snapshot, discovery, inventory, reconcile


def lag_discovery():
    data = discovery()
    data["interfaces"].append(
        {
            "name": "TwoGigabitEthernet1/0/22",
            "type": "2.5gbase-t",
            "enabled": False,
            "description": None,
            "mtu": 1500,
            "mac_address": None,
        }
    )
    data["lag_memberships"] = [{"member": "Tw1/0/22", "lag": "Po1", "source": {"mode": "active"}}]
    return data


class LagReconciliationTests(unittest.TestCase):
    def test_new_down_member_and_lag_link_then_repeat_without_changes(self):
        data, before = lag_discovery(), inventory()
        first = reconcile.build_plan(data, before)
        self.assertFalse(first["errors"])
        self.assertEqual(len(first["interface_creates"]), 2)
        assignment = first["lag_assignments"][0]
        self.assertEqual(assignment["member"], "TwoGigabitEthernet1/0/22")
        self.assertEqual(assignment["lag"], "Port-channel1")
        self.assertIsNone(assignment["member_id"])
        self.assertIsNone(assignment["lag_id"])
        self.assertEqual(first["summary"]["lag_memberships_updated"], 1)
        self.assertEqual(first["summary"]["interfaces_updated"], 0)
        after = apply_to_snapshot(first, before)
        second = reconcile.build_plan(data, after)
        self.assertEqual(second["lag_assignments"], [])
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])

    def test_existing_short_names_fill_relationship_and_count_member_once(self):
        data, before = lag_discovery(), inventory()
        before = apply_to_snapshot(reconcile.build_plan(data, before), before)
        parent = next(row for row in before["interfaces"] if row["type"] == "lag")
        member = next(row for row in before["interfaces"] if row["type"] != "lag")
        parent["name"] = "Po1"
        member.update(name="Tw1/0/22", lag_id=None, lag=None, mtu=None)
        frozen = deepcopy(before)
        plan = reconcile.build_plan(data, before)
        self.assertEqual(before, frozen)
        self.assertEqual(plan["lag_assignments"][0]["member_id"], member["id"])
        self.assertEqual(plan["lag_assignments"][0]["lag_id"], parent["id"])
        self.assertEqual(plan["lag_assignments"][0]["member"], "Tw1/0/22")
        self.assertEqual(plan["summary"]["interfaces_updated"], 1)

    def test_populated_different_assignment_is_preserved_as_conflict(self):
        data, before = lag_discovery(), inventory()
        before = apply_to_snapshot(reconcile.build_plan(data, before), before)
        member = next(row for row in before["interfaces"] if row["type"] != "lag")
        member.update(lag_id="operator-lag", lag="Port-channel99")
        plan = reconcile.build_plan(data, before)
        self.assertEqual(plan["lag_assignments"], [])
        conflict = next(row for row in plan["conflicts"] if row["field"] == "lag")
        self.assertEqual(conflict["before"], "Port-channel99")
        self.assertEqual(conflict["observed"], "Port-channel1")
        self.assertFalse(plan["errors"])

    def test_same_name_on_different_target_uuid_is_a_conflict(self):
        data, before = lag_discovery(), inventory()
        before = apply_to_snapshot(reconcile.build_plan(data, before), before)
        member = next(row for row in before["interfaces"] if row["type"] != "lag")
        member["lag_id"] = "different-device-parent"
        plan = reconcile.build_plan(data, before)
        self.assertEqual(plan["lag_assignments"], [])
        self.assertTrue(any(row["field"] == "lag" for row in plan["conflicts"]))

    def test_missing_membership_observation_never_clears_existing_links(self):
        data, before = lag_discovery(), inventory()
        before = apply_to_snapshot(reconcile.build_plan(data, before), before)
        data.pop("lag_memberships")
        plan = reconcile.build_plan(data, before)
        self.assertEqual(plan["lag_assignments"], [])
        self.assertEqual(plan["summary"]["interfaces_updated"], 0)

    def test_unsupported_or_missing_endpoint_skips_membership_with_warning(self):
        for missing in ("member", "lag"):
            with self.subTest(missing=missing):
                data = lag_discovery()
                data["lag_memberships"][0][missing] = "TenGigabitEthernet1/1/99"
                plan = reconcile.build_plan(data, inventory())
                self.assertEqual(plan["lag_assignments"], [])
                self.assertTrue(any("endpoint is unavailable" in row for row in plan["warnings"]))
        data = lag_discovery()
        data["interfaces"][1]["type"] = None
        plan = reconcile.build_plan(data, inventory())
        self.assertEqual(plan["lag_assignments"], [])
        self.assertTrue(plan["warnings"])

    def test_existing_non_lag_parent_type_is_preserved_and_relationship_skipped(self):
        data, before = lag_discovery(), inventory()
        before["interfaces"] = [{"id": "parent", "name": "Po1", "type": "other"}]
        plan = reconcile.build_plan(data, before)
        self.assertEqual(plan["lag_assignments"], [])
        self.assertTrue(any("target interface type" in row for row in plan["warnings"]))
        self.assertFalse(plan["errors"])

    def test_virtual_or_lag_member_is_not_attached(self):
        for type_ in ("virtual", "bridge", "lag", "tunnel"):
            with self.subTest(type=type_):
                data = lag_discovery()
                data["interfaces"][1]["type"] = type_
                plan = reconcile.build_plan(data, inventory())
                self.assertEqual(plan["lag_assignments"], [])
                self.assertTrue(any("physical interface" in row for row in plan["warnings"]))

    def test_ambiguous_multiple_targets_and_self_membership_block_application(self):
        data = lag_discovery()
        data["lag_memberships"].append({"member": "Tw1/0/22", "lag": "Po2"})
        plan = reconcile.build_plan(data, inventory())
        self.assertTrue(plan["summary"]["blocked"])
        self.assertEqual(plan["lag_assignments"], [])
        data = lag_discovery()
        data["lag_memberships"] = [{"member": "Po1", "lag": "Port-channel1"}]
        self.assertTrue(reconcile.build_plan(data, inventory())["summary"]["blocked"])


if __name__ == "__main__":
    unittest.main()
