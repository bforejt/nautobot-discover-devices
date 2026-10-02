"""Regression coverage for scoped, fill-only VLAN and interface bundles."""

import json
import unittest
from copy import deepcopy

from tests._loader import load

planner = load("reconcile_vlans")


def fact(name="Gi1/0/1", **values):
    return {
        "name": name,
        "mode": "access",
        "untagged_vid": 10,
        "tagged_vids": [],
        "source": {},
        "observations": {},
        **values,
    }


def discovery(*interfaces, vlans=None):
    return {
        "layer2": {
            "schema_version": 1,
            "interfaces": list(interfaces),
            "vlans": [{"vid": 10, "name": "Users"}] if vlans is None else vlans,
            "unresolved": [],
        }
    }


def inventory():
    return {
        "interfaces": [
            {
                "id": "interface-1",
                "name": "Gi1/0/1",
                "type": "1000base-t",
                "mode": "",
                "untagged_vlan_id": None,
                "tagged_vlan_ids": [],
            }
        ],
        "vlan_inventory": {
            "supported": True,
            "group": {"id": "group-1", "name": "Lab"},
            "allowed_vids": list(range(1, 4095)),
            "vlans": [],
        },
    }


def vlan(vid=10, **values):
    return {"id": "vlan-%s" % vid, "vid": vid, "name": "Users", "applicable": True, **values}


def apply_to_snapshot(plan, before):
    after = deepcopy(before)
    refs = {}
    for row in plan["catalog"]:
        refs[row["key"]] = row["id"] or "created-vlan-%s" % row["vid"]
        if row["create"]:
            after["vlan_inventory"]["vlans"].append(
                {
                    "id": refs[row["key"]],
                    "vid": row["vid"],
                    "name": row["name"],
                    "applicable": True,
                }
            )
        else:
            existing = next(
                value for value in after["vlan_inventory"]["vlans"] if value["id"] == row["id"]
            )
            for change in row["changes"]:
                existing[change["field"]] = change["after"]
    for row in plan["assignments"]:
        existing = next(value for value in after["interfaces"] if value["id"] == row["id"])
        for change in row["changes"]:
            if change["field"] == "mode":
                existing["mode"] = change["after"]
            else:
                existing["untagged_vlan_id"] = refs[change["after"]]
        if row["tagged_vlan_keys"] is not None:
            existing["tagged_vlan_ids"] = [refs[key] for key in row["tagged_vlan_keys"]]
    return after


class VLANReconciliationTests(unittest.TestCase):
    def test_access_bundle_creates_only_referenced_vlan_and_preserves_uuid(self):
        before = inventory()
        original = deepcopy(before)
        plan = planner.plan_vlans(
            discovery(
                fact(),
                vlans=[
                    {"vid": 10, "name": "Users"},
                    {"vid": 20, "name": "Unused"},
                ],
            ),
            before,
        )
        self.assertFalse(plan["errors"])
        self.assertEqual([row["vid"] for row in plan["catalog"]], [10])
        self.assertEqual(plan["catalog"][0]["group_id"], "group-1")
        self.assertEqual(plan["assignments"][0]["id"], "interface-1")
        self.assertEqual(plan["assignments"][0]["name"], "Gi1/0/1")
        self.assertEqual(plan["assignments"][0]["tagged_vlan_keys"], None)
        self.assertEqual(before, original)
        json.dumps(plan)

    def test_access_and_tagged_bundles_are_idempotent(self):
        cases = (
            discovery(fact()),
            discovery(
                fact(mode="tagged", tagged_vids=[20]),
                vlans=[
                    {"vid": 10, "name": "Native"},
                    {"vid": 20, "name": "Tagged"},
                ],
            ),
        )
        for observed in cases:
            with self.subTest(observed=observed):
                before = inventory()
                first = planner.plan_vlans(observed, before)
                second = planner.plan_vlans(observed, apply_to_snapshot(first, before))
                self.assertFalse(second["errors"])
                self.assertFalse(second["conflicts"])
                self.assertFalse(second["assignments"])
                self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_tagged_all_does_not_expand_m2m_membership(self):
        plan = planner.plan_vlans(discovery(fact(mode="tagged-all")), inventory())
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["assignments"][0]["mode"], "tagged-all")
        self.assertIsNone(plan["assignments"][0]["tagged_vlan_keys"])
        self.assertEqual(len(plan["catalog"]), 1)

    def test_tagged_all_without_native_needs_no_vlan_catalog(self):
        plan = planner.plan_vlans(
            discovery(fact(mode="tagged-all", untagged_vid=None)), inventory()
        )
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["catalog"])
        self.assertEqual(
            plan["assignments"][0]["changes"],
            [{"field": "mode", "before": "", "after": "tagged-all"}],
        )

    def test_populated_mode_conflict_skips_entire_bundle_and_catalog(self):
        before = inventory()
        before["interfaces"][0]["mode"] = "tagged"
        plan = planner.plan_vlans(discovery(fact()), before)
        self.assertFalse(plan["assignments"])
        self.assertFalse(plan["catalog"])
        self.assertEqual(plan["conflicts"][0]["field"], "mode")

    def test_populated_native_vlan_conflict_skips_missing_tag_catalog_creation(self):
        before = inventory()
        before["interfaces"][0].update(mode="tagged", untagged_vlan_id="operator-vlan")
        plan = planner.plan_vlans(
            discovery(
                fact(mode="tagged", tagged_vids=[20]),
                vlans=[
                    {"vid": 10, "name": "Native"},
                    {"vid": 20, "name": "New tag"},
                ],
            ),
            before,
        )
        self.assertFalse(plan["assignments"])
        self.assertFalse(plan["catalog"])
        self.assertEqual(plan["conflicts"][0]["field"], "untagged_vlan")

    def test_populated_tag_set_is_preserved_without_partial_merge(self):
        before = inventory()
        before["interfaces"][0].update(mode="tagged", tagged_vlan_ids=["vlan-20"])
        before["vlan_inventory"]["vlans"] = [vlan(20, name="Existing")]
        plan = planner.plan_vlans(
            discovery(
                fact(mode="tagged", tagged_vids=[20, 30]),
                vlans=[
                    {"vid": 10, "name": "Native"},
                    {"vid": 20, "name": "Existing"},
                    {"vid": 30, "name": "Extra"},
                ],
            ),
            before,
        )
        self.assertFalse(plan["assignments"])
        self.assertFalse(plan["catalog"])
        self.assertEqual(plan["conflicts"][0]["field"], "tagged_vlans")

    def test_exact_existing_tag_set_can_fill_native_without_replacing_m2m(self):
        before = inventory()
        before["interfaces"][0].update(mode="tagged", tagged_vlan_ids=["vlan-30", "vlan-20"])
        before["vlan_inventory"]["vlans"] = [
            vlan(10, name="Native"),
            vlan(20, name="Tag 20"),
            vlan(30, name="Tag 30"),
        ]
        plan = planner.plan_vlans(
            discovery(fact(mode="tagged", tagged_vids=[20, 30]), vlans=[]), before
        )
        self.assertFalse(plan["conflicts"])
        self.assertEqual(
            plan["assignments"][0]["changes"],
            [{"field": "untagged_vlan", "before": None, "after": "10"}],
        )
        self.assertIsNone(plan["assignments"][0]["tagged_vlan_keys"])

    def test_populated_native_cannot_be_cleared_by_absent_observed_native(self):
        before = inventory()
        before["interfaces"][0].update(mode="tagged-all", untagged_vlan_id="vlan-10")
        plan = planner.plan_vlans(discovery(fact(mode="tagged-all", untagged_vid=None)), before)
        self.assertFalse(plan["assignments"])
        self.assertFalse(plan["catalog"])
        self.assertEqual(plan["conflicts"][0]["field"], "untagged_vlan")

    def test_inconsistent_manual_tags_on_blank_mode_are_not_cleared(self):
        before = inventory()
        before["interfaces"][0]["tagged_vlan_ids"] = ["operator-vlan"]
        for mode in ("access", "tagged-all", "tagged"):
            with self.subTest(mode=mode):
                plan = planner.plan_vlans(discovery(fact(mode=mode)), before)
                self.assertFalse(plan["assignments"])
                self.assertFalse(plan["catalog"])
                self.assertEqual(plan["conflicts"][0]["field"], "mode")

    def test_unknown_name_aborts_only_its_bundle_without_unused_catalogs(self):
        before = inventory()
        before["interfaces"].append({**before["interfaces"][0], "id": "other", "name": "Gi1/0/2"})
        plan = planner.plan_vlans(
            discovery(
                fact(mode="tagged", tagged_vids=[20]),
                fact("Gi1/0/2", untagged_vid=30),
                vlans=[{"vid": 10, "name": "Unused native"}, {"vid": 30, "name": "Valid"}],
            ),
            before,
        )
        self.assertEqual([row["vid"] for row in plan["catalog"]], [30])
        self.assertEqual([row["id"] for row in plan["assignments"]], ["other"])
        self.assertEqual(plan["summary"]["unresolved_switching"], 1)

    def test_no_group_prevents_every_switching_write(self):
        before = inventory()
        before["vlan_inventory"]["group"] = None
        plan = planner.plan_vlans(discovery(fact()), before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["catalog"])
        self.assertFalse(plan["assignments"])
        self.assertEqual(plan["summary"]["unresolved_switching"], 1)

    def test_inapplicable_existing_vlan_is_unresolved_not_duplicated(self):
        before = inventory()
        before["vlan_inventory"]["vlans"] = [vlan(applicable=False)]
        plan = planner.plan_vlans(discovery(fact()), before)
        self.assertFalse(plan["catalog"])
        self.assertFalse(plan["assignments"])
        self.assertTrue(plan["unresolved"])

    def test_vid4000_is_valid_but_group_range_can_exclude_it(self):
        observed = discovery(fact(untagged_vid=4000), vlans=[{"vid": 4000, "name": "Extended"}])
        before = inventory()
        self.assertFalse(planner.plan_vlans(observed, before)["errors"])
        before["vlan_inventory"]["allowed_vids"] = list(range(1, 101))
        plan = planner.plan_vlans(observed, before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["catalog"])
        self.assertTrue(plan["unresolved"])

    def test_existing_name_is_preserved_while_vlan_identity_is_reused(self):
        before = inventory()
        before["vlan_inventory"]["vlans"] = [vlan(name="Operator name")]
        plan = planner.plan_vlans(discovery(fact()), before)
        self.assertEqual(plan["catalog"][0]["id"], "vlan-10")
        self.assertFalse(plan["catalog"][0]["changes"])
        self.assertEqual(plan["conflicts"][0]["field"], "name")
        self.assertEqual(len(plan["assignments"]), 1)

    def test_blank_catalog_name_is_filled(self):
        before = inventory()
        before["vlan_inventory"]["vlans"] = [vlan(name="")]
        plan = planner.plan_vlans(discovery(fact()), before)
        self.assertEqual(
            plan["catalog"][0]["changes"],
            [
                {
                    "field": "name",
                    "before": "",
                    "after": "Users",
                }
            ],
        )
        self.assertEqual(plan["summary"]["vlans_updated"], 1)

    def test_catalog_name_collision_and_vid_ambiguity_are_errors(self):
        examples = (
            [vlan(20, name="Users")],
            [vlan(), vlan(id="duplicate-id")],
        )
        for rows in examples:
            with self.subTest(rows=rows):
                before = inventory()
                before["vlan_inventory"]["vlans"] = rows
                plan = planner.plan_vlans(discovery(fact()), before)
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["assignments"])

    def test_blank_name_fill_cannot_collide_with_another_existing_vid(self):
        before = inventory()
        before["vlan_inventory"]["vlans"] = [vlan(name=""), vlan(20, name="Users")]
        plan = planner.plan_vlans(discovery(fact()), before)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["catalog"])
        self.assertFalse(plan["assignments"])

    def test_two_proposed_vids_cannot_share_one_name(self):
        observed = discovery(
            fact(mode="tagged", tagged_vids=[20]),
            vlans=[
                {"vid": 10, "name": "Duplicate"},
                {"vid": 20, "name": "Duplicate"},
            ],
        )
        plan = planner.plan_vlans(observed, inventory())
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["catalog"])

    def test_planned_interfaces_and_lags_can_receive_bundles(self):
        for interface_type in ("1000base-t", "lag"):
            with self.subTest(interface_type=interface_type):
                before = inventory()
                before["interfaces"] = []
                plan = planner.plan_vlans(
                    discovery(fact()),
                    before,
                    {
                        "interface_creates": [
                            {"name": "GigabitEthernet1/0/1", "type": interface_type}
                        ],
                    },
                )
                self.assertFalse(plan["errors"])
                self.assertIsNone(plan["assignments"][0]["id"])

    def test_effective_type_from_base_plan_rejects_logical_assignment(self):
        for interface_type in ("virtual", "bridge", "tunnel"):
            with self.subTest(interface_type=interface_type):
                plan = planner.plan_vlans(
                    discovery(fact()),
                    inventory(),
                    {
                        "interface_updates": [
                            {
                                "id": "interface-1",
                                "changes": [{"field": "type", "after": interface_type}],
                            }
                        ],
                    },
                )
                self.assertFalse(plan["catalog"])
                self.assertFalse(plan["assignments"])
                self.assertTrue(plan["unresolved"])

    def test_source_vid_mode_and_native_tag_consistency_are_strict(self):
        cases = (
            fact(untagged_vid=True),
            fact(untagged_vid="10"),
            fact(untagged_vid=0),
            fact(untagged_vid=4095),
            fact(mode="routed"),
            fact(mode=[]),
            fact(untagged_vid=None),
            fact(tagged_vids=[20]),
            fact(mode="tagged", tagged_vids=[10]),
            fact(mode="tagged", tagged_vids=[20, 20]),
            fact(mode="tagged-all", tagged_vids=[20]),
        )
        for row in cases:
            with self.subTest(row=row):
                plan = planner.plan_vlans(discovery(row), inventory())
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["assignments"])

        missing_native = fact(mode="tagged-all")
        missing_native.pop("untagged_vid")
        self.assertTrue(planner.plan_vlans(discovery(missing_native), inventory())["errors"])

    def test_catalog_vids_and_names_are_structured_and_strict(self):
        for row in (
            {"vid": True, "name": "Bool"},
            {"vid": "10", "name": "Text VID"},
            {"vid": 4095, "name": "Out of range"},
            {"vid": 10, "name": ["Text"]},
        ):
            with self.subTest(row=row):
                plan = planner.plan_vlans(discovery(fact(), vlans=[row]), inventory())
                self.assertTrue(plan["errors"])

    def test_source_and_interface_identity_ambiguity_are_errors(self):
        observed = discovery(fact(), fact("GigabitEthernet1/0/1"))
        self.assertTrue(planner.plan_vlans(observed, inventory())["errors"])
        observed = discovery(fact(), vlans=[{"vid": 10, "name": "A"}, {"vid": 10, "name": "B"}])
        self.assertTrue(planner.plan_vlans(observed, inventory())["errors"])
        before = inventory()
        before["interfaces"].append({**before["interfaces"][0], "id": "duplicate"})
        self.assertTrue(planner.plan_vlans(discovery(fact()), before)["errors"])

    def test_absent_feature_is_a_noop_and_malformed_schema_is_an_error(self):
        self.assertFalse(planner.plan_vlans({}, inventory())["catalog"])
        for value in (None, {}, {"schema_version": True}, {"schema_version": 2}):
            with self.subTest(value=value):
                self.assertTrue(planner.plan_vlans({"layer2": value}, inventory())["errors"])


if __name__ == "__main__":
    unittest.main()
