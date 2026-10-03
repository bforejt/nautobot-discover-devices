"""Native member identities, active-role changes and preservation regressions."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_reconcile import discovery, inventory

planner = load("reconcile_stack")
reconcile = load("reconcile")


def observed_stack(active=1):
    observed = discovery()
    members = [
        {
            "position": position,
            "priority": priority,
            "serial": serial,
            "model": "C9300-48UXM",
            "role": "role-active" if active == position else "role-standby",
            "state": "state-ready",
            "stack_mode": "mode-stackwise-rear",
            "sources": {
                "serial": {
                    "module": "Cisco-IOS-XE-stack-oper",
                    "field": "stack-node/serial-number",
                }
            },
        }
        for position, priority, serial in ((1, 15, "LAB93000001"), (2, 12, "LAB93000002"))
    ]
    observed["identity"].update(
        serial=members[active - 1]["serial"], model=members[active - 1]["model"]
    )
    observed["stack"] = {
        "schema_version": 1,
        "name": observed["identity"]["hostname"],
        "is_stack": True,
        "active_position": active,
        "members": members,
        "absent_members": [{"position": 3, "state": "state-provisioned"}],
        "observations": {},
        "unresolved": [],
    }
    return observed


def stack_inventory():
    before = inventory()
    selected = {
        **before["device"],
        "manufacturer_id": "cisco",
        "manufacturer_name": "Cisco",
        "device_type_id": "type-1",
        "virtual_chassis_id": None,
        "vc_position": None,
        "vc_priority": None,
        "location_id": "lab",
        "tenant_id": None,
    }
    before["stack"] = {
        "selected": selected,
        "devices": [deepcopy(selected)],
        "virtual_chassis": [],
        "device_types": [{"id": "type-1", "model": "C9300-48UXM", "manufacturer_id": "cisco"}],
    }
    return before


def applied_stack(plan, before):
    after = deepcopy(before)
    catalog = after["stack"]
    vc = plan["virtual_chassis"]
    vc_id = vc["existing_id"] or "created-vc"
    for member in plan["members"]:
        member_id = member["existing_id"] or "created-member-%s" % member["position"]
        if member["create"]:
            catalog["devices"].append(
                {
                    **catalog["selected"],
                    "id": member_id,
                    "name": member["name"],
                    "model": member["model"],
                    "serial": member["serial"],
                    "vc_position": member["position"],
                    "vc_priority": member["priority"],
                    "virtual_chassis_id": vc_id,
                }
            )
        else:
            row = next(row for row in catalog["devices"] if row["id"] == member_id)
            for change in member["changes"]:
                field = change["field"]
                row["virtual_chassis_id" if field == "virtual_chassis" else field] = (
                    vc_id if field == "virtual_chassis" else change["after"]
                )
        if member["selected"]:
            catalog["selected"] = deepcopy(
                next(row for row in catalog["devices"] if row["id"] == member_id)
            )
    master = next(row for row in plan["members"] if row["position"] == vc["master_position"])
    master_id = master["existing_id"] or "created-member-%s" % master["position"]
    if vc["create"]:
        catalog["virtual_chassis"].append({"id": vc_id, "name": vc["name"], "master_id": master_id})
    else:
        next(row for row in catalog["virtual_chassis"] if row["id"] == vc_id)["master_id"] = (
            master_id
        )
    return after


class StackReconciliationTests(unittest.TestCase):
    def test_ntc_names_serials_priorities_and_provisioned_absence(self):
        before = stack_inventory()
        original = deepcopy(before)
        plan = planner.plan_stack(observed_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["virtual_chassis"]["name"], "example-9300")
        self.assertEqual(plan["virtual_chassis"]["master_position"], 1)
        self.assertEqual(
            [row["name"] for row in plan["members"]], ["example-9300", "example-9300:2"]
        )
        self.assertEqual([row["serial"] for row in plan["members"]], ["LAB93000001", "LAB93000002"])
        self.assertEqual(plan["summary"]["stack_members_created"], 1)
        self.assertEqual(plan["summary"]["stack_members_updated"], 1)
        self.assertEqual(len(plan["members"]), 2)
        self.assertEqual(before, original)

    def test_repeat_has_no_catalog_member_or_master_changes(self):
        before = stack_inventory()
        first = planner.plan_stack(observed_stack(), before)
        second = planner.plan_stack(observed_stack(), applied_stack(first, before))
        self.assertFalse(second["errors"])
        self.assertTrue(all(count == 0 for count in second["summary"].values()))

    def test_selected_serial_does_not_follow_active_role(self):
        observed = observed_stack(active=2)
        before = stack_inventory()
        plan = reconcile.build_plan(observed, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["stack"]["identity"]["serial"], before["device"]["serial"])
        self.assertEqual(plan["stack"]["virtual_chassis"]["master_position"], 2)
        self.assertEqual(plan["device_updates"], [])
        self.assertTrue(plan["stack"]["warnings"])
        self.assertNotIn("device", plan["interface_creates"][0])

    def test_active_member_two_is_root_when_its_serial_is_selected(self):
        before = stack_inventory()
        for row in (before["device"], before["stack"]["selected"], before["stack"]["devices"][0]):
            row["serial"] = "LAB93000002"
        plan = planner.plan_stack(observed_stack(active=2), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(
            [row["name"] for row in plan["members"]], ["example-9300:1", "example-9300"]
        )
        self.assertTrue(plan["members"][1]["selected"])

    def test_master_change_preserves_member_names_and_ids(self):
        before = stack_inventory()
        after = applied_stack(planner.plan_stack(observed_stack(), before), before)
        changed = planner.plan_stack(observed_stack(active=2), after)
        self.assertFalse(changed["errors"])
        self.assertEqual(changed["summary"]["virtual_chassis_updated"], 1)
        self.assertEqual(changed["summary"]["stack_members_created"], 0)
        self.assertEqual(changed["summary"]["stack_members_updated"], 0)
        self.assertEqual(
            [row["existing_id"] for row in changed["members"]], ["device-1", "created-member-2"]
        )
        self.assertEqual(
            [row["name"] for row in changed["members"]], ["example-9300", "example-9300:2"]
        )

    def test_blank_selected_serial_binds_active_then_main_identity_fills(self):
        before = stack_inventory()
        for row in (before["device"], before["stack"]["selected"], before["stack"]["devices"][0]):
            row["serial"] = ""
        plan = reconcile.build_plan(observed_stack(active=2), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(
            next(row for row in plan["device_updates"] if row["field"] == "serial")["after"],
            "LAB93000002",
        )
        self.assertTrue(plan["stack"]["members"][1]["selected"])

    def test_reverse_input_order_is_deterministic(self):
        observed = observed_stack()
        first = planner.plan_stack(observed, stack_inventory())
        observed["stack"]["members"].reverse()
        self.assertEqual(first, planner.plan_stack(observed, stack_inventory()))

    def test_existing_member_alias_is_preserved_by_unique_serial(self):
        before = stack_inventory()
        before["stack"]["devices"].append(
            {
                **before["stack"]["selected"],
                "id": "old-2",
                "serial": "LAB93000002",
                "name": "operator-member",
            }
        )
        plan = planner.plan_stack(observed_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["members"][1]["name"], "operator-member")
        self.assertEqual(plan["members"][1]["existing_id"], "old-2")
        self.assertEqual(plan["summary"]["stack_members_created"], 0)

    def test_blank_serial_exact_member_name_can_be_adopted(self):
        before = stack_inventory()
        before["stack"]["devices"].append(
            {**before["stack"]["selected"], "id": "old-2", "serial": "", "name": "example-9300:2"}
        )
        plan = planner.plan_stack(observed_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["members"][1]["existing_id"], "old-2")
        self.assertIn("serial", [change["field"] for change in plan["members"][1]["changes"]])

    def test_member_catalog_exact_pid_created_without_guessed_template(self):
        observed = observed_stack()
        observed["stack"]["members"][1]["model"] = "C9300-24T"
        plan = planner.plan_stack(observed, stack_inventory())
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["device_types_created"], 1)
        self.assertEqual(
            next(row for row in plan["device_types"] if row["create"])["model"], "C9300-24T"
        )

    def test_unrecognized_selected_serial_and_model_block(self):
        for field, value in (("serial", "OTHER-SERIAL"), ("model", "OTHER-MODEL")):
            before = stack_inventory()
            before["device"][field] = value
            plan = planner.plan_stack(observed_stack(), before)
            self.assertTrue(plan["errors"])

    def test_duplicate_global_serials_and_wrong_location_block(self):
        for changed in (
            {},
            {"location_id": "elsewhere"},
            {"model": "OTHER"},
            {"manufacturer_id": "other"},
        ):
            before = stack_inventory()
            row = {
                **before["stack"]["selected"],
                "id": "old-2",
                "serial": "LAB93000002",
                "name": "other",
                **changed,
            }
            before["stack"]["devices"].append(row)
            if not changed:
                before["stack"]["devices"].append({**row, "id": "duplicate"})
            self.assertTrue(planner.plan_stack(observed_stack(), before)["errors"])

    def test_foreign_vc_or_member_name_collision_blocks(self):
        for changed in ({"virtual_chassis_id": "foreign"}, {"serial": "UNRELATED"}):
            before = stack_inventory()
            before["stack"]["devices"].append(
                {
                    **before["stack"]["selected"],
                    "id": "old-2",
                    "serial": "LAB93000002",
                    "name": "example-9300:2",
                    **changed,
                }
            )
            self.assertTrue(planner.plan_stack(observed_stack(), before)["errors"])

    def test_named_vc_occupied_by_different_physical_stack_blocks(self):
        before = stack_inventory()
        before["stack"]["virtual_chassis"] = [
            {"id": "other-vc", "name": "example-9300", "master_id": "other"}
        ]
        before["stack"]["devices"].append(
            {
                **before["stack"]["selected"],
                "id": "other",
                "serial": "UNRELATED",
                "name": "other",
                "virtual_chassis_id": "other-vc",
                "vc_position": 1,
            }
        )
        self.assertTrue(planner.plan_stack(observed_stack(), before)["errors"])

    def test_priority_follows_reported_value_while_position_conflict_blocks(self):
        before = stack_inventory()
        after = applied_stack(planner.plan_stack(observed_stack(), before), before)
        observed = observed_stack()
        observed["stack"]["members"][1]["priority"] = 8
        plan = planner.plan_stack(observed, after)
        self.assertFalse(plan["errors"])
        self.assertEqual(
            plan["members"][1]["changes"], [{"field": "vc_priority", "before": 12, "after": 8}]
        )
        after["stack"]["devices"][1]["vc_position"] = 3
        self.assertTrue(planner.plan_stack(observed, after)["errors"])

    def test_unobserved_members_are_retained_and_occupied_slots_block(self):
        before = stack_inventory()
        after = applied_stack(planner.plan_stack(observed_stack(), before), before)
        after["stack"]["devices"].append(
            {
                **after["stack"]["devices"][1],
                "id": "absent-3",
                "serial": "ABSENT",
                "name": "old:3",
                "vc_position": 3,
            }
        )
        plan = planner.plan_stack(observed_stack(), after)
        self.assertFalse(plan["errors"])
        self.assertTrue(any("unobserved" in warning for warning in plan["warnings"]))
        after["stack"]["devices"][-1]["vc_position"] = 2
        self.assertTrue(planner.plan_stack(observed_stack(), after)["errors"])

    def test_malformed_source_roles_modes_positions_and_identity_block(self):
        cases = [
            ("role", "role-unknown"),
            ("state", "state-provisioned"),
            ("stack_mode", "mode-virtual"),
            ("position", True),
            ("priority", 256),
            ("serial", ""),
            ("sources", {}),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                observed = observed_stack()
                observed["stack"]["members"][1][field] = value
                self.assertTrue(planner.plan_stack(observed, stack_inventory())["errors"])
        observed = observed_stack()
        observed["stack"]["members"][1]["serial"] = "LAB93000001"
        self.assertTrue(planner.plan_stack(observed, stack_inventory())["errors"])
        observed = observed_stack()
        observed["identity"]["serial"] = "WRONG"
        self.assertTrue(planner.plan_stack(observed, stack_inventory())["errors"])

    def test_standalone_never_creates_or_dissolves_vc(self):
        observed = observed_stack()
        observed["stack"]["is_stack"] = False
        before = stack_inventory()
        plan = planner.plan_stack(observed, before)
        self.assertFalse(plan["errors"])
        self.assertIsNone(plan["virtual_chassis"])
        self.assertTrue(all(count == 0 for count in plan["summary"].values()))
        before["stack"]["selected"]["virtual_chassis_id"] = "old-vc"
        self.assertTrue(planner.plan_stack(observed, before)["warnings"])

    def test_unobserved_old_master_can_yield_to_known_active_member(self):
        before = stack_inventory()
        after = applied_stack(planner.plan_stack(observed_stack(), before), before)
        after["stack"]["devices"].append(
            {
                **after["stack"]["devices"][1],
                "id": "absent-3",
                "serial": "ABSENT",
                "name": "old:3",
                "vc_position": 3,
            }
        )
        after["stack"]["virtual_chassis"][0]["master_id"] = "absent-3"
        plan = planner.plan_stack(observed_stack(active=2), after)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["virtual_chassis_updated"], 1)
        self.assertEqual(plan["virtual_chassis"]["master_position"], 2)
        self.assertTrue(any("unobserved" in warning for warning in plan["warnings"]))

    def test_padded_member_serials_and_old_master_identity_do_not_duplicate(self):
        before = stack_inventory()
        after = applied_stack(planner.plan_stack(observed_stack(), before), before)
        after["stack"]["devices"][1]["serial"] = "\tLAB93000002\n"
        after["stack"]["virtual_chassis"][0]["master_id"] = "created-member-2"
        plan = planner.plan_stack(observed_stack(active=2), after)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["stack_members_created"], 0)
        self.assertEqual(plan["summary"]["virtual_chassis_updated"], 0)

    def test_blank_existing_member_name_fills_but_populated_name_preserves(self):
        before = stack_inventory()
        before["stack"]["devices"].append(
            {**before["stack"]["selected"], "id": "old-2", "serial": "LAB93000002", "name": None}
        )
        plan = planner.plan_stack(observed_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["members"][1]["existing_id"], "old-2")
        self.assertEqual(plan["members"][1]["name"], "example-9300:2")
        self.assertIn(
            {"field": "name", "before": None, "after": "example-9300:2"},
            plan["members"][1]["changes"],
        )
        before["stack"]["devices"].append(
            {
                **before["stack"]["selected"],
                "id": "collision",
                "serial": "OTHER",
                "name": "example-9300:2",
            }
        )
        self.assertTrue(planner.plan_stack(observed_stack(), before)["errors"])

    def test_blank_selected_hostname_collision_blocks_before_model_save(self):
        before = stack_inventory()
        for row in (before["device"], before["stack"]["selected"], before["stack"]["devices"][0]):
            row["name"] = None
        before["stack"]["devices"].append(
            {
                **before["stack"]["selected"],
                "id": "collision",
                "serial": "OTHER",
                "name": "example-9300",
            }
        )
        self.assertTrue(planner.plan_stack(observed_stack(), before)["errors"])


if __name__ == "__main__":
    unittest.main()
