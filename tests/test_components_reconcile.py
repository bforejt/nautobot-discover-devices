"""Serialized identity, placement, and interface ownership regression tests."""

import json
import unittest
from copy import deepcopy

from tests._loader import load

planner = load("reconcile_components")


def item(key="uplink:1/1", **values):
    return {
        "key": key,
        "kind": "uplink",
        "manufacturer": "Cisco",
        "model": "C3850-NM-4-1G",
        "part_number": "C3850-NM-4-1G",
        "serial": "LABMODULE001",
        "parent_key": None,
        "bay": {"name": "Uplink Module 1", "position": "1", "label": "Uplink 1"},
        "interfaces": ["GigabitEthernet1/1/1"],
        "source": {},
        "observations": {},
        **values,
    }


def discovery(*items):
    return {
        "components": {
            "schema_version": 1,
            "items": list(items),
            "unresolved": [],
            "excluded": [],
        }
    }


def reported_manufacturer_item(**values):
    manufacturer = values.get("manufacturer", "CISCO-EQUIV")
    return item(
        manufacturer=manufacturer,
        source={
            "manufacturer": {
                "module": "Cisco-IOS-XE-platform-oper",
                "path": "/data/Cisco-IOS-XE-platform-oper:components",
                "field": "state/mfg-name",
                "component": "GigabitEthernet1/1/1",
                "value": manufacturer,
            }
        },
        **{key: value for key, value in values.items() if key != "manufacturer"},
    )


def inventory():
    return {
        "device": {"id": "device-1"},
        "interfaces": [{"id": "interface-1", "name": "Gi1/1/1", "module_id": None}],
        "components": {
            "supported": True,
            "manufacturers": [{"id": "manufacturer-1", "name": "Cisco"}],
            "module_types": [],
            "module_bays": [],
            "modules": [],
        },
    }


def installed(before, *, serial="LABMODULE001", module_id="module-1", bay_name="Uplink Module 1"):
    before["components"]["module_types"] = [
        {
            "id": "type-1",
            "manufacturer_id": "manufacturer-1",
            "model": "C3850-NM-4-1G",
            "part_number": "C3850-NM-4-1G",
        }
    ]
    before["components"]["module_bays"] = [
        {
            "id": "bay-1",
            "parent_device_id": "device-1",
            "parent_module_id": None,
            "name": bay_name,
            "position": "1",
            "label": "Uplink 1",
        }
    ]
    before["components"]["modules"] = [
        {
            "id": module_id,
            "module_type_id": "type-1",
            "serial": serial,
            "parent_module_bay_id": "bay-1",
            "location_id": None,
            "device_id": "device-1",
        }
    ]
    return before


def apply_to_snapshot(plan, before):
    after = deepcopy(before)
    manufacturer_ids = {}
    for row in plan.get("manufacturers", []):
        manufacturer_ids[row["key"]] = "created-manufacturer-" + row["key"]
        after["components"]["manufacturers"].append(
            {"id": manufacturer_ids[row["key"]], "name": row["name"]}
        )
    type_ids, module_ids, bay_ids = {}, {}, {}
    for row in plan["module_types"]:
        type_ids[row["key"]] = row["id"] or "created-type-" + row["key"]
        if row["create"]:
            after["components"]["module_types"].append(
                {
                    "id": type_ids[row["key"]],
                    "manufacturer_id": row["manufacturer_id"]
                    or manufacturer_ids[row["manufacturer_key"]],
                    "model": row["model"],
                    "part_number": row["part_number"],
                }
            )
        else:
            existing = next(
                value for value in after["components"]["module_types"] if value["id"] == row["id"]
            )
            for change in row["changes"]:
                existing[change["field"]] = change["after"]
    for row in plan["modules"]:
        module_ids[row["key"]] = row["id"] or "created-module-" + row["key"]
    for row in plan["bays"]:
        bay_ids[row["key"]] = row["id"] or "created-bay-" + row["key"]
        if row["create"]:
            after["components"]["module_bays"].append(
                {
                    "id": bay_ids[row["key"]],
                    "parent_device_id": after["device"]["id"],
                    "parent_module_id": module_ids.get(row["parent_key"]),
                    "name": row["name"],
                    "position": row["position"],
                    "label": row["label"],
                }
            )
        else:
            existing = next(
                value for value in after["components"]["module_bays"] if value["id"] == row["id"]
            )
            for change in row["changes"]:
                existing[change["field"]] = change["after"]
    for row in plan["modules"]:
        if row["create"]:
            after["components"]["modules"].append(
                {
                    "id": module_ids[row["key"]],
                    "module_type_id": type_ids[row["module_type_key"]],
                    "serial": row["serial"],
                    "parent_module_bay_id": bay_ids[row["bay_key"]],
                    "location_id": None,
                    "device_id": after["device"]["id"],
                }
            )
        else:
            existing = next(
                value for value in after["components"]["modules"] if value["id"] == row["id"]
            )
            for change in row["changes"]:
                existing[change["field"]] = change["after"]
    for row in plan["interface_assignments"]:
        existing = next(value for value in after["interfaces"] if value["id"] == row["id"])
        existing["module_id"] = module_ids[row["module_key"]]
    return after


class ComponentReconciliationTests(unittest.TestCase):
    def test_new_serialized_module_links_existing_alias_without_replacing_uuid(self):
        before = inventory()
        untouched = deepcopy(before)
        plan = planner.plan_components(discovery(item()), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["modules_created"], 1)
        self.assertEqual(plan["summary"]["module_types_created"], 1)
        self.assertEqual(plan["summary"]["module_bays_created"], 1)
        self.assertEqual(
            plan["interface_assignments"],
            [
                {
                    "id": "interface-1",
                    "name": "Gi1/1/1",
                    "module_key": "uplink:1/1",
                    "module_id": None,
                }
            ],
        )
        self.assertEqual(before, untouched)
        json.dumps(plan)

    def test_second_pass_has_no_inventory_writes(self):
        before = inventory()
        first = planner.plan_components(discovery(item()), before)
        after = apply_to_snapshot(first, before)
        second = planner.plan_components(discovery(item()), after)
        self.assertFalse(second["errors"])
        self.assertFalse(second["conflicts"])
        self.assertFalse(second["missing_modules"])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_blank_serial_and_catalog_metadata_fill_in_place(self):
        before = installed(inventory(), serial=None)
        before["components"]["module_types"][0]["part_number"] = ""
        before["components"]["module_bays"][0].update(position="", label=None)
        plan = planner.plan_components(discovery(item()), before)
        self.assertEqual(plan["modules"][0]["id"], "module-1")
        self.assertEqual(
            plan["modules"][0]["changes"],
            [
                {
                    "field": "serial",
                    "before": None,
                    "after": "LABMODULE001",
                }
            ],
        )
        self.assertEqual(plan["summary"]["modules_updated"], 1)
        self.assertEqual(plan["summary"]["module_types_updated"], 1)
        self.assertEqual(plan["summary"]["module_bays_updated"], 1)
        self.assertEqual(plan["summary"]["modules_created"], 0)

    def test_populated_serial_replacement_does_not_create_or_update_asset(self):
        before = installed(inventory(), serial="OTHER-MODULE")
        plan = planner.plan_components(discovery(item()), before)
        self.assertEqual(plan["modules"], [])
        self.assertEqual(plan["module_types"], [])
        self.assertEqual(plan["bays"], [])
        self.assertEqual(plan["conflicts"][0]["field"], "serial")

    def test_serialized_module_elsewhere_is_reported_without_relocation(self):
        for other_device, location in (("other-device", None), (None, "spares-location")):
            with self.subTest(location=location):
                before = installed(inventory())
                before["components"]["module_bays"] = []
                before["components"]["modules"][0].update(
                    parent_module_bay_id="other-bay" if other_device else None,
                    device_id=other_device,
                    location_id=location,
                )
                plan = planner.plan_components(discovery(item()), before)
                self.assertFalse(plan["errors"])
                self.assertEqual(plan["modules"], [])
                self.assertEqual(plan["conflicts"][0]["field"], "parent_module_bay")
                self.assertFalse(plan["missing_modules"])

    def test_blank_serial_cannot_absorb_existing_asset_in_another_bay(self):
        before = installed(inventory(), serial=None)
        before["components"]["modules"].append(
            {
                "id": "global-asset",
                "module_type_id": "type-1",
                "serial": "LABMODULE001",
                "parent_module_bay_id": "another-bay",
                "location_id": None,
                "device_id": "device-2",
            }
        )
        plan = planner.plan_components(discovery(item()), before)
        self.assertEqual(plan["modules"], [])
        self.assertTrue(plan["conflicts"])

    def test_same_serial_can_identify_two_different_module_types(self):
        observed = discovery(
            item(),
            item(
                "psu:1/B",
                kind="psu",
                model="PWR-C1-1100WAC-P",
                part_number="PWR-C1-1100WAC-P",
                bay={"name": "Power Supply B", "position": "PSU-B", "label": "B"},
                interfaces=[],
            ),
        )
        plan = planner.plan_components(observed, inventory())
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["modules_created"], 2)

    def test_duplicate_pid_catalog_is_ambiguous_even_when_model_matches(self):
        before = installed(inventory())
        before["components"]["module_types"].append(
            {
                "id": "other-type",
                "manufacturer_id": "manufacturer-1",
                "model": "Friendly duplicate",
                "part_number": "C3850-NM-4-1G",
            }
        )
        plan = planner.plan_components(discovery(item()), before)
        self.assertTrue(plan["errors"])
        self.assertEqual(plan["modules"], [])

    def test_unique_pid_catalog_alias_is_reused_without_renaming(self):
        before = installed(inventory())
        before["components"]["module_types"][0]["model"] = "Operator-friendly uplink name"
        plan = planner.plan_components(discovery(item()), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["module_types"][0]["id"], "type-1")
        self.assertEqual(plan["module_types"][0]["model"], "Operator-friendly uplink name")
        self.assertEqual(plan["module_types"][0]["changes"], [])

    def test_bay_position_and_label_do_not_change_placement(self):
        before = installed(inventory())
        before["components"]["module_bays"][0].update(
            position="operator-position", label="Operator"
        )
        plan = planner.plan_components(discovery(item()), before)
        self.assertEqual(plan["bays"][0]["id"], "bay-1")
        self.assertEqual(plan["bays"][0]["changes"], [])
        self.assertEqual(plan["modules"][0]["id"], "module-1")
        self.assertEqual({row["field"] for row in plan["conflicts"]}, {"position", "label"})

    def test_interface_populated_ownership_is_preserved(self):
        before = installed(inventory())
        before["interfaces"][0]["module_id"] = "operator-module"
        plan = planner.plan_components(discovery(item()), before)
        self.assertEqual(plan["interface_assignments"], [])
        self.assertEqual(plan["conflicts"][0]["field"], "module")
        self.assertEqual(plan["modules"][0]["id"], "module-1")

    def test_existing_and_planned_logical_interfaces_keep_ownership_unchanged(self):
        for interface_type in ("virtual", "bridge", "lag", "tunnel"):
            with self.subTest(interface_type=interface_type):
                before = inventory()
                before["interfaces"][0]["type"] = interface_type
                plan = planner.plan_components(discovery(item()), before)
                self.assertFalse(plan["interface_assignments"])
                self.assertTrue(plan["warnings"])
                before["interfaces"] = []
                plan = planner.plan_components(
                    discovery(item()),
                    before,
                    {
                        "interface_creates": [{"name": "Gi1/1/1", "type": interface_type}],
                    },
                )
                self.assertFalse(plan["interface_assignments"])
                self.assertTrue(plan["warnings"])

    def test_planned_new_interface_can_be_assigned_but_skipped_interface_cannot(self):
        before = inventory()
        before["interfaces"] = []
        observed = discovery(item(interfaces=["Gi1/1/1", "Gi1/1/2"]))
        plan = planner.plan_components(
            observed, before, {"interface_creates": [{"name": "Gi1/1/1"}]}
        )
        self.assertEqual(len(plan["interface_assignments"]), 1)
        self.assertIsNone(plan["interface_assignments"][0]["id"])
        self.assertEqual(plan["interface_assignments"][0]["name"], "GigabitEthernet1/1/1")
        self.assertTrue(plan["warnings"])

    def test_nested_child_uses_immediate_parent_and_survives_second_pass(self):
        parent = item(interfaces=[])
        child = item(
            "optic:1/1/1",
            kind="optic",
            model="SFP-10G-SR",
            part_number="SFP-10G-SR",
            serial="LABOPTIC001",
            parent_key=parent["key"],
            interfaces=[],
            bay={"name": "Port 1", "position": "1", "label": "Gi1/1/1"},
        )
        before = inventory()
        first = planner.plan_components(discovery(child, parent), before)
        self.assertFalse(first["errors"])
        self.assertEqual(first["bays"][1]["parent_key"], parent["key"])
        after = apply_to_snapshot(first, before)
        second = planner.plan_components(discovery(child, parent), after)
        self.assertFalse(second["errors"])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_ambiguous_source_ownership_identity_and_bay_are_blocked(self):
        examples = [
            discovery(item(), item("second", serial="OTHER", bay={"name": "Other"})),
            discovery(item(interfaces=[]), item("second", bay={"name": "Other"}, interfaces=[])),
            discovery(item(interfaces=[]), item("second", serial="OTHER", interfaces=[])),
        ]
        for observed in examples:
            with self.subTest(observed=observed):
                plan = planner.plan_components(observed, inventory())
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["modules"])

    def test_cycle_unknown_parent_and_malformed_identity_are_errors(self):
        for observed in (
            discovery(item(parent_key="uplink:1/1")),
            discovery(item(parent_key="unknown")),
            discovery(item(serial="")),
            discovery(item(source="not a structured object")),
            {"components": {"schema_version": 2}},
            {"components": {"schema_version": True, "items": []}},
            {"components": None},
            {"components": {"schema_version": 1}},
        ):
            with self.subTest(observed=observed):
                plan = planner.plan_components(observed, inventory())
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["modules"])

    def test_one_manufacturer_model_cannot_claim_two_part_numbers(self):
        observed = discovery(
            item(interfaces=[]),
            item(
                "other",
                serial="LABMODULE002",
                part_number="OTHER-PID",
                bay={"name": "Other Bay"},
                interfaces=[],
            ),
        )
        plan = planner.plan_components(observed, inventory())
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["modules"])

    def test_one_pid_cannot_create_two_module_type_aliases(self):
        observed = discovery(
            item(interfaces=[]),
            item(
                "other",
                serial="LABMODULE002",
                model="Different model alias",
                bay={"name": "Other Bay"},
                interfaces=[],
            ),
        )
        plan = planner.plan_components(observed, inventory())
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["module_types"])

    def test_duplicate_existing_bay_names_are_not_resolved_by_position(self):
        before = installed(inventory())
        before["components"]["module_bays"].append(
            {
                **before["components"]["module_bays"][0],
                "id": "bay-2",
                "position": "other",
            }
        )
        plan = planner.plan_components(discovery(item()), before)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["modules"])

    def test_existing_interface_alias_ambiguity_blocks_ownership(self):
        before = inventory()
        before["interfaces"].append(
            {
                "id": "interface-2",
                "name": "GigabitEthernet1/1/1",
                "module_id": None,
            }
        )
        plan = planner.plan_components(discovery(item()), before)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["interface_assignments"])

    def test_unknown_manufacturer_is_not_created_implicitly(self):
        plan = planner.plan_components(discovery(item(manufacturer="Unknown")), inventory())
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["module_types"])

    def test_reported_manufacturer_is_created_and_repeat_reuses_it(self):
        before = inventory()
        observed = discovery(reported_manufacturer_item())
        plan = planner.plan_components(observed, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["manufacturers_created"], 1)
        self.assertEqual(plan["manufacturers"][0]["name"], "CISCO-EQUIV")
        self.assertIsNone(plan["module_types"][0]["manufacturer_id"])
        after = apply_to_snapshot(plan, before)
        repeat = planner.plan_components(observed, after)
        self.assertFalse(repeat["errors"])
        self.assertFalse(repeat["manufacturers"])
        self.assertTrue(all(count == 0 for count in repeat["summary"].values()))

    def test_reported_manufacturer_is_created_once_for_multiple_assets(self):
        first = reported_manufacturer_item(interfaces=[])
        second = reported_manufacturer_item(
            key="uplink:1/2", serial="LABMODULE002", bay={"name": "Uplink Module 2"}, interfaces=[]
        )
        plan = planner.plan_components(discovery(first, second), inventory())
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["manufacturers_created"], 1)
        self.assertEqual(plan["summary"]["module_types_created"], 1)
        self.assertEqual(plan["summary"]["modules_created"], 2)

    def test_manufacturer_source_must_match_the_exact_reported_name_and_leaf(self):
        for field, value in (
            ("value", "Cisco"),
            ("field", "state/description"),
            ("component", None),
        ):
            with self.subTest(field=field):
                part = reported_manufacturer_item()
                part["source"]["manufacturer"][field] = value
                plan = planner.plan_components(discovery(part), inventory())
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["manufacturers"])
                self.assertFalse(plan["modules"])

    def test_existing_manufacturer_spelling_and_description_are_preserved(self):
        before = inventory()
        before["components"]["manufacturers"].append(
            {"id": "equiv-1", "name": "Cisco-Equiv", "description": "Operator catalog name"}
        )
        plan = planner.plan_components(discovery(reported_manufacturer_item()), before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["manufacturers"])
        self.assertEqual(plan["module_types"][0]["manufacturer_id"], "equiv-1")

    def test_ambiguous_manufacturer_names_block_even_with_source_evidence(self):
        before = inventory()
        before["components"]["manufacturers"].extend(
            [{"id": "equiv-1", "name": "CISCO-EQUIV"}, {"id": "equiv-2", "name": "cisco-equiv"}]
        )
        plan = planner.plan_components(discovery(reported_manufacturer_item()), before)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["manufacturers"])
        self.assertFalse(plan["modules"])

    def test_blocked_occupied_bay_does_not_create_orphan_manufacturer(self):
        before = installed(inventory())
        plan = planner.plan_components(discovery(reported_manufacturer_item()), before)
        self.assertFalse(plan["errors"])
        self.assertTrue(plan["conflicts"])
        self.assertFalse(plan["manufacturers"])
        self.assertFalse(plan["module_types"])

    def test_populated_catalog_identity_is_not_changed(self):
        before = installed(inventory())
        before["components"]["module_types"][0]["part_number"] = "OPERATOR-PID"
        plan = planner.plan_components(discovery(item()), before)
        self.assertFalse(plan["modules"])
        self.assertEqual(plan["conflicts"][0]["field"], "part_number")

    def test_shared_module_type_is_created_once_for_two_assets(self):
        observed = discovery(
            item(interfaces=[]),
            item(
                "uplink:1/2",
                serial="LABMODULE002",
                bay={"name": "Uplink Module 2"},
                interfaces=[],
            ),
        )
        plan = planner.plan_components(observed, inventory())
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["modules_created"], 2)
        self.assertEqual(plan["summary"]["module_types_created"], 1)

    def test_missing_components_are_reported_without_deletion(self):
        before = installed(inventory())
        plan = planner.plan_components(discovery(), before)
        self.assertEqual(plan["missing_modules"][0]["id"], "module-1")
        self.assertFalse(plan["modules"])
        self.assertNotIn("module_deletes", plan)

    def test_missing_feature_does_not_claim_existing_components_disappeared(self):
        self.assertFalse(planner.plan_components({}, installed(inventory()))["missing_modules"])

    def test_unsupported_runtime_and_adapter_unresolved_evidence_are_visible(self):
        before = inventory()
        before["components"]["supported"] = False
        observed = discovery(item())
        observed["components"]["unresolved"] = [{"key": "psu:1/B", "reason": "Serial missing"}]
        observed["components"]["excluded"] = [{"key": "stack-alias", "reason": "Pseudo-entry"}]
        plan = planner.plan_components(observed, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["unresolved_components"], 2)
        self.assertEqual(plan["excluded"], observed["components"]["excluded"])


if __name__ == "__main__":
    unittest.main()
