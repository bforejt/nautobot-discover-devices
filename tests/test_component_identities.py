"""Reported hardware identities seed catalogs without invented installations."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_components_reconcile import apply_to_snapshot, installed, inventory, item

planner = load("reconcile_components")


def identity(key="identity:optic", **values):
    manufacturer = values.get("manufacturer", "Cisco")
    return {
        "key": key,
        "kind": "transceiver",
        "manufacturer": manufacturer,
        "model": "NEW-BIDI-PID",
        "part_number": "NEW-BIDI-PID",
        "serial": "SERIAL-UNKNOWN-PLACEMENT",
        "source": {
            "manufacturer": {
                "module": "Cisco-IOS-XE-platform-oper",
                "path": "/data/Cisco-IOS-XE-platform-oper:components",
                "field": "state/mfg-name",
                "component": "Reported Transceiver",
                "value": manufacturer,
            },
            "identity": {"module": "Cisco-IOS-XE-device-hardware-oper"},
        },
        "observations": {"parent": "Reported chassis", "location": None},
        **values,
    }


def discovery(*identities, items=None, **components):
    return {
        "components": {
            "schema_version": 1,
            "items": list(items or []),
            "identities": list(identities),
            "unresolved": [],
            "excluded": [],
            **components,
        }
    }


class ComponentIdentitiesTests(unittest.TestCase):
    def assert_no_placement(self, plan):
        for field in (
            "bays",
            "modules",
            "power_ports",
            "interface_assignments",
            "interface_ownership_deferred",
            "missing_modules",
        ):
            self.assertEqual([], plan[field], field)

    def test_new_pid_creates_only_catalog_and_repeats_without_changes(self):
        observed = discovery(identity())
        before = inventory()
        original = deepcopy(observed)
        plan = planner.plan_components(observed, before)
        self.assertEqual([], plan["errors"])
        self.assertEqual([], plan["manufacturers"])
        self.assertEqual(1, plan["summary"]["module_types_created"])
        self.assertEqual("NEW-BIDI-PID", plan["module_types"][0]["part_number"])
        self.assert_no_placement(plan)
        repeated = planner.plan_components(observed, apply_to_snapshot(plan, before))
        self.assertEqual([], repeated["errors"])
        self.assertEqual(0, repeated["summary"]["module_types_created"])
        self.assertEqual(0, repeated["summary"]["module_types_updated"])
        self.assert_no_placement(repeated)
        self.assertEqual(original, observed)

    def test_new_reported_oem_creates_one_manufacturer_and_type_per_pid(self):
        observed = discovery(
            identity(manufacturer="New Optics OEM"),
            identity(key="identity:second", manufacturer="New Optics OEM", serial="SECOND"),
        )
        before = inventory()
        plan = planner.plan_components(observed, before)
        self.assertEqual([], plan["errors"])
        self.assertEqual(1, plan["summary"]["manufacturers_created"])
        self.assertEqual(1, plan["summary"]["module_types_created"])
        self.assertEqual("New Optics OEM", plan["manufacturers"][0]["name"])
        self.assert_no_placement(plan)
        repeated = planner.plan_components(observed, apply_to_snapshot(plan, before))
        self.assertEqual([], repeated["errors"])
        self.assertEqual(0, repeated["summary"]["manufacturers_created"])
        self.assertEqual(0, repeated["summary"]["module_types_created"])

    def test_incomplete_fields_remain_unresolved_without_catalogs(self):
        for field in ("key", "kind", "manufacturer", "model", "part_number", "serial"):
            with self.subTest(field=field):
                plan = planner.plan_components(discovery(identity(**{field: None})), inventory())
                self.assertEqual([], plan["errors"])
                self.assertEqual([], plan["module_types"])
                self.assertEqual([], plan["manufacturers"])
                self.assertEqual(1, len(plan["unresolved"]))
                self.assert_no_placement(plan)

    def test_missing_reported_manufacturer_evidence_never_uses_chassis_brand(self):
        for manufacturer in ("Cisco", "New OEM"):
            with self.subTest(manufacturer=manufacturer):
                plan = planner.plan_components(
                    discovery(identity(manufacturer=manufacturer, source={})), inventory()
                )
                self.assertEqual([], plan["errors"])
                self.assertEqual([], plan["module_types"])
                self.assertEqual([], plan["manufacturers"])
                self.assertEqual(1, len(plan["unresolved"]))

    def test_malformed_source_and_contradictory_provenance_are_errors(self):
        for source in (
            None,
            [],
            {"manufacturer": "Cisco"},
            {"manufacturer": {}},
            {"identity": "unstructured", "manufacturer": identity()["source"]["manufacturer"]},
            {"manufacturer": {**identity()["source"]["manufacturer"], "value": "Other OEM"}},
            {"manufacturer": {**identity()["source"]["manufacturer"], "component": None}},
            {"manufacturer": {**identity()["source"]["manufacturer"], "field": "PID prefix"}},
        ):
            with self.subTest(source=source):
                plan = planner.plan_components(discovery(identity(source=source)), inventory())
                self.assertTrue(plan["errors"])
                self.assertEqual([], plan["module_types"])
                self.assertEqual([], plan["manufacturers"])

    def test_unknown_placement_does_not_claim_existing_assets_are_missing(self):
        before = installed(inventory())
        plan = planner.plan_components(discovery(identity()), before)
        self.assertEqual([], plan["errors"])
        self.assert_no_placement(plan)

    def test_identity_relationship_properties_cannot_create_placements(self):
        observed = identity(
            parent_key="unverified-parent",
            bay={"name": "Unverified bay"},
            interfaces=["Gi1/1/1"],
            power_ports=[{"name": "Unverified inlet"}],
            device_serial="Unknown chassis",
            member=99,
        )
        plan = planner.plan_components(discovery(observed), inventory())
        self.assertEqual([], plan["errors"])
        self.assertEqual(1, plan["summary"]["module_types_created"])
        self.assert_no_placement(plan)

    def test_unique_existing_catalog_alias_preserves_operator_model(self):
        before = inventory()
        before["components"]["module_types"] = [
            {
                "id": "type-operator",
                "manufacturer_id": "manufacturer-1",
                "model": "Operator optical module label",
                "part_number": " NEW-BIDI-PID ",
            }
        ]
        plan = planner.plan_components(discovery(identity()), before)
        self.assertEqual([], plan["errors"])
        self.assertEqual("type-operator", plan["module_types"][0]["id"])
        self.assertEqual("Operator optical module label", plan["module_types"][0]["model"])
        self.assertEqual([], plan["module_types"][0]["changes"])
        self.assert_no_placement(plan)

    def test_existing_blank_pid_is_filled_once(self):
        before = inventory()
        before["components"]["module_types"] = [
            {
                "id": "type-1",
                "manufacturer_id": "manufacturer-1",
                "model": "NEW-BIDI-PID",
                "part_number": "",
            }
        ]
        observed = discovery(identity())
        plan = planner.plan_components(observed, before)
        self.assertEqual([], plan["errors"])
        self.assertEqual(1, plan["summary"]["module_types_updated"])
        self.assert_no_placement(plan)
        repeat = planner.plan_components(observed, apply_to_snapshot(plan, before))
        self.assertEqual(0, repeat["summary"]["module_types_updated"])

    def test_populated_conflicting_catalog_pid_is_preserved(self):
        before = inventory()
        before["components"]["module_types"] = [
            {
                "id": "type-1",
                "manufacturer_id": "manufacturer-1",
                "model": "NEW-BIDI-PID",
                "part_number": "OPERATOR-PID",
            }
        ]
        plan = planner.plan_components(discovery(identity()), before)
        self.assertEqual([], plan["errors"])
        self.assertEqual([], plan["module_types"])
        self.assertEqual("OPERATOR-PID", plan["conflicts"][0]["before"])
        self.assertEqual(1, len(plan["unresolved"]))
        self.assert_no_placement(plan)

    def test_ambiguous_existing_model_and_pid_aliases_are_errors(self):
        before = inventory()
        before["components"]["module_types"] = [
            {
                "id": "type-model",
                "manufacturer_id": "manufacturer-1",
                "model": "NEW-BIDI-PID",
                "part_number": "",
            },
            {
                "id": "type-pid",
                "manufacturer_id": "manufacturer-1",
                "model": "Operator alias",
                "part_number": "NEW-BIDI-PID",
            },
        ]
        plan = planner.plan_components(discovery(identity()), before)
        self.assertTrue(plan["errors"])
        self.assertEqual([], plan["module_types"])

    def test_ambiguous_existing_manufacturer_names_are_errors(self):
        before = inventory()
        before["components"]["manufacturers"].append({"id": "second", "name": " CISCO "})
        plan = planner.plan_components(discovery(identity()), before)
        self.assertTrue(plan["errors"])
        self.assertEqual([], plan["module_types"])

    def test_duplicate_serialized_identity_and_keys_are_errors(self):
        for second in (identity(key="second"), identity(serial="SECOND")):
            with self.subTest(second=second):
                plan = planner.plan_components(discovery(identity(), second), inventory())
                self.assertTrue(plan["errors"])
                self.assertEqual([], plan["module_types"])
                self.assertEqual([], plan["manufacturers"])

    def test_identity_and_placed_component_share_catalog_when_facts_agree(self):
        placed = item()
        reported = identity(
            kind=placed["kind"],
            model=placed["model"],
            part_number=placed["part_number"],
            serial=placed["serial"],
        )
        plan = planner.plan_components(discovery(reported, items=[placed]), inventory())
        self.assertEqual([], plan["errors"])
        self.assertEqual(1, plan["summary"]["module_types_created"])
        self.assertEqual(1, plan["summary"]["modules_created"])
        self.assertEqual(plan["module_types"][0]["key"], plan["modules"][0]["module_type_key"])

    def test_identity_and_placed_component_incompatible_type_claims_are_errors(self):
        placed = item()
        for reported in (
            identity(model=placed["model"], part_number="DIFFERENT-PID"),
            identity(model="DIFFERENT-MODEL", part_number=placed["part_number"]),
            identity(
                model=placed["model"], part_number=placed["part_number"], serial=placed["serial"]
            ),
        ):
            with self.subTest(reported=reported):
                plan = planner.plan_components(discovery(reported, items=[placed]), inventory())
                self.assertTrue(plan["errors"])
                self.assertEqual([], plan["module_types"])
                self.assertEqual([], plan["modules"])

    def test_identities_disagreeing_on_type_or_pid_are_errors(self):
        for second in (
            identity(key="second", part_number="DIFFERENT-PID", serial="SECOND"),
            identity(key="second", model="DIFFERENT-MODEL", serial="SECOND"),
        ):
            with self.subTest(second=second):
                plan = planner.plan_components(discovery(identity(), second), inventory())
                self.assertTrue(plan["errors"])
                self.assertEqual([], plan["module_types"])

    def test_deferred_or_unavailable_inventory_never_writes_catalogs(self):
        deferred = planner.plan_components(
            discovery(identity(), writes_deferred_reason="No trustworthy platform source"),
            inventory(),
        )
        self.assertTrue(deferred["errors"])
        self.assertEqual([], deferred["module_types"])
        before = inventory()
        before["components"]["supported"] = False
        unsupported = planner.plan_components(discovery(identity()), before)
        self.assertEqual([], unsupported["errors"])
        self.assertTrue(unsupported["warnings"])
        self.assertEqual([], unsupported["module_types"])
        self.assertEqual(1, len(unsupported["unresolved"]))

    def test_malformed_identity_container_and_rows_are_errors(self):
        for identities in (None, {}, "PID", [None]):
            with self.subTest(identities=identities):
                observed = discovery()
                observed["components"]["identities"] = identities
                plan = planner.plan_components(observed, inventory())
                self.assertTrue(plan["errors"])
                self.assertEqual([], plan["module_types"])


if __name__ == "__main__":
    unittest.main()
