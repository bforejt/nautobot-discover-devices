"""Capacity intent preservation and schema gating without Django models."""

import json
import sys
import unittest
from copy import deepcopy
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from tests._loader import load

planner = load("reconcile_capacity")


def discovery():
    return {
        "adapter": "panos",
        "capacity": {
            "contract": "panos-capacity-v1",
            "fields": {
                key: {"value": value, "source": {"reviewed_allocation": key}}
                for key, value in (("vcpus", 4), ("memory_mb", 8192), ("disk_gb", 60))
            },
            "unresolved": [],
        },
    }


def inventory():
    return {
        "device": {"id": "device-id", "name": "panos-lab", "model": "PA-VM"},
        "capacity_inventory": {
            "supported": True,
            "reason": None,
            "fields": {
                key: {
                    "id": "field-" + key,
                    "type": "integer",
                    "device_scope": True,
                    "supported": True,
                    "scope_filter": None,
                    "validation_minimum": None,
                    "validation_maximum": None,
                }
                for key in planner.CAPACITY_FIELDS
            },
            "values": {key: None for key in planner.CAPACITY_FIELDS},
        },
    }


class CapacityReconcileTests(unittest.TestCase):
    def plan(self, observed=None, existing=None, *, identity=True, source_valid=True):
        """Source validation has its own tests; isolate native planning semantics."""
        validator = ModuleType("jobs.adapters.panos_capacity")
        validator.validate_capacity = Mock(return_value=source_valid)
        with patch.dict(sys.modules, {"jobs.adapters.panos_capacity": validator}):
            return planner.plan_capacity(
                observed or discovery(),
                existing or inventory(),
                identity_verified=identity,
            )

    def test_blank_fields_seed_together_without_mutating_inputs(self):
        observed, existing = discovery(), inventory()
        original = deepcopy((observed, existing))
        plan = self.plan(observed, existing)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["conflicts"])
        self.assertFalse(plan["unresolved"])
        self.assertEqual(plan["summary"]["capacity_fields_updated"], 3)
        self.assertEqual(
            [(row["field"], row["after"]) for row in plan["updates"]],
            [("vcpus", 4), ("memory_mb", 8192), ("disk_gb", 60)],
        )
        self.assertEqual((observed, existing), original)
        json.dumps(plan)

    def test_repeat_after_seed_has_no_changes_or_conflicts(self):
        existing = inventory()
        first = self.plan(existing=existing)
        for update in first["updates"]:
            existing["capacity_inventory"]["values"][update["field"]] = update["after"]
        repeat = self.plan(existing=existing)
        self.assertFalse(repeat["updates"])
        self.assertFalse(repeat["conflicts"])
        self.assertTrue(repeat["preserve_custom_fields"])
        self.assertTrue(all(value == 0 for value in repeat["summary"].values()))

    def test_zero_false_and_populated_noninteger_intent_are_preserved(self):
        for value in (0, False, True, "4", 8, [], {}):
            with self.subTest(value=value):
                existing = inventory()
                existing["capacity_inventory"]["values"]["vcpus"] = deepcopy(value)
                original = deepcopy(existing)
                plan = self.plan(existing=existing)
                self.assertEqual(plan["summary"]["capacity_fields_updated"], 2)
                self.assertNotIn("vcpus", [row["field"] for row in plan["updates"]])
                self.assertEqual(plan["conflicts"][0]["field"], "vcpus")
                self.assertIs(type(plan["conflicts"][0]["before"]), type(value))
                self.assertEqual(plan["conflicts"][0]["before"], value)
                self.assertEqual(existing, original)

    def test_empty_text_and_none_are_blank(self):
        for value in (None, "", " \t"):
            with self.subTest(value=value):
                existing = inventory()
                existing["capacity_inventory"]["values"]["vcpus"] = value
                self.assertEqual(
                    self.plan(existing=existing)["summary"]["capacity_fields_updated"], 3
                )

    def test_missing_definition_defers_only_that_field_without_creating_it(self):
        existing = inventory()
        del existing["capacity_inventory"]["fields"]["memory_mb"]
        plan = self.plan(existing=existing)
        self.assertEqual(plan["summary"]["capacity_fields_updated"], 2)
        self.assertEqual(plan["summary"]["unresolved_capacity"], 1)
        self.assertIn("missing", plan["unresolved"][0]["reason"])
        self.assertFalse(plan["errors"])

    def test_wrong_type_wrong_scope_missing_validator_and_filter_are_report_only(self):
        for key, value in (
            ("type", "text"),
            ("device_scope", False),
            ("supported", False),
            ("scope_filter", {"name": ["some-other-vm"]}),
        ):
            with self.subTest(key=key):
                existing = inventory()
                existing["capacity_inventory"]["fields"]["disk_gb"][key] = value
                plan = self.plan(existing=existing)
                self.assertEqual(plan["summary"]["capacity_fields_updated"], 2)
                self.assertEqual(plan["unresolved"][0]["field"], "disk_gb")
                self.assertFalse(plan["errors"])

    def test_integer_bounds_respected_without_clamping_or_guessing(self):
        for key, value in (
            ("validation_minimum", 5),
            ("validation_maximum", 3),
            ("validation_minimum", True),
            ("validation_maximum", "99"),
        ):
            with self.subTest(key=key, value=value):
                existing = inventory()
                existing["capacity_inventory"]["fields"]["vcpus"][key] = value
                plan = self.plan(existing=existing)
                self.assertEqual(plan["summary"]["capacity_fields_updated"], 2)
                self.assertEqual(plan["unresolved"][0]["observed"], 4)

    def test_positive_integer_allocation_required(self):
        for value in (0, False, -1, "4", 4.0):
            with self.subTest(value=value):
                observed = discovery()
                observed["capacity"]["fields"]["vcpus"]["value"] = value
                plan = self.plan(observed=observed)
                self.assertEqual(plan["summary"]["capacity_fields_updated"], 2)
                self.assertEqual(plan["unresolved"][0]["field"], "vcpus")

    def test_shared_selected_device_identity_required(self):
        plan = self.plan(identity=False)
        self.assertFalse(plan["updates"])
        self.assertEqual(plan["summary"]["unresolved_capacity"], 3)
        self.assertTrue(all("Device identity" in row["reason"] for row in plan["unresolved"]))

    def test_unsupported_native_storage_is_report_only(self):
        for state in (None, {"supported": False, "reason": "Missing reviewed JSON storage"}):
            with self.subTest(state=state):
                existing = inventory()
                existing["capacity_inventory"] = state
                plan = self.plan(existing=existing)
                self.assertFalse(plan["updates"])
                self.assertEqual(plan["summary"]["unresolved_capacity"], 3)

    def test_invalid_source_contract_blocks_capacity_plan(self):
        plan = self.plan(source_valid=False)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["updates"])
        self.assertFalse(plan["observed"])

    def test_explicit_unresolved_sources_survive_without_invented_allocations(self):
        observed = discovery()
        del observed["capacity"]["fields"]["disk_gb"]
        observed["capacity"]["unresolved"].append(
            {"field": "disk_gb", "reason": "No exact primary disk"}
        )
        plan = self.plan(observed=observed)
        self.assertEqual(plan["summary"]["capacity_fields_updated"], 2)
        self.assertEqual(plan["summary"]["unresolved_capacity"], 1)
        self.assertNotIn("disk_gb", plan["observed"])

    def test_other_adapters_and_absent_capacity_have_no_effect(self):
        for observed in ({"adapter": "cisco_iosxe", "capacity": {}}, {"adapter": "panos"}):
            with self.subTest(observed=observed):
                plan = planner.plan_capacity(observed, inventory())
                self.assertFalse(plan["updates"])
                self.assertFalse(plan["unresolved"])
                self.assertFalse(plan["errors"])


class CapacitySourceToPlanTests(unittest.TestCase):
    def source_and_inventory(self):
        from tests.test_panos import vm_payloads
        from tests.test_panos_framework import vm_guest_inventory

        panos = load("adapters.panos")
        source = panos.collect(
            SimpleNamespace(run=vm_payloads().__getitem__),
            expected_vm_uuid="22222222-2222-4222-8222-222222222222",
        )
        existing = vm_guest_inventory(source)
        existing["capacity_inventory"] = inventory()["capacity_inventory"]
        return source, existing

    def test_real_palo_xml_plans_only_verified_cpu_capacity(self):
        source, existing = self.source_and_inventory()
        untouched = deepcopy((source, existing))
        plan = load("reconcile").build_plan(source, existing)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["capacity_fields_updated"], 1)
        self.assertEqual(
            {row["field"]: row["after"] for row in plan["capacity"]["updates"]},
            {"vcpus": 4},
        )
        self.assertEqual(
            {row["field"] for row in plan["capacity"]["unresolved"]},
            {"memory_mb", "disk_gb"},
        )
        self.assertEqual((source, existing), untouched)

    def test_tampered_cpu_value_and_xml_provenance_block_updates(self):
        mutations = (
            lambda row: row["fields"]["vcpus"].update(value=8),
            lambda row: row["fields"]["vcpus"]["source"].update(command="show system resources"),
            lambda row: row["fields"]["vcpus"]["source"].update(path="result/memory"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                source, existing = self.source_and_inventory()
                mutate(source["capacity"])
                plan = load("reconcile").build_plan(source, existing)
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["capacity"]["updates"])

    def test_existing_serial_identity_does_not_require_vm_uuid_binding(self):
        from tests.test_panos import vm_payloads
        from tests.test_panos_framework import vm_guest_inventory

        panos = load("adapters.panos")
        ssh = load("transport_ssh")
        payloads = vm_payloads()
        payloads[ssh.SYSTEM_INFO] = payloads[ssh.SYSTEM_INFO].replace(
            "<serial>unknown</serial>", "<serial>LABPAN00001</serial>"
        )
        source = panos.collect(SimpleNamespace(run=payloads.__getitem__))
        self.assertIsNone(source.get("identity_binding"))
        existing = vm_guest_inventory(source)
        existing["device"]["serial"] = "LABPAN00001"
        existing["capacity_inventory"] = inventory()["capacity_inventory"]
        plan = load("reconcile").build_plan(source, existing)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["capacity_fields_updated"], 1)

    def test_selected_device_model_mismatch_does_not_stage_capacity(self):
        source, existing = self.source_and_inventory()
        existing["device"]["model"] = "another-model"
        plan = load("reconcile").build_plan(source, existing)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["capacity"]["updates"])
