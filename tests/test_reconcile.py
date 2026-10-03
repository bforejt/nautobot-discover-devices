"""Regression coverage for safe, deterministic inventory reconciliation."""

import unittest
from copy import deepcopy

from tests._loader import load

reconcile = load("reconcile")


def discovery(**interface_values):
    """A normalized discovery with one interface; no Nautobot dependencies."""
    interface = {
        "name": "Port-channel1",
        "type": "lag",
        "enabled": True,
        "description": "Example uplink",
        "mtu": 1500,
        "mac_address": "02:00:00:00:00:01",
        "type_source": "logical interface family",
        "observations": {},
    }
    interface.update(interface_values)
    return {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": "example-9300",
            "serial": "LAB93000001",
            "model": "C9300-48UXM",
            "software_version": "17.12.08",
        },
        "interfaces": [interface],
        "excluded_interfaces": [],
        "warnings": [],
        "evidence": {"modules": [], "requests": [], "inventory": []},
    }


def inventory():
    return {
        "device": {
            "id": "device-1",
            "name": "example-9300",
            "serial": "LAB93000001",
            "model": "C9300-48UXM",
            "software_version": "17.12.8",
            "platform_id": "platform-1",
        },
        "interfaces": [],
        "software_versions": [],
        "interface_templates": [],
    }


def apply_to_snapshot(plan, before):
    """Simulate the plan contract to demonstrate second-pass idempotency."""
    after = deepcopy(before)
    for update in plan["device_updates"]:
        after["device"][update["field"]] = update["after"]
    software = plan["software_version"]
    if software:
        after["device"]["software_version"] = software["version"]
        if software["create"]:
            after["software_versions"].append(
                {"id": "created-version", "version": software["version"]}
            )
    for index, create in enumerate(plan["interface_creates"]):
        after["interfaces"].append({"id": "created-%s" % index, **create})
    for update in plan["interface_updates"]:
        interface = next(row for row in after["interfaces"] if row["id"] == update["id"])
        for change in update["changes"]:
            interface[change["field"]] = change["after"]
    for assignment in plan["lag_assignments"]:
        member = next(row for row in after["interfaces"] if row["name"] == assignment["member"])
        lag = next(row for row in after["interfaces"] if row["name"] == assignment["lag"])
        member.update(lag_id=lag["id"], lag=lag["name"])
    return after


class ReconciliationTests(unittest.TestCase):
    def test_reviewed_management_purpose_corrects_default_false_then_repeats(self):
        from tests.test_console_reconcile import profile

        source = {**profile(), "interface": "GigabitEthernet0/0", "value": True}
        observed = discovery(
            name="GigabitEthernet0/0", type="1000base-t", mgmt_only=True, mgmt_only_source=source
        )
        before = inventory()
        before["interfaces"] = [
            {
                "id": "mgmt",
                "name": "Gi0/0",
                "type": "1000base-t",
                "enabled": True,
                "mgmt_only": False,
            }
        ]
        first = reconcile.build_plan(observed, before)
        self.assertFalse(first["errors"])
        change = next(
            change
            for row in first["interface_updates"]
            for change in row["changes"]
            if change["field"] == "mgmt_only"
        )
        self.assertIs(change["before"], False)
        self.assertIs(change["after"], True)
        self.assertEqual(change["source"], source)
        self.assertEqual(first["summary"]["management_interfaces_updated"], 1)
        second = reconcile.build_plan(observed, apply_to_snapshot(first, before))
        self.assertEqual(second["interface_updates"], [])
        self.assertEqual(second["summary"]["management_interfaces_updated"], 0)

    def test_reviewed_management_new_interface_has_true_and_provenance(self):
        from tests.test_console_reconcile import profile

        source = {**profile(), "interface": "GigabitEthernet0/0", "value": True}
        plan = reconcile.build_plan(
            discovery(
                name="GigabitEthernet0/0",
                type="1000base-t",
                mgmt_only=True,
                mgmt_only_source=source,
            ),
            inventory(),
        )
        self.assertIs(plan["interface_creates"][0]["mgmt_only"], True)
        self.assertEqual(plan["interface_creates"][0]["mgmt_only_source"], source)
        self.assertEqual(plan["summary"]["management_interfaces_updated"], 0)

    def test_unclassified_interfaces_do_not_write_management_false(self):
        before = inventory()
        before["interfaces"] = [
            {"id": "ordinary", "name": "Gi1/0/1", "type": "1000base-t", "mgmt_only": True}
        ]
        for value in (None, False):
            plan = reconcile.build_plan(
                discovery(name="GigabitEthernet1/0/1", type="1000base-t", mgmt_only=value), before
            )
            self.assertFalse(
                any(
                    change["field"] == "mgmt_only"
                    for row in plan["interface_updates"]
                    for change in row["changes"]
                )
            )
        plan = reconcile.build_plan(discovery(), inventory())
        self.assertIsNone(plan["interface_creates"][0]["mgmt_only"])

    def test_unreviewed_or_malformed_management_facts_block_apply(self):
        from tests.test_console_reconcile import profile

        source = {**profile(), "interface": "GigabitEthernet0/0", "value": True}
        cases = [
            ("mgmt_only", "true"),
            ("mgmt_only", 1),
            ("mgmt_only_source", None),
            ("name", "GigabitEthernet1/0/1"),
            ("type", "virtual"),
        ]
        for field, value in cases:
            observed = discovery(
                name="GigabitEthernet0/0",
                type="1000base-t",
                mgmt_only=True,
                mgmt_only_source=source,
            )
            observed["interfaces"][0][field] = value
            plan = reconcile.build_plan(observed, inventory())
            self.assertTrue(plan["errors"])
            self.assertEqual(plan["summary"]["management_interfaces_updated"], 0)

    def test_management_purpose_is_deferred_when_native_type_or_relationships_conflict(self):
        from tests.test_console_reconcile import profile

        source = {**profile(), "interface": "GigabitEthernet0/0", "value": True}
        observed = discovery(
            name="GigabitEthernet0/0", type="1000base-t", mgmt_only=True, mgmt_only_source=source
        )
        for fields in (
            {"type": "other"},
            {"module_id": "module"},
            {"lag_id": "lag"},
            {"mode": "access"},
            {"untagged_vlan_id": "vlan"},
            {"tagged_vlan_ids": ["vlan"]},
            {"port_type": "lc"},
        ):
            with self.subTest(fields=fields):
                before = inventory()
                before["interfaces"] = [
                    {
                        "id": "mgmt",
                        "name": "Gi0/0",
                        "type": "1000base-t",
                        "mgmt_only": False,
                        **fields,
                    }
                ]
                plan = reconcile.build_plan(observed, before)
                self.assertFalse(plan["errors"])
                self.assertEqual(plan["summary"]["management_interfaces_updated"], 0)
                self.assertTrue(any(row["field"] == "mgmt_only" for row in plan["conflicts"]))

    def test_older_schema_skips_management_only_field(self):
        from tests.test_console_reconcile import profile

        before = inventory()
        before["unsupported_interface_fields"] = ["mgmt_only"]
        source = {**profile(), "interface": "GigabitEthernet0/0", "value": True}
        plan = reconcile.build_plan(
            discovery(
                name="GigabitEthernet0/0",
                type="1000base-t",
                mgmt_only=True,
                mgmt_only_source=source,
            ),
            before,
        )
        self.assertIsNone(plan["interface_creates"][0]["mgmt_only"])
        self.assertTrue(any("mgmt_only" in message for message in plan["warnings"]))

    def test_operational_fields_respect_preserved_type(self):
        before = inventory()
        before["interfaces"] = [{"id": "port-1", "name": "Gi1/0/1", "type": "1000base-x-sfp"}]
        plan = reconcile.build_plan(
            discovery(name="GigabitEthernet1/0/1", type="1000base-t", speed=1000000, duplex="full"),
            before,
        )
        fields = {c["field"] for r in plan["interface_updates"] for c in r["changes"]}
        self.assertIn("speed", fields)
        self.assertNotIn("duplex", fields)
        self.assertTrue(any("duplex" in message for message in plan["warnings"]))

    def test_lag_and_older_schema_do_not_receive_unsupported_operational_fields(self):
        plan = reconcile.build_plan(
            discovery(speed=1000000, duplex="full", port_type="8p8c"), inventory()
        )
        self.assertIsNone(plan["interface_creates"][0]["speed"])
        self.assertIsNone(plan["interface_creates"][0]["duplex"])
        self.assertIsNone(plan["interface_creates"][0]["port_type"])
        before = inventory()
        before["unsupported_interface_fields"] = ["speed", "duplex", "port_type"]
        plan = reconcile.build_plan(
            discovery(
                name="GigabitEthernet1/0/1",
                type="1000base-t",
                speed=1000000,
                duplex="full",
                port_type="8p8c",
            ),
            before,
        )
        self.assertIsNone(plan["interface_creates"][0]["speed"])
        self.assertIsNone(plan["interface_creates"][0]["duplex"])
        self.assertIsNone(plan["interface_creates"][0]["port_type"])
        self.assertEqual(sum("release" in message for message in plan["warnings"]), 3)

    def test_apply_then_repeat_has_no_inventory_changes(self):
        before = inventory()
        before["device"]["serial"] = ""
        before["device"]["software_version"] = None
        first = reconcile.build_plan(discovery(), before)
        self.assertFalse(first["errors"])
        self.assertEqual(first["summary"]["interfaces_created"], 1)
        self.assertTrue(first["software_version"]["create"])
        after = apply_to_snapshot(first, before)
        second = reconcile.build_plan(discovery(), after)
        self.assertEqual(second["device_updates"], [])
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertIsNone(second["software_version"])
        self.assertEqual(second["conflicts"], [])
        self.assertFalse(second["summary"]["blocked"])

    def test_conflicts_preserve_existing_values_including_false(self):
        before = inventory()
        before["device"].update(name="operator-name", software_version="17.9.6")
        before["interfaces"] = [
            {
                "id": "interface-1",
                "name": "Po1",
                "type": "other",
                "enabled": False,
                "description": "Operator description",
                "mtu": 9000,
                "mac_address": "02:00:00:00:00:02",
            }
        ]
        before_copy = deepcopy(before)
        plan = reconcile.build_plan(discovery(), before)
        self.assertEqual(before, before_copy)
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(plan["interface_updates"], [])
        self.assertIsNone(plan["software_version"])
        conflict_fields = {row["field"] for row in plan["conflicts"]}
        self.assertTrue({"name", "software_version", "type", "enabled"} <= conflict_fields)
        self.assertFalse(plan["errors"])

    def test_existing_canonical_match_keeps_uuid_and_name(self):
        before = inventory()
        before["interfaces"] = [
            {
                "id": "interface-1",
                "name": "Po1",
                "type": "lag",
                "enabled": False,
                "description": "",
                "mtu": None,
                "mac_address": None,
            }
        ]
        plan = reconcile.build_plan(discovery(), before)
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(len(plan["interface_updates"]), 1)
        update = plan["interface_updates"][0]
        self.assertEqual(update["id"], "interface-1")
        self.assertEqual(update["name"], "Po1")
        changes = {row["field"]: row["after"] for row in update["changes"]}
        self.assertEqual(changes["description"], "Example uplink")
        self.assertEqual(changes["mtu"], 1500)
        self.assertNotIn("name", changes)
        self.assertNotIn("enabled", changes)

    def test_wrong_serial_or_model_blocks_application(self):
        for field, wrong in (("serial", "OTHERDEVICE001"), ("model", "C9300-24T")):
            with self.subTest(field=field):
                before = inventory()
                before["device"][field] = wrong
                plan = reconcile.build_plan(discovery(), before)
                self.assertTrue(plan["errors"])
                self.assertTrue(plan["summary"]["blocked"])

    def test_unknown_required_type_is_skipped_with_warning(self):
        plan = reconcile.build_plan(discovery(type=None, type_source=None), inventory())
        self.assertEqual(plan["interface_creates"], [])
        self.assertTrue(plan["warnings"])
        self.assertFalse(plan["errors"])

    def test_unique_template_can_resolve_unknown_type(self):
        before = inventory()
        before["interface_templates"] = [{"name": "Po1", "type": "lag"}]
        plan = reconcile.build_plan(discovery(type=None, type_source=None), before)
        self.assertEqual(plan["interface_creates"][0]["type"], "lag")

    def test_missing_interfaces_are_reported_without_deletion(self):
        before = inventory()
        before["interfaces"] = [{"id": "old-interface", "name": "Loopback99", "type": "virtual"}]
        plan = reconcile.build_plan(discovery(), before)
        self.assertEqual(
            plan["missing_interfaces"], [{"id": "old-interface", "name": "Loopback99"}]
        )
        self.assertNotIn("interface_deletes", plan)
        self.assertFalse(plan["errors"])

    def test_ambiguous_existing_aliases_block_application(self):
        before = inventory()
        before["interfaces"] = [
            {"id": "one", "name": "Po1", "type": "lag"},
            {"id": "two", "name": "Port-channel1", "type": "lag"},
        ]
        plan = reconcile.build_plan(discovery(), before)
        self.assertTrue(plan["errors"])
        self.assertTrue(plan["summary"]["blocked"])

    def test_ambiguous_discovered_aliases_block_application(self):
        observed = discovery()
        observed["interfaces"].append({**observed["interfaces"][0], "name": "Po1"})
        plan = reconcile.build_plan(observed, inventory())
        self.assertTrue(plan["errors"])
        self.assertTrue(plan["summary"]["blocked"])

    def test_software_catalog_uses_canonical_version_without_duplicate(self):
        before = inventory()
        before["device"]["software_version"] = None
        before["software_versions"] = [{"id": "software-1", "version": "17.12.8"}]
        plan = reconcile.build_plan(discovery(), before)
        self.assertEqual(plan["software_version"]["existing_id"], "software-1")
        self.assertFalse(plan["software_version"]["create"])

    def test_unknown_existing_software_is_a_conflict(self):
        before = inventory()
        before["device"]["software_version"] = "custom-image-A"
        observed = discovery()
        observed["identity"]["software_version"] = "custom-image-B"
        plan = reconcile.build_plan(observed, before)
        self.assertTrue(any(row["field"] == "software_version" for row in plan["conflicts"]))

    def test_zero_mac_does_not_fill_blank(self):
        plan = reconcile.build_plan(discovery(mac_address="00:00:00:00:00:00"), inventory())
        self.assertFalse(plan["interface_creates"][0].get("mac_address"))

    def test_plan_is_deterministic_and_keeps_collection_warnings(self):
        observed = discovery()
        observed["warnings"] = ["Optional structured module unavailable"]
        first = reconcile.build_plan(observed, inventory())
        self.assertEqual(first, reconcile.build_plan(deepcopy(observed), inventory()))
        self.assertIn("Optional structured module unavailable", first["warnings"])


if __name__ == "__main__":
    unittest.main()
