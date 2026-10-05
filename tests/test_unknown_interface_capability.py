"""Observed Ethernet interfaces remain useful without chassis capability matrices."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_reconcile import apply_to_snapshot, discovery, inventory

reconcile = load("reconcile")
iosxe = load("adapters.cisco_iosxe")


def unknown_discovery(**values):
    """A synthetic unlisted chassis with explicit operational Ethernet facts."""
    name = values.get("name", "TenGigabitEthernet1/0/1")
    interface = dict(
        name=name,
        type=None,
        enabled=True,
        type_source="No documented hardware profile for this chassis",
        speed=1_000_000,
        duplex="full",
        port_type=None,
        physical_ethernet=True,
        physical_ethernet_source={
            "module": "Cisco-IOS-XE-interfaces-oper",
            "path": "interfaces/interface/interface-type",
            "value": "iana-iftype-ethernet-csmacd",
            "name": name,
            "admin_status": "if-state-up",
            "oper_status": "if-oper-state-ready",
        },
    )
    interface.update(values)
    source = discovery(**interface)
    source["identity"]["model"] = "SYNTHETIC-UNLISTED-CHASSIS"
    before = inventory()
    before["device"]["model"] = source["identity"]["model"]
    return source, before


class UnknownPhysicalCapabilityTests(unittest.TestCase):
    def test_explicit_ethernet_stores_known_facts_with_other_type(self):
        source, before = unknown_discovery()
        plan = reconcile.build_plan(source, before)
        self.assertFalse(plan["errors"])
        created = plan["interface_creates"][0]
        self.assertEqual(created["type"], "other")
        self.assertIs(created["capability_unknown"], True)
        self.assertIn("capability unknown", created["type_source"])
        self.assertEqual(created["speed"], 1_000_000)
        self.assertEqual(created["mac_address"], "02:00:00:00:00:01")
        self.assertEqual(created["mtu"], 1500)
        self.assertTrue(created["enabled"])
        self.assertIsNone(created["port_type"])
        self.assertIsNone(created["duplex"])
        self.assertEqual(plan["summary"]["unknown_interface_capabilities"], 1)
        self.assertEqual(
            plan["unknown_interface_capabilities"][0]["classification_source"],
            source["interfaces"][0]["physical_ethernet_source"],
        )
        self.assertTrue(any("maximum capability unknown" in line for line in plan["warnings"]))

    def test_unknown_type_apply_then_repeat_is_fill_only(self):
        source, before = unknown_discovery()
        first = reconcile.build_plan(source, before)
        after = apply_to_snapshot(first, before)
        second = reconcile.build_plan(source, after)
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertEqual(second["conflicts"], [])
        self.assertEqual(second["unknown_interface_capabilities"][0]["preserved_type"], "other")

    def test_existing_populated_types_are_preserved_without_other_conflict(self):
        for type_ in ("other", "1000base-t", "25gbase-x-sfp28"):
            with self.subTest(type=type_):
                source, before = unknown_discovery()
                before["interfaces"] = [
                    {"id": "preserved-port", "name": "Te1/0/1", "type": type_, "enabled": False}
                ]
                plan = reconcile.build_plan(source, before)
                self.assertEqual(plan["interface_creates"], [])
                self.assertFalse(any(row["field"] == "type" for row in plan["conflicts"]))
                self.assertFalse(
                    any(
                        change["field"] == "type"
                        for row in plan["interface_updates"]
                        for change in row["changes"]
                    )
                )
                self.assertEqual(plan["unknown_interface_capabilities"][0]["preserved_type"], type_)
                self.assertEqual(before["interfaces"][0]["enabled"], False)

    def test_unique_device_type_template_has_priority(self):
        source, before = unknown_discovery()
        before["interface_templates"] = [{"name": "Te1/0/1", "type": "10gbase-x-sfpp"}]
        plan = reconcile.build_plan(source, before)
        self.assertEqual(plan["interface_creates"][0]["type"], "10gbase-x-sfpp")
        self.assertEqual(
            plan["interface_creates"][0]["type_source"], "existing DeviceType interface template"
        )
        self.assertEqual(plan["unknown_interface_capabilities"], [])
        self.assertNotIn("capability_unknown", plan["interface_creates"][0])

    def test_documented_type_keeps_priority(self):
        source, before = unknown_discovery()
        source["interfaces"][0]["type"] = "10gbase-t"
        plan = reconcile.build_plan(source, before)
        self.assertEqual(plan["interface_creates"][0]["type"], "10gbase-t")
        self.assertEqual(plan["unknown_interface_capabilities"], [])

    def test_missing_or_invalid_classification_never_falls_back(self):
        source, before = unknown_discovery()
        for change in (
            {"physical_ethernet": None},
            {"physical_ethernet": 1},
            {"physical_ethernet_source": None},
            {"physical_ethernet_source": {}},
        ):
            with self.subTest(change=change):
                observed = deepcopy(source)
                observed["interfaces"][0].update(change)
                plan = reconcile.build_plan(observed, before)
                self.assertEqual(plan["interface_creates"], [])
                self.assertEqual(plan["unknown_interface_capabilities"], [])
        for field, value in (
            ("module", "some-other-module"),
            ("path", "interfaces/interface/speed"),
            ("value", "iana-iftype-propvirtual"),
            ("name", "GigabitEthernet1/0/2"),
            ("oper_status", "if-oper-state-not-present"),
            ("admin_status", None),
            ("admin_status", ["if-state-up"]),
            ("admin_status", "if-state-down"),
        ):
            with self.subTest(field=field, value=value):
                observed = deepcopy(source)
                observed["interfaces"][0]["physical_ethernet_source"][field] = value
                self.assertEqual(reconcile.build_plan(observed, before)["interface_creates"], [])

    def test_unknown_admin_state_never_creates(self):
        source, before = unknown_discovery()
        for value in (None, "true", 1):
            source["interfaces"][0]["enabled"] = value
            self.assertEqual(reconcile.build_plan(source, before)["interface_creates"], [])

    def test_internal_logical_subinterface_breakout_names_never_create_cages(self):
        for name in (
            "AppGigabitEthernet1/0/1",
            "Loopback1/0/1",
            "Port-channel1/0/1",
            "TenGigabitEthernet1/0/1.100",
            "TenGigabitEthernet1/0/1/1",
            "TenGigabitEthernet1",
        ):
            with self.subTest(name=name):
                source, before = unknown_discovery(name=name)
                self.assertEqual(reconcile.build_plan(source, before)["interface_creates"], [])

    def test_known_rj45_connector_can_be_stored_without_inferring_maximum_type(self):
        source, before = unknown_discovery(port_type="8p8c")
        plan = reconcile.build_plan(source, before)
        self.assertEqual(plan["interface_creates"][0]["type"], "other")
        self.assertEqual(plan["interface_creates"][0]["port_type"], "8p8c")
        self.assertIsNone(plan["interface_creates"][0]["duplex"])

    def test_unknown_chassis_adapter_and_planner_use_structured_classification(self):
        raw = {
            "Cisco-IOS-XE-interfaces-oper:interfaces": {
                "interface": [
                    {
                        "name": "TenGigabitEthernet1/0/1",
                        "interface-type": "iana-iftype-ethernet-csmacd",
                        "admin-status": "if-state-up",
                        "oper-status": "if-oper-state-ready",
                        "phys-address": "02:00:00:00:00:01",
                        "description": "Structured facts for an unlisted chassis",
                        "mtu": 9216,
                        "speed": 1_000_000_000,
                    }
                ]
            }
        }
        source, before = unknown_discovery()
        facts, excluded = iosxe._interfaces(raw, source["identity"]["model"], 1, [], [])
        self.assertIsNone(facts[0]["type"])
        self.assertNotIn("hardware_profile", facts[0])
        source["interfaces"], source["excluded_interfaces"] = facts, excluded
        plan = reconcile.build_plan(source, before)
        self.assertEqual(plan["interface_creates"][0]["type"], "other")
        self.assertEqual(plan["interface_creates"][0]["speed"], 1_000_000)
        self.assertEqual(plan["interface_creates"][0]["mtu"], 9216)
        # Removing the IANA classification keeps the observation report-only.
        del raw["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"][0]["interface-type"]
        source["interfaces"], _ = iosxe._interfaces(raw, source["identity"]["model"], 1, [], [])
        self.assertEqual(reconcile.build_plan(source, before)["interface_creates"], [])


if __name__ == "__main__":
    unittest.main()
