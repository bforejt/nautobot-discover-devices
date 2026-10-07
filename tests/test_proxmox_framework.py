"""Shared planner proves Proxmox host writes from reconstructed source evidence."""

import copy
import unittest

from tests._loader import load
from tests.test_proxmox import HOST_UUID, NODE, Client, inventory
from tests.test_reconcile import apply_to_snapshot

proxmox = load("adapters.proxmox")
reconcile = load("reconcile")


def discovery(raw=None, *, expected_uuid=HOST_UUID):
    return proxmox.collect(Client(raw), expected_node=NODE, expected_host_uuid=expected_uuid)


def snapshot():
    return {
        "device": {
            "id": "dce30001-0002-0003-0004-000000000007",
            "name": NODE,
            "serial": "LABHOST1",
            "model": "ThinkSystem SE350",
            "manufacturer_name": "Lenovo",
            "platform_network_driver": "proxmox",
            "platform_name": "Proxmox VE",
            "platform_id": "platform-1",
            "software_version": None,
        },
        "interfaces": [],
        "interface_templates": [],
        "software_versions": [],
    }


def existing_interface(name="eno1", **fields):
    return {
        "id": "interface-1",
        "name": name,
        "type": "1000base-t",
        "enabled": False,
        "description": None,
        "mtu": None,
        "mac_address": None,
        "speed": None,
        "duplex": None,
        "port_type": None,
        "mgmt_only": False,
        **fields,
    }


class ProxmoxFrameworkTests(unittest.TestCase):
    def plan(self, observed=None, before=None):
        return reconcile.build_plan(
            discovery() if observed is None else observed, snapshot() if before is None else before
        )

    def test_host_plan_maps_exact_release_and_unknown_physical_capability(self):
        plan = self.plan()
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["software_version"]["version"], "9.2.2")
        self.assertEqual([row["type"] for row in plan["interface_creates"]], ["other"])
        self.assertTrue(plan["interface_creates"][0]["enabled"])
        self.assertEqual(plan["interface_creates"][0]["speed"], 1000000)
        self.assertEqual(plan["summary"]["unknown_interface_capabilities"], 1)
        self.assertIsNone(plan["interface_creates"][0]["port_type"])
        self.assertIsNone(plan["interface_creates"][0]["duplex"])

    def test_missing_admin_flags_defer_creation_but_not_verified_identity(self):
        raw = inventory()
        raw["ssh"]["links"][0].pop("flags")
        plan = self.plan(discovery(raw))
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["interface_creates"], [])
        self.assertTrue(
            any(row["reason"] == "unknown admin state" for row in plan["excluded_interfaces"])
        )
        self.assertEqual(plan["software_version"]["version"], "9.2.2")

    def test_unplugged_enabled_interface_retains_admin_and_unknown_speed(self):
        raw = inventory()
        raw["ssh"]["links"][0]["flags"] = ["BROADCAST", "MULTICAST", "UP"]
        raw["ssh"]["links"][0]["operstate"] = "DOWN"
        raw["ssh"]["host"]["net"][0]["carrier"] = "0"
        before = snapshot()
        before["interfaces"] = [existing_interface(enabled=True)]
        plan = self.plan(discovery(raw), before)
        changes = [change for row in plan["interface_updates"] for change in row["changes"]]
        self.assertFalse(any(row["field"] in {"enabled", "speed"} for row in changes))

    def test_live_disabled_flags_create_disabled_interface_without_policy(self):
        raw = inventory()
        raw["ssh"]["links"][0]["flags"] = ["BROADCAST", "MULTICAST"]
        raw["ssh"]["host"]["net"][0]["carrier"] = "0"
        port = self.plan(discovery(raw))["interface_creates"][0]
        self.assertIs(port["enabled"], False)
        self.assertIsNone(port["speed"])

    def test_populated_false_zero_other_and_all_interface_intent_are_preserved(self):
        before = snapshot()
        before["interfaces"] = [
            existing_interface(
                type="other",
                enabled=False,
                speed=0,
                description="Operator uplink",
                mtu=9000,
                mac_address="02:aa:bb:cc:dd:ee",
                mgmt_only=False,
                cable_id="cable",
                lag_id="lag",
                module_id="module",
                mode="access",
                untagged_vlan_id="vlan",
                device_id=before["device"]["id"],
                custom_field_data={"zero": 0, "false": False},
            )
        ]
        plan = self.plan(before=before)
        changes = [change for row in plan["interface_updates"] for change in row["changes"]]
        self.assertEqual(changes, [])
        self.assertTrue(any(row["field"] == "speed" for row in plan["conflicts"]))
        self.assertTrue(any(row["field"] == "mac_address" for row in plan["conflicts"]))
        self.assertTrue(any(row["field"] == "enabled" for row in plan["conflicts"]))

    def test_existing_native_type_preserved_and_operational_speed_fill_remains_valid(self):
        before = snapshot()
        before["interfaces"] = [existing_interface()]
        plan = self.plan(before=before)
        changes = [change for row in plan["interface_updates"] for change in row["changes"]]
        self.assertFalse(any(row["field"] == "type" for row in changes))
        self.assertEqual(plan["unknown_interface_capabilities"][0]["preserved_type"], "1000base-t")
        self.assertTrue(any(row["field"] == "speed" and row["after"] == 1000000 for row in changes))

    def test_device_type_template_type_is_respected_without_source_capability_guess(self):
        before = snapshot()
        before["interface_templates"] = [{"name": "eno1", "type": "10gbase-t"}]
        port = self.plan(before=before)["interface_creates"][0]
        self.assertEqual(port["type"], "10gbase-t")
        self.assertEqual(port["type_source"], "existing DeviceType interface template")
        self.assertIsNone(port["port_type"])

    def test_existing_virtual_interface_never_receives_physical_only_fields(self):
        before = snapshot()
        before["interfaces"] = [existing_interface(type="virtual")]
        changes = [
            change
            for row in self.plan(before=before)["interface_updates"]
            for change in row["changes"]
        ]
        self.assertFalse(any(row["field"] in {"speed", "duplex", "port_type"} for row in changes))

    def test_native_unsupported_fields_are_deferred(self):
        before = snapshot()
        before["unsupported_interface_fields"] = ["speed", "duplex", "mac_address"]
        plan = self.plan(before=before)
        self.assertTrue(
            all(
                row["speed"] is None and row["duplex"] is None and row["mac_address"] is None
                for row in plan["interface_creates"]
            )
        )
        self.assertTrue(
            any("does not support interface field speed" in text for text in plan["warnings"])
        )

    def test_normalized_fact_tamper_blocks_every_planner_write(self):
        for domain, field, value in (
            ("identity", "serial", "FORGED"),
            ("identity", "software_version", "9.2"),
            ("interfaces", "enabled", False),
            ("interfaces", "type", "1000base-t"),
            ("interfaces", "speed", 1),
            ("interfaces", "mac_address", "02:aa:bb:cc:dd:ee"),
        ):
            observed = discovery()
            target = observed[domain][0] if domain == "interfaces" else observed[domain]
            target[field] = value
            with self.subTest(domain=domain, field=field):
                plan = self.plan(observed)
                self.assertTrue(plan["summary"]["blocked"])
                self.assertEqual(plan["interface_creates"], [])
                self.assertEqual(plan["device_updates"], [])

    def test_source_contract_raw_source_and_binding_tamper_block_writes(self):
        for case in ("contract", "source", "binding", "scope"):
            observed = discovery()
            if case == "contract":
                observed["source"]["contract"] = "esxi-host-v1"
            elif case == "source":
                observed["source"]["inventory"]["api"]["version"]["version"] = "9.2.3"
            elif case == "binding":
                observed["identity_binding"]["observed_uuid"] = (
                    "00000002-0000-4000-8000-000000000002"
                )
            else:
                observed["source"]["inventory"]["node"] = "peer"
            with self.subTest(case=case):
                self.assertTrue(self.plan(observed)["summary"]["blocked"])

    def test_boolean_schema_version_is_not_integer_version_one(self):
        observed = discovery()
        observed["schema_version"] = True
        with self.assertRaises(ValueError):
            self.plan(observed)

    def test_unreviewed_native_domains_are_rejected(self):
        for domain in load("reconcile_proxmox").UNSUPPORTED_DOMAINS:
            observed = discovery()
            observed[domain] = {} if domain != "lag_memberships" else []
            with self.subTest(domain=domain):
                plan = self.plan(observed)
                self.assertTrue(plan["summary"]["blocked"])
                self.assertTrue(any(domain in error for error in plan["errors"]))

    def test_selected_hardware_vendor_model_and_serial_collisions_block_writes(self):
        for field, value in (
            ("model", "WRONG"),
            ("serial", "WRONG"),
            ("manufacturer_name", "Dell"),
        ):
            before = snapshot()
            before["device"][field] = value
            with self.subTest(field=field):
                self.assertTrue(self.plan(before=before)["summary"]["blocked"])

    def test_selected_proxmox_platform_aliases_are_explicit(self):
        for driver, allowed in (
            ("proxmox", True),
            ("proxmox_ve", True),
            ("ios", False),
            ("esxi", False),
        ):
            before = snapshot()
            before["device"]["platform_network_driver"] = driver
            with self.subTest(driver=driver):
                self.assertEqual(not self.plan(before=before)["summary"]["blocked"], allowed)

    def test_missing_chassis_serial_requires_explicit_matching_dmi_uuid(self):
        raw = inventory()
        raw["ssh"]["host"]["dmi"].update(product_serial="unknown", chassis_serial="unknown")
        raw["ssh"]["hardware"]["serial"] = "unknown"
        before = snapshot()
        before["device"]["serial"] = ""
        unbound = self.plan(discovery(raw, expected_uuid=None), before)
        self.assertTrue(unbound["summary"]["blocked"])
        self.assertIn(
            "Discovery did not provide required identity field: serial", unbound["errors"]
        )
        bound = self.plan(discovery(raw), before)
        self.assertFalse(bound["summary"]["blocked"])
        self.assertFalse(any(row["field"] == "serial" for row in bound["device_updates"]))
        self.assertEqual(bound["identity_binding"]["observed_uuid"], HOST_UUID)

    def test_existing_exact_software_version_reused(self):
        before = snapshot()
        before["software_versions"] = [{"id": "existing", "version": "9.2.2"}]
        plan = self.plan(before=before)
        self.assertEqual(plan["software_version"]["existing_id"], "existing")
        self.assertFalse(plan["software_version"]["create"])
        before["software_versions"][0]["version"] = "9.2.1"
        self.assertTrue(self.plan(before=before)["software_version"]["create"])

    def test_operator_host_name_and_software_version_are_preserved(self):
        before = snapshot()
        before["device"].update(name="operator-name", software_version="9.2.1")
        plan = self.plan(before=before)
        self.assertIsNone(plan["software_version"])
        self.assertFalse(
            any(row["field"] in {"name", "software_version"} for row in plan["device_updates"])
        )
        self.assertTrue(any(row["field"] == "name" for row in plan["conflicts"]))
        self.assertTrue(any(row["field"] == "software_version" for row in plan["conflicts"]))

    def test_second_pass_is_unchanged(self):
        observed, before = discovery(), snapshot()
        first = self.plan(observed, before)
        second = self.plan(observed, apply_to_snapshot(first, before))
        self.assertFalse(second["summary"]["blocked"])
        self.assertEqual(second["device_updates"], [])
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertIsNone(second["software_version"])

    def test_missing_source_interfaces_are_preserved_in_native_inventory(self):
        before = snapshot()
        before["interfaces"] = [existing_interface("eno99", cable_id="operator-cable")]
        plan = self.plan(before=before)
        self.assertEqual(plan["missing_interfaces"], [{"id": "interface-1", "name": "eno99"}])
        self.assertFalse(any(row["id"] == "interface-1" for row in plan["interface_updates"]))
        self.assertNotIn("interface_deletes", plan)

    def test_nfv_observations_do_not_create_unselected_capacity_ipam_or_guest_assets(self):
        before = snapshot()
        before["device"]["custom_field_data"] = {"vcpus": 0, "memory_mb": 1, "disk_gb": 2}
        plan = self.plan(before=before)
        self.assertEqual(plan["capacity"]["updates"], [])
        self.assertEqual(plan["proxmox_guests"]["creates"], [])
        for key in ("ip_addresses", "prefixes", "vrfs", "ip_assignments"):
            self.assertEqual(plan["ipam"][key], [])
        for key in (
            "vrfs_created",
            "ip_addresses_created",
            "capacity_fields_updated",
            "hosted_on_created",
            "modules_created",
            "vpn_objects_created",
        ):
            self.assertEqual(plan["summary"][key], 0)
        self.assertEqual(before["device"]["custom_field_data"]["vcpus"], 0)

    def test_planning_never_mutates_source_or_snapshot_inputs(self):
        observed, before = discovery(), snapshot()
        original_observed, original_before = copy.deepcopy(observed), copy.deepcopy(before)
        self.plan(observed, before)
        self.assertEqual(observed, original_observed)
        self.assertEqual(before, original_before)


if __name__ == "__main__":
    unittest.main()
