"""Shared-planner regressions using production ESXi adapter source reconstruction."""

import copy
import unittest
from unittest.mock import Mock

from tests._loader import load
from tests.test_esxi import HOST_UUID, POLICY
from tests.test_esxi import inventory as source_inventory
from tests.test_reconcile import apply_to_snapshot

esxi = load("adapters.esxi")
reconcile = load("reconcile")


def discovery(raw=None, *, policy=POLICY, expected_uuid=HOST_UUID):
    client = Mock()
    client.discovery.return_value = source_inventory() if raw is None else raw
    return esxi.collect(client, expected_host_uuid=expected_uuid, interface_enabled_policy=policy)


def snapshot():
    return {
        "device": {
            "id": "dce30001-0002-0003-0004-000000000007",
            "name": "nfv-esxi-1",
            "serial": "LABHOST1",
            "model": "ThinkSystem SE350",
            "manufacturer_name": "Lenovo",
            "platform_network_driver": "esxi",
            "platform_name": "ESXi",
            "platform_id": "platform-1",
            "software_version": None,
        },
        "interfaces": [],
        "interface_templates": [],
        "software_versions": [],
    }


def existing_interface(name="vmnic0", **fields):
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


class EsxiFrameworkTests(unittest.TestCase):
    def plan(self, observed=None, before=None):
        return reconcile.build_plan(
            discovery() if observed is None else observed, snapshot() if before is None else before
        )

    def test_core_host_plan_preserves_exact_build_and_unknown_physical_capability(self):
        plan = self.plan()
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["software_version"]["version"], "8.0.3 build-24677879")
        self.assertEqual([row["type"] for row in plan["interface_creates"]], ["other", "other"])
        self.assertEqual(plan["interface_creates"][0]["speed"], 10000000)
        self.assertEqual(plan["summary"]["unknown_interface_capabilities"], 2)
        self.assertTrue(all(row["port_type"] is None for row in plan["interface_creates"]))

    def test_creation_policy_true_and_false_never_become_discovered_admin_state(self):
        for enabled in (True, False):
            observed = discovery(policy={**POLICY, "new_enabled": enabled})
            plan = self.plan(observed)
            self.assertEqual(plan["errors"], [])
            self.assertTrue(all(row["enabled"] is enabled for row in plan["interface_creates"]))
            self.assertTrue(
                all(
                    row["enabled_source"]["new_enabled"] is enabled
                    for row in plan["interface_creates"]
                )
            )
            self.assertTrue(all(row["enabled"] is None for row in observed["interfaces"]))

    def test_missing_creation_policy_defers_new_interfaces(self):
        observed = discovery(policy=None)
        plan = self.plan(observed)
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["interface_creates"], [])
        self.assertTrue(
            all(row["reason"] == "unknown admin state" for row in plan["excluded_interfaces"])
        )
        self.assertEqual(plan["software_version"]["version"], "8.0.3 build-24677879")

    def test_unplugged_link_cannot_set_existing_admin_false(self):
        before = snapshot()
        before["interfaces"] = [existing_interface("vmnic1", enabled=True)]
        plan = self.plan(discovery(policy=None), before)
        changes = [change for row in plan["interface_updates"] for change in row["changes"]]
        self.assertFalse(any(row["field"] == "enabled" for row in changes))
        self.assertFalse(any(row["field"] == "speed" for row in changes))

    def test_existing_false_zero_other_and_operator_intent_are_populated(self):
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
            )
        ]
        first = self.plan(before=before)
        port_changes = [
            change
            for row in first["interface_updates"]
            if row["id"] == "interface-1"
            for change in row["changes"]
        ]
        self.assertEqual(port_changes, [])
        self.assertTrue(any(row["field"] == "speed" for row in first["conflicts"]))
        self.assertTrue(any(row["field"] == "mac_address" for row in first["conflicts"]))

    def test_native_ethernet_type_is_preserved_with_source_capacity_unknown(self):
        before = snapshot()
        before["interfaces"] = [existing_interface()]
        plan = self.plan(before=before)
        self.assertFalse(
            any(
                change["field"] == "type"
                for row in plan["interface_updates"]
                for change in row["changes"]
            )
        )
        self.assertEqual(plan["unknown_interface_capabilities"][0]["preserved_type"], "1000base-t")
        changes = [change for row in plan["interface_updates"] for change in row["changes"]]
        self.assertTrue(
            any(change["field"] == "speed" and change["after"] == 10000000 for change in changes)
        )

    def test_exact_device_type_template_supplies_native_type_without_guessing(self):
        before = snapshot()
        before["interface_templates"] = [{"name": "vmnic0", "type": "10gbase-t"}]
        plan = self.plan(before=before)
        port = plan["interface_creates"][0]
        self.assertEqual(port["type"], "10gbase-t")
        self.assertEqual(port["type_source"], "existing DeviceType interface template")
        self.assertIsNone(port["duplex"])

    def test_virtual_existing_type_cannot_receive_physical_speed_or_connector(self):
        before = snapshot()
        before["interfaces"] = [existing_interface(type="virtual")]
        plan = self.plan(before=before)
        changes = [change for row in plan["interface_updates"] for change in row["changes"]]
        self.assertFalse(any(row["field"] in {"speed", "port_type", "duplex"} for row in changes))

    def test_nested_qemu_vmxnet3_creates_native_virtual_interface(self):
        raw = source_inventory()
        properties = raw["host"]["properties"]
        for row in (properties["hardware.systemInfo"], properties["summary"]["hardware"]):
            row.update(vendor="QEMU", model="Standard PC (Q35 + ICH9, 2009)")
        properties["config.network.pnic"][0]["driver"] = "nvmxnet3"
        properties["hardware.pciDevice"][0].update(vendorId=0x15AD, deviceId=0x07B0)
        before = snapshot()
        before["device"].update(manufacturer_name="QEMU", model="Standard PC (Q35 + ICH9, 2009)")
        plan = self.plan(discovery(raw), before)
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["interface_creates"][0]["type"], "virtual")
        self.assertIsNone(plan["interface_creates"][0]["speed"])
        self.assertIsNone(plan["interface_creates"][0]["duplex"])

    def test_installed_native_field_limitations_defer_unsupported_values(self):
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
            any("does not support interface field speed" in warning for warning in plan["warnings"])
        )

    def test_source_and_normalized_tampering_block_all_planner_writes(self):
        cases = (
            ("identity", "serial", "FAKE"),
            ("identity", "software_version", "8.0.3"),
            ("interfaces", "enabled", True),
            ("interfaces", "type", "1000base-t"),
            ("interfaces", "speed", 1),
            ("interfaces", "mac_address", "02:aa:bb:cc:dd:ee"),
        )
        for domain, field, value in cases:
            observed = discovery()
            target = observed[domain][0] if domain == "interfaces" else observed[domain]
            target[field] = value
            with self.subTest(field=field):
                plan = self.plan(observed)
                self.assertTrue(plan["summary"]["blocked"])
                self.assertEqual(plan["interface_creates"], [])
                self.assertEqual(plan["device_updates"], [])

    def test_source_provenance_and_binding_changes_are_rejected(self):
        for target in ("contract", "source", "binding"):
            observed = discovery()
            if target == "contract":
                observed["source"]["contract"] = "cisco"
            elif target == "source":
                observed["source"]["inventory"]["host"]["properties"]["config.product"]["build"] = (
                    "1"
                )
            else:
                observed["identity_binding"]["observed_uuid"] = (
                    "dce40001-0002-0003-0004-000000000008"
                )
            with self.subTest(target=target):
                self.assertTrue(self.plan(observed)["summary"]["blocked"])

    def test_boolean_schema_version_is_never_integer_version_one(self):
        observed = discovery()
        observed["schema_version"] = True
        with self.assertRaises(ValueError):
            self.plan(observed)

    def test_unsupported_native_domains_are_rejected(self):
        domains = load("reconcile_esxi").UNSUPPORTED_DOMAINS
        for domain in domains:
            observed = discovery()
            observed[domain] = {} if domain != "lag_memberships" else []
            with self.subTest(domain=domain):
                plan = self.plan(observed)
                self.assertTrue(plan["summary"]["blocked"])
                self.assertTrue(any(domain in error for error in plan["errors"]))

    def test_selected_hardware_identity_conflicts_block_application(self):
        for field, value in (
            ("model", "WRONG"),
            ("serial", "WRONG"),
            ("manufacturer_name", "Dell"),
        ):
            before = snapshot()
            before["device"][field] = value
            with self.subTest(field=field):
                self.assertTrue(self.plan(before=before)["summary"]["blocked"])

    def test_esxi_platform_is_required_and_alias_is_explicit(self):
        for driver, allowed in (
            ("esxi", True),
            ("vmware_esxi", True),
            ("ios", False),
            ("proxmox", False),
        ):
            before = snapshot()
            before["device"]["platform_network_driver"] = driver
            with self.subTest(driver=driver):
                self.assertEqual(not self.plan(before=before)["summary"]["blocked"], allowed)

    def test_missing_serial_requires_explicit_matching_host_uuid_binding(self):
        raw = source_inventory()
        raw["host"]["properties"]["hardware.systemInfo"].pop("serialNumber")
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

    def test_software_version_match_preserves_build_identity(self):
        before = snapshot()
        before["software_versions"] = [{"id": "existing", "version": "8.0.3 build-24677879"}]
        plan = self.plan(before=before)
        self.assertEqual(plan["software_version"]["existing_id"], "existing")
        self.assertFalse(plan["software_version"]["create"])
        before["software_versions"][0]["version"] = "8.0.3 build-1"
        self.assertTrue(self.plan(before=before)["software_version"]["create"])

    def test_existing_software_and_host_name_are_preserved(self):
        before = snapshot()
        before["device"].update(name="Operator-name", software_version="8.0.3 build-1")
        plan = self.plan(before=before)
        self.assertIsNone(plan["software_version"])
        self.assertFalse(
            any(row["field"] in {"name", "software_version"} for row in plan["device_updates"])
        )
        self.assertTrue(any(row["field"] == "name" for row in plan["conflicts"]))
        self.assertTrue(any(row["field"] == "software_version" for row in plan["conflicts"]))

    def test_unchanged_second_pass_has_zero_proposals(self):
        observed, before = discovery(), snapshot()
        first = self.plan(observed, before)
        second = self.plan(observed, apply_to_snapshot(first, before))
        self.assertFalse(second["summary"]["blocked"])
        self.assertEqual(second["device_updates"], [])
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertIsNone(second["software_version"])

    def test_missing_interfaces_are_observations_without_delete_or_relocation(self):
        before = snapshot()
        before["interfaces"] = [existing_interface("vmnic99", cable_id="operator-cable")]
        plan = self.plan(before=before)
        self.assertEqual(plan["missing_interfaces"], [{"id": "interface-1", "name": "vmnic99"}])
        self.assertFalse(any(row["id"] == "interface-1" for row in plan["interface_updates"]))
        self.assertNotIn("interface_deletes", plan)

    def test_nfv_observations_do_not_guess_capacity_ipam_or_guest_attributes(self):
        observed = discovery()
        before = snapshot()
        before["device"].update(custom_field_data={"vcpus": 0, "memory_mb": 1, "disk_gb": 2})
        plan = self.plan(observed, before)
        self.assertEqual(plan["capacity"]["updates"], [])
        self.assertEqual(plan["esxi_guests"]["creates"], [])
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

    def test_planner_never_mutates_source_or_snapshot_inputs(self):
        observed, before = discovery(), snapshot()
        original_observed, original_before = copy.deepcopy(observed), copy.deepcopy(before)
        self.plan(observed, before)
        self.assertEqual(observed, original_observed)
        self.assertEqual(before, original_before)


if __name__ == "__main__":
    unittest.main()
