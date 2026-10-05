"""PAN-OS uses its own names, release tokens and conservative inventory contract."""

import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests import test_discovery_job, test_panos, test_reconcile
from tests._loader import FIXTURES, load
from tests.test_reconcile import apply_to_snapshot

reconcile = load("reconcile")
ssh = load("transport_ssh")
panos = load("adapters.panos")
VM_UUID = "7ec6197d-9b3b-4b52-8d47-4c2167208938"


def discovery(**interface_values):
    interface = {
        "name": "ethernet1/1",
        "type": None,
        "enabled": None,
        "description": "Verified running description",
        "mtu": 1500,
        "mac_address": "02:00:00:00:00:01",
        "type_source": None,
        "observations": {"state": "down", "speed": "unknown"},
    }
    interface.update(interface_values)
    interface["source"] = {
        "contract": "panos-interface-v1",
        "operational_command": ssh.INTERFACES,
        "hardware_path": "result/hw/entry",
        "name": interface["name"],
        "id": "16",
        "applied_command": ssh.RUNNING_INTERFACES,
        "applied_path": "result/interface/ethernet/entry",
        "link_state": {True: "up", False: "down"}.get(interface["enabled"])
        if type(interface["enabled"]) is bool
        else None,
        "mtu": str(interface["mtu"]) if interface["mtu"] is not None else None,
        "comment": interface["description"],
    }
    return {
        "adapter": "panos",
        "schema_version": 1,
        "identity": {
            "hostname": "example-firewall",
            "model": "PA-VM",
            "serial": "LABPAN00001",
            "software_version": "11.1.4-h3",
        },
        "interfaces": [interface],
        "excluded_interfaces": [],
        "warnings": [],
        "evidence": {"sources": []},
    }


def inventory():
    return {
        "device": {
            "id": "pan-device",
            "name": "example-firewall",
            "model": "PA-VM",
            "serial": "LABPAN00001",
            "software_version": "11.1.4-h3",
            "platform_id": "pan-platform",
            "manufacturer_name": "Palo Alto Networks",
            "platform_name": "PAN-OS",
            "platform_network_driver": "paloalto_panos",
        },
        "interfaces": [],
        "interface_templates": [],
        "software_versions": [],
    }


def vm_discovery(**interface_values):
    result = discovery(**interface_values)
    result["identity"]["serial"] = None
    result["observations"] = {
        "system": {"family": "vm", "vm-mode": "KVM", "vm-uuid": VM_UUID, "vm-license": "none"}
    }
    result["sources"] = {"identity": {"command": ssh.SYSTEM_INFO, "path": "result/system"}}
    result["identity_binding"] = {
        "contract": "panos-vm-identity-v1",
        "system_command": ssh.SYSTEM_INFO,
        "system_path": "result/system",
        "expected_uuid": VM_UUID,
        "observed_uuid": VM_UUID,
        "model": "PA-VM",
        "family": "vm",
        "vm_mode": "KVM",
    }
    return result


def vm_guest_discovery():
    outputs = test_panos.vm_payloads()
    outputs[ssh.SYSTEM_INFO] = outputs[ssh.SYSTEM_INFO].replace(
        "22222222-2222-4222-8222-222222222222", VM_UUID
    )
    return panos.collect(SimpleNamespace(run=outputs.__getitem__), expected_vm_uuid=VM_UUID)


def vm_guest_inventory(source):
    before = inventory()
    before["device"].update(
        name=source["identity"]["hostname"],
        serial="",
        software_version=source["identity"]["software_version"],
    )
    before["interface_templates"] = [
        {"name": "ethernet1/%d" % port, "type": "virtual"} for port in (1, 2, 3)
    ]
    return before


class PanosReconciliationTests(unittest.TestCase):
    def test_production_collector_sources_validate_and_repeat_with_native_templates(self):
        outputs = {
            **test_panos.empty_ha_vpn_payloads(),
            ssh.SYSTEM_INFO: (FIXTURES / "panos_system_info.txt").read_text(),
            ssh.INTERFACES: (FIXTURES / "panos_interfaces.txt").read_text(),
            ssh.RUNNING_INTERFACES: (FIXTURES / "panos_applied_interfaces.xml").read_text(),
        }
        source = panos.collect(SimpleNamespace(run=outputs.__getitem__))
        before = inventory()
        identity = source["identity"]
        before["device"].update(
            name=identity["hostname"],
            serial=identity["serial"],
            model=identity["model"],
            software_version=identity["software_version"],
        )
        before["interface_templates"] = [
            {"name": "ethernet1/%d" % port, "type": "other"} for port in (1, 2, 7)
        ]
        first = reconcile.build_plan(source, before)
        self.assertFalse(first["errors"])
        self.assertEqual(len(first["interface_creates"]), 3)
        last = next(row for row in first["interface_creates"] if row["name"] == "ethernet1/7")
        self.assertIs(last["enabled"], False)
        self.assertEqual(first["interface_creates"][0]["mtu"], 1500)
        second = reconcile.build_plan(source, apply_to_snapshot(first, before))
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertEqual(second["device_updates"], [])
        self.assertEqual(second["conflicts"], [])

    def test_production_collector_vm_binding_crosses_the_planner_contract(self):
        system = (FIXTURES / "panos_system_info.txt").read_text()
        system = system.replace("<model>PA-5250</model>", "<model>PA-VM</model>")
        system = system.replace("<family>5200</family>", "<family>vm</family>")
        system = system.replace("<serial>013201000001</serial>", "<serial>unknown</serial>")
        system = system.replace(
            "</system>",
            "<vm-mode>KVM</vm-mode><vm-license>none</vm-license>"
            "<vm-uuid>%s</vm-uuid></system>" % VM_UUID.upper(),
        )
        outputs = {
            **test_panos.empty_ha_vpn_payloads(),
            ssh.SYSTEM_INFO: system,
            ssh.INTERFACES: (FIXTURES / "panos_interfaces.txt").read_text(),
            ssh.RUNNING_INTERFACES: (FIXTURES / "panos_applied_interfaces.xml").read_text(),
            ssh.VM_INTERFACES: (FIXTURES / "panos_vm_guest_interfaces.xml")
            .read_text()
            .replace("Ethernet1/3", "Ethernet1/7"),
        }
        source = panos.collect(
            SimpleNamespace(run=outputs.__getitem__), expected_vm_uuid=VM_UUID.upper()
        )
        before = inventory()
        before["device"].update(
            name=source["identity"]["hostname"],
            model="PA-VM",
            serial="",
            software_version=source["identity"]["software_version"],
        )
        before["interface_templates"] = [
            {"name": "ethernet1/%d" % port, "type": "virtual"} for port in (1, 2, 7)
        ]
        plan = reconcile.build_plan(source, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(len(plan["interface_creates"]), 3)
        self.assertEqual(plan["identity_binding"]["expected_uuid"], VM_UUID)
        self.assertEqual(plan["identity_binding"]["observed_uuid"], VM_UUID)
        self.assertIsNone(source["identity"]["serial"])
        self.assertFalse(any(row["field"] == "serial" for row in plan["device_updates"]))

    def test_live_vm_source_with_empty_hw_creates_only_explicitly_configured_ports(self):
        source = vm_guest_discovery()
        before = vm_guest_inventory(source)
        plan = reconcile.build_plan(source, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(
            [row["name"] for row in plan["interface_creates"]], ["ethernet1/1", "ethernet1/2"]
        )
        self.assertEqual([row["enabled"] for row in plan["interface_creates"]], [True, False])
        self.assertEqual({row["type"] for row in plan["interface_creates"]}, {"virtual"})
        self.assertIn(
            {"name": "ethernet1/3", "reason": "unknown admin state"}, plan["excluded_interfaces"]
        )
        for row in plan["interface_creates"]:
            for field in ("mac_address", "speed", "duplex", "port_type", "mgmt_only"):
                self.assertIsNone(row[field])
        repeated = reconcile.build_plan(source, apply_to_snapshot(plan, before))
        self.assertFalse(repeated["errors"])
        self.assertEqual(repeated["interface_creates"], [])
        self.assertEqual(repeated["interface_updates"], [])
        self.assertEqual(repeated["device_updates"], [])

    def test_actual_post_commit_vm_source_applies_only_explicit_admin_and_repeats(self):
        outputs = test_panos.vm_post_commit_payloads()
        source = panos.collect(
            SimpleNamespace(run=outputs.__getitem__),
            expected_vm_uuid="22222222-2222-4222-8222-222222222222",
        )
        before = vm_guest_inventory(source)
        plan = reconcile.build_plan(source, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(
            [row["name"] for row in plan["interface_creates"]], ["ethernet1/1", "ethernet1/2"]
        )
        self.assertEqual([row["enabled"] for row in plan["interface_creates"]], [True, False])
        self.assertEqual([row["mtu"] for row in plan["interface_creates"]], [1400, 1500])
        self.assertIn(
            {"name": "ethernet1/3", "reason": "unknown admin state"}, plan["excluded_interfaces"]
        )
        self.assertFalse(any(row["field"] == "serial" for row in plan["device_updates"]))
        after = apply_to_snapshot(plan, before)
        self.assertEqual(after["device"]["serial"], "")
        repeated = reconcile.build_plan(source, after)
        self.assertFalse(repeated["errors"])
        self.assertEqual(repeated["interface_creates"], [])
        self.assertEqual(repeated["interface_updates"], [])
        self.assertEqual(repeated["device_updates"], [])

    def test_vm_enumeration_does_not_supply_a_native_type_without_exact_templates(self):
        source = vm_guest_discovery()
        before = vm_guest_inventory(source)
        before["interface_templates"] = []
        plan = reconcile.build_plan(source, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(plan["unknown_interface_capabilities"], [])

    def test_vm_enumeration_fact_provenance_is_independently_required(self):
        mutations = (
            ("enumeration_command", "debug show vm-series interfaces text"),
            ("enumeration_path", "result/hw/entry"),
            ("raw_name", "Ethernet1/2"),
            ("raw_name", "ethernet1/1"),
            ("name", "ethernet1/2"),
            ("base_os_port", "eth9"),
            ("base_os_bus", "0000:00:16.0"),
            ("applied_command", "show config candidate"),
            ("applied_path", "result/candidate/interface/ethernet/entry"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                source = vm_guest_discovery()
                before = vm_guest_inventory(source)
                source["interfaces"][0]["source"][field] = value
                self.assertTrue(reconcile.build_plan(source, before)["errors"])
        source = vm_guest_discovery()
        before = vm_guest_inventory(source)
        source["interfaces"][2]["source"]["name"] = "ethernet1/99"
        self.assertTrue(reconcile.build_plan(source, before)["errors"])

    def test_vm_enumeration_observation_and_source_tampering_blocks(self):
        mutations = (
            ("vm_source", "command", "show interface hardware"),
            ("vm_source", "path", "result/hw/entry"),
            ("identity_source", "command", "show system peer info"),
            ("identity_source", "path", "result/peer/system"),
            ("system", "family", "hardware"),
            ("system", "vm-mode", "ESXi"),
            ("observation", "base_os_port", "eth99"),
            ("observation", "base_os_bus", "0000:00:19.0"),
            ("observation", "raw_name", "Ethernet1/99"),
        )
        for scope, field, value in mutations:
            with self.subTest(scope=scope, field=field):
                source = vm_guest_discovery()
                before = vm_guest_inventory(source)
                {
                    "vm_source": source["sources"]["vm_interfaces"],
                    "identity_source": source["sources"]["identity"],
                    "system": source["observations"]["system"],
                    "observation": source["observations"]["vm_interfaces"][0],
                }[scope][field] = value
                self.assertTrue(reconcile.build_plan(source, before)["errors"])

    def test_vm_enumeration_duplicate_proof_and_hardware_override_block(self):
        for field in ("name", "base_os_port", "base_os_bus"):
            with self.subTest(field=field):
                source = vm_guest_discovery()
                before = vm_guest_inventory(source)
                rows = source["observations"]["vm_interfaces"]
                rows[1][field] = rows[0][field]
                self.assertTrue(reconcile.build_plan(source, before)["errors"])
        source = vm_guest_discovery()
        before = vm_guest_inventory(source)
        source["observations"]["interfaces"][0]["hardware"] = [{"field": "id", "text": "16"}]
        self.assertTrue(reconcile.build_plan(source, before)["errors"])

    def test_vm_enumeration_mac_never_becomes_native_identity_or_a_write(self):
        source = vm_guest_discovery()
        before = vm_guest_inventory(source)
        for observation in source["observations"]["vm_interfaces"]:
            observation["base_os_mac"] = "duplicate-or-unknown"
        plan = reconcile.build_plan(source, before)
        self.assertFalse(plan["errors"])
        self.assertTrue(all(row["mac_address"] is None for row in plan["interface_creates"]))

    def test_collector_rejects_invalid_expected_uuid_before_reads(self):
        for value in (True, [], "unknown", "00000000-0000-0000-0000-000000000000"):
            with self.subTest(value=value):
                client = Mock()
                with self.assertRaisesRegex(ValueError, "VM UUID"):
                    panos.collect(client, expected_vm_uuid=value)
                client.run.assert_not_called()

    def test_repeated_or_nested_vm_uuid_is_failed_identity_evidence(self):
        system = (FIXTURES / "panos_system_info.txt").read_text()
        for extra in (
            "<vm-uuid>%s</vm-uuid><vm-uuid>%s</vm-uuid>" % (VM_UUID, VM_UUID),
            "<vm-uuid><nested>%s</nested></vm-uuid>" % VM_UUID,
        ):
            with self.subTest(extra=extra):
                with self.assertRaises(panos.DiscoveryError):
                    panos.parse_system_info(system.replace("</system>", extra + "</system>"))

    def test_explicit_mtu_native_bounds_are_shared_with_adapter(self):
        before = inventory()
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "other"}]
        for value in (1, 65536):
            with self.subTest(mtu=value):
                plan = reconcile.build_plan(discovery(enabled=True, mtu=value), before)
                self.assertFalse(plan["errors"])
                self.assertEqual(plan["interface_creates"][0]["mtu"], value)
        for value in (0, 65537):
            with self.subTest(mtu=value):
                self.assertTrue(reconcile.build_plan(discovery(mtu=value), before)["errors"])

    def test_unreviewed_schema_versions_are_rejected(self):
        for version in (True, "1", 0, 2):
            with self.subTest(version=version):
                source = discovery()
                source["schema_version"] = version
                with self.assertRaisesRegex(ValueError, "schema version"):
                    reconcile.build_plan(source, inventory())

    def test_unknown_type_and_admin_state_defer_creation(self):
        source, before = discovery(), inventory()
        plan = reconcile.build_plan(source, before)
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(plan["unknown_interface_capabilities"], [])
        self.assertEqual(plan["excluded_interfaces"][0]["name"], "ethernet1/1")
        self.assertFalse(plan["errors"])

    def test_template_does_not_supply_unknown_admin_state(self):
        before = inventory()
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "1000base-t"}]
        plan = reconcile.build_plan(discovery(), before)
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(plan["excluded_interfaces"][0]["reason"], "unknown admin state")

    def test_explicit_admin_and_exact_template_create_then_repeat_without_changes(self):
        source, before = discovery(enabled=False), inventory()
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "1000base-t"}]
        source_before, inventory_before = deepcopy(source), deepcopy(before)
        first = reconcile.build_plan(source, before)
        self.assertEqual(source, source_before)
        self.assertEqual(before, inventory_before)
        self.assertFalse(first["errors"])
        created = first["interface_creates"][0]
        self.assertEqual(created["name"], "ethernet1/1")
        self.assertEqual(created["type"], "1000base-t")
        self.assertIs(created["enabled"], False)
        second = reconcile.build_plan(source, apply_to_snapshot(first, before))
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertEqual(second["device_updates"], [])
        self.assertEqual(second["conflicts"], [])

    def test_unreviewed_native_type_cannot_bypass_physical_proof(self):
        for interface_type in ("other", "1000base-t", "virtual"):
            with self.subTest(type=interface_type):
                plan = reconcile.build_plan(
                    discovery(type=interface_type, enabled=True), inventory()
                )
                self.assertEqual(plan["interface_creates"], [])
                self.assertEqual(plan["unknown_interface_capabilities"], [])

    def test_hw_and_cisco_provenance_do_not_classify_vm_ethernet_as_physical(self):
        source = discovery(
            enabled=True,
            physical_ethernet=True,
            physical_ethernet_source={
                "module": "Cisco-IOS-XE-interfaces-oper",
                "path": "interfaces/interface/interface-type",
                "value": "iana-iftype-ethernet-csmacd",
                "name": "ethernet1/1",
                "admin_status": "if-state-up",
                "oper_status": "if-oper-state-ready",
            },
        )
        plan = reconcile.build_plan(source, inventory())
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(plan["unknown_interface_capabilities"], [])

    def test_existing_false_zero_other_aliases_and_ownership_are_preserved(self):
        before = inventory()
        before["device"]["name"] = "inventory-alias"
        before["interfaces"] = [
            {
                "id": "kept-uuid",
                "name": "ethernet1/1",
                "type": "other",
                "enabled": False,
                "mtu": 0,
                "description": "",
                "module_id": "owned-module",
                "lag_id": "owned-lag",
                "cable_id": "kept-cable",
                "ip_address_ids": ["kept-ip"],
                "mgmt_only": False,
            }
        ]
        original = deepcopy(before)
        plan = reconcile.build_plan(discovery(enabled=True), before)
        self.assertEqual(before, original)
        self.assertEqual(plan["interface_creates"], [])
        self.assertEqual(plan["interface_updates"][0]["id"], "kept-uuid")
        fields = {change["field"] for change in plan["interface_updates"][0]["changes"]}
        self.assertEqual(fields, {"description"})
        self.assertEqual(plan["device_updates"], [])
        self.assertTrue(any(row["field"] == "enabled" for row in plan["conflicts"]))
        self.assertTrue(any(row["field"] == "mtu" for row in plan["conflicts"]))
        self.assertTrue(any(row["field"] == "name" for row in plan["conflicts"]))

    def test_panos_names_never_use_cisco_alias_rewriting(self):
        before = inventory()
        before["interfaces"] = [{"id": "short-name", "name": "Gi1/1", "type": "other"}]
        source = discovery(name="GigabitEthernet1/1")
        plan = reconcile.build_plan(source, before)
        self.assertEqual(plan["interface_updates"], [])
        self.assertEqual(plan["missing_interfaces"], [{"id": "short-name", "name": "Gi1/1"}])

    def test_exact_release_preserves_hotfix_and_uses_matching_native_version(self):
        before = inventory()
        before["device"]["software_version"] = None
        before["software_versions"] = [{"id": "hotfix-version", "version": "11.1.4-h3"}]
        plan = reconcile.build_plan(discovery(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["software_version"]["version"], "11.1.4-h3")
        self.assertEqual(plan["software_version"]["existing_id"], "hotfix-version")
        self.assertFalse(plan["software_version"]["create"])

    def test_changed_catalog_context_blocks_pan_os_inventory(self):
        for field, value in (
            ("manufacturer_name", "Cisco"),
            ("platform_network_driver", "cisco_iosxe"),
            ("platform_name", None),
        ):
            with self.subTest(field=field):
                before = inventory()
                before["device"][field] = value
                if field == "platform_name":
                    before["device"]["platform_network_driver"] = None
                self.assertTrue(reconcile.build_plan(discovery(), before)["errors"])

    def test_conflicting_native_release_is_preserved(self):
        before = inventory()
        before["device"]["software_version"] = "11.1.4-h2"
        plan = reconcile.build_plan(discovery(), before)
        self.assertIsNone(plan["software_version"])
        self.assertEqual(plan["device_updates"], [])
        self.assertTrue(any(row["field"] == "software_version" for row in plan["conflicts"]))

    def test_duplicate_names_and_identity_disagreement_block_apply(self):
        for field, value in (("serial", "OTHER-SERIAL"), ("model", "PA-440")):
            with self.subTest(field=field):
                source = discovery()
                source["identity"][field] = value
                self.assertTrue(reconcile.build_plan(source, inventory())["errors"])
        source = discovery()
        source["interfaces"].append(deepcopy(source["interfaces"][0]))
        self.assertTrue(reconcile.build_plan(source, inventory())["errors"])

    def test_operational_fields_never_become_unreviewed_native_writes(self):
        before = inventory()
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "1000base-t"}]
        source = discovery(
            enabled=True, speed=1_000_000, duplex="full", port_type="8p8c", mgmt_only=True
        )
        plan = reconcile.build_plan(source, before)
        created = plan["interface_creates"][0]
        for field in ("mac_address", "speed", "duplex", "port_type", "mgmt_only"):
            self.assertIsNone(created[field])
        self.assertFalse(plan["errors"])

    def test_missing_serial_blocks_without_filling_a_placeholder(self):
        source, before = discovery(), inventory()
        source["identity"]["serial"] = None
        plan = reconcile.build_plan(source, before)
        self.assertTrue(plan["errors"])
        self.assertFalse(any(row["field"] == "serial" for row in plan["device_updates"]))
        self.assertEqual(before["device"]["serial"], "LABPAN00001")

    def test_explicit_vm_identity_allows_missing_serial_and_remains_blank_on_repeat(self):
        source, before = vm_discovery(enabled=False), inventory()
        before["device"]["serial"] = ""
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "virtual"}]
        original_source, original_inventory = deepcopy(source), deepcopy(before)
        first = reconcile.build_plan(source, before)
        self.assertFalse(first["errors"])
        self.assertEqual(first["identity_binding"]["observed_uuid"], VM_UUID)
        self.assertEqual(first["interface_creates"][0]["type"], "virtual")
        self.assertIs(first["interface_creates"][0]["enabled"], False)
        self.assertFalse(any(row["field"] == "serial" for row in first["device_updates"]))
        after = apply_to_snapshot(first, before)
        self.assertEqual(after["device"]["serial"], "")
        second = reconcile.build_plan(source, after)
        self.assertFalse(second["errors"])
        self.assertEqual(second["device_updates"], [])
        self.assertEqual(second["interface_creates"], [])
        self.assertEqual(second["interface_updates"], [])
        self.assertEqual(source, original_source)
        self.assertEqual(before, original_inventory)

    def test_unlicensed_vm_without_explicit_binding_still_requires_serial(self):
        source, before = vm_discovery(), inventory()
        before["device"]["serial"] = ""
        source.pop("identity_binding")
        plan = reconcile.build_plan(source, before)
        self.assertIn("Discovery did not provide required identity field: serial", plan["errors"])
        self.assertNotIn("identity_binding", plan)

    def test_vm_identity_never_bypasses_a_populated_selected_serial(self):
        source, before = vm_discovery(), inventory()
        plan = reconcile.build_plan(source, before)
        self.assertIn("Discovery did not provide required identity field: serial", plan["errors"])
        self.assertEqual(before["device"]["serial"], "LABPAN00001")
        self.assertFalse(any(row["field"] == "serial" for row in plan["device_updates"]))

    def test_vm_binding_requires_matching_nonzero_uuid_and_reviewed_source(self):
        mutations = (
            ("binding", "contract", "panos-vm-identity-v2"),
            ("binding", "system_command", "show system info text"),
            ("binding", "system_path", "result/peer/system"),
            ("binding", "model", "PA-440"),
            ("binding", "family", "400"),
            ("binding", "vm_mode", "ESXi"),
            ("binding", "expected_uuid", None),
            ("binding", "expected_uuid", True),
            ("binding", "expected_uuid", "unknown"),
            ("binding", "expected_uuid", "00000000-0000-0000-0000-000000000000"),
            ("binding", "expected_uuid", "b924dbfd-1b08-4e22-ae0e-71164c2257c9"),
            ("binding", "observed_uuid", None),
            ("binding", "observed_uuid", "b924dbfd-1b08-4e22-ae0e-71164c2257c9"),
            ("system", "vm-uuid", None),
            ("system", "vm-uuid", "b924dbfd-1b08-4e22-ae0e-71164c2257c9"),
            ("system", "family", "hardware"),
            ("system", "vm-mode", "ESXi"),
            ("source", "command", "show system peer info"),
            ("source", "path", "result/peer/system"),
            ("identity", "model", "PA-440"),
            ("device", "model", "PA-440"),
        )
        for scope, field, value in mutations:
            with self.subTest(scope=scope, field=field, value=value):
                source, before = vm_discovery(), inventory()
                before["device"]["serial"] = ""
                target = {
                    "binding": source["identity_binding"],
                    "system": source["observations"]["system"],
                    "source": source["sources"]["identity"],
                    "identity": source["identity"],
                    "device": before["device"],
                }[scope]
                target[field] = value
                plan = reconcile.build_plan(source, before)
                self.assertTrue(plan["errors"])
                self.assertNotIn("identity_binding", plan)
                self.assertIn(
                    "Discovery did not provide required identity field: serial", plan["errors"]
                )

    def test_malformed_vm_identity_structures_block_without_crashing(self):
        for field, value in (
            ("identity_binding", []),
            ("observations", []),
            ("sources", None),
        ):
            with self.subTest(field=field):
                source, before = vm_discovery(), inventory()
                before["device"]["serial"] = ""
                source[field] = value
                self.assertTrue(reconcile.build_plan(source, before)["errors"])

    def test_explicit_vm_binding_also_validates_licensed_identity(self):
        source, before = vm_discovery(), inventory()
        source["identity"]["serial"] = before["device"]["serial"]
        self.assertFalse(reconcile.build_plan(source, before)["errors"])
        source["identity_binding"]["expected_uuid"] = "b924dbfd-1b08-4e22-ae0e-71164c2257c9"
        self.assertTrue(reconcile.build_plan(source, before)["errors"])
        source["identity_binding"]["expected_uuid"] = VM_UUID
        source["identity"]["serial"] = "CONFLICTING-SERIAL"
        self.assertTrue(reconcile.build_plan(source, before)["errors"])

    def test_physical_panos_serial_remains_required_with_copied_vm_binding(self):
        source, before = vm_discovery(), inventory()
        before["device"].update(model="PA-440", serial="")
        source["identity"]["model"] = "PA-440"
        source["identity_binding"]["model"] = "PA-440"
        source["observations"]["system"].update(family="400", **{"vm-mode": None})
        source["identity_binding"].update(family="400", vm_mode=None)
        plan = reconcile.build_plan(source, before)
        self.assertIn("Discovery did not provide required identity field: serial", plan["errors"])

    def test_cisco_required_serial_cannot_be_bypassed_by_copied_vm_binding(self):
        source, before = test_reconcile.discovery(), test_reconcile.inventory()
        source["identity"]["serial"] = None
        before["device"]["serial"] = ""
        source["identity_binding"] = vm_discovery()["identity_binding"]
        plan = reconcile.build_plan(source, before)
        self.assertIn("Discovery did not provide required identity field: serial", plan["errors"])
        self.assertNotIn("identity_binding", plan)

    def test_applied_field_provenance_is_required_for_every_native_write(self):
        mutations = (
            ("contract", "unknown-contract"),
            ("name", "ethernet1/2"),
            ("applied_command", "show config candidate"),
            ("hardware_path", "result/ifnet/entry"),
            ("link_state", "auto"),
            ("link_state", "down"),
            ("comment", "different comment"),
            ("mtu", "MTU 1500"),
            ("mtu", "1501"),
        )
        before = inventory()
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "1000base-t"}]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                source = discovery(enabled=True)
                source["interfaces"][0]["source"][field] = value
                self.assertTrue(reconcile.build_plan(source, before)["errors"])
        source = discovery(enabled=True)
        source["interfaces"][0].pop("source")
        self.assertTrue(reconcile.build_plan(source, before)["errors"])

    def test_typed_mtu_rejects_boolean_prose_out_of_range_and_disagreement(self):
        for value, raw in ((True, "1"), (70000, "70000"), (1500, "15e2"), (1500, "1501")):
            with self.subTest(value=value, raw=raw):
                source = discovery(mtu=value)
                source["interfaces"][0]["source"]["mtu"] = raw
                self.assertTrue(reconcile.build_plan(source, inventory())["errors"])

    def test_malformed_boolean_blocks_instead_of_using_orm_default(self):
        before = inventory()
        before["interface_templates"] = [{"name": "ethernet1/1", "type": "1000base-t"}]
        for value in ("yes", 1, 0):
            with self.subTest(enabled=value):
                plan = reconcile.build_plan(discovery(enabled=value), before)
                self.assertTrue(plan["errors"])
                self.assertEqual(plan["interface_creates"], [])

    def test_advanced_domain_facts_block_and_do_not_reach_cisco_planners(self):
        for field in ("stack", "components", "console_ports", "layer2", "ipam", "lag_memberships"):
            with self.subTest(field=field):
                source = discovery()
                source[field] = {"schema_version": 1, "invalid": "advanced-domain-sentinel"}
                plan = reconcile.build_plan(source, inventory())
                self.assertTrue(plan["errors"])
                self.assertEqual(plan["interface_creates"], [])
                self.assertEqual(plan["components"]["modules"], [])
                self.assertEqual(plan["layer2"]["assignments"], [])
                self.assertEqual(plan["console_ports"]["creates"], [])
                self.assertEqual(plan["stack"]["members"], [])
                self.assertIsNone(plan["ipam"]["policy"])


class PanosJobTests(unittest.TestCase):
    def setUp(self):
        test_discovery_job.DiscoveryJobTests.setUp(self)
        self.device.platform = SimpleNamespace(network_driver="paloalto_panos", name="PAN-OS")
        self.device.device_type = SimpleNamespace(
            manufacturer=SimpleNamespace(name="Palo Alto Networks")
        )
        self.observed = discovery()
        self.ssh = Mock(return_value=self.client)
        patcher = patch.object(self.module, "PanosSshClient", self.ssh)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(self.module.panos, "collect", Mock(return_value=self.observed))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ssh_dispatch_uses_credentials_port_and_host_key_policy(self):
        self.job.run(self.device, ssh_port=2222, ssh_strict=True)
        self.module.resolve_credentials.assert_called_once_with(
            self.device, override_group=None, transport="ssh"
        )
        self.ssh.assert_called_once_with(
            "192.0.2.1", "test-user", "test-password", port=2222, ssh_strict=True
        )
        self.module.RestconfClient.assert_not_called()
        self.client.close.assert_called_once_with()
        report = self.job.request.meta["discovery_report"]
        self.assertEqual(report["transport"], "ssh")
        self.assertEqual(report["ssh_port"], 2222)
        self.assertIs(report["ssh_strict"], True)
        self.assertNotIn("test-password", str(report))

    def test_ssh_strict_boolean_is_validated_before_resolving_credentials(self):
        with self.assertRaisesRegex(ValueError, "host key"):
            self.job.run(self.device, ssh_strict="false")
        self.module.resolve_credentials.assert_not_called()
        self.ssh.assert_not_called()

    def test_panos_guessing_option_carries_no_new_defaults(self):
        self.job.run(self.device, use_ntc_defaults=True)
        messages = test_discovery_job.rendered_logs(self.job.logger)
        self.assertTrue(any("applies only to Cisco IOS XE" in message for message in messages))
        self.module.panos.collect.assert_called_once_with(
            self.client, use_ntc_defaults=True, expected_vm_uuid=None, max_vpn_flow_details=256
        )

    def test_selected_vpn_detail_budget_is_forwarded_and_reported(self):
        self.job.run(self.device, max_vpn_flow_details=4096)
        self.module.panos.collect.assert_called_once_with(
            self.client, use_ntc_defaults=False, expected_vm_uuid=None, max_vpn_flow_details=4096
        )
        self.assertEqual(self.job.request.meta["discovery_report"]["max_vpn_flow_details"], 4096)

    def test_invalid_vpn_detail_budget_fails_before_credentials_or_transport(self):
        for value in (True, 0, -1, 65536, "256", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "VPN flow details"):
                self.job.run(self.device, max_vpn_flow_details=value)
            self.module.resolve_credentials.assert_not_called()
            self.ssh.assert_not_called()

    def test_ha_vpn_facts_are_retained_in_advanced_and_attachment(self):
        from tests.test_panos_ha_vpn_collection import payloads

        client = Mock(run=Mock(side_effect=payloads().__getitem__))
        ha, vpn = panos._collect_ha_vpn(client, 256)
        self.observed["observations"] = {"ha": ha, "vpn": vpn}
        self.job.run(self.device)
        report = self.job.request.meta["discovery_report"]
        self.assertIn("ha", report["discovery"]["observations"])
        self.assertIn("vpn", report["discovery"]["observations"])
        self.assertFalse(report["applied"])
        self.assertFalse(report["discovery"]["observations"]["vpn"]["native_writes"])
        self.module.apply_discovery.assert_not_called()
        import json

        attachment = json.loads(self.job.create_file.call_args.args[1])
        self.assertEqual(attachment, report)

    def test_expected_vm_uuid_is_canonicalized_forwarded_and_reported(self):
        self.job.run(self.device, expected_vm_uuid=VM_UUID.upper())
        self.module.panos.collect.assert_called_once_with(
            self.client, use_ntc_defaults=False, expected_vm_uuid=VM_UUID, max_vpn_flow_details=256
        )
        self.assertEqual(self.job.request.meta["discovery_report"]["expected_vm_uuid"], VM_UUID)

    def test_invalid_expected_vm_uuid_fails_before_credentials_or_transport(self):
        for value in (True, 123, [], "unknown", "00000000-0000-0000-0000-000000000000"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "VM UUID"):
                    self.job.run(self.device, expected_vm_uuid=value)
                self.module.resolve_credentials.assert_not_called()
                self.ssh.assert_not_called()
                self.module.panos.collect.assert_not_called()

    def test_non_panos_expected_vm_uuid_fails_before_credentials_or_transport(self):
        self.device.platform = SimpleNamespace(network_driver="cisco_iosxe", name="IOS XE")
        self.device.device_type.manufacturer.name = "Cisco"
        with self.assertRaisesRegex(ValueError, "only for PAN-OS"):
            self.job.run(self.device, expected_vm_uuid=VM_UUID)
        self.module.resolve_credentials.assert_not_called()
        self.module.RestconfClient.assert_not_called()
        self.ssh.assert_not_called()

    def test_panos_errors_close_transport_and_survive_job_exception_boundary(self):
        for error_type in (self.module.SshError, self.module.panos.DiscoveryError):
            with self.subTest(error_type=error_type):
                self.client.close.reset_mock()
                self.module.panos.collect.side_effect = error_type("Sanitized PAN-OS failure")
                with self.assertRaisesRegex(RuntimeError, "Sanitized PAN-OS failure") as raised:
                    self.job.run(self.device)
                self.assertIs(type(raised.exception), RuntimeError)
                self.assertTrue(raised.exception.__suppress_context__)
                self.client.close.assert_called_once_with()
                report = self.job.request.meta["discovery_report"]
                self.assertEqual(report["error"], "Sanitized PAN-OS failure")
                self.assertEqual(report["requests"], self.client.trace)

    def test_panos_requires_supported_platform_and_manufacturer(self):
        for driver, platform_name, manufacturer in (
            ("paloalto_panos", "PAN-OS", "Cisco"),
            ("junos", "PAN-OS", "Palo Alto Networks"),
            ("", "PAN-ish", "Palo Alto Networks"),
        ):
            with self.subTest(driver=driver, name=platform_name, manufacturer=manufacturer):
                self.device.platform = SimpleNamespace(network_driver=driver, name=platform_name)
                self.device.device_type.manufacturer.name = manufacturer
                with self.assertRaises(ValueError):
                    self.module._adapter(self.device)


if __name__ == "__main__":
    unittest.main()
