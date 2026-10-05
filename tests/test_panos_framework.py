"""PAN-OS uses its own names, release tokens and conservative inventory contract."""

import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests import test_discovery_job
from tests._loader import FIXTURES, load
from tests.test_reconcile import apply_to_snapshot

reconcile = load("reconcile")
ssh = load("transport_ssh")
panos = load("adapters.panos")


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


class PanosReconciliationTests(unittest.TestCase):
    def test_production_collector_sources_validate_and_repeat_with_native_templates(self):
        outputs = {
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
        self.module.panos.collect.assert_called_once_with(self.client, use_ntc_defaults=True)

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
