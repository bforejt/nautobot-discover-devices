"""Standalone ESXi adapter source-contract and no-guessing regression tests."""

import copy
import unittest
from unittest.mock import Mock

from tests._loader import load

esxi = load("adapters.esxi")
HOST_UUID = "dce10001-0002-0003-0004-000000000005"
GUEST_UUID = "dce20001-0002-0003-0004-000000000006"
POLICY = {"contract": "esxi-interface-policy-v1", "new_enabled": True}


def inventory():
    product = {
        "apiType": "HostAgent",
        "apiVersion": "8.0.3.0",
        "productLineId": "embeddedEsx",
        "vendor": "VMware, Inc.",
        "version": "8.0.3",
        "build": "24677879",
    }
    return {
        "service": dict(product),
        "host": {
            "ref": "ha-host",
            "properties": {
                "name": "nfv-esxi-1",
                "config.product": dict(product),
                "hardware.systemInfo": {
                    "uuid": HOST_UUID,
                    "vendor": "Lenovo",
                    "model": "ThinkSystem SE350",
                    "serialNumber": "LABHOST1",
                },
                "summary": {
                    "hardware": {
                        "uuid": HOST_UUID,
                        "vendor": "Lenovo",
                        "model": "ThinkSystem SE350",
                        "cpuModel": "Intel Xeon",
                        "numCpuPkgs": "1",
                        "numCpuCores": "8",
                        "numCpuThreads": "16",
                        "memorySize": "68719476736",
                    },
                    "config": {"name": "nfv-esxi-1"},
                },
                "hardware.pciDevice": [
                    {"id": "0000:00:12.0", "vendorId": "-32634", "deviceId": "4110"},
                ],
                "config.network.pnic": [
                    {
                        "device": "vmnic0",
                        "key": "key-vim.host.PhysicalNic-vmnic0",
                        "pci": "0000:00:12.0",
                        "mac": "02:AC:00:00:00:01",
                        "driver": "ixgben",
                        "linkSpeed": {"speedMb": "10000", "duplex": "true"},
                        "validLinkSpecification": [{"speedMb": "10000", "duplex": "true"}],
                    },
                    {
                        "device": "vmnic1",
                        "key": "key-vim.host.PhysicalNic-vmnic1",
                        "pci": "0000:00:13.0",
                        "mac": "02:ac:00:00:00:02",
                        "driver": "ixgben",
                    },
                ],
                "config.network.vnic": [
                    {
                        "device": "vmk0",
                        "key": "key-vim.host.VirtualNic-vmk0",
                        "portgroup": "Management Network",
                        "spec": {
                            "mac": "02:ac:00:00:00:03",
                            "mtu": "1500",
                            "ip": {
                                "ipAddress": "10.40.3.124",
                                "subnetMask": "255.255.255.0",
                                "dhcp": "false",
                            },
                        },
                    },
                ],
                "config.network.vswitch": [
                    {
                        "name": "vSwitch0",
                        "key": "key-vim.host.VirtualSwitch-vSwitch0",
                        "pnic": ["key-vim.host.PhysicalNic-vmnic0"],
                        "mtu": "1500",
                    },
                ],
                "config.network.portgroup": [
                    {"spec": {"name": "VM Network", "vswitchName": "vSwitch0", "vlanId": "4095"}},
                    {
                        "spec": {
                            "name": "Management Network",
                            "vswitchName": "vSwitch0",
                            "vlanId": "0",
                        }
                    },
                ],
                "vm": [{"type": "VirtualMachine", "ref": "1"}],
                "datastore": [{"type": "Datastore", "ref": "ds1"}],
            },
        },
        "guests": [
            {
                "ref": "1",
                "properties": {
                    "name": "nfv-firewall",
                    "config.uuid": GUEST_UUID,
                    "config.template": False,
                    "config.hardware.numCPU": "2",
                    "config.hardware.memoryMB": "4096",
                    "runtime.host": {"type": "HostSystem", "ref": "ha-host"},
                    "runtime.powerState": "poweredOff",
                    "runtime.connectionState": "connected",
                    "config.hardware.device": [
                        {
                            "type": "VirtualVmxnet3",
                            "key": "4000",
                            "macAddress": "02:ac:00:00:01:01",
                            "connectable": {"startConnected": "false"},
                        }
                    ],
                },
            }
        ],
        "datastores": [
            {
                "ref": "ds1",
                "properties": {
                    "summary": {
                        "name": "datastore1",
                        "type": "VMFS",
                        "accessible": False,
                        "capacity": "107374182400",
                        "freeSpace": "0",
                    },
                },
            }
        ],
        "completeness": {
            "host": True,
            "guests": "permission-scoped",
            "datastores": "permission-scoped",
        },
    }


class EsxiTests(unittest.TestCase):
    def collect(self, raw=None, **kwargs):
        client = Mock()
        client.discovery.return_value = inventory() if raw is None else raw
        result = esxi.collect(client, **kwargs)
        client.discovery.assert_called_once_with()
        return result

    def test_exact_build_and_hardware_identity(self):
        data = self.collect()
        self.assertEqual(
            data["identity"],
            {
                "hostname": "nfv-esxi-1",
                "vendor": "Lenovo",
                "model": "ThinkSystem SE350",
                "serial": "LABHOST1",
                "host_uuid": HOST_UUID,
                "software_version": "8.0.3 build-24677879",
            },
        )
        self.assertEqual(esxi.reconstruct(data), data)

    def test_binding_and_creation_policy_are_distinct_source_contracts(self):
        data = self.collect(expected_host_uuid=HOST_UUID.upper(), interface_enabled_policy=POLICY)
        self.assertEqual(data["identity_binding"]["expected_uuid"], HOST_UUID)
        self.assertEqual(data["identity_binding"]["observed_uuid"], HOST_UUID)
        self.assertEqual(data["interface_policy"], POLICY)
        self.assertTrue(all(row["enabled"] is None for row in data["interfaces"]))
        self.assertEqual(esxi.reconstruct(data), data)

    def test_wrong_endpoint_uuid_is_rejected(self):
        with self.assertRaisesRegex(esxi.DiscoveryError, "selected endpoint"):
            self.collect(expected_host_uuid=GUEST_UUID)

    def test_invalid_bindings_are_rejected_before_network_access(self):
        for value in (
            "unknown",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "10.40.3.124",
            12,
        ):
            client = Mock()
            with self.subTest(value=value), self.assertRaises(ValueError):
                esxi.collect(client, expected_host_uuid=value)
            client.discovery.assert_not_called()

    def test_vcenter_or_other_host_agent_is_rejected(self):
        for field, value in (("apiType", "VirtualCenter"), ("productLineId", "gsx")):
            raw = inventory()
            raw["service"][field] = value
            raw["host"]["properties"]["config.product"][field] = value
            with self.subTest(field=field), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_product_and_service_must_corroborate_exact_release(self):
        for field in ("apiType", "apiVersion", "productLineId", "vendor", "version", "build"):
            raw = inventory()
            raw["host"]["properties"]["config.product"][field] = "different"
            with self.subTest(field=field), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_summary_must_corroborate_system_hardware(self):
        for field, value in (("uuid", GUEST_UUID), ("vendor", "Dell"), ("model", "Other")):
            raw = inventory()
            raw["host"]["properties"]["summary"]["hardware"][field] = value
            with self.subTest(field=field), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_invalid_summary_uuid_is_not_missing_corroboration(self):
        raw = inventory()
        raw["host"]["properties"]["summary"]["hardware"]["uuid"] = "unknown"
        with self.assertRaises(esxi.DiscoveryError):
            self.collect(raw)

    def test_host_scope_and_complete_host_outcome_are_required(self):
        for key in ("scope", "complete"):
            raw = inventory()
            if key == "scope":
                raw["host"]["ref"] = "host-123"
            else:
                raw["completeness"]["host"] = False
            with self.subTest(key=key), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_serial_placeholder_is_not_host_uuid(self):
        for value in ("unknown", "none", "0", "N/A", "to be filled by o.e.m."):
            raw = inventory()
            raw["host"]["properties"]["hardware.systemInfo"]["serialNumber"] = value
            data = self.collect(raw)
            self.assertIsNone(data["identity"]["serial"])
            self.assertEqual(data["identity"]["host_uuid"], HOST_UUID)

    def test_typed_service_tag_is_only_serial_fallback(self):
        raw = inventory()
        system = raw["host"]["properties"]["hardware.systemInfo"]
        system.pop("serialNumber")
        system["otherIdentifyingInfo"] = [
            {"identifierType": {"key": "AssetTag"}, "identifierValue": "NOT-A-SERIAL"},
            {"identifierType": {"key": "ServiceTag"}, "identifierValue": "LABHOST1"},
        ]
        self.assertEqual(self.collect(raw)["identity"]["serial"], "LABHOST1")

    def test_conflicting_serial_sources_are_rejected(self):
        raw = inventory()
        raw["host"]["properties"]["hardware.systemInfo"]["otherIdentifyingInfo"] = [
            {"identifierType": {"key": "ServiceTag"}, "identifierValue": "OTHERHOST"},
        ]
        with self.assertRaises(esxi.DiscoveryError):
            self.collect(raw)

    def test_build_is_preserved_without_release_guessing(self):
        for version, build in (
            ("8.0.3-U3e", "24677879"),
            ("8.0.3", "build-24677879"),
            ("8.0.3", "0"),
            ("8.0.3", "2" * 100),
        ):
            self.assertIsNone(esxi.canonical_software_version(version, build))

    def test_mbps_to_kbps_native_speed_and_duplex(self):
        data = self.collect()
        nic = data["interfaces"][0]
        self.assertEqual(nic["speed"], 10000000)
        self.assertIsNone(nic["duplex"])
        self.assertEqual(nic["mac_address"], "02:ac:00:00:00:01")
        self.assertIsNone(nic["type"])
        self.assertIs(nic["physical_ethernet"], True)
        self.assertIsNone(nic["port_type"])
        self.assertIsNone(nic["enabled"])

    def test_unplugged_port_retained_without_admin_or_speed_guess(self):
        nic = self.collect()["interfaces"][1]
        self.assertEqual(nic["name"], "vmnic1")
        self.assertIsNone(nic["enabled"])
        self.assertIsNone(nic["speed"])
        self.assertIsNone(nic["duplex"])

    def test_false_duplex_and_false_policy_survive(self):
        raw = inventory()
        raw["host"]["properties"]["config.network.pnic"][0]["linkSpeed"]["duplex"] = False
        data = self.collect(raw, interface_enabled_policy={**POLICY, "new_enabled": False})
        self.assertIsNone(data["interfaces"][0]["duplex"])
        self.assertIs(
            data["source"]["inventory"]["host"]["properties"]["config.network.pnic"][0][
                "linkSpeed"
            ]["duplex"],
            False,
        )
        self.assertIs(data["interface_policy"]["new_enabled"], False)
        self.assertIsNone(data["interfaces"][0]["enabled"])

    def test_malformed_speed_never_uses_embedded_number_or_truthy_bool(self):
        for value in (True, "10Gbps", "-1", "0", "10000.0", "2147484"):
            raw = inventory()
            raw["host"]["properties"]["config.network.pnic"][0]["linkSpeed"]["speedMb"] = value
            with self.subTest(value=value):
                self.assertIsNone(self.collect(raw)["interfaces"][0]["speed"])

    def test_pnic_duplicates_reject_whole_collection(self):
        for field in ("device", "key", "pci"):
            raw = inventory()
            rows = raw["host"]["properties"]["config.network.pnic"]
            rows[1][field] = rows[0][field]
            with self.subTest(field=field), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_only_exact_reviewed_vmnic_identifiers_are_eligible(self):
        for field, value in (
            ("device", "vmk0"),
            ("device", "vmnic01"),
            ("pci", "12.0"),
            ("key", None),
        ):
            raw = inventory()
            raw["host"]["properties"]["config.network.pnic"][0][field] = value
            data = self.collect(raw)
            self.assertEqual(len(data["interfaces"]), 1)
            self.assertEqual(len(data["excluded_interfaces"]), 1)

    def test_nested_vmxnet3_needs_host_driver_and_exact_pci_tuple(self):
        raw = inventory()
        props = raw["host"]["properties"]
        model = "Standard PC (Q35 + ICH9, 2009)"
        for source in (props["hardware.systemInfo"], props["summary"]["hardware"]):
            source.update(vendor="QEMU", model=model)
        props["config.network.pnic"][0]["driver"] = "nvmxnet3"
        props["hardware.pciDevice"][0].update(vendorId="5549", deviceId="1968")
        nic = self.collect(raw)["interfaces"][0]
        self.assertEqual(nic["type"], "virtual")
        self.assertIs(nic["physical_ethernet"], False)
        self.assertIsNone(nic["speed"])
        props["hardware.pciDevice"][0]["deviceId"] = "1969"
        self.assertNotIn("vmnic0", [row["name"] for row in self.collect(raw)["interfaces"]])

    def test_driver_alone_is_not_virtual_hardware_identity(self):
        raw = inventory()
        raw["host"]["properties"]["config.network.pnic"][0]["driver"] = "nvmxnet3"
        data = self.collect(raw)
        self.assertNotIn("vmnic0", [row["name"] for row in data["interfaces"]])
        self.assertEqual(
            data["excluded_interfaces"][0]["reason"], "unresolved VMXNET3 PCI identity"
        )

    def test_vmxnet3_exact_pci_driver_is_virtual_independent_of_bios_identity(self):
        for vendor, model in (
            ("VMware, Inc.", "VMware Virtual Platform"),
            ("Dell", "PowerEdge R750"),
        ):
            raw = inventory()
            props = raw["host"]["properties"]
            for hardware in (props["hardware.systemInfo"], props["summary"]["hardware"]):
                hardware.update(vendor=vendor, model=model)
            props["config.network.pnic"][0]["driver"] = "nvmxnet3"
            props["hardware.pciDevice"][0].update(vendorId=0x15AD, deviceId=0x07B0)
            with self.subTest(vendor=vendor):
                nic = self.collect(raw)["interfaces"][0]
                self.assertEqual(nic["type"], "virtual")
                self.assertIs(nic["physical_ethernet"], False)

    def test_unjoined_known_virtual_driver_never_becomes_physical_ethernet(self):
        raw = inventory()
        props = raw["host"]["properties"]
        props["config.network.pnic"][0]["driver"] = "vmxnet3"
        props["hardware.pciDevice"] = []
        data = self.collect(raw)
        self.assertNotIn("vmnic0", [row["name"] for row in data["interfaces"]])
        self.assertEqual(
            data["excluded_interfaces"][0]["reason"], "unresolved VMXNET3 PCI identity"
        )

    def test_unknown_and_zero_mac_remain_unresolved(self):
        for value in ("unknown", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "abcdef"):
            raw = inventory()
            raw["host"]["properties"]["config.network.pnic"][0]["mac"] = value
            self.assertIsNone(self.collect(raw)["interfaces"][0]["mac_address"])

    def test_guest_identity_uses_bios_uuid_without_instance_uuid(self):
        data = self.collect()
        guest = data["observations"]["guests"][0]
        self.assertEqual(
            guest["identity"],
            {
                "host_uuid": HOST_UUID,
                "guest_uuid": GUEST_UUID,
                "unique": True,
            },
        )
        self.assertNotIn("instance_uuid", guest["identity"])
        self.assertIs(guest["properties"]["config.template"], False)
        self.assertEqual(guest["properties"]["runtime.powerState"], "poweredOff")

    def test_duplicate_guest_bios_uuid_cannot_join_native_relationship(self):
        raw = inventory()
        twin = copy.deepcopy(raw["guests"][0])
        twin["ref"] = "2"
        raw["guests"].append(twin)
        raw["host"]["properties"]["vm"].append({"type": "VirtualMachine", "ref": "2"})
        data = self.collect(raw)
        self.assertEqual(len(data["observations"]["guest_identity_unresolved"]), 2)
        self.assertTrue(
            all(not row["identity"]["unique"] for row in data["observations"]["guests"])
        )

    def test_empty_guest_inventory_is_permission_scoped(self):
        raw = inventory()
        raw["guests"] = []
        raw["host"]["properties"]["vm"] = []
        data = self.collect(raw)
        self.assertEqual(data["observations"]["guests"], [])
        self.assertEqual(data["observations"]["completeness"]["guests"], "permission-scoped")
        self.assertIs(data["observations"]["completeness"]["permission_scoped"], True)

    def test_vmk_switch_vlan_and_storage_are_observations_only(self):
        data = self.collect()
        self.assertEqual([row["name"] for row in data["interfaces"]], ["vmnic0", "vmnic1"])
        self.assertEqual(
            data["observations"]["network"]["config.network.portgroup"][0]["spec"]["vlanId"], "4095"
        )
        self.assertIs(
            data["observations"]["datastores"][0]["properties"]["summary"]["accessible"], False
        )
        for domain in ("capacity", "logical_interfaces", "ipam", "layer2", "lag_memberships"):
            self.assertNotIn(domain, data)

    def test_unreviewed_secret_bearing_properties_never_enter_evidence(self):
        raw = inventory()
        props = raw["host"]["properties"]
        props["config.option"] = [{"key": "token", "value": "HIDDEN-SECRET"}]
        props["config.network.pnic"][0]["password"] = "HIDDEN-SECRET"
        raw["guests"][0]["properties"]["config.extraConfig"] = [{"value": "HIDDEN-SECRET"}]
        self.assertNotIn("HIDDEN-SECRET", str(self.collect(raw)))

    def test_normalized_identity_and_every_interface_field_are_revalidated(self):
        for domain, field, value in (
            ("identity", "serial", "FAKE"),
            ("identity", "software_version", "8.0.3"),
            ("interfaces", "enabled", True),
            ("interfaces", "type", "1000base-t"),
            ("interfaces", "speed", 1),
            ("interfaces", "mac_address", "02:aa:bb:cc:dd:ee"),
        ):
            data = self.collect()
            target = data[domain][0] if domain == "interfaces" else data[domain]
            target[field] = value
            with self.subTest(field=field), self.assertRaises(esxi.DiscoveryError):
                esxi.reconstruct(data)

    def test_binding_and_source_contract_tampering_is_rejected(self):
        data = self.collect(expected_host_uuid=HOST_UUID)
        data["identity_binding"]["observed_uuid"] = GUEST_UUID
        with self.assertRaises(esxi.DiscoveryError):
            esxi.reconstruct(data)
        data = self.collect()
        data["source"]["inventory"]["host"]["properties"]["config.option"] = []
        with self.assertRaises(esxi.DiscoveryError):
            esxi.reconstruct(data)

    def test_unknown_native_guest_policy_is_left_for_parent_validation(self):
        data = self.collect()
        data["guest_policy"] = {"contract": "esxi-guest-policy-v1"}
        self.assertEqual(esxi.reconstruct(data)["identity"], data["identity"])

    def test_invalid_operator_policy_is_rejected_before_access(self):
        for value in (
            True,
            {"contract": POLICY["contract"], "new_enabled": "true"},
            {**POLICY, "enabled": True},
            {"contract": "wrong", "new_enabled": True},
        ):
            client = Mock()
            with self.subTest(value=value), self.assertRaises(ValueError):
                esxi.collect(client, interface_enabled_policy=value)
            client.discovery.assert_not_called()

    def test_missing_property_containers_and_malformed_rows_are_failures(self):
        for target in ("product", "summary", "pnic"):
            raw = inventory()
            props = raw["host"]["properties"]
            if target == "product":
                props.pop("config.product")
            elif target == "summary":
                props.pop("summary")
            else:
                props["config.network.pnic"] = [None]
            with self.subTest(target=target), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_absent_pnic_array_never_establishes_hardware_absence(self):
        raw = inventory()
        raw["host"]["properties"].pop("config.network.pnic")
        data = self.collect(raw)
        self.assertEqual(data["interfaces"], [])
        self.assertTrue(
            any(
                "does not establish complete hardware absence" in warning
                for warning in data["warnings"]
            )
        )

    def test_canonical_build_token_accepts_single_value(self):
        self.assertEqual(
            esxi.canonical_software_version("8.0.3 build-24677879"), "8.0.3 build-24677879"
        )
        self.assertIsNone(esxi.canonical_software_version("8.0.3"))
        self.assertIsNone(esxi.canonical_software_version("8.0.3 build-0"))

    def test_physical_provenance_matches_exact_source_identity(self):
        nic = self.collect()["interfaces"][0]
        self.assertTrue(esxi.observed_physical_ethernet(nic, "vmnic0"))
        self.assertFalse(esxi.observed_physical_ethernet(nic, "vmnic1"))
        nic["source"]["classification"] = "guessed"
        self.assertFalse(esxi.observed_physical_ethernet(nic, "vmnic0"))

    def test_guest_scope_is_revalidated_independently_of_normalized_identity(self):
        for problem in ("references", "runtime"):
            raw = inventory()
            if problem == "references":
                raw["host"]["properties"]["vm"] = []
            else:
                raw["guests"][0]["properties"]["runtime.host"]["ref"] = "host-123"
            with self.subTest(problem=problem), self.assertRaises(esxi.DiscoveryError):
                self.collect(raw)

    def test_observation_edits_cannot_mutate_authoritative_source_aliases(self):
        data = self.collect()
        data["observations"]["host"]["properties"]["config.product"]["build"] = "1"
        self.assertEqual(
            esxi.reconstruct(data)["identity"]["software_version"], "8.0.3 build-24677879"
        )


if __name__ == "__main__":
    unittest.main()
