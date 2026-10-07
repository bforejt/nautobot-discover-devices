"""Proxmox structured collection, source reconstruction and no-guessing checks."""

import copy
import unittest

from tests._loader import load

proxmox = load("adapters.proxmox")
NODE = "pve"
HOST_UUID = "00000001-0000-4000-8000-000000000001"
GUEST_UUID = "00000003-0000-4000-8000-000000000003"
PCI = "0000:03:00.0"
DRIVER = "/sys/bus/pci/drivers/igb"


def inventory():
    version = {"version": "9.2.2", "release": "9.2", "repoid": "b9984c6d90a4bd80"}
    qemu = {
        "vmid": 100,
        "name": "lab-router",
        "status": "stopped",
        "template": 0,
        "maxmem": 4294967296,
        "cpus": 2,
    }
    config = {
        "name": "lab-router",
        "smbios1": "uuid=" + GUEST_UUID,
        "memory": 4096,
        "cores": 2,
        "net0": "virtio=02:00:00:00:01:00,bridge=vmbr0,tag=10",
        "scsi0": "local-lvm:vm-100-disk-0,size=32G",
    }
    return {
        "node": NODE,
        "api": {
            "version": dict(version),
            "node_version": dict(version),
            "cluster_status": [
                {"type": "node", "name": NODE, "local": 1, "online": 1, "id": "node/pve"}
            ],
            "node_status": {
                "cpu": 0.1,
                "memory": {"total": 68719476736, "used": 1000000000, "free": 67719476736},
                "cpuinfo": {"cores": 8, "cpus": 16, "sockets": 1},
                "rootfs": {"total": 100000000000, "used": 1000000000},
            },
            "permissions": {
                "/nodes/" + NODE: {"Sys.Audit": 0},
                "/vms": {"VM.Audit": 1},
                "/vms/100": {"VM.Audit": 0},
            },
            "node_network": [
                {"iface": "eno1", "type": "eth", "autostart": 1},
                {
                    "iface": "vmbr0",
                    "type": "bridge",
                    "address": "192.0.2.10/24",
                    "bridge_ports": "eno1",
                },
            ],
            "node_network_changes": False,
            "storage": [
                {
                    "storage": "local-lvm",
                    "type": "lvmthin",
                    "total": 100000000000,
                    "used": 0,
                    "avail": 100000000000,
                }
            ],
            "qemu": [qemu],
            "lxc": [],
        },
        "ssh": {
            "host": {
                "hostname": NODE,
                "guest_registry": {
                    "version": 1,
                    "ids": {"100": {"node": NODE, "type": "qemu", "version": 1}},
                },
                "dmi": {
                    "sys_vendor": "Lenovo",
                    "product_name": "ThinkSystem SE350",
                    "product_serial": "LABHOST1",
                    "chassis_serial": "LABHOST1",
                    "product_uuid": HOST_UUID,
                    "board_serial": "BOARD-NOT-SERIAL",
                },
                "net": [
                    {
                        "name": "eno1",
                        "device": "/sys/devices/pci0000:00/0000:03:00.0",
                        "driver": DRIVER,
                        "physical_function": None,
                        "virtual_functions": [],
                        "wireless": False,
                        "speed": "1000",
                        "carrier": "1",
                        "type": "1",
                        "duplex": "full",
                        "mtu": "1500",
                        "address": "02:00:00:00:00:01",
                    },
                    {
                        "name": "vmbr0",
                        "device": None,
                        "driver": None,
                        "physical_function": None,
                        "wireless": False,
                    },
                ],
                "pci": [
                    {
                        "id": PCI,
                        "driver": DRIVER,
                        "physical_function": None,
                        "virtual_functions": [],
                        "vendor": "0x8086",
                        "device": "0x1521",
                        "class": "0x020000",
                    }
                ],
                "errors": [],
                "unavailable": [],
            },
            "hardware": {
                "id": "computer",
                "class": "system",
                "vendor": "Lenovo",
                "product": "ThinkSystem SE350",
                "serial": "LABHOST1",
                "configuration": {"uuid": HOST_UUID},
                "children": [
                    {
                        "id": "network",
                        "class": "network",
                        "logicalname": "eno1",
                        "businfo": "pci@" + PCI,
                        "serial": "02:00:00:00:00:01",
                        "configuration": {"driver": "igb", "speed": "1Gbit/s", "duplex": "full"},
                        "capabilities": {"ethernet": True, "physical": True},
                    }
                ],
            },
            "links": [
                {
                    "ifindex": 2,
                    "ifname": "eno1",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "mtu": 1500,
                    "link_type": "ether",
                    "address": "02:00:00:00:00:01",
                    "master": "vmbr0",
                },
                {
                    "ifindex": 3,
                    "ifname": "vmbr0",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "mtu": 1500,
                    "link_type": "ether",
                    "address": "02:00:00:00:00:01",
                    "linkinfo": {"info_kind": "bridge", "info_data": {"vlan_filtering": 1}},
                },
            ],
            "addresses": [
                {
                    "ifname": "vmbr0",
                    "addr_info": [
                        {
                            "family": "inet",
                            "local": "192.0.2.10",
                            "prefixlen": 24,
                            "scope": "global",
                        }
                    ],
                }
            ],
            "bridge_vlans": [
                {"ifname": "eno1", "vlans": [{"vlan": 1, "flags": ["PVID", "Egress Untagged"]}]}
            ],
        },
        "guests": [
            {
                "kind": "qemu",
                "vmid": 100,
                "node": NODE,
                "summary": copy.deepcopy(qemu),
                "config": dict(config),
                "current_config": dict(config),
                "pending": [],
                "status": {"vmid": 100, "status": "stopped", "maxmem": 4294967296, "cpus": 2},
            }
        ],
        "completeness": {
            "host": True,
            "interfaces": True,
            "network": True,
            "guests": True,
            "storage": "permission-scoped",
            "permission_scoped": True,
        },
    }


class Client:
    """Exercise the adapter's exact source reads without transport mocking internals."""

    def __init__(self, raw=None):
        self.raw = inventory() if raw is None else raw
        self.calls = []

    def get(self, path, params=None):
        self.calls.append((path, params))
        api, node = self.raw["api"], self.raw["node"]
        if path == "/cluster/status":
            return copy.deepcopy(api["cluster_status"])
        if path == "/version":
            return copy.deepcopy(api["version"])
        if path == "/access/permissions":
            scope = params["path"]
            return {scope: copy.deepcopy(api["permissions"].get(scope, {}))}
        suffix = path.removeprefix("/nodes/" + node + "/")
        for endpoint, key in (
            ("version", "node_version"),
            ("status", "node_status"),
            ("storage", "storage"),
            ("qemu", "qemu"),
            ("lxc", "lxc"),
        ):
            if suffix == endpoint:
                return copy.deepcopy(api[key])
        parts = suffix.split("/")
        row = next(
            row
            for row in self.raw["guests"]
            if row["kind"] == parts[0] and str(row["vmid"]) == parts[1]
        )
        key = (
            "current_config"
            if parts[2] == "config" and params == {"current": 1}
            else "config"
            if parts[2] == "config"
            else "pending"
            if parts[2] == "pending"
            else "status"
        )
        return copy.deepcopy(row[key])

    def get_envelope(self, path, params=None):
        self.calls.append((path, params))
        return {
            "data": copy.deepcopy(self.raw["api"]["node_network"]),
            "changes": "pending display text" if self.raw["api"]["node_network_changes"] else "",
        }

    def ssh_json(self, source):
        self.calls.append((source, None))
        return copy.deepcopy(self.raw["ssh"][source])


class ProxmoxTests(unittest.TestCase):
    def collect(self, raw=None, **kwargs):
        return proxmox.collect(Client(raw), **kwargs)

    def test_host_identity_and_exact_release(self):
        data = self.collect(expected_node=NODE, expected_host_uuid=HOST_UUID.upper())
        self.assertEqual(
            data["identity"],
            {
                "hostname": NODE,
                "vendor": "Lenovo",
                "model": "ThinkSystem SE350",
                "serial": "LABHOST1",
                "host_uuid": HOST_UUID,
                "software_version": "9.2.2",
            },
        )
        self.assertEqual(data["identity_binding"]["node"], NODE)
        self.assertEqual(proxmox.reconstruct(data), data)

    def test_lshw_sku_decoration_requires_exact_named_source_corroboration(self):
        sku = "Lenovo_MT_7Z46_BU_Think_FM_ThinkSystem SE350"
        for source in ("dmi", "hardware", "both"):
            raw = inventory()
            raw["ssh"]["hardware"]["product"] += " (" + sku + ")"
            if source in {"dmi", "both"}:
                raw["ssh"]["host"]["dmi"]["product_sku"] = sku
            if source in {"hardware", "both"}:
                raw["ssh"]["hardware"]["configuration"]["sku"] = sku
            with self.subTest(source=source):
                data = self.collect(raw)
                self.assertEqual(data["identity"]["model"], "ThinkSystem SE350")
                self.assertEqual(
                    data["source"]["inventory"]["ssh"]["hardware"]["product"],
                    "ThinkSystem SE350 (" + sku + ")",
                )
                self.assertEqual(proxmox.reconstruct(data), data)

    def test_lshw_sku_unknown_suffix_and_conflicts_do_not_relax_host_binding(self):
        for dmi_sku, hardware_sku, product in (
            (None, None, "ThinkSystem SE350 (SKU)"),
            ("SKU", "OTHER", "ThinkSystem SE350 (SKU)"),
            ("SKU", "SKU", "ThinkSystem SE350 (OTHER)"),
            ("SKU", "SKU", "Other host (SKU)"),
            ("SKU", "SKU", "ThinkSystem SE350 (SKU) (OTHER)"),
            ("SKU", "SKU", "ThinkSystem SE350 (SKU"),
            ("unknown", "unknown", "ThinkSystem SE350 (unknown)"),
        ):
            raw = inventory()
            raw["ssh"]["host"]["dmi"]["product_sku"] = dmi_sku
            raw["ssh"]["hardware"]["configuration"]["sku"] = hardware_sku
            raw["ssh"]["hardware"]["product"] = product
            with self.subTest(product=product), self.assertRaises(proxmox.DiscoveryError):
                self.collect(raw)

    def test_native_nic_requires_complete_exact_join_and_netlink_values(self):
        data = self.collect()
        row = data["interfaces"][0]
        self.assertEqual(len(data["interfaces"]), 1)
        self.assertTrue(proxmox.observed_physical_ethernet(row, "eno1"))
        self.assertEqual(row["speed"], 1000000)
        self.assertEqual(row["mtu"], 1500)
        self.assertTrue(row["enabled"])
        self.assertIsNone(row["duplex"])
        self.assertIsNone(row["type"])
        self.assertIsNone(row["description"])
        self.assertIsNone(row["mgmt_only"])

    def test_operational_state_does_not_define_admin_state(self):
        raw = inventory()
        raw["ssh"]["links"][0]["flags"] = ["BROADCAST", "MULTICAST", "UP"]
        raw["ssh"]["links"][0]["operstate"] = "DOWN"
        raw["ssh"]["host"]["net"][0]["carrier"] = "0"
        row = self.collect(raw)["interfaces"][0]
        self.assertTrue(row["enabled"])
        self.assertIsNone(row["speed"])
        raw["ssh"]["links"][0]["flags"] = ["BROADCAST", "MULTICAST"]
        self.assertFalse(self.collect(raw)["interfaces"][0]["enabled"])
        raw["ssh"]["links"][0].pop("flags")
        self.assertIsNone(self.collect(raw)["interfaces"][0]["enabled"])

    def test_unknown_or_impossible_rates_mac_and_mtu_stay_blank(self):
        for speed in ("-1", "0", "4294967295", "unknown", 100.0):
            raw = inventory()
            raw["ssh"]["host"]["net"][0]["speed"] = speed
            with self.subTest(speed=speed):
                self.assertIsNone(self.collect(raw)["interfaces"][0]["speed"])
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "invalid"):
            raw = inventory()
            raw["ssh"]["links"][0]["address"] = mac
            self.assertIsNone(self.collect(raw)["interfaces"][0]["mac_address"])
        raw["ssh"]["links"][0]["mtu"] = 0
        self.assertIsNone(self.collect(raw)["interfaces"][0]["mtu"])

    def test_nic_classification_excludes_vf_wireless_virtual_and_ambiguous_joins(self):
        mutations = (
            lambda r: r["ssh"]["host"]["net"][0].update(
                physical_function="/sys/devices/pci0000:00/0000:03:00.1"
            ),
            lambda r: r["ssh"]["host"]["net"][0].update(wireless=True),
            lambda r: r["ssh"]["host"]["pci"][0].update(vendor="0x1af4", device="0x1041"),
            lambda r: r["ssh"]["host"]["pci"][0].update(driver="/sys/bus/pci/drivers/different"),
            lambda r: r["ssh"]["hardware"]["children"][0].update(businfo="pci@0000:03:00.1"),
            lambda r: r["ssh"]["hardware"]["children"][0].update(capabilities={"wireless": True}),
            lambda r: r["ssh"]["hardware"]["children"][0].update(capabilities={"ethernet": False}),
            lambda r: r["ssh"]["links"][0].update(linkinfo={"info_kind": "vlan"}),
        )
        for change in mutations:
            raw = inventory()
            change(raw)
            with self.subTest(change=change):
                self.assertEqual(self.collect(raw)["interfaces"], [])

    def test_known_nested_host_cannot_claim_emulated_ports_are_physical(self):
        raw = inventory()
        raw["ssh"]["host"]["dmi"].update(product_name="KVM", sys_vendor="QEMU")
        raw["ssh"]["hardware"].update(product="KVM", vendor="QEMU")
        self.assertEqual(self.collect(raw)["interfaces"], [])

    def test_repeated_hardware_names_fail_and_unjoined_links_are_deferred(self):
        raw = inventory()
        raw["ssh"]["hardware"]["children"] *= 2
        with self.assertRaises(proxmox.DiscoveryError):
            self.collect(raw)
        raw = inventory()
        raw["ssh"]["host"]["net"].pop(0)
        self.assertEqual(self.collect(raw)["interfaces"], [])

    def test_api_local_and_exact_ssh_hostname_are_mandatory(self):
        for change in (
            lambda r: r["api"]["cluster_status"][0].update(local=0),
            lambda r: r["ssh"]["host"].update(hostname="peer"),
            lambda r: r["api"]["cluster_status"].append(dict(r["api"]["cluster_status"][0])),
        ):
            raw = inventory()
            change(raw)
            with self.assertRaises(proxmox.DiscoveryError):
                self.collect(raw)

    def test_named_lshw_capability_description_is_affirmative_structured_evidence(self):
        raw = inventory()
        raw["ssh"]["hardware"]["children"][0]["capabilities"].update(
            ethernet="Ethernet interface", physical="Physical interface"
        )
        data = self.collect(raw)
        self.assertEqual([row["name"] for row in data["interfaces"]], ["eno1"])
        self.assertEqual(
            data["source"]["inventory"]["ssh"]["hardware"]["children"][0]["capabilities"][
                "ethernet"
            ],
            "Ethernet interface",
        )
        self.assertEqual(proxmox.reconstruct(data), data)

    def test_nonaffirmative_lshw_capability_payload_never_proves_ethernet(self):
        for value in (False, None, "", 0, 1):
            raw = inventory()
            raw["ssh"]["hardware"]["children"][0]["capabilities"]["ethernet"] = value
            with self.subTest(value=value):
                data = self.collect(raw)
                self.assertEqual(data["interfaces"], [])
        self.assertFalse(proxmox._affirmative_hardware_capability(" "))

    def test_switch_ports_and_representors_cannot_supply_native_physical_facts(self):
        for port_name, switch_id in (
            ("p0", "01234567"),
            (None, "01234567"),
            ("pf0", None),
            ("pf0vf1", None),
            ("pf0sf2", None),
            ("p0pf1vf2", None),
            ("c1pf0vf3", None),
            ("c1p0pf0sf4", None),
        ):
            raw = inventory()
            # Deliberately retain otherwise valid PCI/lshw/driver joins. They
            # cannot establish a physical socket for a virtual switch endpoint.
            raw["ssh"]["host"]["net"][0].update(phys_port_name=port_name, phys_switch_id=switch_id)
            with self.subTest(port_name=port_name, switch_id=switch_id):
                data = self.collect(raw)
                self.assertEqual(data["interfaces"], [])
                self.assertEqual(
                    [row for row in data["excluded_interfaces"] if row["name"] == "eno1"],
                    [
                        {
                            "name": "eno1",
                            "reason": "unreviewed switch port or network function representor",
                        }
                    ],
                )
                retained = data["observations"]["host"]["sysfs"]["net"][0]
                self.assertEqual(retained["phys_port_name"], port_name)
                self.assertEqual(retained["phys_switch_id"], switch_id)
                self.assertEqual(proxmox.reconstruct(data), data)
                from tests.test_proxmox_framework import snapshot

                plan = load("reconcile").build_plan(data, snapshot())
                self.assertEqual(plan["errors"], [])
                self.assertEqual(plan["interface_creates"], [])
                self.assertEqual(plan["interface_updates"], [])
                self.assertEqual(plan["summary"]["unknown_interface_capabilities"], 0)

    def test_ordinary_physical_port_names_keep_exact_physical_joins(self):
        for switch_id in (None, ""):
            raw = inventory()
            raw["ssh"]["host"]["net"][0].update(phys_port_name="p0", phys_switch_id=switch_id)
            data = self.collect(raw)
            self.assertEqual([row["name"] for row in data["interfaces"]], ["eno1"])
            self.assertEqual(data["interfaces"][0]["speed"], 1000000)

    def test_system_serial_never_falls_back_to_board_uuid_or_nic(self):
        raw = inventory()
        raw["ssh"]["host"]["dmi"]["product_serial"] = "unknown"
        raw["ssh"]["host"]["dmi"]["chassis_serial"] = "unknown"
        raw["ssh"]["hardware"]["serial"] = "unknown"
        data = self.collect(raw)
        self.assertIsNone(data["identity"]["serial"])
        self.assertEqual(data["identity"]["host_uuid"], HOST_UUID)
        raw["ssh"]["host"]["dmi"]["product_serial"] = "FIRST"
        raw["ssh"]["hardware"]["serial"] = "SECOND"
        with self.assertRaises(proxmox.DiscoveryError):
            self.collect(raw)

    def test_wrong_endpoint_bindings_fail_and_invalid_values_do_not_read(self):
        for kwargs in ({"expected_node": "other"}, {"expected_host_uuid": GUEST_UUID}):
            with self.assertRaises(proxmox.DiscoveryError):
                self.collect(**kwargs)
        for kwargs in (
            {"expected_node": "../pve"},
            {"expected_host_uuid": "00000000-0000-0000-0000-000000000000"},
            {"use_ntc_defaults": 1},
        ):
            client = Client()
            with self.assertRaises(ValueError):
                proxmox.collect(client, **kwargs)
            self.assertEqual(client.calls, [])

    def test_release_scopes_and_hardware_identity_must_corroborate(self):
        for change in (
            lambda r: r["api"]["node_version"].update(version="9.2.3"),
            lambda r: r["ssh"]["hardware"].update(vendor="Dell"),
            lambda r: r["ssh"]["host"]["dmi"].update(product_uuid=GUEST_UUID),
        ):
            raw = inventory()
            change(raw)
            with self.assertRaises(proxmox.DiscoveryError):
                self.collect(raw)

    def test_api_network_visibility_remains_scoped_with_complete_live_nics(self):
        raw = inventory()
        # Sys.Audit proves host read access, but SDN.Audit/Use may filter the
        # bridge configuration table independently of successful Linux reads.
        raw["api"]["node_network"] = []
        data = self.collect(raw)
        self.assertEqual([row["name"] for row in data["interfaces"]], ["eno1"])
        self.assertIs(data["observations"]["completeness"]["network"], True)
        self.assertEqual(
            data["source"]["inventory"]["completeness"]["network_configuration"],
            "permission-scoped",
        )
        self.assertEqual(
            data["observations"]["network"]["configuration_visibility"], "permission-scoped"
        )
        self.assertEqual(data["observations"]["network"]["configuration"], [])
        self.assertEqual(proxmox.reconstruct(data), data)
        data["source"]["inventory"]["completeness"]["network_configuration"] = True
        with self.assertRaises(proxmox.DiscoveryError):
            proxmox.reconstruct(data)

    def test_guest_current_pending_runtime_and_storage_are_report_only(self):
        raw = inventory()
        raw["api"]["node_network_changes"] = True
        raw["guests"][0]["config"]["memory"] = 8192
        raw["guests"][0]["pending"] = [
            {"key": "memory", "value": 4096, "pending": 8192},
            {"key": "net0", "value": raw["guests"][0]["current_config"]["net0"], "delete": 1},
        ]
        data = self.collect(raw)
        guest = data["observations"]["guests"][0]
        self.assertEqual(guest["identity"]["guest_uuid"], GUEST_UUID)
        self.assertTrue(guest["identity"]["unique"])
        self.assertEqual(guest["config"]["memory"], 8192)
        self.assertEqual(guest["current_config"]["memory"], 4096)
        self.assertEqual(guest["pending"][1]["delete"], 1)
        self.assertTrue(data["observations"]["network"]["pending_changes_present"])
        self.assertEqual(data["observations"]["storage"][0]["used"], 0)
        self.assertNotIn("capacity", data["identity"])

    def test_secrets_and_arbitrary_configuration_are_never_retained(self):
        raw = inventory()
        raw["api"]["node_network"][0]["comments"] = "SECRET"
        for key in ("config", "current_config"):
            raw["guests"][0][key].update(
                cipassword="SECRET",
                sshkeys="SECRET",
                args="SECRET",
                hookscript="SECRET",
                unknown={"token": "SECRET"},
            )
            raw["guests"][0][key]["net0"] += ",password=SECRET"
            raw["guests"][0][key]["smbios1"] += ",serial=SECRET"
        raw["guests"][0]["pending"] = [
            {"key": "cipassword", "value": "SECRET", "pending": "SECRET"}
        ]
        data = self.collect(raw)
        self.assertNotIn("SECRET", repr(data))
        self.assertEqual(proxmox.reconstruct(data), data)

    def test_missing_permissions_and_incomplete_sources_fail(self):
        for change in (
            lambda r: r["api"]["permissions"]["/nodes/" + NODE].clear(),
            lambda r: r["api"]["permissions"]["/vms/100"].clear(),
            lambda r: r["ssh"]["host"].update(errors=["failure"]),
            lambda r: r["ssh"].update(links=None),
        ):
            raw = inventory()
            change(raw)
            with self.assertRaises(proxmox.DiscoveryError):
                self.collect(raw)
        raw = inventory()
        raw["api"]["permissions"]["/vms"]["VM.Audit"] = 0
        self.assertIs(self.collect(raw)["observations"]["completeness"]["guests"], True)

    def test_guest_uuid_duplicates_missing_and_lxc_remain_unresolved(self):
        for smbios in (
            "uuid=invalid",
            "uuid=" + GUEST_UUID + ",uuid=" + GUEST_UUID,
            "garbage",
            "uuid=" + GUEST_UUID + ",bad=",
            "uuid=" + GUEST_UUID + ",serial=a,serial=b",
            None,
        ):
            raw = inventory()
            raw["guests"][0]["current_config"]["smbios1"] = smbios
            self.assertFalse(self.collect(raw)["observations"]["guests"][0]["identity"]["unique"])
        raw = inventory()
        row = copy.deepcopy(raw["guests"][0])
        row["kind"] = "lxc"
        raw["api"]["qemu"] = []
        raw["api"]["lxc"] = [row["summary"]]
        raw["guests"] = [row]
        raw["ssh"]["host"]["guest_registry"]["ids"]["100"]["type"] = "lxc"
        self.assertIsNone(self.collect(raw)["observations"]["guests"][0]["identity"]["guest_uuid"])

    def test_forged_normalized_native_facts_or_unreviewed_source_fail(self):
        data = self.collect(expected_host_uuid=HOST_UUID)
        changes = (
            lambda d: d["identity"].update(serial="FORGED"),
            lambda d: d["interfaces"][0].update(speed=42),
            lambda d: d["identity_binding"].update(observed_uuid=GUEST_UUID),
            lambda d: d["source"]["inventory"]["guests"][0]["config"].update(cipassword="SECRET"),
        )
        for change in changes:
            forged = copy.deepcopy(data)
            change(forged)
            with self.assertRaises(proxmox.DiscoveryError):
                proxmox.reconstruct(forged)

    def test_known_nic_driver_requires_matching_hardware_and_pci_id(self):
        raw = inventory()
        raw["ssh"]["hardware"]["children"][0]["configuration"]["driver"] = "vmxnet3"
        raw["ssh"]["host"]["net"][0]["driver"] = "/sys/bus/pci/drivers/vmxnet3"
        raw["ssh"]["host"]["pci"][0]["driver"] = "/sys/bus/pci/drivers/vmxnet3"
        self.assertEqual(self.collect(raw)["interfaces"], [])
        raw = inventory()
        raw["ssh"]["host"]["net"][0]["wireless"] = None
        self.assertEqual(self.collect(raw)["interfaces"], [])

    def test_pci_function_can_have_multiple_distinct_physical_port_names(self):
        raw = inventory()
        network = copy.deepcopy(raw["ssh"]["hardware"]["children"][0])
        network["id"] = "network:1"
        network["logicalname"] = "eno2"
        raw["ssh"]["hardware"]["children"].append(network)
        kernel = copy.deepcopy(raw["ssh"]["host"]["net"][0])
        kernel["name"] = "eno2"
        raw["ssh"]["host"]["net"].append(kernel)
        link = copy.deepcopy(raw["ssh"]["links"][0])
        link.update(ifname="eno2", ifindex=4)
        raw["ssh"]["links"].append(link)
        self.assertEqual([r["name"] for r in self.collect(raw)["interfaces"]], ["eno1", "eno2"])

    def test_unknown_flags_do_not_supply_enabled_or_speed(self):
        raw = inventory()
        raw["ssh"]["links"][0]["flags"] = ["UP", "LOWER_UP", True]
        row = self.collect(raw)["interfaces"][0]
        self.assertIsNone(row["enabled"])
        self.assertIsNone(row["speed"])

    def test_capacity_units_and_runtime_counters_do_not_become_native_capacity(self):
        raw = inventory()
        raw["ssh"]["hardware"]["children"].append(
            {
                "class": "disk",
                "id": "disk",
                "size": 100000000000,
                "units": "bytes",
                "children": [{"id": "volume", "class": "volume", "size": 100000000000}],
            }
        )
        raw["guests"][0]["status"]["ballooninfo"] = {
            "actual": 1073741824,
            "total_mem": 4096000000,
            "unknown": "omit",
        }
        raw["guests"][0]["status"].update(cpu=0.25, mem=1073741824)
        data = self.collect(raw)
        self.assertEqual(data["observations"]["guests"][0]["status"]["mem"], 1073741824)
        self.assertNotIn("unknown", data["observations"]["guests"][0]["status"]["ballooninfo"])
        self.assertNotIn("capacity", data)
        self.assertNotIn("custom_fields", data)

    def test_empty_authoritative_guest_and_scoped_storage_views_are_explicit(self):
        raw = inventory()
        raw["guests"] = []
        raw["api"]["qemu"] = []
        raw["api"]["storage"] = []
        raw["api"]["permissions"]["/vms"] = {}
        raw["ssh"]["host"]["guest_registry"] = {"version": 1}
        data = self.collect(raw)
        self.assertEqual(data["observations"]["guests"], [])
        self.assertIs(data["observations"]["completeness"]["guests"], True)
        self.assertEqual(data["observations"]["completeness"]["storage"], "permission-scoped")

    def test_authoritative_local_guest_registration_mismatches_fail_collection(self):
        for change in (
            lambda r: r["ssh"]["host"]["guest_registry"]["ids"].update(
                {"101": {"node": NODE, "type": "qemu", "version": 1}}
            ),
            lambda r: r["ssh"]["host"]["guest_registry"]["ids"].clear(),
            lambda r: r["ssh"]["host"]["guest_registry"]["ids"]["100"].update(node="peer"),
            lambda r: r["ssh"]["host"]["guest_registry"]["ids"]["100"].update(type="lxc"),
        ):
            raw = inventory()
            change(raw)
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(proxmox.DiscoveryError, "authoritative local registrations"),
            ):
                self.collect(raw)

    def test_authoritative_registry_keeps_peers_without_querying_their_sources(self):
        raw = inventory()
        raw["ssh"]["host"]["guest_registry"]["ids"]["101"] = {
            "node": "peer",
            "type": "lxc",
            "version": 2,
        }
        raw["api"]["permissions"]["/vms"] = {}
        client = Client(raw)
        data = proxmox.collect(client)
        self.assertIs(data["observations"]["completeness"]["guests"], True)
        self.assertEqual(
            data["observations"]["host"]["sysfs"]["guest_registry"]["ids"]["101"]["node"], "peer"
        )
        self.assertFalse(
            any("/nodes/peer" in call[0] or "/vms/101" in call[0] for call in client.calls)
        )
        self.assertEqual(proxmox.reconstruct(data), data)

    def test_authoritative_registry_requires_bounded_native_typed_identities(self):
        invalid = (
            None,
            {},
            {"version": True},
            {"version": "1"},
            {"version": -1},
            {"version": 1, "ids": []},
            {"version": 1, "ids": {"0100": {"node": NODE, "type": "qemu", "version": 1}}},
            {"version": 1, "ids": {"100": {"node": "../peer", "type": "qemu", "version": 1}}},
            {"version": 1, "ids": {"100": {"node": NODE, "type": "other", "version": 1}}},
            {"version": 1, "ids": {"100": {"node": NODE, "type": "qemu", "version": True}}},
        )
        for registry in invalid:
            raw = inventory()
            raw["ssh"]["host"]["guest_registry"] = registry
            with self.subTest(registry=registry), self.assertRaises(proxmox.DiscoveryError):
                self.collect(raw)

    def test_reconstruction_requires_guest_local_registration_and_grant_proofs(self):
        data = self.collect()
        changes = (
            lambda i: i["guests"][0].update(node="peer"),
            lambda i: i["guests"][0]["summary"].update(vmid=101),
            lambda i: i["guests"][0]["status"].update(node="peer"),
            lambda i: i["api"]["qemu"].append(copy.deepcopy(i["api"]["qemu"][0])),
            lambda i: i["api"]["qemu"].clear(),
            lambda i: i["ssh"]["host"]["guest_registry"]["ids"]["100"].update(type="lxc"),
        )
        for change in changes:
            forged = copy.deepcopy(data)
            change(forged["source"]["inventory"])
            with self.subTest(change=change), self.assertRaises(proxmox.DiscoveryError):
                proxmox.reconstruct(forged)

    def test_optional_unknowns_do_not_replace_current_reported_values(self):
        data = self.collect()
        data["observations"]["guests"][0]["current_config"]["memory"] = 1
        data["observations"]["network"]["live_links"][0]["mtu"] = 1
        rebuilt = proxmox.reconstruct(data)
        self.assertEqual(rebuilt["interfaces"][0]["mtu"], 1500)
        self.assertEqual(rebuilt["observations"]["guests"][0]["current_config"]["memory"], 4096)

    def test_required_source_shapes_fail_with_safe_discovery_error(self):
        data = self.collect()
        changes = (
            lambda i: i["ssh"]["host"].update(dmi=None),
            lambda i: i["api"].update(version=None),
            lambda i: i["ssh"].update(links=[None]),
            lambda i: i["api"].update(storage=[None]),
            lambda i: i["ssh"]["host"].update(pci=[None]),
            lambda i: i["ssh"]["host"].update(net=[None]),
            lambda i: i["ssh"].update(hardware={"class": "system", "children": [None]}),
        )
        for change in changes:
            forged = copy.deepcopy(data)
            change(forged["source"]["inventory"])
            with self.subTest(change=change), self.assertRaises(proxmox.DiscoveryError):
                proxmox.reconstruct(forged)

    def test_controls_nonfinite_scalars_and_containers_are_rejected(self):
        changes = (
            lambda r: r["api"]["node_status"].update(cpu=float("nan")),
            lambda r: r["api"]["node_status"].update(cpu={"bad": 1}),
            lambda r: r["ssh"]["host"]["dmi"].update(product_serial="host\nserial"),
            lambda r: r["ssh"]["links"][0].update(mtu=[1500]),
        )
        for change in changes:
            raw = inventory()
            change(raw)
            with self.subTest(change=change), self.assertRaises(proxmox.DiscoveryError):
                self.collect(raw)

    def test_schema_and_contract_are_exact_and_bool_is_not_version(self):
        data = self.collect()
        for key, value in (("schema_version", True), ("schema_version", 2), ("adapter", "esxi")):
            forged = copy.deepcopy(data)
            forged[key] = value
            with self.assertRaises(proxmox.DiscoveryError):
                proxmox.reconstruct(forged)
        forged = copy.deepcopy(data)
        forged["source"]["contract"] = "unreviewed"
        with self.assertRaises(proxmox.DiscoveryError):
            proxmox.reconstruct(forged)

    def test_serial_placeholder_boundaries_and_typed_uuid_validation(self):
        self.assertEqual(proxmox.canonical_host_uuid(HOST_UUID.upper()), HOST_UUID)
        for value in (True, HOST_UUID.replace("-", ""), "ffffffff-ffff-ffff-ffff-ffffffffffff"):
            self.assertIsNone(proxmox.canonical_host_uuid(value))
        for value in ("unknown", "none", "default string", "0", "to be filled by o.e.m."):
            raw = inventory()
            raw["ssh"]["host"]["dmi"].update(product_serial=value, chassis_serial=value)
            raw["ssh"]["hardware"]["serial"] = value
            self.assertIsNone(self.collect(raw)["identity"]["serial"])

    def test_qemu_property_strings_retain_reviewed_allocation_and_device_options(self):
        raw = inventory()
        raw["guests"][0]["current_config"].update(
            cpu="host,flags=+aes;+pcid,unknown=SECRET",
            hostpci0="0000:03:00,pcie=1,password=SECRET",
            rootfs="local-lvm:vm-100-disk-1,size=8G,ro=0",
        )
        data = self.collect(raw)
        config = data["observations"]["guests"][0]["current_config"]
        self.assertEqual(config["cpu"], "host,flags=+aes;+pcid")
        self.assertEqual(config["hostpci0"], "0000:03:00,pcie=1")
        self.assertEqual(config["rootfs"], "local-lvm:vm-100-disk-1,size=8G,ro=0")
        self.assertNotIn("SECRET", repr(data))

    def test_custom_qemu_args_preserve_only_ambiguous_identity_presence(self):
        raw = inventory()
        raw["guests"][0]["config"]["args"] = "-uuid SECRET"
        raw["guests"][0]["current_config"]["args"] = "-smbios SECRET"
        raw["guests"][0]["pending"] = [
            {"key": "args", "value": "-uuid SECRET", "pending": "-smbios SECRET", "delete": 1}
        ]
        data = self.collect(raw)
        guest = data["observations"]["guests"][0]
        self.assertTrue(guest["config"]["args"])
        self.assertTrue(guest["current_config"]["args"])
        self.assertEqual(
            guest["pending"], [{"key": "args", "value": True, "pending": True, "delete": 1}]
        )
        self.assertNotIn("SECRET", repr(data))
        self.assertEqual(proxmox.reconstruct(data), data)

    def test_no_guest_agent_or_peer_reads_and_shared_lists_read_once(self):
        client = Client()
        proxmox.collect(client)
        self.assertFalse(any("/agent" in path or "/nodes/peer" in path for path, _ in client.calls))
        for path in (
            "/cluster/status",
            "/nodes/pve/qemu",
            "/nodes/pve/lxc",
            "hardware",
            "links",
            "host",
        ):
            self.assertEqual(sum(item[0] == path for item in client.calls), 1)


if __name__ == "__main__":
    unittest.main()
