"""Explicit PAN routing intent and shared static IPAM safety, without models."""

import json
import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from tests._loader import load
from tests.test_ipam_reconcile import apply_snapshot, inventory

parser = load("adapters.panos_ipam")
ha = load("adapters.panos_ha")
planner = load("reconcile_panos_ipam")
FIXTURES = Path(__file__).parent / "fixtures"


def raw_discovery(network=None, vsys=None):
    return {
        "adapter": "panos",
        "ipam": parser.parse_ipam_configuration(
            network or (FIXTURES / "panos_ipam_network.xml").read_text(),
            vsys or (FIXTURES / "panos_ipam_vsys.xml").read_text(),
        ),
        "observations": {
            "ha": {"runtime": ha.parse_ha_state((FIXTURES / "panos_ha_disabled.xml").read_text())}
        },
    }


def existing(discovery=None, *, vrf=False):
    observed = discovery or raw_discovery()
    before = inventory()
    before["interfaces"] = [
        {"id": "native-" + row["name"], "name": row["name"], "vrf_id": None}
        for row in observed["ipam"]["interfaces"]
    ]
    catalog = before["ipam_inventory"]
    catalog["namespaces"] = [
        {"id": "public", "name": "Public"},
        {"id": "private", "name": "Private"},
    ]
    target = (
        {
            "id": "chosen-vrf",
            "name": "Operator native name",
            "namespace_id": "private",
            "rd": "65000:77",
        }
        if vrf
        else None
    )
    catalog["vrfs"] = [deepcopy(target)] if target else []
    catalog["policy"].update(
        {
            "contract": "panos-ipam-policy-v1",
            "default_namespace": None,
            "panos_routing_domains": [
                {
                    "vsys": "vsys1",
                    "virtual_router": "vr-public",
                    "namespace": {"id": "public", "name": "Public"},
                    "vrf": None,
                },
                {
                    "vsys": "vsys2",
                    "virtual_router": "vr-internal",
                    "namespace": {"id": "private", "name": "Private"},
                    "vrf": deepcopy(target),
                },
            ],
        }
    )
    return before


def edit_network(mutator):
    root = ET.fromstring((FIXTURES / "panos_ipam_network.xml").read_text())
    mutator(root)
    return ET.tostring(root, encoding="unicode")


class PanosIpamReconcileTests(unittest.TestCase):
    def test_static_dual_stack_exact_native_interfaces_are_pure_and_idempotent(self):
        observed = raw_discovery()
        before = existing(observed)
        untouched = deepcopy((observed, before))
        first = planner.plan_panos_ipam(observed, before)
        self.assertFalse(first["errors"])
        self.assertFalse(first["unresolved"])
        self.assertEqual(first["adapter"], "panos")
        self.assertEqual(first["summary"]["ip_addresses_created"], 12)
        self.assertEqual(first["summary"]["prefixes_created"], 12)
        self.assertEqual(
            {row["namespace_id"] for row in first["ip_addresses"]}, {"public", "private"}
        )
        self.assertIn("ethernet1/1", [row["name"] for row in first["ip_assignments"]])
        self.assertEqual((observed, before), untouched)
        json.dumps(first)
        second = planner.plan_panos_ipam(observed, apply_snapshot(first, before))
        self.assertFalse(second["errors"])
        self.assertFalse(second["unresolved"])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_live_static_dual_stack_uses_existing_logical_interfaces(
        self,
    ):
        observed = raw_discovery(
            (FIXTURES / "panos_ipam_live_network.xml").read_text(),
            (FIXTURES / "panos_ipam_live_vsys.xml").read_text(),
        )
        before = existing(observed)
        before["ipam_inventory"]["policy"]["panos_routing_domains"] = [
            {
                "vsys": "vsys1",
                "virtual_router": "lab-vpn-vr",
                "namespace": {"id": "public", "name": "Public"},
                "vrf": None,
            }
        ]
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["unresolved"])
        self.assertEqual(plan["summary"]["ip_addresses_created"], 4)
        self.assertEqual(
            {row["name"] for row in plan["ip_assignments"]},
            {"ethernet1/1", "loopback.1", "tunnel.1"},
        )
        second = planner.plan_panos_ipam(observed, apply_snapshot(plan, before))
        self.assertFalse(second["errors"])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_shared_engine_is_called_with_exact_names_and_explicit_targets(self):
        observed = raw_discovery()
        with patch.object(planner, "plan_ipam", wraps=planner.plan_ipam) as shared:
            plan = planner.plan_panos_ipam(observed, existing(observed))
        self.assertFalse(plan["errors"])
        call = shared.call_args
        self.assertIs(call.kwargs["canonical_name"], planner.canonical_panos_ipam_name)
        self.assertEqual(call.kwargs["routing_targets"]["ethernet1/1"]["namespace"]["id"], "public")
        self.assertIsNone(call.kwargs["routing_targets"]["ethernet1/1"]["vrf"])
        self.assertEqual(call.args[0]["ipam"]["vrfs"], [])
        self.assertTrue(all(row["vrf"] is None for row in call.args[0]["ipam"]["interfaces"]))

    def test_private_addresses_use_explicit_mapping_without_cisco_rfc1918_override(self):
        observed = raw_discovery()
        plan = planner.plan_panos_ipam(observed, existing(observed))
        self.assertFalse(plan["errors"])
        loopback = next(row for row in plan["ip_addresses"] if row["host"] == "10.255.1.1")
        self.assertEqual(loopback["namespace_id"], "public")
        self.assertEqual({row["namespace_id"] for row in plan["prefixes"]}, {"public", "private"})

    def test_routing_labels_with_spaces_remain_exact_operator_bindings(self):
        network = (
            (FIXTURES / "panos_ipam_network.xml")
            .read_text()
            .replace("vr-public", "public routing domain")
        )
        vsys = (
            (FIXTURES / "panos_ipam_vsys.xml")
            .read_text()
            .replace("vr-public", "public routing domain")
            .replace("vsys1", "vsys with space")
        )
        observed = raw_discovery(network, vsys)
        before = existing(observed)
        binding = before["ipam_inventory"]["policy"]["panos_routing_domains"][0]
        binding.update(vsys="vsys with space", virtual_router="public routing domain")
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["unresolved"])
        self.assertEqual(plan["summary"]["ip_addresses_created"], 12)

    def test_explicit_existing_vrf_uses_uuid_and_preserves_canonical_rd(self):
        observed = raw_discovery()
        before = existing(observed, vrf=True)
        before["ipam_inventory"]["policy"]["group_user_vrfs"] = True
        first = planner.plan_panos_ipam(observed, before)
        self.assertFalse(first["errors"])
        self.assertEqual(first["summary"]["vrfs_created"], 0)
        self.assertEqual(first["summary"]["vrf_device_assignments_created"], 1)
        self.assertEqual(len(first["vrfs"]), 1)
        self.assertEqual(first["vrfs"][0]["id"], "chosen-vrf")
        self.assertEqual(first["vrfs"][0]["name"], "Operator native name")
        self.assertEqual(first["vrfs"][0]["rd"], "65000:77")
        self.assertEqual(first["vrfs"][0]["changes"], [])
        self.assertEqual(first["vrf_device_assignments"][0]["name"], "")
        self.assertIsNone(first["vrf_device_assignments"][0]["rd"])
        self.assertEqual(first["summary"]["interface_vrfs_updated"], 2)
        second = planner.plan_panos_ipam(observed, apply_snapshot(first, before))
        self.assertFalse(second["errors"])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_existing_device_assignment_name_and_rd_are_preserved_without_alias_matching(self):
        observed = raw_discovery()
        before = existing(observed, vrf=True)
        before["ipam_inventory"]["vrf_device_assignments"] = [
            {
                "id": "selected-assignment",
                "device_id": "device-1",
                "vrf_id": "chosen-vrf",
                "name": "Unrelated preserved alias",
                "rd": "65000:99",
            }
        ]
        plan = planner.plan_panos_ipam(observed, before)
        assignment = plan["vrf_device_assignments"][0]
        self.assertFalse(assignment["create"])
        self.assertEqual(assignment["id"], "selected-assignment")
        self.assertEqual(assignment["name"], "Unrelated preserved alias")
        self.assertEqual(assignment["rd"], "65000:99")
        self.assertEqual(assignment["changes"], [])

    def test_virtual_context_assignment_is_not_adopted_as_device_assignment(self):
        observed = raw_discovery()
        before = existing(observed, vrf=True)
        before["ipam_inventory"]["vrf_device_assignments"] = [
            {
                "id": "vdc-assignment",
                "device_id": None,
                "vrf_id": "chosen-vrf",
                "virtual_device_context_id": "other-context",
                "name": "vr-internal",
                "rd": None,
            }
        ]
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertTrue(plan["vrf_device_assignments"][0]["create"])
        self.assertIsNone(plan["vrf_device_assignments"][0]["id"])

    def test_duplicate_device_assignments_keep_target_routing_scope_unresolved(self):
        observed = raw_discovery()
        before = existing(observed, vrf=True)
        before["ipam_inventory"]["vrf_device_assignments"] = [
            {
                "id": identity,
                "device_id": "device-1",
                "vrf_id": "chosen-vrf",
                "name": name,
                "rd": None,
            }
            for identity, name in (("a1", "first"), ("a2", "second"))
        ]
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["vrf_device_assignments"])
        self.assertNotIn("10.100.0.1", [row["host"] for row in plan["ip_addresses"]])
        self.assertTrue(
            any(
                "Several existing Device assignments" in row["reason"] for row in plan["unresolved"]
            )
        )

    def test_missing_or_duplicate_mappings_never_fall_back_to_default_namespace(self):
        observed = raw_discovery()
        before = existing(observed)
        policy = before["ipam_inventory"]["policy"]
        policy["default_namespace"] = {"id": "public", "name": "Public"}
        policy["panos_routing_domains"] = []
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["ip_addresses_created"], 0)
        self.assertEqual(plan["summary"]["prefixes_created"], 0)
        self.assertTrue(plan["unresolved"])
        before = existing(observed)
        policy = before["ipam_inventory"]["policy"]
        policy["panos_routing_domains"].append(deepcopy(policy["panos_routing_domains"][0]))
        self.assertTrue(planner.plan_panos_ipam(observed, before)["errors"])

    def test_mapping_requires_explicit_global_or_matching_existing_vrf_namespace(self):
        observed = raw_discovery()
        for mutate in (
            lambda p: p[0].pop("vrf"),
            lambda p: p[0]["namespace"].update(id="missing-namespace"),
            lambda p: p[1].update(vrf={"id": "missing-vrf"}),
            lambda p: p[0].update(vrf={"id": "chosen-vrf"}),
        ):
            before = existing(observed, vrf=True)
            mutate(before["ipam_inventory"]["policy"]["panos_routing_domains"])
            plan = planner.plan_panos_ipam(observed, before)
            self.assertTrue(plan["errors"])
            self.assertFalse(plan["prefixes"])

    def test_missing_logical_interface_remains_unresolved_without_guessed_create(self):
        observed = raw_discovery()
        before = existing(observed)
        before["interfaces"] = [row for row in before["interfaces"] if row["name"] != "loopback.1"]
        proposed = {"interface_creates": [{"name": "loopback.1", "enabled": None}]}
        plan = planner.plan_panos_ipam(observed, before, proposed)
        self.assertFalse(plan["errors"])
        self.assertNotIn("10.255.1.1", [row["host"] for row in plan["ip_addresses"]])
        self.assertTrue(any(row.get("name") == "loopback.1" for row in plan["unresolved"]))

    def test_approved_ethernet_create_is_reused_by_the_shared_engine(self):
        observed = raw_discovery()
        before = existing(observed)
        before["interfaces"] = [row for row in before["interfaces"] if row["name"] != "ethernet1/1"]
        plan = planner.plan_panos_ipam(
            observed, before, {"interface_creates": [{"name": "ethernet1/1"}]}
        )
        self.assertFalse(plan["errors"])
        self.assertIn("192.0.2.1", [row["host"] for row in plan["ip_addresses"]])
        assignment = next(row for row in plan["ip_assignments"] if row["name"] == "ethernet1/1")
        self.assertIsNone(assignment["interface_id"])

    def test_ha_enabled_or_unknown_blocks_ipam_only(self):
        for mode in ("enabled", "unknown", "tampered-disabled"):
            observed = raw_discovery()
            if mode == "enabled":
                observed["observations"]["ha"]["configuration"] = {"enabled": True}
            elif mode == "unknown":
                observed["observations"]["ha"] = {}
            else:
                observed["observations"]["ha"]["runtime"]["source"]["command"] = "unreviewed"
            preserved = deepcopy(observed)
            plan = planner.plan_panos_ipam(observed, existing(observed, vrf=True))
            self.assertFalse(plan["errors"])
            self.assertFalse(plan["vrf_device_assignments"])
            self.assertFalse(plan["prefixes"])
            self.assertFalse(plan["ip_addresses"])
            self.assertEqual(observed, preserved)

    def test_dynamic_and_unknown_dhcp_defer_ipv4_without_inventing_a_prefix(self):
        for enabled in (None, "yes"):

            def mutate(root, enabled=enabled):
                body = root.find("result/network/interface/ethernet/entry/layer3")
                branch = ET.SubElement(body, "dhcp-client")
                if enabled is not None:
                    ET.SubElement(branch, "enable").text = enabled

            observed = raw_discovery(edit_network(mutate))
            plan = planner.plan_panos_ipam(observed, existing(observed))
            self.assertFalse(plan["errors"])
            self.assertNotIn("192.0.2.1", [row["host"] for row in plan["ip_addresses"]])
            self.assertNotIn("192.0.2.0/24", [row["prefix"] for row in plan["prefixes"]])
            self.assertIn("2001:db8:1::1", [row["host"] for row in plan["ip_addresses"]])

    def test_ipv6_unknown_enable_and_generated_or_anycast_markers_remain_observations(self):
        for flag in ("interface-unknown", "address-unknown", "prefix", "anycast"):

            def mutate(root, flag=flag):
                body = root.find("result/network/interface/ethernet/entry/layer3/ipv6")
                address = body.find("address/entry")
                if flag == "interface-unknown":
                    body.remove(body.find("enabled"))
                elif flag == "address-unknown":
                    address.remove(address.find("enable-on-interface"))
                else:
                    ET.SubElement(address, flag)

            observed = raw_discovery(edit_network(mutate))
            plan = planner.plan_panos_ipam(observed, existing(observed))
            self.assertFalse(plan["errors"])
            self.assertNotIn("2001:db8:1::1", [row["host"] for row in plan["ip_addresses"]])
            self.assertNotIn("2001:db8:1::/64", [row["prefix"] for row in plan["prefixes"]])
            self.assertIn("192.0.2.1", [row["host"] for row in plan["ip_addresses"]])

    def test_vpn_selectors_and_management_observations_are_not_connected_networks(self):
        observed = raw_discovery()
        observed["observations"]["vpn"] = {"selectors": [{"local": "198.18.9.0/24"}]}
        observed["observations"]["management"] = {"address": "198.18.10.1/24"}
        plan = planner.plan_panos_ipam(observed, existing(observed))
        self.assertFalse(plan["errors"])
        self.assertNotIn("198.18.9.0/24", [row["prefix"] for row in plan["prefixes"]])
        self.assertNotIn("198.18.10.0/24", [row["prefix"] for row in plan["prefixes"]])

    def test_tampered_address_or_routing_provenance_blocks_whole_ipam_plan(self):
        for mutate in (
            lambda r: r["ipv4"][0].update(host="192.0.2.9"),
            lambda r: r["ipv4"][0].update(network="192.0.3.0/24"),
            lambda r: r["ipv4"][0]["source"].update(command="show system info"),
            lambda r: r["source"].update(mode="layer3", path="unsupported"),
            lambda r: r["source"]["vr_membership"].update(router="another"),
            lambda r: r["source"]["vsys_import"].update(vsys="another"),
            lambda r: r["ipv6"][0]["source"].update(fields=None),
            lambda r: r["addressing"]["ipv4_dhcp"]["source"].update(path="unsupported"),
        ):
            observed = raw_discovery()
            before = existing(observed)
            mutate(observed["ipam"]["interfaces"][0])
            plan = planner.plan_panos_ipam(observed, before)
            self.assertTrue(plan["errors"])
            self.assertFalse(plan["prefixes"])
            self.assertFalse(plan["vrf_device_assignments"])

    def test_native_feature_failure_reason_is_preserved_without_ipam_proposals(self):
        observed = raw_discovery()
        before = existing(observed)
        before["ipam_inventory"] = {
            "supported": False,
            "reason": "Reviewed native field unavailable",
        }
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["prefixes"])
        self.assertEqual(
            {row["reason"] for row in plan["unresolved"]}, {"Reviewed native field unavailable"}
        )

    def test_populated_interface_vrf_is_preserved(self):
        observed = raw_discovery()
        before = existing(observed, vrf=True)
        before["interfaces"][1]["vrf_id"] = "other-native-vrf"
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertTrue(any(row["field"] == "vrf_id" for row in plan["conflicts"]))
        self.assertNotIn("10.100.0.1", [row["host"] for row in plan["ip_addresses"]])

    def test_foreign_ip_assignment_is_not_stolen(self):
        observed = raw_discovery()
        before = existing(observed)
        after = apply_snapshot(planner.plan_panos_ipam(observed, before), before)
        assignment = next(
            row
            for row in after["ipam_inventory"]["ip_assignments"]
            if row["interface_id"] == "native-ethernet1/1"
        )
        foreign_ip = assignment["ip_address_id"]
        assignment["interface_id"] = "foreign-interface"
        assignment["interface_device_id"] = "foreign-device"
        plan = planner.plan_panos_ipam(observed, after)
        self.assertFalse(plan["errors"])
        self.assertNotIn(foreign_ip, [row["id"] for row in plan["ip_addresses"]])
        self.assertTrue(any("assigned elsewhere" in row["reason"] for row in plan["unresolved"]))

    def test_unknown_secondary_order_does_not_change_existing_assignment_flag(self):
        observed = raw_discovery()
        before = existing(observed)
        after = apply_snapshot(planner.plan_panos_ipam(observed, before), before)
        for assignment in after["ipam_inventory"]["ip_assignments"]:
            assignment["is_secondary"] = True
        plan = planner.plan_panos_ipam(observed, after)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["conflicts"])
        self.assertFalse(plan["ip_assignments"])

    def test_exact_panos_names_do_not_adopt_cisco_aliases_or_case_variants(self):
        observed = raw_discovery()
        for populated_name in ("Ethernet1/1", "ethernet1/1 ", " ethernet1/1"):
            with self.subTest(name=populated_name):
                before = existing(observed)
                before["interfaces"][0]["name"] = populated_name
                plan = planner.plan_panos_ipam(observed, before)
                self.assertNotIn("192.0.2.1", [row["host"] for row in plan["ip_addresses"]])
        self.assertEqual(planner.canonical_panos_ipam_name("Lo1"), "Lo1")
        self.assertIsNone(planner.canonical_panos_ipam_name("ethernet1/1 "))

    def test_malformed_catalog_members_or_provenance_block_whole_ipam_plan(self):
        for mutate in (
            lambda r: r["routers"][0].update(interfaces="ethernet1/1"),
            lambda r: r["routers"][0].update(interfaces=["ethernet1/1", 1]),
            lambda r: r["routers"][0]["interfaces"].append("ethernet1/1"),
            lambda r: r["routers"][1]["interfaces"].append("ethernet1/1"),
            lambda r: r["vsys"][0].update(imported_interfaces="ethernet1/1"),
            lambda r: r["vsys"][1]["imported_interfaces"].append("ethernet1/1"),
            lambda r: r["vsys"][1]["imported_virtual_routers"].append("vr-public"),
            lambda r: r["vsys"][0]["imported_virtual_routers"].append("missing-router"),
            lambda r: r["routers"][0]["source"].update(command="show system info"),
            lambda r: r["vsys"][0]["source"].update(configured_name="another"),
            lambda r: r["routers"][0]["source"]["fields"]["interfaces"].update(presence="absent"),
            lambda r: r["vsys"][0]["source"]["fields"]["imported_interfaces"].update(
                path="unsupported"
            ),
            lambda r: r["routers"][0]["source"]["vsys_import"].update(vsys="vsys2"),
            lambda r: r["routers"][0].update(vsys="vsys2"),
            lambda r: r["interfaces"][0].update(virtual_router=None),
        ):
            observed = raw_discovery()
            before = existing(observed)
            mutate(observed["ipam"])
            plan = planner.plan_panos_ipam(observed, before)
            self.assertTrue(plan["errors"])
            self.assertFalse(plan["prefixes"])
            self.assertFalse(plan["ip_addresses"])
            self.assertFalse(plan["vrf_device_assignments"])

    def test_independently_valid_but_conflicting_router_and_interface_imports_reject(self):
        observed = raw_discovery()
        before = existing(observed)
        raw = observed["ipam"]
        raw["vsys"][0]["imported_virtual_routers"].remove("vr-public")
        raw["vsys"][1]["imported_virtual_routers"].append("vr-public")
        raw["routers"][0]["vsys"] = "vsys2"
        raw["routers"][0]["source"]["vsys_import"]["vsys"] = "vsys2"
        plan = planner.plan_panos_ipam(observed, before)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["ip_addresses"])

    def test_unknown_source_interface_family_cannot_promote_a_native_alias(self):
        network = (FIXTURES / "panos_ipam_network.xml").read_text().replace("ethernet1/1", "Gi0/0")
        vsys = (FIXTURES / "panos_ipam_vsys.xml").read_text().replace("ethernet1/1", "Gi0/0")
        observed = raw_discovery(network, vsys)
        before = existing(observed)
        before["interfaces"].append({"id": "native-fake", "name": "Gi0/0", "vrf_id": None})
        plan = planner.plan_panos_ipam(observed, before)
        self.assertFalse(plan["errors"])
        self.assertNotIn("192.0.2.1", [row["host"] for row in plan["ip_addresses"]])
        self.assertTrue(plan["unresolved"])


if __name__ == "__main__":
    unittest.main()
