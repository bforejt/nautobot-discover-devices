"""Namespace policy, device-local VRF identity and hierarchy safety regressions."""

import json
import unittest
from copy import deepcopy
from ipaddress import IPv4Network

from tests._loader import load

planner = load("reconcile_ipam")


def address(host="10.40.12.1", length=24, secondary=False):
    return {
        "address": host,
        "mask": str(IPv4Network("0.0.0.0/%s" % length).netmask),
        "prefix_length": length,
        "secondary": secondary,
        "method": "configured-static",
    }


def fact(name="Gi0/0", vrf=None, addresses=None):
    return {"name": name, "vrf": vrf, "ipv4": addresses or [], "source": {"method": "restconf"}}


def vrf(name="Mgmt-vrf", rd=None):
    return {"name": name, "rd": rd, "address_families": ["ipv4"], "source": {}}


def discovery(*interfaces, vrfs=None):
    return {
        "ipam": {
            "schema_version": 1,
            "interfaces": list(interfaces),
            "vrfs": vrfs or [],
            "unresolved": [],
            "sources": [],
        }
    }


def inventory():
    return {
        "interfaces": [{"id": "int-1", "name": "Gi0/0", "vrf_id": None}],
        "ipam_inventory": {
            "supported": True,
            "device": {"id": "device-1", "name": "switch-A", "location_id": "site-1"},
            "policy": {
                "default_namespace": {"id": "internet", "name": "Internet"},
                "override_namespace": {"id": "corporate", "name": "Corporate"},
                "override_rfc1918": True,
                "override_networks": [],
                "create_missing_prefixes": True,
                "group_user_vrfs": False,
                "local_vrf_names": ["Mgmt-vrf"],
                "location": {"id": "site-1", "name": "Lab"},
            },
            "vrfs": [],
            "vrf_device_assignments": [],
            "prefixes": [],
            "ip_addresses": [],
            "ip_assignments": [],
            "ip_ranges": [],
        },
    }


def prefix(value="10.40.12.0/24", **values):
    return {
        "id": "prefix-1",
        "prefix": value,
        "namespace_id": "corporate",
        "type": "network",
        "parent_id": None,
        "location_ids": [],
        "vrf_ids": [],
        **values,
    }


def ip(host="10.40.12.1", **values):
    return {
        "id": "ip-1",
        "host": host,
        "mask_length": 24,
        "namespace_id": "corporate",
        "parent_id": "prefix-1",
        "type": "host",
        **values,
    }


def assignment(**values):
    return {
        "id": "ip-assignment-1",
        "ip_address_id": "ip-1",
        "interface_id": "int-1",
        "interface_device_id": "device-1",
        **values,
    }


def existing_vrf(name="operator-name", **values):
    return {"id": "vrf-1", "name": name, "namespace_id": "corporate", "rd": None, **values}


def device_vrf(name="Mgmt-vrf", **values):
    return {
        "id": "device-vrf-1",
        "device_id": "device-1",
        "vrf_id": "vrf-1",
        "name": name,
        "rd": None,
        **values,
    }


def apply_snapshot(plan, before):
    """Apply the dependency contract to a copy, sufficient for idempotence."""
    after = deepcopy(before)
    catalog = after["ipam_inventory"]
    refs = {}
    for spec in plan["vrfs"]:
        refs[spec["key"]] = spec["id"] or "created-" + spec["key"]
        if spec["create"]:
            catalog["vrfs"].append(
                {
                    "id": refs[spec["key"]],
                    "name": spec["name"],
                    "namespace_id": spec["namespace_id"],
                    "rd": spec["rd"],
                }
            )
    for spec in plan["vrf_device_assignments"]:
        if spec["create"]:
            catalog["vrf_device_assignments"].append(
                {
                    "id": "created-" + spec["key"],
                    "device_id": spec["device_id"],
                    "vrf_id": refs[spec["vrf_key"]],
                    "name": spec["name"],
                    "rd": spec["rd"],
                }
            )
        else:
            existing = next(
                row for row in catalog["vrf_device_assignments"] if row["id"] == spec["id"]
            )
            for change in spec["changes"]:
                existing[change["field"]] = change["after"]
    for spec in plan["interface_vrfs"]:
        row = next(row for row in after["interfaces"] if row["id"] == spec["id"])
        row["vrf_id"] = refs[spec["vrf_key"]]
    for spec in plan["prefixes"]:
        refs[spec["key"]] = spec["id"] or "created-" + spec["key"]
    for spec in plan["prefixes"]:
        if spec["create"]:
            catalog["prefixes"].append(
                {
                    "id": refs[spec["key"]],
                    "prefix": spec["prefix"],
                    "namespace_id": spec["namespace_id"],
                    "type": spec["type"],
                    "parent_id": refs.get(spec["parent_key"]) or spec["parent_id"],
                    "location_ids": [spec["location_id"]] if spec["location_id"] else [],
                    "vrf_ids": [refs[value] for value in spec["add_vrf_keys"]],
                }
            )
        else:
            row = next(row for row in catalog["prefixes"] if row["id"] == spec["id"])
            row["vrf_ids"].extend(refs[value] for value in spec["add_vrf_keys"])
    for spec in plan["ip_addresses"]:
        refs[spec["key"]] = spec["id"] or "created-" + spec["key"]
        if spec["create"]:
            catalog["ip_addresses"].append(
                {
                    "id": refs[spec["key"]],
                    "host": spec["host"],
                    "mask_length": spec["mask_length"],
                    "namespace_id": spec["namespace_id"],
                    "parent_id": refs[spec["parent_key"]],
                    "type": "host",
                }
            )
    for spec in plan["ip_assignments"]:
        catalog["ip_assignments"].append(
            {
                "id": "created-" + spec["key"],
                "ip_address_id": refs[spec["ip_key"]],
                "interface_id": spec["interface_id"],
                "interface_device_id": "device-1",
                "is_secondary": spec["is_secondary"],
            }
        )
    return after


class IPAMReconciliationTests(unittest.TestCase):
    def test_static_prefix_ip_interface_assignment_are_idempotent_and_pure(self):
        before = inventory()
        original = deepcopy(before)
        observed = discovery(fact(addresses=[address()]))
        first = planner.plan_ipam(observed, before)
        self.assertFalse(first["errors"])
        self.assertFalse(first["unresolved"])
        self.assertEqual(first["prefixes"][0]["prefix"], "10.40.12.0/24")
        self.assertEqual(first["prefixes"][0]["location_id"], "site-1")
        self.assertEqual(first["ip_assignments"][0]["interface_id"], "int-1")
        self.assertEqual(before, original)
        json.dumps(first)
        second = planner.plan_ipam(observed, apply_snapshot(first, before))
        self.assertFalse(second["errors"])
        self.assertFalse(second["unresolved"])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_single_namespace_ignores_unselected_override_checkbox(self):
        before = inventory()
        before["ipam_inventory"]["policy"]["override_namespace"] = None
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["ip_addresses"][0]["namespace_id"], "internet")

    def test_rfc1918_is_exact_and_manual_overrides_are_unioned(self):
        before = inventory()
        before["ipam_inventory"]["policy"]["override_networks"] = ["100.64.0.0/10", "198.18.0.0/15"]
        for host, expected in (
            ("10.0.0.1", "corporate"),
            ("172.16.0.1", "corporate"),
            ("172.31.255.1", "corporate"),
            ("192.168.1.1", "corporate"),
            ("172.32.0.1", "internet"),
            ("100.64.1.1", "corporate"),
            ("198.18.0.1", "corporate"),
            ("169.254.1.1", "internet"),
            ("203.0.113.1", "internet"),
        ):
            with self.subTest(host=host):
                plan = planner.plan_ipam(discovery(fact(addresses=[address(host)])), before)
                self.assertEqual(plan["ip_addresses"][0]["namespace_id"], expected)

    def test_unchecking_rfc1918_only_uses_manual_networks(self):
        before = inventory()
        policy = before["ipam_inventory"]["policy"]
        policy["override_rfc1918"] = False
        policy["override_networks"] = ["10.40.0.0/16"]
        for host, expected in (("10.40.12.1", "corporate"), ("10.50.12.1", "internet")):
            plan = planner.plan_ipam(discovery(fact(addresses=[address(host)])), before)
            self.assertEqual(plan["ip_addresses"][0]["namespace_id"], expected)

    def test_entire_connected_network_must_resolve_to_one_namespace(self):
        before = inventory()
        policy = before["ipam_inventory"]["policy"]
        policy["override_rfc1918"] = False
        policy["override_networks"] = ["10.40.12.0/25"]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["prefixes"])
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("boundaries", plan["unresolved"][0]["reason"])
        policy["override_networks"].append("10.40.12.128/25")
        complete = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertEqual(complete["prefixes"][0]["namespace_id"], "corporate")

    def test_same_namespace_selectors_cannot_produce_policy_boundary_conflict(self):
        before = inventory()
        policy = before["ipam_inventory"]["policy"]
        policy["override_namespace"] = policy["default_namespace"]
        policy["override_networks"] = ["203.0.113.0/25"]
        plan = planner.plan_ipam(discovery(fact(addresses=[address("203.0.113.1")])), before)
        self.assertFalse(plan["unresolved"])

    def test_report_only_without_namespace_has_zero_mutations(self):
        before = inventory()
        before["ipam_inventory"]["policy"] = None
        plan = planner.plan_ipam(
            discovery(fact(vrf="Mgmt-vrf", addresses=[address()]), vrfs=[vrf()]), before
        )
        self.assertTrue(plan["settings"])
        self.assertTrue(plan["unresolved"])
        self.assertTrue(all(not plan[key] for key in planner.COLLECTIONS))

    def test_invalid_masks_duplicate_aliases_and_unreported_vrf_are_errors(self):
        cases = []
        missing = address()
        missing.pop("mask")
        cases.append(discovery(fact(addresses=[missing])))
        wrong = address()
        wrong["prefix_length"] = 25
        cases.append(discovery(fact(addresses=[wrong])))
        cases.append(discovery(fact("Gi0/0"), fact("GigabitEthernet0/0")))
        cases.append(discovery(fact(vrf="missing")))
        cases.append(discovery(fact(addresses=[address(), address()])))
        for observed in cases:
            with self.subTest(observed=observed):
                plan = planner.plan_ipam(observed, inventory())
                self.assertTrue(plan["errors"])
                self.assertTrue(all(not plan[key] for key in planner.COLLECTIONS))

    def test_secondary_masks_and_shut_interfaces_need_no_operational_evidence(self):
        plan = planner.plan_ipam(
            discovery(
                fact(
                    addresses=[
                        address(),
                        address("10.50.1.1", length=30, secondary=True),
                    ]
                )
            ),
            inventory(),
        )
        self.assertEqual(plan["summary"]["prefixes_created"], 2)
        self.assertEqual([row["is_secondary"] for row in plan["ip_assignments"]], [False, True])

    def test_management_vrf_is_device_local_and_rd_only_on_assignment(self):
        before = inventory()
        observed = discovery(fact(vrf="Mgmt-vrf", addresses=[address()]), vrfs=[vrf(rd="65000:10")])
        first = planner.plan_ipam(observed, before)
        self.assertEqual(first["vrfs"][0]["name"], "switch-A / Mgmt-vrf")
        self.assertIsNone(first["vrfs"][0]["rd"])
        self.assertEqual(first["vrf_device_assignments"][0]["name"], "Mgmt-vrf")
        self.assertEqual(first["vrf_device_assignments"][0]["rd"], "65000:10")
        self.assertEqual(first["interface_vrfs"][0]["id"], "int-1")
        after = apply_snapshot(first, before)
        after["ipam_inventory"]["device"]["name"] = "renamed-switch"
        repeat = planner.plan_ipam(observed, after)
        self.assertEqual(repeat["vrfs"][0]["name"], "switch-A / Mgmt-vrf")
        self.assertTrue(all(value == 0 for value in repeat["summary"].values()))

    def test_unused_named_vrf_is_added_and_management_is_never_shared_by_default(self):
        before = inventory()
        before["ipam_inventory"]["policy"]["group_user_vrfs"] = True
        plan = planner.plan_ipam(discovery(vrfs=[vrf(), vrf("CORP")]), before)
        self.assertEqual({row["name"] for row in plan["vrfs"]}, {"switch-A / Mgmt-vrf", "CORP"})
        self.assertEqual(plan["summary"]["vrf_device_assignments_created"], 2)

    def test_user_vrf_grouping_is_opt_in_and_reuses_namespace_plus_name(self):
        before = inventory()
        observed = discovery(vrfs=[vrf("CORP", rd="65000:2")])
        local = planner.plan_ipam(observed, before)
        self.assertEqual(local["vrfs"][0]["name"], "switch-A / CORP")
        before["ipam_inventory"]["policy"]["group_user_vrfs"] = True
        before["ipam_inventory"]["vrfs"] = [existing_vrf("CORP", namespace_id="internet")]
        shared = planner.plan_ipam(observed, before)
        self.assertFalse(shared["vrfs"][0]["create"])
        self.assertEqual(shared["vrfs"][0]["id"], "vrf-1")
        self.assertEqual(shared["vrf_device_assignments"][0]["rd"], "65000:2")

    def test_local_name_collision_cannot_hijack_an_unassigned_vrf(self):
        before = inventory()
        before["ipam_inventory"]["vrfs"] = [
            existing_vrf("switch-A / Mgmt-vrf", namespace_id="internet")
        ]
        plan = planner.plan_ipam(discovery(vrfs=[vrf()]), before)
        self.assertFalse(plan["vrfs"])
        self.assertIn("collides", plan["unresolved"][0]["reason"])

    def test_existing_assignment_wins_over_name_policy_and_preserves_rd_conflict(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["vrfs"] = [existing_vrf("operator-name")]
        catalog["vrf_device_assignments"] = [device_vrf(rd="65000:1")]
        before["interfaces"][0]["vrf_id"] = "vrf-1"
        plan = planner.plan_ipam(
            discovery(fact(vrf="Mgmt-vrf", addresses=[address()]), vrfs=[vrf(rd="65000:2")]), before
        )
        self.assertEqual(plan["vrfs"][0]["name"], "operator-name")
        self.assertFalse(plan["vrfs"][0]["create"])
        self.assertFalse(plan["vrf_device_assignments"][0]["changes"])
        self.assertEqual(plan["conflicts"][0]["field"], "rd")
        self.assertTrue(plan["ip_addresses"])

    def test_assignment_namespace_conflict_and_duplicate_local_names_defer(self):
        for values in (
            {
                "vrfs": [existing_vrf(namespace_id="internet")],
                "vrf_device_assignments": [device_vrf()],
            },
            {
                "vrfs": [existing_vrf()],
                "vrf_device_assignments": [device_vrf(), device_vrf(id="assignment-2")],
            },
        ):
            before = inventory()
            before["ipam_inventory"].update(values)
            plan = planner.plan_ipam(
                discovery(fact(vrf="Mgmt-vrf", addresses=[address()]), vrfs=[vrf()]), before
            )
            self.assertFalse(plan["vrfs"])
            self.assertFalse(plan["ip_addresses"])
            self.assertTrue(plan["unresolved"])

    def test_one_named_vrf_cannot_be_split_between_selected_namespaces(self):
        before = inventory()
        plan = planner.plan_ipam(
            discovery(
                fact(
                    vrf="CORP",
                    addresses=[
                        address(),
                        address("203.0.113.1"),
                    ],
                ),
                vrfs=[vrf("CORP")],
            ),
            before,
        )
        self.assertTrue(all(not plan[key] for key in planner.COLLECTIONS))
        self.assertIn("cannot span", plan["unresolved"][0]["reason"])

    def test_existing_populated_interface_vrf_is_preserved(self):
        before = inventory()
        before["interfaces"][0]["vrf_id"] = "operator-vrf"
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["ip_addresses"])
        self.assertFalse(plan["prefixes"])
        self.assertEqual(plan["conflicts"][0]["field"], "vrf_id")

    def test_existing_location_type_and_address_mask_conflicts_are_preserved(self):
        for record in (
            prefix(location_ids=["another-site"]),
            prefix(type="container"),
        ):
            before = inventory()
            before["ipam_inventory"]["prefixes"] = [record]
            plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
            self.assertFalse(plan["prefixes"])
            self.assertFalse(plan["ip_addresses"])
        before = inventory()
        before["ipam_inventory"]["prefixes"] = [prefix()]
        before["ipam_inventory"]["ip_addresses"] = [ip(mask_length=25)]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["ip_addresses"])
        self.assertEqual(plan["conflicts"][0]["field"], "mask_length")

    def test_existing_foreign_assignments_and_duplicate_discovered_hosts_do_not_share(self):
        before = inventory()
        before["ipam_inventory"]["prefixes"] = [prefix()]
        before["ipam_inventory"]["ip_addresses"] = [ip()]
        before["ipam_inventory"]["ip_assignments"] = [assignment(interface_id="foreign-int")]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["ip_assignments"])
        self.assertFalse(plan["ip_addresses"])
        before = inventory()
        before["interfaces"].append({"id": "int-2", "name": "Vlan10", "vrf_id": None})
        plan = planner.plan_ipam(
            discovery(fact(addresses=[address()]), fact("Vlan10", addresses=[address()])), before
        )
        self.assertFalse(plan["ip_assignments"])
        self.assertFalse(plan["ip_addresses"])

    def test_existing_target_host_in_other_namespace_is_not_duplicated(self):
        before = inventory()
        before["ipam_inventory"]["ip_addresses"] = [ip(namespace_id="internet")]
        before["ipam_inventory"]["ip_assignments"] = [assignment()]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["prefixes"])
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("namespaces", plan["unresolved"][0]["reason"])

    def test_optional_network_creation_disabled_defers_address(self):
        before = inventory()
        before["ipam_inventory"]["policy"]["create_missing_prefixes"] = False
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["prefixes"])
        self.assertFalse(plan["ip_addresses"])

    def test_new_interface_dependency_uses_alias_join_without_id(self):
        before = inventory()
        before["interfaces"] = []
        plan = planner.plan_ipam(
            discovery(fact(addresses=[address()])),
            before,
            {"interface_creates": [{"name": "GigabitEthernet0/0"}]},
        )
        self.assertIsNone(plan["ip_assignments"][0]["interface_id"])
        self.assertEqual(plan["ip_assignments"][0]["name"], "GigabitEthernet0/0")

    def test_ipv6_inventory_is_preserved_and_does_not_block_ipv4_global_assignment(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [prefix("2001:db8::/64", namespace_id="internet")]
        catalog["ip_addresses"] = [ip("2001:db8::1", mask_length=64, namespace_id="internet")]
        catalog["ip_ranges"] = [
            {
                "id": "range-6",
                "namespace_id": "internet",
                "start_address": "2001:db8::10",
                "end_address": "2001:db8::20",
                "parent_id": "prefix-1",
            }
        ]
        catalog["ip_assignments"] = [assignment()]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["ip_addresses_created"], 1)

    def test_new_prefix_reports_reparenting_without_changing_routing_semantics(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [prefix("10.40.0.0/16", id="aggregate", type="container")]
        catalog["ip_addresses"] = [ip("10.40.12.2", parent_id="aggregate")]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertEqual(plan["prefixes"][0]["affected_ip_ids"], ["ip-1"])
        self.assertEqual(plan["prefixes"][0]["parent_id"], "aggregate")

    def test_new_prefix_cannot_change_unrelated_ip_inherited_vrf_associations(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [
            prefix("10.40.0.0/16", id="aggregate", type="container", vrf_ids=["vrf-1"])
        ]
        catalog["ip_addresses"] = [ip("10.40.12.2", parent_id="aggregate")]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["prefixes"])
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("inherited VRF", plan["unresolved"][0]["reason"])

    def test_existing_prefix_vrf_addition_cannot_change_child_ip_associations(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [prefix()]
        catalog["ip_addresses"] = [ip("10.40.12.2")]
        plan = planner.plan_ipam(
            discovery(fact(vrf="CORP", addresses=[address()]), vrfs=[vrf("CORP")]), before
        )
        self.assertFalse(plan["prefixes"])
        self.assertIn(
            "inherited VRF",
            next(row["reason"] for row in plan["unresolved"] if row["scope"] == "prefix"),
        )

    def test_closest_child_prefix_controls_actual_ip_parent_and_vrf(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["vrfs"] = [existing_vrf()]
        catalog["vrf_device_assignments"] = [device_vrf("CORP")]
        before["interfaces"][0]["vrf_id"] = "vrf-1"
        catalog["prefixes"] = [prefix("10.40.12.0/25", id="child", vrf_ids=[])]
        catalog["ip_addresses"] = [ip("10.40.12.2", parent_id="child")]
        plan = planner.plan_ipam(
            discovery(fact(vrf="CORP", addresses=[address()]), vrfs=[vrf("CORP")]), before
        )
        connected = next(row for row in plan["prefixes"] if row["create"])
        self.assertEqual(connected["affected_prefix_ids"], ["child"])
        self.assertFalse(connected["affected_ip_ids"])
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("Closest actual parent", plan["unresolved"][-1]["reason"])
        catalog["prefixes"][0]["vrf_ids"] = ["vrf-1"]
        valid = planner.plan_ipam(
            discovery(fact(vrf="CORP", addresses=[address()]), vrfs=[vrf("CORP")]), before
        )
        self.assertEqual(valid["ip_addresses"][0]["parent_key"], "prefix-existing:child")

    def test_global_address_cannot_inherit_named_vrf_from_closest_child(self):
        before = inventory()
        before["ipam_inventory"]["prefixes"] = [prefix("10.40.12.0/25", vrf_ids=["vrf-1"])]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("Global routing context", plan["unresolved"][-1]["reason"])

    def test_interface_vrf_fill_cannot_change_existing_ip_routing_context(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [prefix()]
        catalog["ip_addresses"] = [ip()]
        catalog["ip_assignments"] = [assignment()]
        plan = planner.plan_ipam(
            discovery(fact(vrf="CORP", addresses=[address()]), vrfs=[vrf("CORP")]), before
        )
        self.assertFalse(plan["interface_vrfs"])
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("existing IP routing", plan["unresolved"][0]["reason"])

    def test_nested_new_connected_prefixes_resolve_nearest_staged_parent(self):
        before = inventory()
        before["interfaces"].append({"id": "int-2", "name": "Vlan10", "vrf_id": None})
        plan = planner.plan_ipam(
            discovery(
                fact(addresses=[address("10.40.12.200")]),
                fact("Vlan10", addresses=[address("10.40.12.1", length=25)]),
            ),
            before,
        )
        wider, narrow = plan["prefixes"]
        self.assertEqual(narrow["parent_key"], wider["key"])
        self.assertEqual(plan["ip_addresses"][1]["parent_key"], narrow["key"])

    def test_ranges_cannot_be_split_or_reparented_to_different_vrfs(self):
        for end, routing in (("10.40.13.20", []), ("10.40.12.20", ["vrf-1"])):
            before = inventory()
            catalog = before["ipam_inventory"]
            catalog["prefixes"] = [
                prefix("10.40.0.0/16", id="aggregate", type="container", vrf_ids=routing)
            ]
            catalog["ip_ranges"] = [
                {
                    "id": "range-1",
                    "start_address": "10.40.12.10",
                    "end_address": end,
                    "namespace_id": "corporate",
                    "parent_id": "aggregate",
                }
            ]
            plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
            self.assertFalse(plan["prefixes"])
            self.assertTrue(plan["unresolved"])

    def test_exclusive_ip_range_blocks_new_address(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [prefix()]
        catalog["ip_ranges"] = [
            {
                "id": "range-1",
                "start_address": "10.40.12.1",
                "end_address": "10.40.12.20",
                "namespace_id": "corporate",
                "parent_id": "prefix-1",
                "is_exclusive": True,
            }
        ]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("exclusive", plan["unresolved"][-1]["reason"])

    def test_shared_prefix_can_have_multiple_explicit_named_routing_contexts(self):
        before = inventory()
        before["interfaces"].append({"id": "int-2", "name": "Vlan20", "vrf_id": None})
        observed = discovery(
            fact(vrf="CORP", addresses=[address()]),
            fact("Vlan20", vrf="OT", addresses=[address("10.40.12.2")]),
            vrfs=[vrf("CORP"), vrf("OT")],
        )
        plan = planner.plan_ipam(observed, before)
        self.assertFalse(plan["unresolved"])
        self.assertEqual(len(plan["prefixes"][0]["add_vrf_keys"]), 2)
        self.assertEqual(plan["summary"]["ip_addresses_created"], 2)

    def test_missing_location_defers_new_network_and_existing_network_can_be_reused(self):
        before = inventory()
        policy = before["ipam_inventory"]["policy"]
        policy["location"] = None
        policy["location_reason"] = "Location Type does not permit Prefix associations"
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["prefixes"])
        self.assertFalse(plan["ip_addresses"])
        self.assertIn("Location Type", plan["unresolved"][0]["reason"])
        before["ipam_inventory"]["prefixes"] = [prefix()]
        existing = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertEqual(existing["summary"]["ip_addresses_created"], 1)

    def test_mixed_global_and_named_prefix_contexts_defer_entire_prefix_bundle(self):
        before = inventory()
        before["interfaces"].append({"id": "int-2", "name": "Vlan20", "vrf_id": None})
        plan = planner.plan_ipam(
            discovery(
                fact(addresses=[address()]),
                fact("Vlan20", vrf="CORP", addresses=[address("10.40.12.2")]),
                vrfs=[vrf("CORP")],
            ),
            before,
        )
        self.assertFalse(plan["prefixes"])
        self.assertFalse(plan["ip_addresses"])
        self.assertFalse(plan["ip_assignments"])
        self.assertIn("both global and named", plan["unresolved"][0]["reason"])

    def test_unused_existing_vrf_assignment_namespace_is_preserved(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["vrfs"] = [existing_vrf()]
        catalog["vrf_device_assignments"] = [device_vrf()]
        plan = planner.plan_ipam(discovery(vrfs=[vrf()]), before)
        self.assertFalse(plan["unresolved"])
        self.assertFalse(plan["vrfs"][0]["create"])
        self.assertEqual(plan["vrfs"][0]["namespace_id"], "corporate")

    def test_existing_primary_secondary_setting_is_preserved_and_conflict_reported(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [prefix()]
        catalog["ip_addresses"] = [ip()]
        catalog["ip_assignments"] = [assignment(is_secondary=True)]
        plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
        self.assertFalse(plan["ip_assignments"])
        self.assertEqual(plan["conflicts"][0]["field"], "is_secondary")
        self.assertTrue(catalog["ip_assignments"][0]["is_secondary"])

    def test_nested_prefix_reparent_preserves_existing_child_routing_context(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["prefixes"] = [
            prefix("10.40.0.0/16", id="aggregate", type="container", vrf_ids=["outer-vrf"]),
            prefix("10.40.12.0/25", id="child", parent_id="aggregate", vrf_ids=["inner-vrf"]),
        ]
        catalog["ip_addresses"] = [ip("10.40.12.2", parent_id="child")]
        plan = planner.plan_ipam(discovery(fact(addresses=[address("10.40.12.200")])), before)
        self.assertEqual(plan["summary"]["prefixes_created"], 1)
        self.assertEqual(plan["prefixes"][0]["affected_prefix_ids"], ["child"])
        self.assertFalse(plan["prefixes"][0]["affected_ip_ids"])
        self.assertTrue(plan["ip_addresses"])

    def test_explicit_local_vrf_exception_excludes_grouping(self):
        before = inventory()
        policy = before["ipam_inventory"]["policy"]
        policy["group_user_vrfs"] = True
        policy["local_vrf_names"].append("OT")
        plan = planner.plan_ipam(discovery(vrfs=[vrf("OT")]), before)
        self.assertEqual(plan["vrfs"][0]["name"], "switch-A / OT")

    def test_manual_override_requires_selected_namespace_and_valid_network_cidr(self):
        for namespace, value in ((None, "203.0.113.0/24"), ({"id": "corporate"}, "203.0.113.1/24")):
            before = inventory()
            policy = before["ipam_inventory"]["policy"]
            policy["override_namespace"] = namespace
            policy["override_networks"] = [value]
            plan = planner.plan_ipam(discovery(fact(addresses=[address()])), before)
            self.assertTrue(plan["errors"])
            self.assertTrue(all(not plan[key] for key in planner.COLLECTIONS))

    def test_new_shared_assignment_cannot_inherit_unreported_global_rd(self):
        before = inventory()
        catalog = before["ipam_inventory"]
        catalog["policy"]["group_user_vrfs"] = True
        catalog["vrfs"] = [existing_vrf("CORP", namespace_id="internet", rd="65000:1")]
        plan = planner.plan_ipam(discovery(vrfs=[vrf("CORP")]), before)
        self.assertFalse(plan["vrfs"])
        self.assertFalse(plan["vrf_device_assignments"])
        self.assertIn("unreported", plan["unresolved"][0]["reason"])
        reported = planner.plan_ipam(discovery(vrfs=[vrf("CORP", rd="65000:2")]), before)
        self.assertEqual(reported["vrf_device_assignments"][0]["rd"], "65000:2")

    def test_new_network_cannot_overlap_exclusive_range_even_when_host_is_outside_it(self):
        for more_specific_parent in (False, True):
            with self.subTest(more_specific_parent=more_specific_parent):
                before = inventory()
                catalog = before["ipam_inventory"]
                if more_specific_parent:
                    catalog["prefixes"] = [prefix("10.40.12.0/25", id="range-parent")]
                catalog["ip_ranges"] = [
                    {
                        "id": "range-1",
                        "start_address": "10.40.12.10",
                        "end_address": "10.40.12.20",
                        "namespace_id": "corporate",
                        "parent_id": "range-parent" if more_specific_parent else None,
                        "is_exclusive": True,
                    }
                ]
                plan = planner.plan_ipam(
                    discovery(fact(addresses=[address("10.40.12.200")])), before
                )
                self.assertFalse(plan["errors"])
                self.assertFalse(plan["prefixes"])
                self.assertFalse(plan["ip_addresses"])
                self.assertIn("exclusive IP range", plan["unresolved"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
