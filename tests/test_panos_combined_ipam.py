"""One source-scoped hierarchy for management and PAN data-plane addresses."""

import unittest
from copy import deepcopy
from ipaddress import ip_interface

from tests._loader import load
from tests.test_panos_ipam_reconcile import FIXTURES, existing, raw_discovery
from tests.test_panos_management import CONFIG, OP, facts

planner = load("reconcile_panos_ipam")


def management_input(*, host="192.0.2.10", mask="255.255.255.0", dhcp=False):
    operational = OP.replace("192.0.2.10", host).replace("255.255.255.0", mask)
    configuration = CONFIG
    if not dhcp:
        operational = operational.replace("dhcp-client", "static")
        configuration = configuration.replace(
            "<type><dhcp-client><send-hostname>yes</send-hostname></dhcp-client></type>",
            "<ip-address>%s</ip-address><netmask>%s</netmask>" % (host, mask),
        )
    raw = facts(operational, configuration)["management"]
    declared = raw["addresses"][0]
    literal = ip_interface(declared["address"])
    return {
        "interface": {
            "name": raw["interface"]["name"],
            "vrf": None,
            "ipv4": [
                {
                    "address": str(literal.ip),
                    "mask": str(literal.network.netmask),
                    "prefix_length": literal.network.prefixlen,
                    "secondary": False,
                    "secondary_known": False,
                    "method": "observed-dhcp-lease" if dhcp else "configured-static",
                    "source": deepcopy(declared["source"]),
                }
            ],
            "ipv6": [],
        },
        "target": {"namespace": {"id": "public", "name": "Public"}, "vrf": None},
    }


def combined_existing(observed):
    before = existing(observed)
    before["interfaces"].append(
        {"id": "mgmt-native", "name": "Management Interface", "vrf_id": None}
    )
    return before


class CombinedPanosIpamTests(unittest.TestCase):
    def test_management_and_data_plane_duplicate_host_is_unresolved_in_one_graph(self):
        observed = raw_discovery()
        plan = planner.plan_panos_ipam(
            observed,
            combined_existing(observed),
            management_input=management_input(host="192.0.2.1"),
        )
        self.assertFalse(plan["errors"])
        self.assertNotIn("192.0.2.1", {row["host"] for row in plan["ip_addresses"]})
        ambiguous = [row for row in plan["unresolved"] if row.get("name") == "192.0.2.1"]
        self.assertEqual(len(ambiguous), 2)
        self.assertEqual(
            {row["interface"] for row in ambiguous}, {"ethernet1/1", "Management Interface"}
        )

    def test_nested_management_and_data_plane_prefixes_share_exact_closest_parents(self):
        observed = raw_discovery()
        plan = planner.plan_panos_ipam(
            observed,
            combined_existing(observed),
            management_input=management_input(mask="255.255.0.0"),
        )
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["unresolved"])
        prefixes = {
            row["prefix"]: row for row in plan["prefixes"] if row["namespace_id"] == "public"
        }
        self.assertEqual(prefixes["192.0.2.0/24"]["parent_key"], prefixes["192.0.0.0/16"]["key"])
        addresses = {row["host"]: row for row in plan["ip_addresses"]}
        self.assertEqual(addresses["192.0.2.1"]["parent_key"], prefixes["192.0.2.0/24"]["key"])
        self.assertEqual(addresses["192.0.2.10"]["parent_key"], prefixes["192.0.2.0/24"]["key"])
        self.assertEqual(addresses["192.0.2.10"]["mask_length"], 16)

    def test_management_only_empty_applied_data_plane_and_ha_deferred_both_work(self):
        for empty in (True, False):
            with self.subTest(empty=empty):
                observed = raw_discovery(
                    '<response status="success"><result><network/></result></response>'
                    if empty
                    else None,
                    '<response status="success"><result><vsys/></result></response>'
                    if empty
                    else None,
                )
                if not empty:
                    observed["observations"]["ha"]["runtime"]["enabled"] = True
                before = combined_existing(observed)
                before["ipam_inventory"]["policy"]["panos_routing_domains"] = []
                plan = planner.plan_panos_ipam(
                    observed, before, management_input=management_input(dhcp=True)
                )
                self.assertFalse(plan["errors"])
                self.assertEqual(plan["summary"]["ip_addresses_created"], 1)
                self.assertEqual(plan["ip_addresses"][0]["type"], "dhcp")
                self.assertEqual(
                    [row["name"] for row in plan["ip_assignments"]], ["Management Interface"]
                )

    def test_only_canonical_management_lease_method_and_existing_namespace_enter(self):
        observed = raw_discovery()
        for mutation in ("namespace", "path", "method", "marker", "vrf", "interface_collision"):
            with self.subTest(mutation=mutation):
                value = management_input(dhcp=True)
                if mutation == "namespace":
                    value["target"]["namespace"]["id"] = "another-namespace"
                elif mutation == "path":
                    value["interface"]["ipv4"][0]["source"]["path"] = "guessed/path"
                elif mutation == "method":
                    value["interface"]["ipv4"][0]["method"] = "configured-static"
                elif mutation == "marker":
                    value["interface"]["ipv4"][0]["source"]["applied_dhcp_client_present"] = False
                elif mutation == "vrf":
                    value["target"]["vrf"] = {"id": "inferred-vrf"}
                else:
                    value["interface"]["name"] = "ethernet1/1"
                plan = planner.plan_panos_ipam(
                    observed, combined_existing(observed), management_input=value
                )
                self.assertTrue(plan["errors"])
                self.assertEqual(plan["ip_addresses"], [])

    def test_management_appending_is_pure_and_applied_panos_fields_cannot_be_leases(self):
        observed = raw_discovery((FIXTURES / "panos_ipam_network.xml").read_text())
        before = combined_existing(observed)
        value = management_input(dhcp=True)
        untouched = deepcopy((observed, before, value))
        plan = planner.plan_panos_ipam(observed, before, management_input=value)
        self.assertFalse(plan["errors"])
        self.assertEqual((observed, before, value), untouched)
        self.assertEqual(
            {row["host"] for row in plan["ip_addresses"] if row["type"] == "dhcp"}, {"192.0.2.10"}
        )
