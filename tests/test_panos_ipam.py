"""Applied PAN-OS IPAM identities, literal addressing, complete scope and privacy."""

import json
import unittest
import xml.etree.ElementTree as ET
from ipaddress import IPv4Address
from pathlib import Path

from tests._loader import load

ipam = load("adapters.panos_ipam")
ssh = load("transport_ssh")
FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / ("panos_ipam_" + name + ".xml")).read_text()


def response(body, parent="network"):
    return (
        '<response status="success"><result><'
        + parent
        + ">"
        + body
        + "</"
        + parent
        + "></result></response>"
    )


def ethernet(body, name="ethernet1/1"):
    return response(
        '<interface><ethernet><entry name="'
        + name
        + '"><layer3>'
        + body
        + "</layer3></entry></ethernet></interface>"
    )


def ipv6(address="2001:db8::1/64", flags="", enabled=""):
    return (
        "<ipv6>"
        + enabled
        + '<address><entry name="'
        + address
        + '">'
        + flags
        + "</entry></address></ipv6>"
    )


class PanosIpamTests(unittest.TestCase):
    def parse(self, network=None, vsys=None):
        return ipam.parse_ipam_configuration(
            fixture("network") if network is None else network,
            fixture("vsys") if vsys is None else vsys,
        )

    def minimal(self, body):
        return self.parse(ethernet(body), response("", "vsys"))

    def test_actual_applied_network_and_vsys_keep_observed_scope(self):
        facts = self.parse(fixture("live_network"), fixture("live_vsys"))
        self.assertEqual(facts["contract"], "panos-ipam-v1")
        self.assertEqual(facts["schema_version"], 1)
        rows = {row["name"]: row for row in facts["interfaces"]}
        self.assertEqual(rows["ethernet1/1"]["ipv4"][0]["address"], "198.18.101.3/29")
        self.assertEqual(rows["ethernet1/1"]["ipv4"][0]["network"], "198.18.101.0/29")
        self.assertEqual(rows["loopback.1"]["ipv4"][0]["prefix_length"], 32)
        self.assertEqual(rows["loopback.1"]["ipv6"][0]["address"], "2001:db8:103::1/128")
        self.assertIs(rows["loopback.1"]["ipv6_enabled"], True)
        self.assertIs(rows["loopback.1"]["ipv6"][0]["enable_on_interface"], True)
        self.assertEqual(
            rows["loopback.1"]["ipv6"][0]["source"]["fields"]["prefix"]["presence"], "absent"
        )
        self.assertEqual(rows["tunnel.1"]["ipv4"][0]["address"], "198.18.102.2/30")
        self.assertEqual(rows["ethernet1/1"]["virtual_router"], "lab-vpn-vr")
        self.assertEqual(rows["ethernet1/1"]["vsys"], "vsys1")
        unused = next(row for row in facts["routers"] if row["name"] == "default")
        self.assertEqual(unused["interfaces"], [])
        self.assertIsNone(unused["vsys"])
        self.assertIsNone(rows["ethernet1/2"]["virtual_router"])
        self.assertIsNone(rows["ethernet1/2"]["vsys"])

    def test_reviewed_kinds_preserve_configured_identity_without_name_rewriting(self):
        rows = self.parse()["interfaces"]
        self.assertEqual(
            [row["kind"] for row in rows],
            [
                "ethernet",
                "ethernet-subinterface",
                "aggregate-ethernet",
                "aggregate-subinterface",
                "loopback",
                "tunnel",
            ],
        )
        self.assertEqual(
            [row["name"] for row in rows],
            [
                "ethernet1/1",
                "ethernet1/1.100",
                "ae1",
                "ae1.200",
                "loopback.1",
                "tunnel.1",
            ],
        )
        self.assertTrue(all(row["mode"] == "layer3" for row in rows))
        for row in rows:
            self.assertEqual(row["source"]["path"], ipam.INTERFACE_PATHS[row["kind"]])
            self.assertEqual(row["source"]["configured_name"], row["name"])
            self.assertEqual(row["source"]["network_command"], ssh.RUNNING_VPN)
        self.assertEqual(rows[1]["source"]["parent_name"], "ethernet1/1")
        self.assertEqual(rows[3]["source"]["parent_name"], "ae1")
        self.assertTrue(all(ipam.reviewed_interface_identity(row) for row in rows))

    def test_unreviewed_interface_names_and_wrong_direct_parents_are_deferred(self):
        for name in ("Gi0/0", "Ethernet1/1", "ethernet1/1.100", "ethernet1/1;show"):
            facts = self.parse(
                ethernet('<ip><entry name="192.0.2.1/24"/></ip>', name=name),
                response("", "vsys"),
            )
            self.assertEqual(facts["interfaces"], [])
            self.assertEqual(facts["excluded"][0]["name"], name)
            self.assertEqual(
                facts["unresolved"][0]["interface"]["ipv4"][0]["address"], "192.0.2.1/24"
            )
        raw = ethernet(
            '<units><entry name="ethernet1/2.100"><ip>'
            '<entry name="192.0.2.1/24"/></ip></entry></units>'
        )
        facts = self.parse(raw, response("", "vsys"))
        self.assertEqual([row["name"] for row in facts["interfaces"]], ["ethernet1/1"])
        self.assertEqual(facts["excluded"][0]["name"], "ethernet1/2.100")
        row = self.parse()["interfaces"][1]
        row["source"]["parent_name"] = "ethernet1/2"
        self.assertFalse(ipam.reviewed_interface_identity(row))

    def test_routing_labels_with_spaces_are_exact_opaque_names(self):
        network = fixture("network").replace("vr-public", "VR with spaces")
        vsys = fixture("vsys").replace("vr-public", "VR with spaces").replace("vsys1", "Vsys label")
        facts = self.parse(network, vsys)
        self.assertEqual(facts["interfaces"][0]["virtual_router"], "VR with spaces")
        self.assertEqual(facts["interfaces"][0]["vsys"], "Vsys label")

    def test_static_ipv6_flags_and_presence_are_not_defaults(self):
        row = self.parse()["interfaces"][0]
        address = row["ipv6"][0]
        self.assertIs(row["ipv6_enabled"], True)
        self.assertIs(address["enable_on_interface"], True)
        self.assertIsNone(address["prefix"])
        self.assertIsNone(address["anycast"])
        self.assertIs(address["advertise_enabled"], True)
        self.assertIs(address["onlink_flag"], False)
        self.assertEqual(address["source"]["fields"]["prefix"]["presence"], "absent")
        self.assertEqual(address["source"]["configured_name"], address["address"])
        self.assertEqual(address["source"]["interface"], row["name"])
        self.assertEqual(address["source"]["path"], row["source"]["path"] + "/ipv6/address/entry")

    def test_missing_explicit_enable_flags_remain_none(self):
        row = self.minimal(ipv6())["interfaces"][0]
        self.assertIsNone(row["ipv6_enabled"])
        self.assertIsNone(row["ipv6"][0]["enable_on_interface"])
        self.assertEqual(row["source"]["fields"]["ipv6_enabled"]["presence"], "absent")
        self.assertEqual(
            row["ipv6"][0]["source"]["fields"]["enable_on_interface"]["presence"], "absent"
        )
        row = self.minimal(
            ipv6(
                flags="<enable-on-interface>no</enable-on-interface>",
                enabled="<enabled>no</enabled>",
            )
        )["interfaces"][0]
        self.assertIs(row["ipv6_enabled"], False)
        self.assertIs(row["ipv6"][0]["enable_on_interface"], False)

    def test_generated_and_anycast_markers_are_observed_as_markers(self):
        row = self.minimal(ipv6(flags="<prefix/><anycast/>"))["interfaces"][0]
        address = row["ipv6"][0]
        self.assertIs(address["prefix"], True)
        self.assertIs(address["anycast"], True)
        self.assertEqual(address["source"]["fields"]["prefix"]["presence"], "marker")
        self.assertEqual(address["host"], "2001:db8::1")
        self.assertNotIn("generated_host", address)

    def test_markers_do_not_accept_yes_no_or_nested_content(self):
        for marker in (
            "<prefix>yes</prefix>",
            "<anycast>no</anycast>",
            "<prefix><nested/></prefix>",
        ):
            with self.subTest(marker=marker), self.assertRaises(ipam.DiscoveryError):
                self.minimal(ipv6(flags=marker))

    def test_dynamic_and_incomplete_addresses_remain_observations(self):
        body = (
            '<ip><entry name="address-object"/><entry name="192.0.2.1"/></ip>'
            "<dhcp-client><enable>yes</enable></dhcp-client>"
            "<pppoe><static-address><ip>198.51.100.5</ip></static-address></pppoe>"
            "<ipv6><dhcp-client><enable>no</enable></dhcp-client>"
            '<inherited><enable>yes</enable></inherited><address><entry name="named-prefix">'
            "<prefix/></entry></address></ipv6>"
        )
        facts = self.minimal(body)
        row = facts["interfaces"][0]
        self.assertEqual(row["ipv4"], [])
        self.assertEqual(row["ipv6"], [])
        self.assertIs(row["addressing"]["ipv4_dhcp"]["enabled"], True)
        self.assertIsNone(row["addressing"]["ipv4_pppoe"]["enabled"])
        self.assertIs(row["addressing"]["ipv6_dhcp"]["enabled"], False)
        names = [item.get("configured_name") for item in facts["unresolved"]]
        self.assertIn("address-object", names)
        self.assertIn("192.0.2.1", names)
        self.assertIn("named-prefix", names)
        self.assertIn("198.51.100.5", names)
        symbolic = next(
            item for item in facts["unresolved"] if item.get("configured_name") == "named-prefix"
        )
        self.assertIs(symbolic["ipv6_flags"]["prefix"], True)

    def test_static_and_dynamic_settings_are_preserved_without_resolving_conflict(self):
        row = self.minimal(
            '<ip><entry name="192.0.2.1/24"/></ip><dhcp-client><enable>yes</enable></dhcp-client>'
        )["interfaces"][0]
        self.assertEqual(row["ipv4"][0]["address"], "192.0.2.1/24")
        self.assertIs(row["addressing"]["ipv4_dhcp"]["enabled"], True)

    def test_present_malformed_boolean_fails_even_on_symbolic_ipv6_entry(self):
        for body in (
            ipv6(flags="<enable-on-interface>auto</enable-on-interface>"),
            ipv6(address="named-prefix", flags="<enable-on-interface>auto</enable-on-interface>"),
            ipv6(enabled="<enabled/>"),
            "<dhcp-client><enable>YES</enable></dhcp-client>",
            "<ipv6><inherited><enable/></inherited></ipv6>",
        ):
            with self.subTest(body=body), self.assertRaises(ipam.DiscoveryError):
                self.minimal(body)

    def test_multiple_addresses_share_a_subnet_without_inventing_primary(self):
        facts = self.minimal('<ip><entry name="192.0.2.1/24"/><entry name="192.0.2.2/24"/></ip>')
        rows = facts["interfaces"][0]["ipv4"]
        self.assertEqual([row["host"] for row in rows], ["192.0.2.1", "192.0.2.2"])
        self.assertTrue(all("secondary" not in row for row in rows))

    def test_duplicate_and_overlapping_interface_address_identity_fails(self):
        for body in (
            '<ip><entry name="192.0.2.1/24"/><entry name="192.0.2.1/24"/></ip>',
            '<ip><entry name="192.0.2.1/24"/><entry name="192.0.2.1/32"/></ip>',
            '<ipv6><address><entry name="2001:db8::1/64"/>'
            '<entry name="2001:DB8::1/128"/></address></ipv6>',
        ):
            with self.subTest(body=body), self.assertRaises(ipam.DiscoveryError):
                self.minimal(body)

    def test_literal_wrong_family_and_scoped_host_not_native_candidates(self):
        with self.assertRaises(ipam.DiscoveryError):
            self.minimal('<ip><entry name="2001:db8::1/64"/></ip>')
        with self.assertRaises(ipam.DiscoveryError):
            self.minimal(ipv6(address="192.0.2.1/24"))
        facts = self.minimal(ipv6(address="fe80::1%ethernet1/1/64"))
        self.assertEqual(facts["interfaces"][0]["ipv6"], [])
        self.assertTrue(facts["unresolved"])

    def test_parent_addresses_are_not_copied_to_subinterfaces(self):
        rows = self.parse()["interfaces"]
        self.assertEqual(rows[1]["ipv4"][0]["address"], "10.100.0.1/24")
        self.assertEqual(rows[3]["ipv4"][0]["address"], "10.200.0.1/24")
        self.assertEqual(len(rows[1]["ipv4"]), 1)
        self.assertEqual(len(rows[3]["ipv6"]), 1)

    def test_non_l3_management_and_unreviewed_types_cannot_supply_addresses(self):
        facts = self.parse()
        self.assertEqual(
            {row["name"] for row in facts["excluded"]},
            {
                "ethernet1/2",
                "ethernet1/2.101",
                "ethernet1/3",
                "ethernet1/4",
                "ethernet1/5",
                "vlan.10",
            },
        )
        self.assertFalse(any(row["name"] == "vlan.10" for row in facts["interfaces"]))
        unknown = response(
            '<interface><ethernet><entry name="ethernet1/9"><future-mode/>'
            '<ip><entry name="192.0.2.9/24"/></ip></entry></ethernet></interface>'
        )
        self.assertEqual(self.parse(unknown, response("", "vsys"))["interfaces"], [])

    def test_duplicate_identity_across_kinds_and_conflicting_modes_fail(self):
        cases = [
            response(
                '<interface><ethernet><entry name="same"><layer3/></entry></ethernet>'
                '<loopback><units><entry name="same"/></units></loopback></interface>'
            ),
            response(
                '<interface><ethernet><entry name="ethernet1/1"><layer3/><ha/>'
                "</entry></ethernet></interface>"
            ),
            response(
                '<interface><ethernet><entry name="ethernet1/1"><layer3/><layer3/>'
                "</entry></ethernet></interface>"
            ),
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ipam.DiscoveryError):
                self.parse(raw, response("", "vsys"))

    def test_membership_sources_match_exact_imported_interface_identity(self):
        row = self.parse()["interfaces"][1]
        self.assertEqual(
            row["source"]["vr_membership"],
            {
                "command": ssh.RUNNING_VPN,
                "path": ipam.VR_MEMBERSHIP_PATH,
                "router": "vr-internal",
                "interface": "ethernet1/1.100",
            },
        )
        self.assertEqual(
            row["source"]["vsys_import"],
            {
                "command": ssh.RUNNING_VSYS,
                "path": ipam.VSYS_INTERFACE_PATH,
                "vsys": "vsys2",
                "interface": "ethernet1/1.100",
            },
        )
        router = next(item for item in self.parse()["routers"] if item["name"] == "vr-internal")
        self.assertEqual(router["source"]["vsys_import"]["path"], ipam.VSYS_ROUTER_PATH)
        self.assertEqual(router["vsys"], "vsys2")

    def test_missing_membership_never_becomes_default_router_or_vsys1(self):
        facts = self.minimal('<ip><entry name="192.0.2.1/24"/></ip>')
        row = facts["interfaces"][0]
        self.assertIsNone(row["virtual_router"])
        self.assertIsNone(row["vsys"])
        self.assertIsNone(row["source"]["vr_membership"])
        self.assertIsNone(row["source"]["vsys_import"])
        self.assertTrue(facts["unresolved"])
        # A router import alone cannot substitute for an interface import.
        root = ET.fromstring(fixture("vsys"))
        root.find("result/vsys/entry/import/network").remove(
            root.find("result/vsys/entry/import/network/interface")
        )
        row = self.parse(vsys=ET.tostring(root, encoding="unicode"))["interfaces"][0]
        self.assertIsNone(row["vsys"])

    def test_multiple_router_or_vsys_memberships_fail_closed(self):
        for target in ("network", "vsys"):
            root = ET.fromstring(fixture(target))
            path = (
                "result/network/virtual-router/entry/interface"
                if target == "network"
                else "result/vsys/entry/import/network/interface"
            )
            rows = root.findall(path)
            ET.SubElement(rows[1], "member").text = "ethernet1/1"
            kwargs = {target: ET.tostring(root, encoding="unicode")}
            with self.subTest(target=target), self.assertRaises(ipam.DiscoveryError):
                self.parse(**kwargs)

    def test_duplicate_members_and_missing_or_conflicting_router_import_fail(self):
        root = ET.fromstring(fixture("network"))
        ET.SubElement(
            root.find("result/network/virtual-router/entry/interface"), "member"
        ).text = "ethernet1/1"
        with self.assertRaises(ipam.DiscoveryError):
            self.parse(network=ET.tostring(root, encoding="unicode"))
        for router in ("missing-router", "vr-internal"):
            root = ET.fromstring(fixture("vsys"))
            root.find("result/vsys/entry/import/network/virtual-router/member").text = router
            with self.subTest(router=router), self.assertRaises(ipam.DiscoveryError):
                self.parse(vsys=ET.tostring(root, encoding="unicode"))

    def test_empty_structured_parents_are_valid_complete_absence(self):
        facts = self.parse(response(""), response("", "vsys"))
        for name in ("interfaces", "routers", "vsys", "unresolved", "excluded"):
            self.assertEqual(facts[name], [])
        self.assertEqual(
            [row["command"] for row in facts["sources"]], [ssh.RUNNING_VPN, ssh.RUNNING_VSYS]
        )

    def test_unknown_logical_router_is_retained_without_legacy_vr_inference(self):
        facts = self.parse(
            response('<logical-router><entry name="lr-new"/></logical-router>'),
            response("", "vsys"),
        )
        self.assertEqual(facts["routers"], [])
        self.assertEqual(facts["unresolved"][0]["name"], "lr-new")

    def test_complete_success_expected_parents_and_unambiguous_scopes_required(self):
        cases = [
            '<response status="error"><msg>PRIVATE-ERROR</msg></response>',
            '<response status="success"><result/></response>',
            response("", "interface"),
            '<response status="success"><result><network/><network/></result></response>',
            '<response status="success"><result><network/><other/></result></response>',
            '<response status="success"><result><![CDATA[PRIVATE-DISPLAY]]></result></response>',
            response("<interface><ethernet><![CDATA[PRIVATE-DISPLAY]]></ethernet></interface>"),
            response(
                '<virtual-router><entry name="vr"><interface><member>ethernet1/1</member>'
                "<error>PRIVATE-ERROR</error></interface></entry></virtual-router>"
            ),
            response(
                '<interface><ethernet><entry name="ethernet1/1"><layer3><ip>'
                '<entry name="192.0.2.1/24"><unknown><msg>PRIVATE-ERROR</msg></unknown>'
                "</entry></ip></layer3></entry></ethernet></interface>"
            ),
            response(
                '<interface><ethernet><entry name="ethernet1/1" vsys="vsys2">'
                "<layer3/></entry></ethernet></interface>"
            ),
            response("<interface/>").replace("<network>", '<network vsys="vsys2">'),
            "Server error : No such node",
            fixture("network")[:-20],
        ]
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(ipam.DiscoveryError) as error:
                self.parse(network=raw)
            self.assertNotIn("PRIVATE-", str(error.exception))

    def test_unrelated_private_and_error_branches_are_discarded(self):
        root = ET.fromstring(fixture("network"))
        network = root.find("result/network")
        vpn = ET.SubElement(network, "ike")
        ET.SubElement(vpn, "error").text = "PRIVATE-UNRELATED-ERROR"
        layer3 = root.find("result/network/interface/ethernet/entry/layer3")
        pppoe = ET.SubElement(layer3, "pppoe")
        ET.SubElement(pppoe, "enable").text = "no"
        for tag in ("username", "password", "key", "private-key", "secret"):
            ET.SubElement(pppoe, tag).text = "PRIVATE-CREDENTIAL"
        router = root.find("result/network/virtual-router/entry")
        protocol = ET.SubElement(router, "protocol")
        ET.SubElement(protocol, "authentication").text = "PRIVATE-AUTHENTICATION"
        vsys = ET.fromstring(fixture("vsys"))
        zone = ET.SubElement(vsys.find("result/vsys/entry"), "zone")
        ET.SubElement(zone, "error").text = "PRIVATE-UNRELATED-ERROR"
        facts = self.parse(
            ET.tostring(root, encoding="unicode"), ET.tostring(vsys, encoding="unicode")
        )
        serialized = json.dumps(facts)
        for forbidden in (
            "PRIVATE-",
            "username",
            "password",
            "private-key",
            "secret",
            "authentication",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_large_configured_population_uses_membership_indexes(self):
        root = ET.fromstring(
            response(
                '<interface><ethernet/></interface><virtual-router><entry name="vr">'
                "<interface/></entry></virtual-router>"
            )
        )
        vsys = ET.fromstring(
            response(
                '<entry name="vsys"><import><network><interface/><virtual-router>'
                "<member>vr</member></virtual-router></network></import></entry>",
                "vsys",
            )
        )
        ethernet_rows = root.find("result/network/interface/ethernet")
        members = root.find("result/network/virtual-router/entry/interface")
        imports = vsys.find("result/vsys/entry/import/network/interface")
        for number in range(2000):
            name = "ethernet1/" + str(number + 1)
            entry = ET.SubElement(ethernet_rows, "entry", {"name": name})
            addresses = ET.SubElement(ET.SubElement(entry, "layer3"), "ip")
            ET.SubElement(
                addresses, "entry", {"name": str(IPv4Address(0x0A000001 + number)) + "/32"}
            )
            ET.SubElement(members, "member").text = name
            ET.SubElement(imports, "member").text = name
        facts = self.parse(
            ET.tostring(root, encoding="unicode"), ET.tostring(vsys, encoding="unicode")
        )
        self.assertEqual(len(facts["interfaces"]), 2000)
        self.assertEqual(facts["interfaces"][-1]["virtual_router"], "vr")
        self.assertEqual(facts["interfaces"][-1]["vsys"], "vsys")

    def test_public_fixtures_have_only_safe_configuration_branches(self):
        for filename in ("network", "vsys", "live_network", "live_vsys"):
            root = ET.fromstring(fixture(filename))
            for node in root.iter():
                self.assertNotIn(
                    node.tag,
                    {
                        "password",
                        "username",
                        "key",
                        "authentication",
                        "secret",
                        "private-key",
                        "pre-shared-key",
                        "certificate",
                        "zone",
                        "policy",
                        "rules",
                    },
                )


if __name__ == "__main__":
    unittest.main()
