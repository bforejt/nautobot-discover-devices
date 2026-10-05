"""Applied VPN configuration: literal observations, strict shape, secret exclusion."""

import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from tests._loader import load

vpn = load("adapters.panos_vpn_config")
transport = load("transport_ssh")
FIXTURES = Path(__file__).parent / "fixtures"


def response(network=""):
    return (
        '<response status="success"><result><network>' + network + "</network></result></response>"
    )


def gateways(rows):
    return response("<ike><gateway>" + rows + "</gateway></ike>")


def tunnels(rows):
    return response("<tunnel><ipsec>" + rows + "</ipsec></tunnel>")


def profile(rows, kind="ike"):
    tag = kind + "-crypto-profiles"
    return response(
        "<ike><crypto-profiles><" + tag + ">" + rows + "</" + tag + "></crypto-profiles></ike>"
    )


class VpnConfigurationTests(unittest.TestCase):
    def parse(self, raw):
        return vpn.parse_vpn_configuration(raw)

    def test_live_applied_configuration_and_literal_sources(self):
        facts = self.parse((FIXTURES / "panos_vpn_applied_network.xml").read_text())
        self.assertEqual(facts["contract"], "panos-vpn-config-v1")
        self.assertEqual(
            facts["sources"]["ike_gateways"],
            {
                "command": transport.RUNNING_VPN,
                "path": "result/network/ike/gateway",
                "present": True,
            },
        )
        gateway = facts["ike_gateways"][0]
        self.assertEqual(gateway["name"], "lab-ike")
        self.assertEqual(gateway["local_address"]["ip"], "198.18.101.1/29")
        self.assertEqual(
            gateway["peer_address"],
            {
                "kind": "ip",
                "ip": "198.18.101.3",
                "fqdn": None,
                "dynamic": None,
            },
        )
        self.assertEqual(gateway["protocol"]["version"], "ikev2")
        self.assertEqual(gateway["protocol"]["ikev2_profile"], "lab-ike-profile")
        self.assertIs(gateway["disabled"], False)
        tunnel = facts["ipsec_tunnels"][0]
        self.assertEqual(tunnel["auto_key"]["ike_gateways"], ["lab-ike"])
        self.assertEqual(tunnel["auto_key"]["crypto_profile"], "lab-ipsec-profile")
        self.assertEqual(tunnel["auto_key"]["selectors_ipv4"][0]["remote"], "10.255.103.1/32")
        self.assertIsNone(tunnel["disabled"])
        self.assertIsNone(tunnel["monitor"]["enabled"])
        ike = next(row for row in facts["ike_crypto_profiles"] if row["name"] == "lab-ike-profile")
        ipsec = next(
            row for row in facts["ipsec_crypto_profiles"] if row["name"] == "lab-ipsec-profile"
        )
        self.assertEqual(ike["dh_groups"], ["group14"])
        self.assertEqual(ike["lifetime"]["hours"], 8)
        self.assertEqual(ipsec["dh_group"], "group14")
        self.assertEqual(ipsec["esp"]["authentication"], ["sha256"])
        self.assertEqual(ipsec["lifetime"]["hours"], 1)

    def test_absent_configuration_is_observed_without_defaults(self):
        facts = self.parse(response("<interface/><virtual-router/>"))
        for key in (
            "ike_gateways",
            "ipsec_tunnels",
            "ike_crypto_profiles",
            "ipsec_crypto_profiles",
        ):
            self.assertEqual(facts[key], [])
            self.assertIs(facts["sources"][key]["present"], False)

    def test_present_empty_collection_differs_from_absence(self):
        facts = self.parse(gateways(""))
        self.assertEqual(facts["ike_gateways"], [])
        self.assertIs(facts["sources"]["ike_gateways"]["present"], True)

    def test_missing_gateway_options_remain_none(self):
        fact = self.parse(gateways('<entry name="minimal"/>'))["ike_gateways"][0]
        self.assertIsNone(fact["disabled"])
        self.assertEqual(
            fact["local_address"], {"interface": None, "ip": None, "floating_ip": None}
        )
        self.assertEqual(
            fact["protocol"], {"version": None, "ikev1_profile": None, "ikev2_profile": None}
        )

    def test_fqdn_and_dynamic_peers_are_not_resolved(self):
        facts = self.parse(
            gateways(
                '<entry name="fqdn"><peer-address><fqdn>vpn.example.invalid</fqdn>'
                "</peer-address></entry>"
                '<entry name="dynamic"><peer-address><dynamic/></peer-address></entry>'
            )
        )["ike_gateways"]
        self.assertEqual(facts[0]["peer_address"]["kind"], "fqdn")
        self.assertEqual(facts[0]["peer_address"]["fqdn"], "vpn.example.invalid")
        self.assertIsNone(facts[0]["peer_address"]["ip"])
        self.assertIs(facts[1]["peer_address"]["dynamic"], True)
        self.assertIsNone(facts[1]["peer_address"]["ip"])

    def test_unknown_version_and_algorithm_values_are_preserved(self):
        raw = '<entry name="future"><protocol><version>ike-future</version></protocol></entry>'
        self.assertEqual(
            self.parse(gateways(raw))["ike_gateways"][0]["protocol"]["version"], "ike-future"
        )
        raw = '<entry name="future"><encryption><member>future-cipher</member></encryption></entry>'
        self.assertEqual(
            self.parse(profile(raw))["ike_crypto_profiles"][0]["encryption"], ["future-cipher"]
        )

    def test_configured_monitor_and_disabled_are_independent_of_runtime(self):
        raw = (
            '<entry name="disabled"><disabled>yes</disabled>'
            "<tunnel-interface>tunnel.5</tunnel-interface>"
            "<tunnel-monitor><enable>no</enable><destination-ip>2001:db8::2</destination-ip>"
            "<tunnel-monitor-profile>recover</tunnel-monitor-profile><proxy-id>v6</proxy-id>"
            "</tunnel-monitor><auto-key/></entry>"
        )
        fact = self.parse(tunnels(raw))["ipsec_tunnels"][0]
        self.assertIs(fact["disabled"], True)
        self.assertEqual(
            fact["monitor"],
            {
                "enabled": False,
                "destination_ip": "2001:db8::2",
                "profile": "recover",
                "proxy_id": "v6",
            },
        )
        self.assertIsNone(fact["auto_key"]["selectors_ipv4"])
        self.assertIsNone(fact["auto_key"]["ike_gateways"])

    def test_ipv4_ipv6_selectors_preserve_prefixes_and_protocol(self):
        raw = (
            '<entry name="dual"><auto-key><proxy-id><entry name="v4">'
            "<local>192.0.2.5/24</local><remote>198.51.100.8/32</remote>"
            "<protocol><tcp><local-port>0</local-port><remote-port>443</remote-port></tcp></protocol>"
            '</entry></proxy-id><proxy-id-v6><entry name="v6">'
            "<local>2001:DB8:1::/64</local><remote>2001:db8:2::1/128</remote>"
            "<protocol><number>58</number></protocol></entry></proxy-id-v6></auto-key></entry>"
        )
        auto = self.parse(tunnels(raw))["ipsec_tunnels"][0]["auto_key"]
        self.assertEqual(auto["selectors_ipv4"][0]["local"], "192.0.2.5/24")
        self.assertEqual(
            auto["selectors_ipv4"][0]["protocol"],
            {
                "kind": "tcp",
                "number": None,
                "local_port": 0,
                "remote_port": 443,
            },
        )
        self.assertEqual(auto["selectors_ipv6"][0]["local"], "2001:DB8:1::/64")
        self.assertEqual(auto["selectors_ipv6"][0]["protocol"]["number"], 58)

    def test_any_udp_and_missing_selector_protocol_are_explicit(self):
        raw = (
            '<entry name="t"><auto-key><proxy-id>'
            '<entry name="any"><protocol><any/></protocol></entry>'
            '<entry name="udp"><protocol><udp><remote-port>53</remote-port>'
            "</udp></protocol></entry>"
            '<entry name="none"/></proxy-id></auto-key></entry>'
        )
        rows = self.parse(tunnels(raw))["ipsec_tunnels"][0]["auto_key"]["selectors_ipv4"]
        self.assertEqual([row["protocol"]["kind"] for row in rows], ["any", "udp", None])
        self.assertIsNone(rows[1]["protocol"]["local_port"])
        self.assertIsNone(rows[2]["local"])

    def test_manual_key_retains_only_safe_configured_identifiers(self):
        raw = (
            '<entry name="manual"><manual-key><local-address><interface>ethernet1/2</interface>'
            "<floating-ip>192.0.2.1</floating-ip></local-address><peer-address><ip>192.0.2.2</ip>"
            "</peer-address><local-spi>0000abcd</local-spi><remote-spi>0x00001234</remote-spi>"
            "<esp/></manual-key></entry>"
        )
        fact = self.parse(tunnels(raw))["ipsec_tunnels"][0]
        self.assertEqual(fact["mode"], "manual-key")
        self.assertIsNone(fact["auto_key"])
        self.assertEqual(fact["manual_key"]["local_spi"], "0000abcd")
        self.assertEqual(fact["manual_key"]["protocol"], "esp")
        self.assertEqual(fact["manual_key"]["local_address"]["floating_ip"], "192.0.2.1")

    def test_unknown_mode_does_not_invent_auto_key(self):
        facts = self.parse(tunnels('<entry name="future"><future-mode/></entry>'))["ipsec_tunnels"][
            0
        ]
        self.assertEqual(facts["mode"], "unknown")
        self.assertIsNone(facts["mode_observed"])
        self.assertIsNone(facts["auto_key"])
        self.assertIsNone(facts["manual_key"])

    def test_profile_empty_lists_absent_options_and_explicit_units(self):
        raw = '<entry name="empty"><encryption/><lifetime><seconds>900</seconds></lifetime></entry>'
        fact = self.parse(profile(raw))["ike_crypto_profiles"][0]
        self.assertEqual(fact["encryption"], [])
        self.assertIsNone(fact["hash"])
        self.assertEqual(
            fact["lifetime"], {"seconds": 900, "minutes": None, "hours": None, "days": None}
        )
        raw = (
            '<entry name="ah"><ah><authentication><member>sha384</member></authentication></ah>'
            "<lifesize><gb>4</gb></lifesize></entry>"
        )
        fact = self.parse(profile(raw, "ipsec"))["ipsec_crypto_profiles"][0]
        self.assertEqual(fact["ah"]["authentication"], ["sha384"])
        self.assertIsNone(fact["esp"]["encryption"])
        self.assertEqual(fact["lifesize"]["gb"], 4)

    def test_duplicate_names_are_rejected_in_every_named_collection(self):
        cases = [
            gateways('<entry name="same"/><entry name="same"/>'),
            tunnels('<entry name="same"/><entry name="same"/>'),
            profile('<entry name="same"/><entry name="same"/>'),
            profile('<entry name="same"/><entry name="same"/>', "ipsec"),
            tunnels(
                '<entry name="t"><auto-key><ike-gateway><entry name="same"/>'
                '<entry name="same"/></ike-gateway></auto-key></entry>'
            ),
            tunnels(
                '<entry name="t"><auto-key><proxy-id><entry name="same"/>'
                '<entry name="same"/></proxy-id></auto-key></entry>'
            ),
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(vpn.DiscoveryError):
                self.parse(raw)

    def test_duplicate_intermediate_containers_and_scalars_fail(self):
        cases = [
            response("<ike/><ike/>"),
            gateways('<entry name="g"><protocol/><protocol/></entry>'),
            gateways('<entry name="g"><disabled>no</disabled><disabled>no</disabled></entry>'),
            profile(
                '<entry name="p"><lifetime><hours>1</hours><hours>2</hours></lifetime></entry>'
            ),
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(vpn.DiscoveryError):
                self.parse(raw)

    def test_conflicting_configuration_choices_fail(self):
        cases = [
            gateways(
                '<entry name="g"><peer-address><ip>192.0.2.1</ip><dynamic/></peer-address></entry>'
            ),
            gateways(
                '<entry name="g"><local-address><ip>192.0.2.1</ip>'
                "<floating-ip>192.0.2.2</floating-ip></local-address></entry>"
            ),
            tunnels('<entry name="t"><auto-key/><manual-key/></entry>'),
            tunnels('<entry name="t"><manual-key><esp/><ah/></manual-key></entry>'),
            tunnels(
                '<entry name="t"><auto-key><proxy-id><entry name="s">'
                "<protocol><any/><tcp/></protocol></entry></proxy-id></auto-key></entry>"
            ),
            profile(
                '<entry name="p"><lifetime><seconds>60</seconds><hours>1</hours></lifetime></entry>'
            ),
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(vpn.DiscoveryError):
                self.parse(raw)

    def test_malformed_typed_values_are_not_extracted_or_defaulted(self):
        for value in ("false", "YES", "", "no extra"):
            with self.subTest(value=value), self.assertRaises(vpn.DiscoveryError):
                self.parse(gateways('<entry name="g"><disabled>' + value + "</disabled></entry>"))
        for value in ("1 hour", "-1", "", "18446744073709551616"):
            with self.subTest(value=value), self.assertRaises(vpn.DiscoveryError):
                self.parse(
                    profile(
                        '<entry name="p"><lifetime><hours>' + value + "</hours></lifetime></entry>"
                    )
                )
        for value in ("not-an-address", "192.0.2.1/99"):
            with self.subTest(value=value), self.assertRaises(vpn.DiscoveryError):
                self.parse(
                    gateways(
                        '<entry name="g"><peer-address><ip>'
                        + value
                        + "</ip></peer-address></entry>"
                    )
                )
        with self.assertRaises(vpn.DiscoveryError):
            self.parse(
                tunnels(
                    '<entry name="t"><manual-key><local-spi>extract-deadbeef-here</local-spi>'
                    "</manual-key></entry>"
                )
            )

    def test_selector_family_and_port_bounds_fail(self):
        for selector in (
            "<local>2001:db8::/64</local>",
            "<protocol><tcp><remote-port>65536</remote-port></tcp></protocol>",
            "<protocol><number>256</number></protocol>",
        ):
            raw = (
                '<entry name="t"><auto-key><proxy-id><entry name="s">'
                + selector
                + "</entry></proxy-id></auto-key></entry>"
            )
            with self.subTest(selector=selector), self.assertRaises(vpn.DiscoveryError):
                self.parse(tunnels(raw))

    def test_complete_success_and_expected_network_parent_are_required(self):
        cases = [
            '<response status="error"><msg>private diagnostic</msg></response>',
            "<response><result><network/></result></response>",
            '<response status="success"><result/></response>',
            '<response status="success"><result><network/><network/></result></response>',
            '<response status="success"><result><gateway/></result></response>',
            '<response status="success"><result><network/><other/></result></response>',
            '<response status="success"><result><![CDATA[display output]]></result></response>',
            response("<ike><gateway><![CDATA[display output]]></gateway></ike>"),
            response('<ike><gateway><entry name="g"/>unexpected tail</gateway></ike>'),
            response("<ike><gateway><member>display</member></gateway></ike>"),
            "Server error : No such node",
            response()[:-5],
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(vpn.DiscoveryError):
                self.parse(raw)

    def test_exact_echo_and_prompt_are_allowed_without_scraping(self):
        raw = transport.RUNNING_VPN + "\n" + response() + "\nadmin@lab(active)>"
        self.assertEqual(self.parse(raw)["ike_gateways"], [])
        with self.assertRaises(vpn.DiscoveryError):
            self.parse("unrelated display\n" + raw)
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_configuration(response(), command="unreviewed command")

    def test_embedded_errors_in_selected_collections_fail_without_echo(self):
        valid_rows = [
            gateways('<entry name="g"><disabled>no</disabled></entry>'),
            tunnels('<entry name="t"><auto-key/></entry>'),
            profile(
                '<entry name="p"><encryption><member>aes-256-cbc</member></encryption></entry>'
            ),
            profile('<entry name="p"><dh-group>group14</dh-group></entry>', "ipsec"),
        ]
        for raw in valid_rows:
            for tag in ("error", "errors", "errmsg", "error-message", "msg", "{urn:test}error"):
                root = ET.fromstring(raw)
                entry = root.find(".//entry")
                unknown = ET.SubElement(entry, "unreviewed-container")
                ET.SubElement(unknown, tag).text = "SYNTHETIC-PRIVATE-DIAGNOSTIC"
                with self.subTest(tag=tag), self.assertRaises(vpn.DiscoveryError) as error:
                    self.parse(ET.tostring(root, encoding="unicode"))
                self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))
                self.assertNotIn("<" + tag, str(error.exception))

    def test_semantic_error_status_in_unknown_selected_fields_fails(self):
        root = ET.fromstring(gateways('<entry name="g"><disabled>no</disabled></entry>'))
        field = ET.SubElement(root.find(".//entry"), "unreviewed-field", {"status": "ERROR"})
        field.text = "SYNTHETIC-PRIVATE-DIAGNOSTIC"
        with self.assertRaises(vpn.DiscoveryError) as error:
            self.parse(ET.tostring(root, encoding="unicode"))
        self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))

    def test_ancestor_errors_do_not_become_absent_configuration(self):
        for path in (
            "result",
            "result/network",
            "result/network/ike",
            "result/network/tunnel",
            "result/network/ike/crypto-profiles",
        ):
            root = ET.fromstring(response("<ike><crypto-profiles/></ike><tunnel/>"))
            node = root.find(path)
            ET.SubElement(node, "msg").text = "SYNTHETIC-PRIVATE-DIAGNOSTIC"
            with self.subTest(path=path), self.assertRaises(vpn.DiscoveryError) as error:
                self.parse(ET.tostring(root, encoding="unicode"))
            self.assertNotIn("SYNTHETIC-PRIVATE", str(error.exception))
        for path in ("result", "result/network", "result/network/ike"):
            root = ET.fromstring(response("<ike/>"))
            root.find(path).set("status", "error")
            with self.subTest(path=path), self.assertRaises(vpn.DiscoveryError):
                self.parse(ET.tostring(root, encoding="unicode"))

    def test_errors_inside_discarded_network_branches_are_not_vpn_evidence(self):
        raw = response(
            '<interface status="error"><error>SYNTHETIC-PRIVATE-DIAGNOSTIC</error></interface>'
            '<ike><unreviewed status="error"><msg>SYNTHETIC-PRIVATE-DIAGNOSTIC</msg>'
            '</unreviewed><gateway><entry name="g"><disabled>no</disabled></entry></gateway></ike>'
        )
        facts = self.parse(raw)
        self.assertEqual(facts["ike_gateways"][0]["name"], "g")
        self.assertEqual(facts["ipsec_tunnels"], [])
        self.assertNotIn("SYNTHETIC-PRIVATE", json.dumps(facts))

    def test_all_secret_and_unrelated_branches_are_discarded(self):
        root = ET.fromstring(
            gateways('<entry name="safe"><protocol><version>ikev2</version></protocol></entry>')
        )
        gateway = root.find("result/network/ike/gateway/entry")
        blocked = ["pre-shared-key", "private-key", "auth-hash", "username", "password", "secret"]
        for tag in blocked:
            node = ET.SubElement(gateway, tag)
            ET.SubElement(node, "key").text = "SYNTHETIC-SENSITIVE-" + tag
        auth = ET.SubElement(gateway, "authentication")
        ET.SubElement(auth, "certificate").text = "SYNTHETIC-SENSITIVE-CERTIFICATE"
        protocol = gateway.find("protocol")
        ET.SubElement(protocol, "future-key-container").text = "SYNTHETIC-SENSITIVE-FUTURE"
        unrelated = ET.SubElement(root.find("result/network"), "unrelated")
        ET.SubElement(unrelated, "credential").text = "SYNTHETIC-SENSITIVE-UNRELATED"
        facts = json.dumps(self.parse(ET.tostring(root, encoding="unicode")))
        for value in [*blocked, "SYNTHETIC-SENSITIVE", "future-key-container", "credential"]:
            self.assertNotIn(value, facts)

    def test_secret_values_never_appear_in_structural_errors(self):
        raw = gateways(
            '<entry name="g"><disabled><secret>SYNTHETIC-SENSITIVE</secret></disabled></entry>'
        )
        with self.assertRaises(vpn.DiscoveryError) as error:
            self.parse(raw)
        self.assertNotIn("SYNTHETIC-SENSITIVE", str(error.exception))
        self.assertNotIn("<secret>", str(error.exception))

    def test_fixture_contains_no_key_bearing_or_unrelated_subtrees(self):
        root = ET.fromstring((FIXTURES / "panos_vpn_applied_network.xml").read_text())
        for node in root.iter():
            self.assertNotIn(
                node.tag,
                {
                    "key",
                    "pre-shared-key",
                    "private-key",
                    "auth-hash",
                    "password",
                    "username",
                    "secret",
                    "virtual-router",
                },
            )
        self.assertEqual(root.findall("result/network/ike/gateway/entry/authentication"), [])


if __name__ == "__main__":
    unittest.main()
