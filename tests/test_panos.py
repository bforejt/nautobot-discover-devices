"""Strict PAN-OS parser tests; source fixtures and synthetic applied cases."""

import unittest
from pathlib import Path
from unittest.mock import Mock

from tests._loader import load

panos = load("adapters.panos")
transport = load("transport_ssh")
FIXTURES = Path(__file__).parent / "fixtures"


def output(name):
    return (FIXTURES / name).read_text()


class PanosParserTests(unittest.TestCase):
    def setUp(self):
        self.system = output("panos_system_info.txt")
        self.ports = output("panos_interfaces.txt")
        self.running = output("panos_applied_interfaces.xml")

    def parse(self, ports=None, running=None):
        return panos.parse_interfaces(
            ports if ports is not None else self.ports,
            panos.parse_running_interfaces(running if running is not None else self.running),
        )

    def test_identity_exact_release_and_context_are_separate(self):
        identity, context = panos.parse_system_info(self.system)
        self.assertEqual(identity["model"], "PA-5250")
        self.assertEqual(identity["software_version"], "11.1.4-h7")
        self.assertEqual(context["multi-vsys"], "off")
        self.assertNotIn("app-version", identity)

    def test_missing_and_placeholder_serial_are_not_identity(self):
        for value in ("unknown", "none", "N/A", "0", ""):
            raw = self.system.replace("013201000001", value)
            self.assertIsNone(panos.parse_system_info(raw)[0]["serial"])

    def test_complete_hardware_names_retain_down_unaddressed_port(self):
        facts, excluded, warnings, observations = self.parse()
        self.assertEqual(
            [row["name"] for row in facts], ["ethernet1/1", "ethernet1/2", "ethernet1/7"]
        )
        last = facts[-1]
        self.assertIs(last["enabled"], False)
        self.assertIsNone(last["type"])
        self.assertIsNone(last["mac_address"])
        self.assertEqual(last["source"]["link_state"], "down")
        self.assertEqual(len(observations), 6)
        self.assertEqual(len(excluded), 3)
        self.assertTrue(warnings)

    def test_configured_description_mtu_and_evidence_are_retained(self):
        fact = self.parse()[0][0]
        self.assertEqual(fact["description"], "External interface")
        self.assertEqual(fact["mtu"], 1500)
        self.assertEqual(fact["source"]["mtu"], "1500")
        self.assertEqual(fact["source"]["contract"], "panos-interface-v1")
        self.assertEqual(fact["source"]["applied_command"], transport.RUNNING_INTERFACES)

    def test_operational_down_never_sets_admin_state(self):
        raw = self.running.replace("<link-state>down</link-state>", "")
        self.assertIsNone(self.parse(running=raw)[0][-1]["enabled"])

    def test_auto_admin_state_remains_unresolved(self):
        raw = self.running.replace("<link-state>up</link-state>", "<link-state>auto</link-state>")
        self.assertIsNone(self.parse(running=raw)[0][0]["enabled"])

    def test_multiple_logical_addresses_join_one_hardware_identity(self):
        extra = "<entry><name>ethernet1/1</name><id>16</id><ip>203.0.113.11/28</ip></entry>"
        raw = self.ports.replace("</ifnet>", extra + "</ifnet>")
        facts, _, _, observations = self.parse(ports=raw)
        self.assertEqual(len(facts), 3)
        self.assertEqual(len(observations[0]["logical"]), 2)

    def test_conflicting_logical_identity_defers_port_writes(self):
        raw = self.ports.replace("<id>16</id><addr/>", "<id>900</id><addr/>")
        facts, excluded, _, observations = self.parse(ports=raw)
        self.assertNotIn("ethernet1/1", [row["name"] for row in facts])
        self.assertIn(
            "ambiguous hardware/logical identity join", [row["reason"] for row in excluded]
        )
        self.assertEqual(len(observations), 6)

    def test_duplicate_hardware_identity_fails_collection(self):
        extra = "<entry><name>ethernet1/1</name><id>16</id></entry>"
        with self.assertRaises(panos.DiscoveryError):
            self.parse(ports=self.ports.replace("</hw>", extra + "</hw>"))

    def test_duplicate_hardware_id_under_different_names_fails(self):
        with self.assertRaises(panos.DiscoveryError):
            self.parse(ports=self.ports.replace("<id>22</id>", "<id>16</id>"))

    def test_container_display_text_is_not_structured_inventory(self):
        for raw in (
            self.ports.replace("<hw>", "<hw>Server error"),
            self.ports.replace("</hw>", "</hw>Server error"),
        ):
            with self.assertRaises(panos.DiscoveryError):
                self.parse(ports=raw)

    def test_repeated_configuration_mode_is_ambiguous(self):
        raw = self.running.replace("</layer3>", "</layer3><layer3/>")
        with self.assertRaises(panos.DiscoveryError):
            self.parse(running=raw)

    def test_applied_credentials_are_not_retained_in_reports(self):
        raw = self.running.replace(
            "</layer3>",
            "<pppoe><username>example-user</username><password>example-password</password>"
            "</pppoe></layer3>",
        )
        facts, _, _, observations = self.parse(running=raw)
        self.assertNotIn("example-password", str((facts, observations)))
        self.assertNotIn("example-user", str((facts, observations)))

    def test_duplicate_applied_identity_fails_collection(self):
        raw = self.running.replace("</ethernet>", '<entry name="ethernet1/1"/></ethernet>')
        with self.assertRaises(panos.DiscoveryError):
            self.parse(running=raw)

    def test_missing_expected_containers_are_not_empty_inventory(self):
        for raw in (
            '<response status="success"><result/></response>',
            '<response status="success"><result><hw/></result></response>',
        ):
            with self.subTest(raw=raw), self.assertRaises(panos.DiscoveryError):
                self.parse(ports=raw)

    def test_explicit_empty_containers_are_accepted_with_no_completeness_claim(self):
        facts, excluded, _, observations = self.parse(
            ports='<response status="success"><result><hw/><ifnet/></result></response>',
            running=(
                '<response status="success"><result><interface>'
                "<ethernet/></interface></result></response>"
            ),
        )
        self.assertEqual((facts, excluded, observations), ([], [], []))

    def test_numeric_mtu_never_extracts_arbitrary_embedded_number(self):
        for value in ("1500 bytes", "unknown1500", "-1500", "0", "65537", "9" * 5000):
            facts = self.parse(
                running=self.running.replace("<mtu>1500</mtu>", "<mtu>%s</mtu>" % value)
            )[0]
            self.assertIsNone(facts[0]["mtu"])

    def test_unsuccessful_or_incomplete_responses_never_supply_facts(self):
        for raw in (
            self.system.replace('status="success"', 'status="error"'),
            self.system.replace(' status="success"', ""),
            self.system[: self.system.rfind("</response>")],
            "show system info\nmodel PA-5250\nserial 013201000001",
            self.system + '<response status="success"><result>',
        ):
            with self.subTest(raw=raw[:50]), self.assertRaises(panos.DiscoveryError) as raised:
                panos.parse_system_info(raw)
            self.assertNotIn("013201000001", str(raised.exception))

    def test_xml_error_body_and_entities_are_never_exposed(self):
        for raw in (
            '<response status="error"><msg>example-password</msg></response>',
            (
                '<!DOCTYPE response [<!ENTITY x "example-password">]>'
                '<response status="success"><result>&x;</result></response>'
            ),
        ):
            with self.assertRaises(panos.DiscoveryError) as raised:
                panos.parse_system_info(raw)
            self.assertNotIn("example-password", str(raised.exception))

    def test_identity_containers_reject_mixed_display_text(self):
        for raw in (
            self.system.replace(
                '<response status="success">', '<response status="success">Server error'
            ),
            self.system.replace("<system>", "<system>Server error"),
        ):
            with self.assertRaises(panos.DiscoveryError):
                panos.parse_system_info(raw)

    def test_repeated_scalars_and_nested_identity_fail(self):
        for extra in ("<model>PA-VM</model>", "<serial><nested/></serial>"):
            with self.assertRaises(panos.DiscoveryError):
                panos.parse_system_info(self.system.replace("</system>", extra + "</system>"))

    def test_cli_echo_and_prompt_framing_do_not_allow_extra_documents(self):
        raw = self.system.strip() + "\nadmin@fw-edge-01>"
        self.assertEqual(panos.parse_system_info(raw)[0]["model"], "PA-5250")
        with self.assertRaises(panos.DiscoveryError):
            panos.parse_system_info(raw + "\nServer error")

    def test_collection_has_fixed_reads_and_guessing_does_not_change_facts(self):
        payloads = {
            transport.SYSTEM_INFO: self.system,
            transport.INTERFACES: self.ports,
            transport.RUNNING_INTERFACES: self.running,
        }
        client = Mock(run=Mock(side_effect=lambda command: payloads[command]))
        strict = panos.collect(client)
        self.assertEqual([call.args[0] for call in client.run.call_args_list], list(payloads))
        self.assertEqual(strict, panos.collect(client, use_ntc_defaults=True))
        self.assertFalse(panos.observed_physical_ethernet(strict["interfaces"][0], "ethernet1/1"))


if __name__ == "__main__":
    unittest.main()
