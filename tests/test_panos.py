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


def vm_payloads():
    return {
        transport.SYSTEM_INFO: output("panos_vm_system_info.xml"),
        transport.INTERFACES: output("panos_vm_empty_interfaces.xml"),
        transport.RUNNING_INTERFACES: (
            '<response status="success"><result><interface><ethernet>'
            '<entry name="ethernet1/1"><link-state>up</link-state><comment>VM up port</comment>'
            "<layer3><mtu>1400</mtu></layer3></entry>"
            '<entry name="ethernet1/2"><link-state>down</link-state><comment>VM down port</comment>'
            "<layer3><mtu>1500</mtu></layer3></entry>"
            "</ethernet></interface></result></response>"
        ),
        transport.VM_INTERFACES: output("panos_vm_guest_interfaces.xml"),
    }


def vm_post_commit_payloads():
    return {
        transport.SYSTEM_INFO: output("panos_vm_system_info.xml"),
        transport.INTERFACES: output("panos_vm_configured_interfaces.xml"),
        transport.RUNNING_INTERFACES: output("panos_vm_applied_interfaces.xml"),
        transport.VM_INTERFACES: output("panos_vm_guest_interfaces.xml"),
    }


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

    def test_vm_diagnostic_fixture_has_exact_names_and_guest_identity(self):
        rows = panos.parse_vm_interfaces(output("panos_vm_guest_interfaces.xml"))
        self.assertEqual(
            [row["name"] for row in rows], ["ethernet1/1", "ethernet1/2", "ethernet1/3"]
        )
        self.assertEqual(rows[0]["raw_name"], "Ethernet1/1")
        self.assertEqual(rows[0]["base_os_port"], "eth1")
        self.assertEqual(rows[0]["base_os_bus"], "0000:00:13.0")
        self.assertEqual(rows[0]["base_os_mac"], "02:00:00:00:00:01")
        self.assertNotIn("type", rows[0])

    def test_vm_collection_enumerates_unconfigured_guest_port_without_native_defaults(self):
        payloads = vm_payloads()
        client = Mock(run=Mock(side_effect=payloads.__getitem__))
        result = panos.collect(client)
        self.assertEqual([call.args[0] for call in client.run.call_args_list], list(payloads))
        self.assertEqual(
            [row["name"] for row in result["interfaces"]],
            ["ethernet1/1", "ethernet1/2", "ethernet1/3"],
        )
        self.assertIs(result["interfaces"][0]["enabled"], True)
        self.assertIs(result["interfaces"][1]["enabled"], False)
        self.assertIsNone(result["interfaces"][2]["enabled"])
        self.assertEqual(result["interfaces"][0]["mtu"], 1400)
        self.assertEqual(result["interfaces"][1]["description"], "VM down port")
        self.assertEqual(result["interfaces"][0]["source"]["contract"], "panos-vm-interface-v1")
        self.assertEqual(
            result["sources"]["vm_interfaces"],
            {"command": transport.VM_INTERFACES, "path": "result/entry"},
        )
        self.assertEqual(len(result["observations"]["vm_interfaces"]), 3)
        for fact in result["interfaces"]:
            for field in ("type", "mac_address", "speed", "duplex", "port_type", "mgmt_only"):
                self.assertIsNone(fact[field])
            self.assertIs(fact["physical_ethernet"], False)
        self.assertEqual(result, panos.collect(client, use_ntc_defaults=True))

    def test_post_commit_vm_fixtures_keep_configured_and_unconfigured_ports(self):
        payloads = vm_post_commit_payloads()
        result = panos.collect(Mock(run=Mock(side_effect=payloads.__getitem__)))
        facts = result["interfaces"]
        self.assertEqual(
            [row["name"] for row in facts], ["ethernet1/1", "ethernet1/2", "ethernet1/3"]
        )
        self.assertEqual([row["enabled"] for row in facts], [True, False, None])
        self.assertEqual([row["mtu"] for row in facts], [1400, 1500, None])
        self.assertEqual(
            [row["source"]["contract"] for row in facts],
            ["panos-interface-v1", "panos-interface-v1", "panos-vm-interface-v1"],
        )
        self.assertEqual(facts[2]["source"]["raw_name"], "Ethernet1/3")
        self.assertEqual(len(result["observations"]["vm_interfaces"]), 3)
        self.assertEqual(len(result["observations"]["interfaces"][0]["hardware"]), 1)
        self.assertEqual(result["observations"]["interfaces"][2]["hardware"], [])
        self.assertTrue(all(row["mac_address"] is None for row in facts))
        self.assertTrue(all(row["type"] is None for row in facts))

    def test_vm_enumeration_requires_the_exact_reviewed_system_context(self):
        for field, before, after in (
            ("model", "PA-VM", "PA-440"),
            ("family", "vm", "hardware"),
            ("vm-mode", "KVM", "ESXi"),
        ):
            with self.subTest(field=field):
                payloads = vm_payloads()
                payloads[transport.SYSTEM_INFO] = payloads[transport.SYSTEM_INFO].replace(
                    "<%s>%s</%s>" % (field, before, field),
                    "<%s>%s</%s>" % (field, after, field),
                )
                client = Mock(run=Mock(side_effect=payloads.__getitem__))
                result = panos.collect(client)
                self.assertEqual(len(client.run.call_args_list), 3)
                self.assertNotIn("vm_interfaces", result["sources"])
                self.assertNotIn("vm_interfaces", result["observations"])

    def test_vm_inventory_empty_is_successful_but_failed_shapes_are_not_empty(self):
        self.assertEqual(
            panos.parse_vm_interfaces('<response status="success"><result/></response>'), []
        )
        valid = output("panos_vm_guest_interfaces.xml")
        for raw in (
            '<response status="error"><result/></response>',
            '<response status="success"/>',
            "<response><result/></response>",
            '<response status="success"><result>display table</result></response>',
            '<response status="success"><result><interfaces/></result></response>',
            valid[: valid.rfind("</response>")],
            "Interface_name Base-OS_port Base-OS_MAC Base-OS_BUS",
        ):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(panos.DiscoveryError):
                    panos.parse_vm_interfaces(raw)

    def test_vm_inventory_missing_nested_and_duplicate_scalars_fail(self):
        valid = output("panos_vm_guest_interfaces.xml")
        for raw in (
            valid.replace("<Interface_name>Ethernet1/1</Interface_name>", "", 1),
            valid.replace("<Base-OS_port>eth1</Base-OS_port>", "<Base-OS_port/>", 1),
            valid.replace("<Base-OS_BUS>0000:00:13.0</Base-OS_BUS>", "", 1),
            valid.replace(
                "<Base-OS_BUS>0000:00:13.0</Base-OS_BUS>", "<Base-OS_BUS>PCI 13</Base-OS_BUS>", 1
            ),
            valid.replace(
                "<Base-OS_port>eth1</Base-OS_port>", "<Base-OS_port><nested/></Base-OS_port>", 1
            ),
            valid.replace(
                "<Base-OS_port>eth1</Base-OS_port>",
                "<Base-OS_port>eth1</Base-OS_port><Base-OS_port>eth9</Base-OS_port>",
                1,
            ),
            valid.replace("<entry>", '<entry name="ignored-identity">', 1),
        ):
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(panos.DiscoveryError):
                    panos.parse_vm_interfaces(raw)

    def test_vm_inventory_duplicate_canonical_names_ports_and_buses_fail(self):
        valid = output("panos_vm_guest_interfaces.xml")
        for before, after in (
            ("Ethernet1/2", "ethernet1/1"),
            ("<Base-OS_port>eth2</Base-OS_port>", "<Base-OS_port>eth1</Base-OS_port>"),
            ("0000:00:14.0", "0000:00:13.0"),
        ):
            with self.subTest(before=before):
                with self.assertRaises(panos.DiscoveryError):
                    panos.parse_vm_interfaces(valid.replace(before, after))

    def test_vm_inventory_mac_is_optional_and_never_a_guest_identity_key(self):
        valid = output("panos_vm_guest_interfaces.xml")
        duplicate_mac = valid.replace("02:00:00:00:00:02", "02:00:00:00:00:01")
        self.assertEqual(len(panos.parse_vm_interfaces(duplicate_mac)), 3)
        omitted_mac = valid.replace("<Base-OS_MAC>02:00:00:00:00:01</Base-OS_MAC>", "")
        self.assertIsNone(panos.parse_vm_interfaces(omitted_mac)[0]["base_os_mac"])

    def test_vm_management_and_unknown_kinds_remain_report_only(self):
        payloads = vm_payloads()
        extra = (
            "<entry><Interface_name>mgt</Interface_name><Base-OS_port>eth0</Base-OS_port>"
            "<Base-OS_BUS>0000:00:12.0</Base-OS_BUS></entry>"
            "<entry><Interface_name>future-kind</Interface_name><Base-OS_port>eth4</Base-OS_port>"
            "<Base-OS_BUS>0000:00:16.0</Base-OS_BUS><Future_scalar>value</Future_scalar></entry>"
        )
        payloads[transport.VM_INTERFACES] = payloads[transport.VM_INTERFACES].replace(
            "</result>", extra + "</result>"
        )
        result = panos.collect(Mock(run=Mock(side_effect=payloads.__getitem__)))
        self.assertEqual(len(result["interfaces"]), 3)
        self.assertEqual(len(result["observations"]["vm_interfaces"]), 5)
        self.assertEqual(
            {row["name"] for row in result["excluded_interfaces"]}, {"mgt", "future-kind"}
        )

    def test_vm_enumeration_read_failure_blocks_collection_instead_of_partial_facts(self):
        payloads = vm_payloads()
        payloads[transport.VM_INTERFACES] = '<response status="error"><result/></response>'
        with self.assertRaises(panos.DiscoveryError):
            panos.collect(Mock(run=Mock(side_effect=payloads.__getitem__)))

    def test_operational_guest_name_absent_from_complete_vm_inventory_fails(self):
        payloads = vm_payloads()
        payloads[transport.INTERFACES] = self.ports
        with self.assertRaisesRegex(panos.DiscoveryError, "disagree"):
            panos.collect(Mock(run=Mock(side_effect=payloads.__getitem__)))

    def test_vm_guest_proof_never_repairs_ambiguous_hardware_logical_join(self):
        payloads = vm_payloads()
        payloads[transport.INTERFACES] = self.ports.replace(
            "<id>16</id><addr/>", "<id>900</id><addr/>"
        )
        payloads[transport.VM_INTERFACES] = payloads[transport.VM_INTERFACES].replace(
            "Ethernet1/3", "Ethernet1/7"
        )
        result = panos.collect(Mock(run=Mock(side_effect=payloads.__getitem__)))
        self.assertNotIn("ethernet1/1", [row["name"] for row in result["interfaces"]])
        excluded = next(
            row for row in result["excluded_interfaces"] if row["name"] == "ethernet1/1"
        )
        self.assertEqual(excluded["reason"], "ambiguous hardware/logical identity join")
        self.assertTrue(
            all(row["source"]["contract"] == "panos-interface-v1" for row in result["interfaces"])
        )

    def test_normal_hardware_subset_keeps_existing_source_and_adds_only_absent_guest_rows(self):
        payloads = vm_payloads()
        payloads[transport.INTERFACES] = (
            '<response status="success"><result><hw>'
            "<entry><name>ethernet1/1</name><id>16</id></entry>"
            "</hw><ifnet/></result></response>"
        )
        result = panos.collect(Mock(run=Mock(side_effect=payloads.__getitem__)))
        self.assertEqual(len(result["interfaces"]), 3)
        self.assertEqual(result["interfaces"][0]["source"]["contract"], "panos-interface-v1")
        self.assertEqual(result["interfaces"][1]["source"]["contract"], "panos-vm-interface-v1")
        self.assertEqual(result["interfaces"][2]["source"]["contract"], "panos-vm-interface-v1")

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
