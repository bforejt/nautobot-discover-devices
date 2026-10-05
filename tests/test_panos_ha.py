"""Actual HA source contracts, missing-data semantics and adversarial payloads."""

import json
import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

from tests._loader import load

ha = load("adapters.panos_ha")
panos = load("adapters.panos")
FIXTURES = Path(__file__).parent / "fixtures"


def output(name):
    return (FIXTURES / name).read_text()


def change(raw, path, *, value=None, remove=False, duplicate=False, child=None):
    root = ET.fromstring(raw)
    node = root.find(path)
    if node is None:
        raise AssertionError("Test source path does not exist: " + path)
    if remove or duplicate:
        parent_path = path.rsplit("/", 1)[0]
        parent = root.find(parent_path)
        if remove:
            parent.remove(node)
        else:
            parent.append(deepcopy(node))
    elif child is not None:
        node.append(ET.fromstring(child))
    else:
        node.text = value
    return ET.tostring(root, encoding="unicode")


class HaRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.active = output("panos_ha_active.xml")
        self.passive = output("panos_ha_passive.xml")
        self.disabled = output("panos_ha_disabled.xml")

    def test_actual_roles_links_and_sync_are_separate(self):
        active = ha.parse_ha_state(self.active)
        passive = ha.parse_ha_state(self.passive)
        self.assertIs(active["enabled"], True)
        self.assertEqual(active["local"]["role"], "active")
        self.assertEqual(active["peer"]["role"], "passive")
        self.assertEqual(passive["local"]["role"], "passive")
        self.assertEqual(passive["peer"]["role"], "active")
        self.assertEqual(active["links"]["ha1"]["peer_status"], "up")
        self.assertEqual(active["links"]["ha2"]["peer_status"], "up")
        self.assertEqual(active["synchronization"]["state_status"], "Complete")
        self.assertEqual(active["synchronization"]["running_config_status"], "synchronized")
        self.assertNotIn("healthy", active)
        self.assertNotIn("group_id", active)

    def test_blank_serial_and_missing_uuid_never_bind_peer_identity(self):
        fact = ha.parse_ha_state(self.active)
        self.assertIsNone(fact["local"]["serial"])
        self.assertIsNone(fact["peer"]["serial"])
        self.assertIsNone(fact["peer"]["vm_uuid"])
        self.assertIs(fact["peer_identity_resolved"], False)
        self.assertEqual(fact["peer"]["management_ip"], "192.0.2.102/24")
        self.assertEqual(fact["source"]["fields"]["peer.serial"]["presence"], "blank")
        self.assertEqual(fact["local"]["vm_license_reported"], "vm8000")
        self.assertNotIn("licensed", fact["local"])

    def test_missing_serial_has_different_provenance_from_present_blank(self):
        raw = change(self.active, "result/group/peer-info/serial-num", remove=True)
        fact = ha.parse_ha_state(raw)
        self.assertIsNone(fact["peer"]["serial"])
        self.assertEqual(fact["source"]["fields"]["peer.serial"]["presence"], "absent")

    def test_unreviewed_uuid_leaf_does_not_expand_identity_contract(self):
        raw = change(
            self.active,
            "result/group/peer-info",
            child="<vm-uuid>22222222-2222-4222-8222-222222222222</vm-uuid>",
        )
        self.assertIsNone(ha.parse_ha_state(raw)["peer"]["vm_uuid"])

    def test_disabled_ha_is_a_valid_explicit_false_with_unknown_other_fields(self):
        fact = ha.parse_ha_state(self.disabled)
        self.assertIs(fact["enabled"], False)
        self.assertIsNone(fact["mode"])
        self.assertIsNone(fact["local"]["role"])
        self.assertIsNone(fact["links"]["ha1"]["peer_status"])
        self.assertIsNone(fact["synchronization"]["state_status"])
        self.assertEqual(fact["source"]["contract"], "panos-ha-v1")

    def test_disabled_response_without_group_is_also_explicit_false(self):
        raw = '<response status="success"><result><enabled>no</enabled></result></response>'
        self.assertIs(ha.parse_ha_state(raw)["enabled"], False)

    def test_missing_link_does_not_default_to_up_or_down(self):
        raw = change(self.active, "result/group/peer-info/conn-ha1", remove=True)
        fact = ha.parse_ha_state(raw)
        self.assertIsNone(fact["links"]["ha1"]["peer_status"])
        self.assertIsNone(fact["links"]["ha1"]["peer_primary"])
        self.assertEqual(fact["links"]["ha1"]["local_port"], "ethernet1/2")
        self.assertEqual(fact["links"]["ha2"]["peer_status"], "up")
        self.assertEqual(fact["synchronization"]["state_status"], "Complete")

    def test_missing_enabled_remains_unknown_when_other_group_evidence_exists(self):
        raw = change(self.active, "result/enabled", remove=True)
        self.assertIsNone(ha.parse_ha_state(raw)["enabled"])

    def test_empty_missing_or_enabled_group_structure_is_unsupported(self):
        for result in (
            "",
            "<group/>",
            "<enabled>yes</enabled>",
            "<enabled>yes</enabled><group/>",
            "<group><unreviewed-group-schema/></group>",
            "<enabled>yes</enabled><group><unreviewed-group-schema/></group>",
        ):
            with self.subTest(result=result), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(
                    '<response status="success"><result>' + result + "</result></response>"
                )

    def test_unknown_safe_enum_tokens_remain_observed_values(self):
        raw = change(self.active, "result/group/local-info/state", value="maintenance")
        raw = change(raw, "result/group/peer-info/conn-ha2/conn-status", value="pending")
        fact = ha.parse_ha_state(raw)
        self.assertEqual(fact["local"]["role"], "maintenance")
        self.assertEqual(fact["links"]["ha2"]["peer_status"], "pending")

    def test_explicit_false_and_counter_zero_are_not_missing(self):
        raw = change(self.active, "result/group/local-info/state-duration", value="0")
        fact = ha.parse_ha_state(raw)
        self.assertIs(fact["local"]["preemptive"], False)
        self.assertEqual(fact["local"]["state_duration"], 0)
        self.assertEqual(fact["links"]["ha2"]["peer_keepalive_hold"], 0)

    def test_blank_counter_is_unknown(self):
        raw = change(self.active, "result/group/local-info/state-duration", value="")
        self.assertIsNone(ha.parse_ha_state(raw)["local"]["state_duration"])

    def test_invalid_nonblank_counter_fails_instead_of_defaulting(self):
        for value in ("-1", "+1", "1.5", "NaN", "18446744073709551616"):
            raw = change(self.active, "result/group/local-info/state-duration", value=value)
            with self.subTest(value=value), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(raw)

    def test_invalid_explicit_boolean_fails(self):
        for value in ("True", "False", "1", "0", "YES", "unknown"):
            raw = change(self.active, "result/enabled", value=value)
            with self.subTest(value=value), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(raw)

    def test_invalid_address_and_wrong_family_fail(self):
        for value in ("999.0.0.1", "peer.example.test", "192.0.2.1/99", "2001:db8::1"):
            raw = change(self.active, "result/group/peer-info/mgmt-ip", value=value)
            with self.subTest(value=value), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(raw)

    def test_explicit_ipv6_locator_is_typed_without_guessing_identity(self):
        raw = change(self.active, "result/group/peer-info/mgmt-ipv6", value="2001:db8::102/64")
        fact = ha.parse_ha_state(raw)
        self.assertEqual(fact["peer"]["management_ipv6"], "2001:db8::102/64")
        self.assertIs(fact["peer_identity_resolved"], False)

    def test_invalid_mac_fails(self):
        raw = change(self.active, "result/group/local-info/ha1-macaddr", value="02:00:00:00:00")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_state(raw)

    def test_priority_out_of_supported_field_bounds_fails(self):
        raw = change(self.active, "result/group/peer-info/priority", value="256")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_state(raw)

    def test_duplicate_fields_and_containers_fail_whole_parse(self):
        for path in (
            "result/enabled",
            "result/group",
            "result/group/local-info",
            "result/group/local-info/state",
            "result/group/peer-info/conn-ha2",
            "result/group/peer-info/conn-ha2/conn-status",
        ):
            raw = change(self.active, path, duplicate=True)
            with self.subTest(path=path), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(raw)

    def test_multiple_group_row_shapes_are_not_silently_dropped(self):
        for rows in (
            '<entry name="1"/><entry name="2"/>',
            "<group/><group/>",
            '<groups><entry name="1"/></groups>',
        ):
            raw = change(self.active, "result/group", child="<unreviewed/>")
            root = ET.fromstring(raw)
            group = root.find("result/group")
            group.clear()
            group.extend(ET.fromstring("<rows>" + rows + "</rows>"))
            with self.subTest(rows=rows), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(ET.tostring(root, encoding="unicode"))

    def test_nested_scalar_or_identity_attribute_is_not_a_leaf(self):
        raw = change(self.active, "result/group/local-info/state", child="<value>active</value>")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_state(raw)
        root = ET.fromstring(self.active)
        root.find("result/group").set("name", "unreviewed-group")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_state(ET.tostring(root, encoding="unicode"))

    def test_semantic_errors_fail_even_with_outer_success(self):
        for error in ("<error/>", "<error>No such HA group</error>"):
            raw = change(self.active, "result", child=error)
            with self.subTest(error=error), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(raw)

    def test_nested_error_msg_and_error_status_fail_without_echoing_contents(self):
        for path in (
            "result/group",
            "result/group/local-info",
            "result/group/peer-info/conn-ha2",
        ):
            for marker in (
                "<error/>",
                "<error>never-echo-diagnostic</error>",
                "<msg><line>never-echo-diagnostic</line></msg>",
                '<unreviewed status="error">never-echo-diagnostic</unreviewed>',
            ):
                raw = change(self.active, path, child=marker)
                with self.subTest(path=path, marker=marker):
                    with self.assertRaises(panos.DiscoveryError) as raised:
                        ha.parse_ha_state(raw)
                    self.assertNotIn("never-echo", str(raised.exception))

    def test_disabled_ha_does_not_hide_nested_error_markers(self):
        raw = change(self.disabled, "result/group", child="<msg>read failed</msg>")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_state(raw)

    def test_error_status_on_known_runtime_container_fails(self):
        root = ET.fromstring(self.active)
        root.find("result/group/peer-info").set("status", "error")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_state(ET.tostring(root, encoding="unicode"))

    def test_credentials_in_unknown_branches_are_never_retained(self):
        raw = change(
            self.active,
            "result/group/local-info",
            child="<authentication><username>never-report-user</username>"
            "<password>never-report-secret</password></authentication>",
        )
        encoded = json.dumps(ha.parse_ha_state(raw))
        self.assertNotIn("never-report", encoded)
        self.assertNotIn("authentication", encoded)

    def test_exact_command_echo_prompt_and_source_command_are_supported(self):
        command = "captured exact HA read"
        raw = command + "\n" + self.active + "\nlab-admin@pa-vm>"
        self.assertEqual(ha.parse_ha_state(raw, command)["source"]["command"], command)

    def test_shared_strict_response_boundary_is_not_bypassed(self):
        for raw in (
            self.active.replace('status="success"', 'status="error"'),
            self.active[:-12],
            "Server error : No such node",
            "arbitrary display\n" + self.active,
            '<!DOCTYPE response [<!ENTITY x "active">]>' + self.active,
        ):
            with self.subTest(raw=raw[:60]), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_state(raw)


class HaConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.configured = output("panos_ha_configured.xml")
        self.absent = output("panos_ha_unconfigured_deviceconfig.xml")

    def test_actual_parent_read_has_explicit_settings_and_separate_runtime(self):
        fact = ha.parse_ha_configuration(self.configured)
        self.assertIs(fact["present"], True)
        self.assertIs(fact["enabled"], True)
        self.assertEqual(fact["group_id"], 42)
        self.assertEqual(fact["mode"], "active-passive")
        self.assertEqual(fact["interfaces"]["ha1"]["port"], "ethernet1/2")
        self.assertEqual(fact["interfaces"]["ha1"]["ip_address"], "198.18.100.1")
        self.assertEqual(fact["interfaces"]["ha1"]["netmask"], "255.255.255.252")
        self.assertEqual(fact["interfaces"]["ha2"]["port"], "ethernet1/3")
        self.assertIsNone(fact["interfaces"]["ha2"]["ip_address"])
        self.assertIs(fact["election"]["preemptive"], False)
        self.assertIs(fact["synchronization"]["running_config_enabled"], True)
        self.assertIs(fact["synchronization"]["state_enabled"], True)
        self.assertNotIn("role", fact)
        self.assertNotIn("state_status", fact["synchronization"])

    def test_absent_ha_in_valid_ancestor_does_not_infer_enabled_false(self):
        fact = ha.parse_ha_configuration(self.absent)
        self.assertIs(fact["present"], False)
        self.assertIsNone(fact["enabled"])
        self.assertIsNone(fact["group_id"])
        self.assertIsNone(fact["mode"])
        self.assertEqual(fact["source"]["fields"]["present"]["presence"], "absent")

    def test_present_empty_configuration_is_distinct_from_absent(self):
        raw = '<response status="success"><result><deviceconfig><high-availability/>'
        raw += "</deviceconfig></result></response>"
        fact = ha.parse_ha_configuration(raw)
        self.assertIs(fact["present"], True)
        self.assertIsNone(fact["enabled"])
        self.assertIsNone(fact["group_id"])

    def test_explicit_disabled_configuration_keeps_configured_data(self):
        raw = change(self.configured, "result/deviceconfig/high-availability/enabled", value="no")
        fact = ha.parse_ha_configuration(raw)
        self.assertIs(fact["enabled"], False)
        self.assertEqual(fact["group_id"], 42)

    def test_missing_settings_and_blank_values_do_not_receive_orm_defaults(self):
        raw = change(
            self.configured,
            "result/deviceconfig/high-availability/group/election-option/preemptive",
            remove=True,
        )
        raw = change(raw, "result/deviceconfig/high-availability/group/group-id", value="")
        fact = ha.parse_ha_configuration(raw)
        self.assertIsNone(fact["election"]["preemptive"])
        self.assertIsNone(fact["group_id"])

    def test_unknown_mode_branch_is_reported_without_guessed_semantics(self):
        root = ET.fromstring(self.configured)
        mode = root.find("result/deviceconfig/high-availability/group/mode")
        mode.clear()
        ET.SubElement(mode, "future-ha-mode")
        fact = ha.parse_ha_configuration(ET.tostring(root, encoding="unicode"))
        self.assertEqual(fact["mode"], "future-ha-mode")
        self.assertIsNone(fact["passive_link_state"])

    def test_ambiguous_modes_fail(self):
        raw = change(
            self.configured,
            "result/deviceconfig/high-availability/group/mode",
            child="<active-active/>",
        )
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_configuration(raw)

    def test_duplicate_group_branch_or_interface_fields_fail(self):
        for path in (
            "result/deviceconfig/high-availability",
            "result/deviceconfig/high-availability/group",
            "result/deviceconfig/high-availability/group/group-id",
            "result/deviceconfig/high-availability/interface/ha1",
            "result/deviceconfig/high-availability/interface/ha1/port",
        ):
            raw = change(self.configured, path, duplicate=True)
            with self.subTest(path=path), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_configuration(raw)

    def test_group_entries_are_an_unsupported_multiple_group_schema(self):
        root = ET.fromstring(self.configured)
        group = root.find("result/deviceconfig/high-availability/group")
        group.extend(ET.fromstring('<rows><entry name="42"/><entry name="43"/></rows>'))
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_configuration(ET.tostring(root, encoding="unicode"))

    def test_missing_ancestor_or_old_leaf_read_is_not_supported_parent_evidence(self):
        for raw in (
            '<response status="success"><result/></response>',
            '<response status="success"><result><high-availability/></result></response>',
            "Server error : No such node",
        ):
            with self.subTest(raw=raw), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_configuration(raw)

    def test_enabled_ha_without_configuration_group_fails(self):
        raw = change(self.configured, "result/deviceconfig/high-availability/group", remove=True)
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_configuration(raw)

    def test_bad_group_id_boolean_ip_and_netmask_fail(self):
        bad = (
            ("group/group-id", "-1"),
            ("group/election-option/preemptive", "auto"),
            ("group/peer-ip", "peer.example.test"),
            ("interface/ha1/netmask", "255.0.255.0"),
            ("interface/ha1/netmask", "0.0.0.3"),
        )
        for path, value in bad:
            raw = change(
                self.configured, "result/deviceconfig/high-availability/" + path, value=value
            )
            with self.subTest(path=path, value=value), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_configuration(raw)

    def test_all_unrelated_ancestor_and_unknown_ha_credentials_are_discarded(self):
        raw = change(
            self.configured,
            "result/deviceconfig",
            child="<system><authentication><password>discard-system-secret</password>"
            "<username>discard-system-user</username></authentication></system>",
        )
        raw = change(
            raw,
            "result/deviceconfig/high-availability",
            child="<authentication><password>discard-ha-secret</password></authentication>",
        )
        encoded = json.dumps(ha.parse_ha_configuration(raw))
        self.assertNotIn("discard-", encoded)
        self.assertNotIn("authentication", encoded)
        self.assertNotIn("system", encoded)

    def test_semantic_error_with_valid_ancestor_still_fails(self):
        raw = change(self.configured, "result", child="<error>configuration read failed</error>")
        with self.assertRaises(panos.DiscoveryError):
            ha.parse_ha_configuration(raw)

    def test_nested_config_error_markers_fail_without_echoing_contents(self):
        for path in (
            "result/deviceconfig/high-availability",
            "result/deviceconfig/high-availability/group/election-option",
            "result/deviceconfig/high-availability/interface/ha1",
        ):
            for marker in (
                "<error/>",
                "<msg><line>never-echo-config-diagnostic</line></msg>",
                '<unreviewed status="error">never-echo-config-diagnostic</unreviewed>',
            ):
                raw = change(self.configured, path, child=marker)
                with self.subTest(path=path, marker=marker):
                    with self.assertRaises(panos.DiscoveryError) as raised:
                        ha.parse_ha_configuration(raw)
                    self.assertNotIn("never-echo", str(raised.exception))

    def test_config_envelope_error_status_and_direct_msg_fail(self):
        for path in ("result", "result/deviceconfig"):
            root = ET.fromstring(self.configured)
            root.find(path).set("status", "error")
            with self.subTest(path=path), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_configuration(ET.tostring(root, encoding="unicode"))
            raw = change(self.configured, path, child="<msg>ancestor read failed</msg>")
            with self.subTest(path=path), self.assertRaises(panos.DiscoveryError):
                ha.parse_ha_configuration(raw)

    def test_unrelated_discarded_config_auth_messages_are_outside_ha_error_scope(self):
        for baseline in (self.configured, self.absent):
            raw = change(
                baseline,
                "result/deviceconfig",
                child='<system><authentication status="error"><msg>discard-auth-message</msg>'
                "<error>discard-auth-detail</error></authentication></system>",
            )
            fact = ha.parse_ha_configuration(raw)
            self.assertEqual(fact["present"], ha.parse_ha_configuration(baseline)["present"])
            self.assertNotIn("discard-auth", json.dumps(fact))

    def test_source_paths_and_command_are_exact_parent_proof(self):
        fact = ha.parse_ha_configuration(self.configured)
        self.assertEqual(fact["source"]["command"], ha.RUNNING_HA)
        self.assertEqual(fact["source"]["path"], "result/deviceconfig")
        self.assertEqual(
            fact["source"]["fields"]["group_id"]["path"],
            "result/deviceconfig/high-availability/group/group-id",
        )


if __name__ == "__main__":
    unittest.main()
