"""Reviewed VPN runtime shapes plus adversarial, empty and multi-SA cases."""

import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from tests._loader import load

vpn = load("adapters.panos_vpn_runtime")
FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / ("panos_vpn_" + name + ".xml")).read_text()


def change_field(raw, field, value):
    root = ET.fromstring(raw)
    node = root.find(".//" + field)
    node.text = value
    return ET.tostring(root, encoding="unicode")


class PanosVpnRuntimeTests(unittest.TestCase):
    def test_ike_roles_are_separate_sas_not_ha_states(self):
        rows = vpn.parse_ike_sas(fixture("ike_sas"), vpn.IKE_SAS)
        self.assertEqual([row["role"] for row in rows], ["Init", "Resp"])
        self.assertEqual([row["gateway_name"] for row in rows], ["gateway-a"] * 2)
        self.assertEqual(
            rows[1]["source"],
            {
                "contract": "panos-vpn-runtime-v1",
                "command": vpn.IKE_SAS,
                "path": "result/entry",
                "index": 2,
            },
        )
        self.assertNotIn("state", rows[0])

    def test_ike_explicit_empty_result_is_no_observed_sas(self):
        self.assertEqual(
            vpn.parse_ike_sas(
                '<response status="success"><result/></response>',
                vpn.IKE_SAS,
            ),
            [],
        )

    def test_blank_or_cdata_ike_output_does_not_claim_no_sas(self):
        for raw in (
            "",
            "\n",
            "   \n\t",
            '<response status="success"><result><![CDATA[]]></result></response>',
            '<response status="success"><result><![CDATA[private-error-body]]></result></response>',
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(vpn.DiscoveryError) as raised:
                vpn.parse_ike_sas(raw, vpn.IKE_SAS)
            self.assertNotIn("private-error-body", str(raised.exception))

    def test_ike_filtered_or_unreviewed_nested_shape_is_not_inventory(self):
        for raw, command in (
            (fixture("ike_sas"), "show vpn ike-sa gateway gateway-a"),
            (
                '<response status="success"><result><IKEv2><entry/></IKEv2></result></response>',
                vpn.IKE_SAS,
            ),
        ):
            with self.subTest(command=command), self.assertRaises(vpn.DiscoveryError):
                vpn.parse_ike_sas(raw, command)

    def test_duplicate_ike_row_is_ambiguous_but_different_creation_is_retained(self):
        root = ET.fromstring(fixture("ike_sas"))
        result = root.find("result")
        result.append(ET.fromstring(ET.tostring(result[0], encoding="unicode")))
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_ike_sas(ET.tostring(root, encoding="unicode"), vpn.IKE_SAS)
        result[-1].find("created").text = "Jan.02 01:00:00"
        self.assertEqual(
            len(
                vpn.parse_ike_sas(
                    ET.tostring(root, encoding="unicode"),
                    vpn.IKE_SAS,
                )
            ),
            3,
        )

    def test_ipsec_keeps_full_selector_name_and_decimal_spis(self):
        row = vpn.parse_ipsec_sas(fixture("ipsec_sas"), vpn.IPSEC_SAS)[0]
        self.assertEqual(row["name"], "vpn-a:protected-hosts")
        self.assertEqual(row["gateway_name"], "gateway-a")
        self.assertEqual(row["inbound_spi"], 2654440482)
        self.assertEqual(row["outbound_spi"], 3647142075)
        self.assertEqual(row["peer_address"], "198.51.100.3")
        self.assertEqual(row["lifetime_kb_raw"], "Unlimited")
        self.assertNotIn("tunnel_name", row)
        self.assertEqual(row["source"]["path"], "result/entries/entry")
        self.assertEqual(
            row["source"]["coverage"],
            {
                "declared_ntun": 1,
                "observed_sa_rows": 1,
                "observed_distinct_tunnel_ids": 1,
            },
        )

    def test_ipsec_explicit_empty_entries_require_success_and_no_embedded_error(self):
        raw = '<response status="success"><result><entries/><ntun>0</ntun></result></response>'
        self.assertEqual(vpn.parse_ipsec_sas(raw, vpn.IPSEC_SAS), [])
        with self.assertRaises(vpn.DiscoveryError) as raised:
            vpn.parse_ipsec_sas(
                raw.replace("</result>", "<error>private-error-body</error></result>"),
                vpn.IPSEC_SAS,
            )
        self.assertNotIn("private-error-body", str(raised.exception))

    def test_ipsec_rekey_count_semantics_are_not_inferred(self):
        root = ET.fromstring(fixture("ipsec_sas"))
        entries = root.find("result/entries")
        entries.append(ET.fromstring(ET.tostring(entries[0], encoding="unicode")))
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_ipsec_sas(ET.tostring(root, encoding="unicode"), vpn.IPSEC_SAS)
        entries[-1].find("i_spi").text = "123"
        # Neither a declared count of one nor two proves the meaning of ntun
        # when two SA rows share one tunnel ID. Keep that shape unsupported.
        for count in ("1", "2"):
            root.find("result/ntun").text = count
            with self.assertRaisesRegex(vpn.DiscoveryError, "unsupported relationship"):
                vpn.parse_ipsec_sas(ET.tostring(root, encoding="unicode"), vpn.IPSEC_SAS)
        root.find("result").remove(root.find("result/ntun"))
        # Without a declared count, preserve distinct SPI rows without a
        # completeness claim or a guessed tunnel/SA count interpretation.
        self.assertEqual(
            len(
                vpn.parse_ipsec_sas(
                    ET.tostring(root, encoding="unicode"),
                    vpn.IPSEC_SAS,
                )
            ),
            2,
        )

    def test_ipsec_count_contradictions_never_claim_empty_or_complete_inventory(self):
        empty = '<response status="success"><result><entries/><ntun>1</ntun></result></response>'
        with self.assertRaisesRegex(vpn.DiscoveryError, "unsupported relationship"):
            vpn.parse_ipsec_sas(empty, vpn.IPSEC_SAS)
        for count in ("0", "2"):
            with (
                self.subTest(count=count),
                self.assertRaisesRegex(vpn.DiscoveryError, "unsupported relationship"),
            ):
                vpn.parse_ipsec_sas(
                    change_field(fixture("ipsec_sas"), "ntun", count), vpn.IPSEC_SAS
                )

    def test_flow_summary_is_not_a_detail_or_an_sa(self):
        row = vpn.parse_vpn_flows(fixture("flows"), vpn.VPN_FLOWS)[0]
        self.assertEqual(row["state"], "active")
        self.assertEqual(row["name"], "vpn-a:protected-hosts")
        self.assertEqual(row["tunnel_interface"], "tunnel.1")
        self.assertEqual(row["monitor_status"], "off")
        self.assertEqual(row["dataplane"], "dp0")
        self.assertEqual(row["source"]["dataplane"], "dp0")
        self.assertNotIn("local_spi", row)
        self.assertNotIn("counters", row)

    def test_flow_detail_has_typed_hex_spis_selectors_and_zero_counters(self):
        row = vpn.parse_vpn_flows(fixture("flow_detail"), "show vpn flow tunnel-id 1", detail=True)[
            0
        ]
        self.assertEqual(row["local_spi"], int("D962F8BB", 16))
        self.assertEqual(row["remote_spi"], int("9E378C22", 16))
        self.assertEqual(row["dataplane"], "dp0")
        self.assertEqual(row["counters"]["pkt_encap"], 90)
        self.assertEqual(row["counters"]["pkt_decap"], 90)
        self.assertEqual(row["counters"]["pkt_encap_v6"], 0)
        self.assertEqual(row["last_rekey"], 1645)
        self.assertNotIn("last_rekey_seconds", row)
        self.assertEqual(row["selectors"]["local"]["start_address"], "192.0.2.3")
        self.assertEqual(row["selectors"]["remote"]["end_port"], 65535)
        self.assertIsNone(row["configured_proxy_id"])

    def test_independently_captured_peer_spis_match_without_name_splitting(self):
        local_sa = vpn.parse_ipsec_sas(fixture("ipsec_sas"), vpn.IPSEC_SAS)[0]
        peer_sa = vpn.parse_ipsec_sas(fixture("peer_ipsec_sas"), vpn.IPSEC_SAS)[0]
        local = vpn.parse_vpn_flows(
            fixture("local_flow_detail"), "show vpn flow tunnel-id 1", detail=True
        )[0]
        peer = vpn.parse_vpn_flows(
            fixture("flow_detail"), "show vpn flow tunnel-id 1", detail=True
        )[0]
        self.assertEqual(local["local_spi"], local_sa["inbound_spi"])
        self.assertEqual(local["remote_spi"], local_sa["outbound_spi"])
        self.assertEqual(peer["local_spi"], peer_sa["inbound_spi"])
        self.assertEqual(peer["local_spi"], local["remote_spi"])
        self.assertEqual(peer["remote_spi"], local["local_spi"])
        self.assertEqual(local["selectors"]["local"], peer["selectors"]["remote"])

    def test_new_unfiltered_single_ike_capture_retains_mode_and_algorithm(self):
        row = vpn.parse_ike_sas(fixture("ike_single"), vpn.IKE_SAS)[0]
        self.assertEqual(row["mode"], "IKEv2")
        self.assertEqual(row["algorithm"], "PSK/DH14/AES256-CBC/SHA256")

    def test_inactive_flow_preserves_zero_spis_and_unnegotiated_proxy_id(self):
        row = vpn.parse_vpn_flows(
            fixture("flow_inactive"), "show vpn flow tunnel-id 1", detail=True
        )[0]
        self.assertEqual(row["state"], "init")
        self.assertEqual(row["authentication"], "not established")
        self.assertEqual(row["local_spi"], 0)
        self.assertEqual(row["counters"]["pkt_decap"], 0)
        self.assertIsNone(row["remaining_seconds"])
        self.assertIsNone(row["selectors"])
        self.assertEqual(row["configured_proxy_id"]["local_prefix"], 32)

    def test_missing_counter_is_none_and_unsigned64_max_is_exact(self):
        raw = fixture("flow_detail")
        raw = change_field(raw, "pkt-encap", str((1 << 64) - 1))
        root = ET.fromstring(raw)
        entry = root.find("result/IPSec/entry")
        entry.remove(entry.find("pkt-decap"))
        row = vpn.parse_vpn_flows(
            ET.tostring(root, encoding="unicode"), "show vpn flow tunnel-id 1", detail=True
        )[0]
        self.assertEqual(row["counters"]["pkt_encap"], (1 << 64) - 1)
        self.assertIsNone(row["counters"]["pkt_decap"])

    def test_invalid_counter_is_never_scraped_or_clamped(self):
        for value in ("-1", "+1", "1 packets", "1.0", "1e3", str(1 << 64), "9" * 5000):
            with self.subTest(value=value[:30]), self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(
                    change_field(fixture("flow_detail"), "pkt-encap", value),
                    "show vpn flow tunnel-id 1",
                    detail=True,
                )

    def test_present_blank_numeric_fields_are_not_missing_observations(self):
        for blank in (None, "", " \n\t "):
            for parse, raw, command, field, kwargs in (
                (vpn.parse_ike_sas, fixture("ike_single"), vpn.IKE_SAS, "gwid", {}),
                (vpn.parse_ipsec_sas, fixture("ipsec_sas"), vpn.IPSEC_SAS, "remain", {}),
                (vpn.parse_ipsec_sas, fixture("ipsec_sas"), vpn.IPSEC_SAS, "ntun", {}),
                (vpn.parse_vpn_flows, fixture("flows"), vpn.VPN_FLOWS, "num_ipsec", {}),
                (
                    vpn.parse_vpn_flows,
                    fixture("flow_detail"),
                    "show vpn flow tunnel-id 1",
                    "pkt-encap",
                    {"detail": True},
                ),
                (
                    vpn.parse_vpn_flows,
                    fixture("flow_detail"),
                    "show vpn flow tunnel-id 1",
                    "mtu",
                    {"detail": True},
                ),
                (
                    vpn.parse_vpn_flows,
                    fixture("flow_detail"),
                    "show vpn flow tunnel-id 1",
                    "local-spi",
                    {"detail": True},
                ),
                (
                    vpn.parse_vpn_flows,
                    fixture("flow_detail"),
                    "show vpn flow tunnel-id 1",
                    "monitor/interval",
                    {"detail": True},
                ),
            ):
                with self.subTest(field=field, blank=blank), self.assertRaises(vpn.DiscoveryError):
                    parse(change_field(raw, field, blank), command, **kwargs)

    def test_unknown_state_and_crypto_strings_are_literal_observations(self):
        raw = change_field(fixture("flow_detail"), "state", "future-operational-state")
        raw = change_field(raw, "enc", "future-reviewed-enum")
        row = vpn.parse_vpn_flows(raw, "show vpn flow tunnel-id 1", detail=True)[0]
        self.assertEqual(row["state"], "future-operational-state")
        self.assertEqual(row["encryption"], "future-reviewed-enum")

    def test_multiple_flows_preserve_complete_names_and_reject_duplicate_ids(self):
        root = ET.fromstring(fixture("flows"))
        entries = root.find("result/IPSec")
        entries.append(ET.fromstring(ET.tostring(entries[0], encoding="unicode")))
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows(ET.tostring(root, encoding="unicode"), vpn.VPN_FLOWS)
        entries[-1].find("id").text = "2"
        entries[-1].find("name").text = "vpn-a:another:selector"
        root.find("result/num_ipsec").text = "2"
        root.find("result/total").text = "2"
        rows = vpn.parse_vpn_flows(ET.tostring(root, encoding="unicode"), vpn.VPN_FLOWS)
        self.assertEqual([row["tunnel_id"] for row in rows], [1, 2])
        self.assertEqual(rows[1]["name"], "vpn-a:another:selector")

    def test_flow_empty_inventory_is_not_missing_inventory(self):
        self.assertEqual(
            vpn.parse_vpn_flows(
                '<response status="success"><result><IPSec/><num_ipsec>0</num_ipsec>'
                "</result></response>",
                vpn.VPN_FLOWS,
            ),
            [],
        )
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows('<response status="success"><result/></response>', vpn.VPN_FLOWS)

    def test_flow_count_contradictions_fail_instead_of_silently_dropping_rows(self):
        for count in ("0", "2"):
            with self.subTest(count=count), self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(
                    change_field(fixture("flows"), "num_ipsec", count), vpn.VPN_FLOWS
                )
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows(
                '<response status="success"><result><dp>dp0</dp><IPSec/>'
                "<num_ipsec>1</num_ipsec></result></response>",
                vpn.VPN_FLOWS,
            )
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows(
                '<response status="success"><result><dp>dp0</dp><IPSec/>'
                "<num_sslvpn>0</num_sslvpn><total>1</total></result></response>",
                vpn.VPN_FLOWS,
            )
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows(change_field(fixture("flows"), "total", "0"), vpn.VPN_FLOWS)

    def test_nonempty_flow_and_numeric_detail_require_explicit_dataplane(self):
        for name, command, detail in (
            ("flows", vpn.VPN_FLOWS, False),
            ("flow_detail", "show vpn flow tunnel-id 1", True),
        ):
            for raw in (
                fixture(name).replace("<dp>dp0</dp>", ""),
                fixture(name).replace("<dp>dp0</dp>", "<dp/>"),
                fixture(name).replace("<dp>dp0</dp>", "<dp> \n\t </dp>"),
            ):
                with self.subTest(name=name), self.assertRaises(vpn.DiscoveryError):
                    vpn.parse_vpn_flows(raw, command, detail=detail)

    def test_numeric_detail_fence_and_exact_observed_id(self):
        for command in (
            "show vpn flow tunnel-id 0",
            "show vpn flow tunnel-id 65536",
            "show vpn flow tunnel-id 01",
            "show vpn flow tunnel-id 2",
            "show vpn flow tunnel-id 1; show config running",
            vpn.VPN_FLOWS,
        ):
            with self.subTest(command=command), self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(fixture("flow_detail"), command, detail=True)

    def test_unreviewed_multi_dataplane_shape_or_attributes_fail(self):
        for raw in (
            fixture("flows").replace("</result>", "<dp>dp1</dp></result>"),
            fixture("flows").replace("<IPSec>", '<IPSec dp="dp1">'),
            fixture("flows").replace("<result>", '<result vsys="vsys2">'),
        ):
            with self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(raw, vpn.VPN_FLOWS)

    def test_name_detail_commands_are_outside_the_production_numeric_contract(self):
        for name in (
            "vpn-a",
            "vpn a",
            "vpn-a\nshow config running",
            "vpn-a|match key",
            "vpn-a;exit",
        ):
            with self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(
                    fixture("flow_detail"), "show vpn flow name " + name, detail=True
                )

    def test_duplicate_scalar_nested_identity_and_missing_identity_fail(self):
        for fragment in ("<id>2</id>", "<name><nested/></name>", "<gwid/>"):
            raw = fixture("flows")
            if fragment == "<gwid/>":
                raw = raw.replace("<gwid>1</gwid>", fragment)
            elif fragment.startswith("<name>"):
                raw = raw.replace("<name>vpn-a:protected-hosts</name>", fragment)
            else:
                raw = raw.replace("</entry>", fragment + "</entry>")
            with self.subTest(fragment=fragment), self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(raw, vpn.VPN_FLOWS)

    def test_invalid_spi_and_negotiated_selector_ranges_fail(self):
        for field, value in (
            ("local-spi", "0x1234"),
            ("local-spi", "FFFFFFFFF"),
            ("sport", "65536"),
            ("eport", "-1"),
            ("ts/local/proto", "256"),
            ("sip", "private-invalid-address"),
        ):
            with self.subTest(field=field), self.assertRaises(vpn.DiscoveryError):
                vpn.parse_vpn_flows(
                    change_field(fixture("flow_detail"), field, value),
                    "show vpn flow tunnel-id 1",
                    detail=True,
                )
        raw = change_field(fixture("flow_detail"), "eip", "192.0.2.1")
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows(raw, "show vpn flow tunnel-id 1", detail=True)

    def test_keys_and_unreviewed_runtime_fields_are_never_retained(self):
        raw = fixture("flow_detail").replace(
            "</entry>",
            "<key>private-key-material</key><enc-key>private-encryption-key</enc-key>"
            "<authentication><secret>private-nested-secret</secret></authentication>"
            "<new-field>private-unknown-value</new-field></entry>",
        )
        rows = vpn.parse_vpn_flows(raw, "show vpn flow tunnel-id 1", detail=True)
        self.assertNotIn("private-", json.dumps(rows))
        for parse, raw, command in (
            (vpn.parse_ike_sas, fixture("ike_sas"), vpn.IKE_SAS),
            (vpn.parse_ipsec_sas, fixture("ipsec_sas"), vpn.IPSEC_SAS),
        ):
            raw = raw.replace("</entry>", "<key>private-key-material</key></entry>")
            self.assertNotIn("private-", json.dumps(parse(raw, command)))

    def test_response_errors_entities_truncation_and_display_text_fail_without_echo(self):
        raw = fixture("flows")
        samples = (
            raw.replace('status="success"', 'status="error"'),
            raw.replace("</entry>", "<error>private-error-body</error></entry>"),
            raw.replace("</entry>", "<msg><line>private-error-body</line></msg></entry>"),
            raw.replace("<IPSec>", "<IPSec>private-display-error"),
            '<!DOCTYPE response [<!ENTITY x "private-secret">]>' + raw,
            raw[:-20],
            raw + raw,
        )
        for value in samples:
            with self.subTest(value=value[:40]), self.assertRaises(vpn.DiscoveryError) as raised:
                vpn.parse_vpn_flows(value, vpn.VPN_FLOWS)
            self.assertNotIn("private-", str(raised.exception))

    def test_exact_echo_and_prompt_are_accepted_without_arbitrary_framing(self):
        raw = vpn.VPN_FLOWS + "\n" + fixture("flows") + "\nadmin@sample>"
        self.assertEqual(len(vpn.parse_vpn_flows(raw, vpn.VPN_FLOWS)), 1)
        with self.assertRaises(vpn.DiscoveryError):
            vpn.parse_vpn_flows(raw + "\nprivate-error-body", vpn.VPN_FLOWS)


if __name__ == "__main__":
    unittest.main()
