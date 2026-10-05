"""Production HA/VPN collection fencing, completeness, privacy and write isolation."""

import json
import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from unittest.mock import Mock

from tests import test_panos, test_panos_framework
from tests._loader import load

panos = load("adapters.panos")
ssh = load("transport_ssh")
reconcile = load("reconcile")


def payloads():
    data = test_panos.vm_payloads()
    data.update(
        {
            ssh.RUNNING_HA: test_panos.output("panos_ha_configured.xml"),
            ssh.HA_STATE: test_panos.output("panos_ha_active.xml"),
            ssh.RUNNING_VPN: test_panos.output("panos_vpn_applied_network.xml"),
            ssh.IKE_SAS: test_panos.output("panos_vpn_ike_sas.xml"),
            ssh.IPSEC_SAS: test_panos.output("panos_vpn_ipsec_sas.xml"),
            ssh.VPN_FLOWS: test_panos.output("panos_vpn_flows.xml"),
            ssh.vpn_flow_detail_command(1): test_panos.output("panos_vpn_local_flow_detail.xml"),
        }
    )
    return data


def change(data, command, path, value):
    root = ET.fromstring(data[command])
    root.find(path).text = value
    data[command] = ET.tostring(root, encoding="unicode")


class PanosHaVpnCollectionTests(unittest.TestCase):
    def collect(self, data=None, **options):
        self.client = Mock()
        self.client.run.side_effect = (data if data is not None else payloads()).__getitem__
        return panos.collect(self.client, **options)

    def test_all_reviewed_sources_and_exact_numeric_details_are_collected(self):
        result = self.collect()
        facts = result["observations"]
        self.assertEqual(facts["ha"]["runtime"]["local"]["role"], "active")
        self.assertEqual(len(facts["vpn"]["configuration"]["ipsec_tunnels"]), 1)
        runtime = facts["vpn"]["runtime"]
        self.assertEqual(len(runtime["ike_sas"]), 2)
        self.assertEqual(len(runtime["ipsec_sas"]), 1)
        self.assertEqual(len(runtime["flow_details"]), 1)
        self.assertTrue(runtime["complete"])
        self.assertEqual(runtime["unresolved"], [])
        self.assertFalse(facts["vpn"]["native_writes"])
        commands = [call.args[0] for call in self.client.run.call_args_list]
        self.assertEqual(len(commands), 11)
        self.assertEqual(commands[-1], "show vpn flow tunnel-id 1")
        self.assertTrue(all(ssh.is_read_command(command) for command in commands))
        self.assertEqual(
            result["sources"]["vpn"]["flow_details"], [runtime["flow_details"][0]["source"]]
        )

    def test_passive_blank_ike_is_unknown_with_explicit_incomplete_read_coverage(self):
        data = payloads()
        data[ssh.HA_STATE] = test_panos.output("panos_ha_passive.xml")
        data[ssh.IKE_SAS] = "\n"
        result = self.collect(data)
        runtime = result["observations"]["vpn"]["runtime"]
        self.assertIsNone(runtime["ike_sas"])
        self.assertFalse(runtime["complete"])
        self.assertEqual(runtime["unresolved"][0]["source"]["command"], ssh.IKE_SAS)
        self.assertTrue(result["warnings"])
        self.assertEqual(len(runtime["ipsec_sas"]), 1)
        self.assertEqual(len(runtime["flow_details"]), 1)

    def test_structured_empty_ike_is_distinct_from_unknown(self):
        data = payloads()
        data[ssh.IKE_SAS] = test_panos.empty_ha_vpn_payloads()[ssh.IKE_SAS]
        runtime = self.collect(data)["observations"]["vpn"]["runtime"]
        self.assertEqual(runtime["ike_sas"], [])
        self.assertTrue(runtime["complete"])

    def test_nonblank_invalid_or_embedded_error_ike_fails_without_echoing_body(self):
        for raw in (
            "private-response-body",
            '<response status="error"><msg>private-response-body</msg></response>',
            '<response status="success"><result><error>private-response-body</error>'
            "</result></response>",
        ):
            data = payloads()
            data[ssh.IKE_SAS] = raw
            with self.subTest(raw=raw), self.assertRaises(panos.DiscoveryError) as raised:
                self.collect(data)
            self.assertNotIn("private-response-body", str(raised.exception))

    def test_detail_identity_change_stops_instead_of_associating_another_flow(self):
        for path, value in (
            ("./result/IPSec/entry/name", "different-selector"),
            ("./result/IPSec/entry/gwid", "12"),
            ("./result/IPSec/entry/inner-if", "tunnel.22"),
            ("./result/IPSec/entry/outer-if", "ethernet1/22"),
            ("./result/IPSec/entry/localip", "198.51.100.22"),
            ("./result/IPSec/entry/peerip", "198.51.100.23"),
            ("./result/dp", "dp9"),
        ):
            data = payloads()
            change(data, ssh.vpn_flow_detail_command(1), path, value)
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(panos.DiscoveryError, "identity changed"),
            ):
                self.collect(data)

    def test_evolving_counters_and_spi_are_separate_observations_not_identity(self):
        data = payloads()
        command = ssh.vpn_flow_detail_command(1)
        change(data, command, "./result/IPSec/entry/local-spi", "FFFFFFFF")
        change(data, command, "./result/IPSec/entry/pkt-encap", "18446744073709551615")
        row = self.collect(data)["observations"]["vpn"]["runtime"]["flow_details"][0]
        self.assertEqual(row["counters"]["pkt_encap"], 18446744073709551615)

    def multiple_flows(self):
        data = payloads()
        root = ET.fromstring(data[ssh.VPN_FLOWS])
        entries = root.find("./result/IPSec")
        # Names remain literal evidence, even if they resemble CLI input.
        names = ("selector-a", "selector-b; configure", "selector-c")
        original = deepcopy(entries[0])
        entries.clear()
        for tunnel_id, name in zip((65535, 27, 3), names):
            entry = deepcopy(original)
            entry.find("id").text = str(tunnel_id)
            entry.find("name").text = name
            entries.append(entry)
            detail = ET.fromstring(data[ssh.vpn_flow_detail_command(1)])
            detail.find("./result/IPSec/entry/id").text = str(tunnel_id)
            detail.find("./result/IPSec/entry/name").text = name
            data[ssh.vpn_flow_detail_command(tunnel_id)] = ET.tostring(detail, encoding="unicode")
        root.find("./result/num_ipsec").text = "3"
        root.find("./result/total").text = "3"
        data[ssh.VPN_FLOWS] = ET.tostring(root, encoding="unicode")
        return data

    def test_arbitrary_observed_ids_scale_without_name_interpolation(self):
        result = self.collect(self.multiple_flows(), max_vpn_flow_details=3)
        commands = [call.args[0] for call in self.client.run.call_args_list]
        self.assertEqual(commands[-3:], [ssh.vpn_flow_detail_command(i) for i in (3, 27, 65535)])
        self.assertEqual(len(result["observations"]["vpn"]["runtime"]["flow_details"]), 3)
        self.assertFalse(any("configure" in command for command in commands))

    def test_budget_exceeded_stops_before_detail_reads_instead_of_truncating(self):
        with self.assertRaisesRegex(panos.DiscoveryError, "detail-read limit"):
            self.collect(self.multiple_flows(), max_vpn_flow_details=2)
        self.assertFalse(
            any("tunnel-id" in call.args[0] for call in self.client.run.call_args_list)
        )

    def test_invalid_budget_is_rejected_before_any_read(self):
        for value in (True, 0, -1, 65536, "256", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.collect(max_vpn_flow_details=value)
            self.client.run.assert_not_called()

    def test_configuration_secrets_and_unrelated_branches_never_reach_facts(self):
        data = payloads()
        sentinel = "private-material-sentinel"
        network = ET.fromstring(data[ssh.RUNNING_VPN])
        gateway = network.find("./result/network/ike/gateway/entry")
        auth = ET.SubElement(gateway, "authentication")
        ET.SubElement(ET.SubElement(auth, "pre-shared-key"), "key").text = sentinel
        unrelated = ET.SubElement(network.find("./result/network"), "unrelated-private-config")
        ET.SubElement(unrelated, "private-key").text = sentinel
        data[ssh.RUNNING_VPN] = ET.tostring(network, encoding="unicode")
        self.assertNotIn(sentinel, json.dumps(self.collect(data)))

    def test_ha_and_vpn_observations_do_not_enter_native_inventory_planning(self):
        observed = test_panos_framework.discovery()
        baseline = reconcile.build_plan(observed, test_panos_framework.inventory())
        collected = self.collect()["observations"]
        observed["observations"] = collected
        self.assertEqual(reconcile.build_plan(observed, test_panos_framework.inventory()), baseline)
        observed["observations"]["ha"]["runtime"]["local"]["role"] = "passive"
        observed["observations"]["vpn"]["runtime"]["flow_details"][0]["counters"]["pkt_encap"] = (
            9999
        )
        self.assertEqual(reconcile.build_plan(observed, test_panos_framework.inventory()), baseline)


if __name__ == "__main__":
    unittest.main()
