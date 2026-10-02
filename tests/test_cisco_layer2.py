"""Configured 802.1Q interpretation without operational or default guessing."""

import unittest

from tests._loader import fixture, load
from tests.test_cisco_iosxe import FixtureClient, cisco, fixture_payloads

layer2 = load("adapters.cisco_layer2")


def payloads():
    values = fixture_payloads()
    values[layer2.NATIVE_PATH] = fixture("iosxe_native_switchports.json")
    return values


def native_row(values, family, name):
    return next(
        row
        for row in values[layer2.NATIVE_PATH]["Cisco-IOS-XE-native:interface"][family]
        if row["name"] == name
    )


def switchport(values, family="TenGigabitEthernet", name="1/0/47"):
    return native_row(values, family, name)["switchport-config"]["switchport"]


class Layer2CollectionTests(unittest.TestCase):
    def collect(self, values=None, client=None):
        return cisco.collect(client or FixtureClient(values or payloads()))["layer2"]

    def test_lab_has19_complete_bundles_and39_unknown_modes(self):
        result = self.collect()
        self.assertEqual(len(result["interfaces"]), 19)
        self.assertEqual(len(result["unresolved"]), 39)
        self.assertEqual(sum(row["mode"] == "access" for row in result["interfaces"]), 14)
        self.assertEqual(sum(row["mode"] == "tagged" for row in result["interfaces"]), 5)
        rows = {row["name"]: row for row in result["interfaces"]}
        self.assertEqual(rows["TwoGigabitEthernet1/0/1"]["untagged_vid"], 2)
        self.assertEqual(rows["TwoGigabitEthernet1/0/20"]["untagged_vid"], 3)
        uplink = rows["TenGigabitEthernet1/0/47"]
        self.assertEqual(uplink["untagged_vid"], 999)
        self.assertEqual(uplink["tagged_vids"], [3, 4])
        self.assertEqual(uplink["observations"]["allowed_vids"], [3, 4, 999])
        self.assertEqual(uplink["observations"]["raw_allowed"], {"vlans": "3,4,999"})
        self.assertEqual(len(result["vlans"]), 9)

    def test_ordinary_trunk_defaults_have_profile_and_documents(self):
        row = next(row for row in self.collect()["interfaces"] if row["name"] == "Port-channel1")
        self.assertEqual(row["untagged_vid"], 1)
        self.assertEqual(row["tagged_vids"], [3, 4])
        self.assertFalse(row["observations"]["native_in_allowed"])
        self.assertEqual(row["observations"]["native_vid_source"], "documented-default")
        profile = row["source"]["defaults"]
        self.assertEqual(profile["model"], "C9300-48UXM")
        self.assertEqual(profile["software_family"], "17.12")
        self.assertTrue(profile["documents"]["ordinary_trunk"].endswith("vlan_commands.html"))

    def test_confirmed204_is_empty_configuration_but200_null_is_unknown(self):
        class EmptyGlobal(FixtureClient):
            def __init__(self, status, body):
                super().__init__(payloads())
                self.status, self.body = status, body

            def get(self, path, **kwargs):
                if path == layer2.GLOBAL_PATH:
                    self.trace.append({"path": path, "status": self.status})
                    self.requests.append(path)
                    return self.body
                return super().get(path, **kwargs)

        for body in (None, {}):
            with self.subTest(status=204, body=body):
                self.assertEqual(len(self.collect(client=EmptyGlobal(204, body))["interfaces"]), 19)
            with self.subTest(status=200, body=body):
                result = self.collect(client=EmptyGlobal(200, body))
                self.assertEqual(len(result["interfaces"]), 14)
                self.assertTrue(any("tagging" in row["reason"] for row in result["unresolved"]))

    def test_default_profile_is_scoped_to_reviewed_chassis_and_release_families(self):
        for model, version in (("C9300-24T", "17.12.08"), ("C9300-48UXM", "17.15.06")):
            with self.subTest(model=model, version=version):
                client = FixtureClient(payloads())
                result = layer2.collect(
                    client,
                    cisco.collect(FixtureClient())["interfaces"],
                    model=model,
                    software_version=version,
                    canonical_name=cisco.canonical_interface_name,
                    warnings=[],
                )
                self.assertEqual(len(result["interfaces"]), 14)
                self.assertTrue(all(row["mode"] == "access" for row in result["interfaces"]))
        self.assertIsNotNone(layer2._profile("C9300-48UXM", "17.9.06"))

    def test_mode_absence_never_infers_access_from_a_vlan_or_allowed_default(self):
        values = payloads()
        row = native_row(values, "TwoGigabitEthernet", "1/0/15")
        row["switchport-config"] = {
            "switchport": {
                "Cisco-IOS-XE-switch:access": {"vlan": {"vlan": 2}},
                "Cisco-IOS-XE-switch:trunk": {
                    "allowed": {"vlan-v2": {"vlan-choices": {"all": True}}}
                },
            }
        }
        result = self.collect(values)
        self.assertNotIn("TwoGigabitEthernet1/0/15", {r["name"] for r in result["interfaces"]})
        self.assertTrue(any(r["name"] == "TwoGigabitEthernet1/0/15" for r in result["unresolved"]))

    def test_global_tagging_enabled_does_not_mislabel_native_as_untagged(self):
        values = payloads()
        values[layer2.GLOBAL_PATH] = {
            "Cisco-IOS-XE-native:vlan": {"Cisco-IOS-XE-vlan:dot1q": {"tag": {"native": [None]}}}
        }
        result = self.collect(values)
        self.assertEqual(len(result["interfaces"]), 14)
        self.assertTrue(all(row["mode"] == "access" for row in result["interfaces"]))

    def test_unavailable_optional_sources_preserve_independent_facts(self):
        class Missing(FixtureClient):
            def __init__(self, missing):
                super().__init__(payloads())
                self.missing = missing

            def get(self, path, **kwargs):
                if path.split("?", 1)[0] == self.missing:
                    raise cisco.RestconfError("unavailable", status_code=404)
                return super().get(path, **kwargs)

        self.assertEqual(len(self.collect(client=Missing(layer2.NATIVE_PATH))["interfaces"]), 0)
        self.assertEqual(len(self.collect(client=Missing(layer2.GLOBAL_PATH))["interfaces"]), 14)
        missing_vlan = self.collect(client=Missing(layer2.VLAN_PATH))
        self.assertEqual(len(missing_vlan["interfaces"]), 19)
        self.assertEqual(missing_vlan["vlans"], [])

    def test_filter400_retries_same_json_endpoint_and_discards_unrelated_fields(self):
        class Filter(FixtureClient):
            def get(self, path, **kwargs):
                if "?fields=" in path and path.split("?", 1)[0] in (
                    layer2.NATIVE_PATH,
                    layer2.VLAN_PATH,
                ):
                    raise cisco.RestconfError("filter", status_code=400)
                return super().get(path, **kwargs)

        values = payloads()
        native_row(values, "TwoGigabitEthernet", "1/0/1")["unrelated-secret"] = "DO-NOT-RETAIN"
        client = Filter(values)
        result = cisco.collect(client)
        self.assertEqual(len(result["layer2"]["interfaces"]), 19)
        self.assertNotIn("DO-NOT-RETAIN", str(result))
        self.assertIn(layer2.NATIVE_PATH, client.requests)
        self.assertIn(layer2.VLAN_PATH, client.requests)

    def test_supported_allowed_forms_and_default_all_remain_distinct(self):
        for allowed, expected in (
            ({"vlan-v2": {"vlan-choices": {"vlans": "3-5,999"}}}, ("tagged", [3, 4, 5])),
            ({"vlan-v2": {"vlan-choices": {"none": [None]}}}, ("tagged", [])),
            ({"vlan-v2": {"vlan-choices": {"all": True}}}, ("tagged-all", [])),
            ({"vlan": {"vlans": "3,4,999"}}, ("tagged", [3, 4])),
            ({"vlan": {"all": [None]}}, ("tagged-all", [])),
            (None, ("tagged-all", [])),
        ):
            with self.subTest(allowed=allowed):
                values = payloads()
                trunk = switchport(values)["Cisco-IOS-XE-switch:trunk"]
                if allowed is None:
                    del trunk["allowed"]
                else:
                    trunk["allowed"] = allowed
                row = next(
                    row
                    for row in self.collect(values)["interfaces"]
                    if row["name"] == "TenGigabitEthernet1/0/47"
                )
                self.assertEqual((row["mode"], row["tagged_vids"]), expected)
                self.assertEqual(row["untagged_vid"], 999)

    def test_incremental_allowed_expressions_are_not_interpreted_as_complete_sets(self):
        values = payloads()
        switchport(values)["Cisco-IOS-XE-switch:trunk"]["allowed"] = {
            "vlan-v2": {"vlan-choices": {"all": True}, "remove": "999"}
        }
        result = self.collect(values)
        self.assertNotIn("TenGigabitEthernet1/0/47", {r["name"] for r in result["interfaces"]})
        self.assertTrue(any("incremental" in r["reason"] for r in result["unresolved"]))

    def test_private_dynamic_tunnel_voice_and_routed_modes_remain_unresolved(self):
        for mode in ({"dynamic": "auto"}, {"private-vlan": {"host": [None]}}, {"dot1q-tunnel": {}}):
            with self.subTest(mode=mode):
                values = payloads()
                switchport(values)["Cisco-IOS-XE-switch:mode"] = mode
                self.assertEqual(len(self.collect(values)["interfaces"]), 18)
        values = payloads()
        switchport(values, "TwoGigabitEthernet", "1/0/1")["Cisco-IOS-XE-switch:voice"] = {
            "vlan": {"vlan": 20}
        }
        self.assertEqual(len(self.collect(values)["interfaces"]), 18)
        values = payloads()
        native_row(values, "TenGigabitEthernet", "1/0/47")["switchport-conf"] = {
            "switchport": False
        }
        self.assertEqual(len(self.collect(values)["interfaces"]), 18)

    def test_operational_vlan_port_membership_never_changes_configured_relationships(self):
        values = payloads()
        before = self.collect(values)["interfaces"]
        for row in values[layer2.VLAN_PATH]["Cisco-IOS-XE-vlan-oper:vlans"]["vlan"]:
            row["vlan-interfaces"] = ["TenGigabitEthernet1/0/47", "TwoGigabitEthernet1/0/1"]
        self.assertEqual(self.collect(values)["interfaces"], before)

    def test_malformed_vlan_shapes_and_ambiguous_choices_block(self):
        for bad in (
            {"vlan-choices": {"vlans": "4-3"}},
            {"vlan-choices": {"vlans": "4095"}},
            {"vlan-choices": {"vlans": "3,4", "all": True}},
            {"vlan-choices": {"all": False}},
        ):
            with self.subTest(bad=bad):
                values = payloads()
                switchport(values)["Cisco-IOS-XE-switch:trunk"]["allowed"] = {"vlan-v2": bad}
                with self.assertRaises(cisco.DiscoveryError):
                    self.collect(values)
        values = payloads()
        values[layer2.GLOBAL_PATH] = {"Cisco-IOS-XE-native:vlan": {"dot1q": "malformed"}}
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)

    def test_duplicate_names_vlan_ids_and_mode_choices_block(self):
        values = payloads()
        values[layer2.NATIVE_PATH]["Cisco-IOS-XE-native:interface"]["Port-channel"].append(
            {"name": 1}
        )
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)
        values = payloads()
        rows = values[layer2.VLAN_PATH]["Cisco-IOS-XE-vlan-oper:vlans"]["vlan"]
        rows.append(dict(rows[0]))
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)
        values = payloads()
        switchport(values)["Cisco-IOS-XE-switch:mode"] = {"access": {}, "trunk": {}}
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)

    def test_worker_interruptions_propagate(self):
        class Interrupted(FixtureClient):
            def get(self, path, **kwargs):
                if path.split("?", 1)[0] == layer2.VLAN_PATH:
                    raise RuntimeError("worker interruption")
                return super().get(path, **kwargs)

        with self.assertRaises(RuntimeError):
            self.collect(client=Interrupted(payloads()))


if __name__ == "__main__":
    unittest.main()
