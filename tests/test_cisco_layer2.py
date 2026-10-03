"""Configured 802.1Q facts with scoped, documented defaults and no mode guessing."""

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

    def collect_ntc(self, values=None, client=None, use_ntc_defaults=True, **overrides):
        values = values or payloads()
        normalized = cisco.collect(FixtureClient(values))["interfaces"]
        return layer2.collect(
            client or FixtureClient(values),
            normalized,
            model=overrides.get("model", "C9300-48UXM"),
            software_version=overrides.get("software_version", "17.12.08"),
            canonical_name=cisco.canonical_interface_name,
            warnings=[],
            use_ntc_defaults=use_ntc_defaults,
        )

    def test_ntc_flag_off_preserves_strict_result_and_has_no_inference_metadata(self):
        result = self.collect_ntc(use_ntc_defaults=False)
        self.assertEqual(len(result["interfaces"]), 19)
        self.assertEqual(len(result["unresolved"]), 34)
        self.assertFalse(any("inference" in row for row in result["settings"]))
        self.assertFalse(any("inferred" in row for row in result["interfaces"]))
        normalized = cisco.collect(FixtureClient(payloads()))["interfaces"]
        default = layer2.collect(
            FixtureClient(payloads()),
            normalized,
            model="C9300-48UXM",
            software_version="17.12.08",
            canonical_name=cisco.canonical_interface_name,
            warnings=[],
        )
        self.assertEqual(result, default)

    def test_ntc_flag_requires_an_actual_boolean(self):
        for invalid in ("true", "false", 0, 1, None, []):
            with self.subTest(invalid=invalid), self.assertRaises(layer2.Layer2DiscoveryError):
                self.collect_ntc(use_ntc_defaults=invalid)

    def test_ntc_opt_in_models_only_down_dynamic_ports_and_labels_assumptions(self):
        result = self.collect_ntc()
        inferred = [row for row in result["interfaces"] if row.get("inferred")]
        self.assertEqual(len(inferred), 33)
        self.assertEqual(len(result["interfaces"]), 52)
        self.assertEqual(len(result["unresolved"]), 1)
        self.assertEqual(result["unresolved"][0]["name"], "TwoGigabitEthernet1/0/14")
        settings = {row["name"]: row for row in result["settings"]}
        for row in inferred:
            self.assertEqual(
                (row["mode"], row["untagged_vid"], row["tagged_vids"]), ("tagged-all", 1, [])
            )
            facts = settings[row["name"]]
            inference = facts["inference"]
            self.assertEqual(inference, row["source"]["ntc_inference"])
            self.assertEqual(inference["policy"], layer2.NTC_DOWN_POLICY)
            self.assertEqual(inference["observed_oper_status"], "if-oper-state-lower-layer-down")
            self.assertEqual(
                inference["inferred_fields"], {"mode": "tagged-all", "untagged_vid": 1}
            )
            self.assertIn("assumption", inference["meaning"])
            self.assertEqual(inference["reason"], facts["unresolved_reason"])
            self.assertEqual(facts["configured_mode"], "dynamic-auto")
            self.assertEqual(facts["field_sources"]["configured_mode"], "documented-default")
            self.assertTrue(inference["upstream_url"].endswith("jinja_filters.py#L95"))

    def test_ntc_down_signal_accepts_only_the_two_reviewed_enums(self):
        values = payloads()
        physical = next(
            row
            for row in values[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
                "interface"
            ]
            if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/15"
        )
        for state in (
            "if-oper-state-no-pass",
            "if-oper-state-lower-layer-down",
            "if-oper-state-ready",
            "if-oper-state-test",
            "if-oper-state-dormant",
            "if-oper-state-unknown",
            None,
            "down",
            "if-oper-state-future",
        ):
            with self.subTest(state=state):
                physical["oper-status"] = state
                result = self.collect_ntc(values)
                selected = [
                    row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/15"
                ]
                self.assertEqual(bool(selected), state in layer2.NTC_DOWN_STATES)

    def test_ntc_opt_in_keeps_static_bundles_unchanged(self):
        strict = self.collect_ntc(use_ntc_defaults=False)
        opt_in = self.collect_ntc()
        original = {row["name"]: row for row in strict["interfaces"]}
        self.assertEqual(
            original, {row["name"]: row for row in opt_in["interfaces"] if row["name"] in original}
        )

    def test_ntc_literal_full_allowed_range_matches_upstream_without_rewriting_facts(self):
        values = payloads()
        native_row(values, "TwoGigabitEthernet", "1/0/15")["switchport-config"] = {
            "switchport": {
                "Cisco-IOS-XE-switch:trunk": {
                    "allowed": {"vlan-v2": {"vlan-choices": {"vlans": "1-4094"}}}
                }
            }
        }
        result = self.collect_ntc(values)
        row = next(row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/15")
        facts = next(row for row in result["settings"] if row["name"] == "TwoGigabitEthernet1/0/15")
        self.assertTrue(row["inferred"])
        self.assertEqual((row["mode"], row["tagged_vids"]), ("tagged-all", []))
        self.assertEqual(facts["allowed_mode"], "list")
        self.assertEqual(facts["allowed_vids"], list(range(1, 4095)))
        self.assertEqual(facts["observations"]["raw_allowed"], {"vlans": "1-4094"})
        self.assertEqual(
            row["source"]["ntc_inference"]["allowed_vlan_evidence"],
            {
                "configured_policy": "list",
                "raw_selection": {"vlans": "1-4094"},
                "source": "explicit",
                "validated_literal_full_range": True,
            },
        )

    def test_ntc_other_finite_or_composed_allowed_ranges_remain_unresolved(self):
        for allowed in ("1-4093", "3,4", "1,2-4094", "1-4093,4094"):
            with self.subTest(allowed=allowed):
                values = payloads()
                native_row(values, "TwoGigabitEthernet", "1/0/15")["switchport-config"] = {
                    "switchport": {
                        "Cisco-IOS-XE-switch:trunk": {
                            "allowed": {"vlan-v2": {"vlan-choices": {"vlans": allowed}}}
                        }
                    }
                }
                result = self.collect_ntc(values)
                self.assertNotIn(
                    "TwoGigabitEthernet1/0/15", {row["name"] for row in result["interfaces"]}
                )

    def test_ntc_literal_full_range_cannot_bypass_validated_range_proof(self):
        strict = self.collect_ntc(use_ntc_defaults=False)
        facts = next(row for row in strict["settings"] if row["name"] == "TwoGigabitEthernet1/0/15")
        facts["allowed_mode"] = "list"
        facts["allowed_vids"] = [1, 2, 3]
        facts["observations"]["raw_allowed"] = {"vlans": "1-4094"}
        interface = {
            "name": facts["name"],
            "observations": {"oper_status": "if-oper-state-lower-layer-down"},
        }
        self.assertIsNone(layer2._ntc_down_bundle(facts, interface, True, "unresolved mode"))

    def test_ntc_explicit_dynamic_modes_retain_native_vid_and_configuration(self):
        for dynamic in ("auto", "desirable"):
            with self.subTest(dynamic=dynamic):
                values = payloads()
                physical = next(
                    row
                    for row in values[cisco.INTERFACES_PATH][
                        "Cisco-IOS-XE-interfaces-oper:interfaces"
                    ]["interface"]
                    if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/1"
                )
                physical["oper-status"] = "if-oper-state-lower-layer-down"
                port = switchport(values, "TwoGigabitEthernet", "1/0/1")
                port["Cisco-IOS-XE-switch:mode"] = {"dynamic": dynamic}
                port["Cisco-IOS-XE-switch:trunk"] = {
                    "native": {"vlan": {"vlan-id": 999}},
                    "allowed": {"vlan-v2": {"vlan-choices": {"all": True}}},
                }
                result = self.collect_ntc(values)
                row = next(
                    row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/1"
                )
                facts = next(
                    candidate
                    for candidate in result["settings"]
                    if candidate["name"] == row["name"]
                )
                self.assertTrue(row["inferred"])
                self.assertEqual(row["untagged_vid"], 999)
                self.assertEqual(row["observations"]["configured_mode"], "dynamic-" + dynamic)
                self.assertEqual(
                    row["source"]["ntc_inference"]["inferred_fields"]["untagged_vid"], 999
                )
                self.assertNotEqual(facts["configured_mode"], "trunk")

    def test_ntc_never_overrides_voice_private_tunnel_native_tagging_or_finite_allowed(self):
        changes = (
            {"Cisco-IOS-XE-switch:voice": {"vlan": {"vlan": 20}}},
            {"Cisco-IOS-XE-switch:private-vlan": {}},
            {"Cisco-IOS-XE-switch:mode": {"private-vlan": {"host": [None]}}},
            {"Cisco-IOS-XE-switch:mode": {"dot1q-tunnel": {}}},
            {"Cisco-IOS-XE-switch:trunk": {"native": {"vlan": {"tag": True, "vlan-id": 1}}}},
            {"Cisco-IOS-XE-switch:trunk": {"native": {"vlan": {"tag": False, "vlan-id": 1}}}},
            {
                "Cisco-IOS-XE-switch:trunk": {
                    "allowed": {"vlan-v2": {"vlan-choices": {"vlans": "3,4"}}}
                }
            },
            {
                "Cisco-IOS-XE-switch:trunk": {
                    "allowed": {"vlan-v2": {"vlan-choices": {"none": [None]}}}
                }
            },
            {"Cisco-IOS-XE-switch:trunk": {"encapsulation": "isl"}},
        )
        for change in changes:
            with self.subTest(change=change):
                values = payloads()
                native_row(values, "TwoGigabitEthernet", "1/0/15")["switchport-config"] = {
                    "switchport": change
                }
                result = self.collect_ntc(values)
                self.assertNotIn(
                    "TwoGigabitEthernet1/0/15", {row["name"] for row in result["interfaces"]}
                )
        for global_config in (
            None,
            {},
            {"Cisco-IOS-XE-native:vlan": {"dot1q": {"tag": {"native": [None]}}}},
        ):
            with self.subTest(global_config=global_config):
                values = payloads()
                values[layer2.GLOBAL_PATH] = global_config
                result = self.collect_ntc(values)
                self.assertFalse(any(row.get("inferred") for row in result["interfaces"]))

    def test_ntc_does_not_guess_management_logical_routed_or_lag_interfaces(self):
        values = payloads()
        switchport(values, "Port-channel", 1)["Cisco-IOS-XE-switch:mode"] = {"dynamic": "auto"}
        native_row(values, "TwoGigabitEthernet", "1/0/15")["switchport-conf"] = {
            "switchport": False
        }
        result = self.collect_ntc(values)
        inferred = {row["name"] for row in result["interfaces"] if row.get("inferred")}
        self.assertNotIn("Port-channel1", inferred)
        self.assertNotIn("GigabitEthernet0/0", inferred)
        self.assertNotIn("TwoGigabitEthernet1/0/15", inferred)
        self.assertFalse(any(name.startswith("Vlan") for name in inferred))

    def test_ntc_unavailable_configuration_or_missing_row_never_enables_a_guess(self):
        class Unavailable(FixtureClient):
            def __init__(self, missing):
                super().__init__(payloads())
                self.missing = missing

            def get(self, path, **kwargs):
                if path.split("?", 1)[0] == self.missing:
                    raise cisco.RestconfError("unavailable", status_code=404)
                return super().get(path, **kwargs)

        for missing in (layer2.NATIVE_PATH, layer2.GLOBAL_PATH):
            with self.subTest(missing=missing):
                result = self.collect_ntc(client=Unavailable(missing))
                self.assertFalse(any(row.get("inferred") for row in result["interfaces"]))
        values = payloads()
        values[layer2.NATIVE_PATH] = None
        self.assertEqual(self.collect_ntc(values)["interfaces"], [])
        values = payloads()
        rows = values[layer2.NATIVE_PATH]["Cisco-IOS-XE-native:interface"]["TwoGigabitEthernet"]
        rows[:] = [row for row in rows if row["name"] != "1/0/15"]
        result = self.collect_ntc(values)
        self.assertNotIn("TwoGigabitEthernet1/0/15", {row["name"] for row in result["interfaces"]})

    def test_ntc_flag_does_not_bypass_malformed_or_competing_selector_errors(self):
        for mode in (None, {"access": {}, "unexpected-mode": {}}):
            with self.subTest(mode=mode):
                values = payloads()
                native_row(values, "TwoGigabitEthernet", "1/0/15")["switchport-config"] = {
                    "switchport": {"Cisco-IOS-XE-switch:mode": mode}
                }
                with self.assertRaises(cisco.DiscoveryError):
                    self.collect_ntc(values)

    def test_lab_has19_complete_bundles_and34_dynamic_modes(self):
        result = self.collect()
        self.assertEqual(len(result["interfaces"]), 19)
        self.assertEqual(len(result["unresolved"]), 34)
        self.assertTrue(all(row["category"] == "dynamic-mode" for row in result["unresolved"]))
        self.assertEqual(len(result["settings"]), 53)
        self.assertEqual(len(result["not_applicable"]), 5)
        self.assertTrue(result["catalog_complete"])
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

    def test_unused_physical_ports_retain_known_defaults_without_an_access_mode_guess(self):
        result = self.collect()
        row = next(row for row in result["settings"] if row["name"] == "TwoGigabitEthernet1/0/15")
        self.assertEqual(row["configured_mode"], "dynamic-auto")
        self.assertEqual((row["access_vid"], row["native_vid"], row["untagged_vid"]), (1, 1, 1))
        self.assertFalse(row["native_tagging"])
        self.assertEqual(row["allowed_mode"], "all")
        self.assertIsNone(row["allowed_vids"])
        self.assertEqual(row["field_sources"]["configured_mode"], "documented-default")
        self.assertEqual(row["field_sources"]["access_vid"], "documented-default")
        self.assertEqual(row["field_sources"]["native_vid"], "documented-default")
        self.assertEqual(
            row["field_sources"]["untagged_vid"],
            "equal-access-and-native-vlans-with-tagging-disabled",
        )
        self.assertTrue(row["source"]["config"]["complete_read"])
        self.assertIn(
            "configuring_interface_characteristics",
            row["source"]["defaults"]["documents"]["interface_defaults"],
        )
        self.assertNotIn(row["name"], {bundle["name"] for bundle in result["interfaces"]})

    def test_explicit_access_without_vid_uses_documented_default_and_provenance(self):
        values = payloads()
        port = switchport(values, "TwoGigabitEthernet", "1/0/1")
        del port["Cisco-IOS-XE-switch:access"]
        result = self.collect(values)
        row = next(row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/1")
        self.assertEqual((row["mode"], row["untagged_vid"]), ("access", 1))
        self.assertEqual(row["observations"]["access_vid_source"], "documented-default")
        self.assertEqual(row["source"]["defaults"]["access_vid"], 1)
        self.assertIn("interface_defaults", row["source"]["defaults"]["documents"])

    def test_dynamic_modes_retain_independent_explicit_vlans_without_mapping_mode(self):
        for administrative in ("auto", "desirable"):
            with self.subTest(administrative=administrative):
                values = payloads()
                port = switchport(values)
                port["Cisco-IOS-XE-switch:mode"] = {"dynamic": administrative}
                port["Cisco-IOS-XE-switch:access"] = {"vlan": {"vlan": 2}}
                result = self.collect(values)
                row = next(
                    row for row in result["settings"] if row["name"] == "TenGigabitEthernet1/0/47"
                )
                self.assertEqual(row["configured_mode"], "dynamic-" + administrative)
                self.assertEqual((row["access_vid"], row["native_vid"]), (2, 999))
                self.assertEqual(row["allowed_vids"], [3, 4, 999])
                self.assertIsNone(row["untagged_vid"])
                self.assertEqual(row["field_sources"]["configured_mode"], "explicit")
                self.assertNotIn(row["name"], {bundle["name"] for bundle in result["interfaces"]})

    def test_equal_dynamic_access_native_settings_establish_only_untagged_vid(self):
        values = payloads()
        port = switchport(values)
        port["Cisco-IOS-XE-switch:mode"] = {"dynamic": "auto"}
        port["Cisco-IOS-XE-switch:access"] = {"vlan": {"vlan": 999}}
        row = next(
            row
            for row in self.collect(values)["settings"]
            if row["name"] == "TenGigabitEthernet1/0/47"
        )
        self.assertEqual(row["untagged_vid"], 999)
        self.assertIn("independently", row["observations"]["untagged_meaning"])

    def test_management_svis_and_explicit_routed_ports_are_not_applicable(self):
        values = payloads()
        native_row(values, "TenGigabitEthernet", "1/0/47")["switchport-conf"] = {
            "switchport": False
        }
        result = self.collect(values)
        rows = {row["name"]: row for row in result["not_applicable"]}
        self.assertEqual(rows["GigabitEthernet0/0"]["category"], "dedicated-management")
        self.assertEqual(rows["Vlan2"]["category"], "virtual-interface")
        self.assertEqual(rows["TenGigabitEthernet1/0/47"]["category"], "routed-interface")
        self.assertEqual(len(rows), 6)
        self.assertNotIn("TenGigabitEthernet1/0/47", {row["name"] for row in result["settings"]})

    def test_missing_row_or_unusable_native_envelope_never_applies_defaults(self):
        values = payloads()
        rows = values[layer2.NATIVE_PATH]["Cisco-IOS-XE-native:interface"]["TwoGigabitEthernet"]
        rows[:] = [row for row in rows if row["name"] != "1/0/15"]
        result = self.collect(values)
        self.assertNotIn("TwoGigabitEthernet1/0/15", {row["name"] for row in result["settings"]})
        unresolved = next(
            row for row in result["unresolved"] if row["name"] == "TwoGigabitEthernet1/0/15"
        )
        self.assertEqual(unresolved["category"], "missing-data")
        for envelope in (None, {}, {"unexpected": {}}):
            with self.subTest(envelope=envelope):
                values = payloads()
                values[layer2.NATIVE_PATH] = envelope
                result = self.collect(values)
                self.assertEqual(result["settings"], [])
                self.assertEqual(result["interfaces"], [])

    def test_unreviewed_profiles_retain_explicit_settings_but_no_absent_leaf_defaults(self):
        interfaces = cisco.collect(FixtureClient())["interfaces"]
        for model, version in (("C9300-24T", "17.12.08"), ("C9300-48UXM", "17.16.01")):
            with self.subTest(model=model, version=version):
                result = layer2.collect(
                    FixtureClient(payloads()),
                    interfaces,
                    model=model,
                    software_version=version,
                    canonical_name=cisco.canonical_interface_name,
                    warnings=[],
                )
                row = next(
                    row for row in result["settings"] if row["name"] == "TwoGigabitEthernet1/0/15"
                )
                self.assertIsNone(row["configured_mode"])
                self.assertIsNone(row["access_vid"])
                self.assertIsNone(row["native_vid"])
                self.assertIsNone(row["allowed_mode"])
                self.assertIsNone(row["untagged_vid"])
                self.assertNotIn("defaults", row["source"])

    def test_port_channel_does_not_receive_an_ethernet_dtp_default(self):
        values = payloads()
        row = native_row(values, "Port-channel", 1)
        row.pop("switchport-config")
        result = self.collect(values)
        settings = next(row for row in result["settings"] if row["name"] == "Port-channel1")
        self.assertIsNone(settings["configured_mode"])
        self.assertIsNone(settings["access_vid"])
        self.assertIsNone(settings["untagged_vid"])
        self.assertNotIn("defaults", settings["source"])

    def test_unsupported_modes_and_voice_retain_explicit_facts_without_untagged_claim(self):
        for mode in ({"private-vlan": {"host": [None]}}, {"dot1q-tunnel": {}}):
            with self.subTest(mode=mode):
                values = payloads()
                switchport(values)["Cisco-IOS-XE-switch:mode"] = mode
                result = self.collect(values)
                row = next(
                    row for row in result["settings"] if row["name"] == "TenGigabitEthernet1/0/47"
                )
                self.assertEqual(row["native_vid"], 999)
                self.assertEqual(row["allowed_vids"], [3, 4, 999])
                self.assertIsNone(row["access_vid"])
                self.assertIsNone(row["untagged_vid"])
                unresolved = next(
                    candidate
                    for candidate in result["unresolved"]
                    if candidate["name"] == row["name"]
                )
                self.assertEqual(unresolved["category"], "unsupported")
        values = payloads()
        port = switchport(values, "TwoGigabitEthernet", "1/0/1")
        port["Cisco-IOS-XE-switch:voice"] = {"vlan": {"vlan": 20}}
        row = next(
            row
            for row in self.collect(values)["settings"]
            if row["name"] == "TwoGigabitEthernet1/0/1"
        )
        self.assertEqual(row["access_vid"], 2)
        self.assertTrue(row["observations"]["voice_vlan_present"])
        self.assertIsNone(row["untagged_vid"])

    def test_native_tagging_override_and_global_tagging_retain_vid_without_untagged_mapping(self):
        for override in (True, False):
            with self.subTest(override=override):
                values = payloads()
                switchport(values)["Cisco-IOS-XE-switch:trunk"]["native"]["vlan"]["tag"] = override
                result = self.collect(values)
                row = next(
                    row for row in result["settings"] if row["name"] == "TenGigabitEthernet1/0/47"
                )
                self.assertEqual(row["native_vid"], 999)
                self.assertEqual(row["observations"]["native_tag_override"], override)
                self.assertIsNone(row["native_tagging"])
                self.assertIsNone(row["untagged_vid"])
                self.assertNotIn(row["name"], {bundle["name"] for bundle in result["interfaces"]})

    def test_complete_catalog_flag_requires_a_valid_successful_database_scope(self):
        for body, expected in (
            (None, False),
            ({}, False),
            ({"unexpected": {}}, False),
            ({"Cisco-IOS-XE-vlan-oper:vlans": {}}, True),
        ):
            with self.subTest(body=body):
                values = payloads()
                values[layer2.VLAN_PATH] = body
                result = self.collect(values)
                self.assertEqual(result["catalog_complete"], expected)
                self.assertEqual(result["vlans"], [])

    def test_wrong_namespace_cannot_supply_default_or_explicit_vlan_evidence(self):
        for field in ("mode", "access", "trunk"):
            with self.subTest(field=field):
                values = payloads()
                port = switchport(values)
                qualified = "Cisco-IOS-XE-switch:" + field
                if qualified not in port:
                    port[qualified] = {"vlan": {"vlan": 2}}
                port["unrelated-model:" + field] = port.pop(qualified)
                with self.assertRaises(cisco.DiscoveryError):
                    self.collect(values)
        values = payloads()
        native = values[layer2.NATIVE_PATH].pop("Cisco-IOS-XE-native:interface")
        values[layer2.NATIVE_PATH]["unrelated-model:interface"] = native
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)

    def test_null_present_containers_block_instead_of_enabling_defaults(self):
        for container in ("mode", "access", "trunk"):
            with self.subTest(container=container):
                values = payloads()
                switchport(values)["Cisco-IOS-XE-switch:" + container] = None
                with self.assertRaises(cisco.DiscoveryError):
                    self.collect(values)
        values = payloads()
        switchport(values)["Cisco-IOS-XE-switch:trunk"]["encapsulation"] = None
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)
        for body in (
            {"Cisco-IOS-XE-native:vlan": None},
            {"Cisco-IOS-XE-native:vlan": {"Cisco-IOS-XE-vlan:dot1q": None}},
            {"Cisco-IOS-XE-native:vlan": {"Cisco-IOS-XE-vlan:dot1q": {"tag": None}}},
        ):
            with self.subTest(global_body=body):
                values = payloads()
                values[layer2.GLOBAL_PATH] = body
                with self.assertRaises(cisco.DiscoveryError):
                    self.collect(values)

    def test_catalog_retains_vid_when_device_does_not_supply_a_name(self):
        values = payloads()
        rows = values[layer2.VLAN_PATH]["Cisco-IOS-XE-vlan-oper:vlans"]["vlan"]
        rows[0].pop("name")
        result = self.collect(values)
        retained = next(row for row in result["vlans"] if row["vid"] == rows[0]["id"])
        self.assertIsNone(retained["name"])
        self.assertTrue(result["catalog_complete"])

    def test_unknown_mode_or_allowed_choice_never_infers_defaults(self):
        values = payloads()
        switchport(values)["Cisco-IOS-XE-switch:mode"] = {"future-mode": {}}
        row = next(
            row
            for row in self.collect(values)["settings"]
            if row["name"] == "TenGigabitEthernet1/0/47"
        )
        self.assertIsNone(row["configured_mode"])
        self.assertIsNone(row["access_vid"])
        self.assertIsNone(row["untagged_vid"])
        values = payloads()
        switchport(values)["Cisco-IOS-XE-switch:trunk"]["allowed"] = {
            "vlan-v2": {"vlan-choices": {"future-choice": True}}
        }
        row = next(
            row
            for row in self.collect(values)["settings"]
            if row["name"] == "TenGigabitEthernet1/0/47"
        )
        self.assertIsNone(row["allowed_mode"])
        self.assertEqual(row["native_vid"], 999)

    def test_known_and_unknown_competing_selectors_block_complete_assignments(self):
        values = payloads()
        switchport(values)["Cisco-IOS-XE-switch:mode"] = {
            "access": {},
            "unexpected-mode": {},
        }
        with self.assertRaises(cisco.DiscoveryError):
            self.collect(values)
        for known_choice in ({"all": True}, {"vlans": "3,4"}):
            with self.subTest(known_choice=known_choice):
                values = payloads()
                switchport(values)["Cisco-IOS-XE-switch:trunk"]["allowed"] = {
                    "vlan-v2": {"vlan-choices": {**known_choice, "unexpected-choice": "3,4"}}
                }
                with self.assertRaises(cisco.DiscoveryError):
                    self.collect(values)

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
                self.assertTrue(
                    all(
                        row["source"]["global_tagging"]["origin"] is None
                        for row in result["settings"]
                    )
                )

    def test_default_profile_is_scoped_to_reviewed_chassis_and_release_families(self):
        for model, version in (("C9300-24T", "17.12.08"), ("C9300-48UXM", "17.16.01")):
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
