"""PSU physical bays, serialized member ownership and inlet evidence."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_cisco_components import inventory, platform
from tests.test_cisco_iosxe import FixtureClient, fixture_payloads

components = load("adapters.cisco_components")
profiles = load("adapters.cisco_psu_profiles")


def collect(payloads=None, **kwargs):
    payloads = payloads or fixture_payloads()
    return components.collect(
        FixtureClient(payloads),
        inventory(payloads),
        chassis_model="C9300-48UXM",
        chassis_serial="LAB93000001",
        member=1,
        interfaces=[],
        warnings=[],
        **kwargs,
    )


def psu(result):
    return next(item for item in result["items"] if item["kind"] == "power-supply")


def second_member(payloads):
    chassis = deepcopy(
        next(row for row in inventory(payloads) if row["hw-type"] == "hw-type-chassis")
    )
    chassis.update({"dev-name": "Switch 2", "serial-number": "LAB93000002", "hw-dev-index": 800})
    inventory(payloads).append(chassis)
    root = deepcopy(next(row for row in platform(payloads) if row["cname"] == "Switch1"))
    root["cname"] = "Switch2"
    root["state"].update({"serial-no": "LAB93000002", "parent": "Switch2", "location": "2/0/0/0"})
    platform(payloads).append(root)
    flat = deepcopy(next(row for row in inventory(payloads) if row["hw-type"] == "hw-type-pem"))
    flat.update(
        {"dev-name": "Switch 2 - Power Supply A", "serial-number": "LABPSU2A", "hw-dev-index": 12}
    )
    inventory(payloads).append(flat)
    part = deepcopy(next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/B"))
    part["cname"] = "PowerSupply2/A"
    part["state"].update({"serial-no": "LABPSU2A", "parent": "Switch2", "location": "2/0/A/0"})
    platform(payloads).append(part)
    return {
        "is_stack": True,
        "members": [
            {"position": 2, "serial": "LAB93000002", "model": "C9300-48UXM"},
            {"position": 1, "serial": "LAB93000001", "model": "C9300-48UXM"},
        ],
    }


class PsuComponentTests(unittest.TestCase):
    def test_known_chassis_creates_both_physical_bays_without_occupant_identity(self):
        result = collect()
        self.assertEqual([bay["key"] for bay in result["physical_bays"]], ["psu:1/A", "psu:1/B"])
        a, b = result["physical_bays"]
        self.assertEqual(a["bay"], profiles.bay("A"))
        self.assertEqual(a["device_serial"], "LAB93000001")
        self.assertEqual(a["member"], 1)
        self.assertEqual(a["observations"]["reported_presence"], "reported-nonempty")
        self.assertEqual(a["observations"]["status_description"], "status-desc-no-input")
        self.assertEqual(b["observations"]["reported_presence"], "reported-nonempty")
        self.assertEqual([row["key"] for row in result["items"]], ["psu:1/B", "uplink:1/1"])

    def test_documented_bays_survive_absent_platform_evidence_without_claiming_occupancy(self):
        payloads = fixture_payloads()
        payloads[components.PLATFORM_PATH] = {}
        result = collect(payloads)
        self.assertEqual(len(result["physical_bays"]), 2)
        self.assertTrue(
            all(
                bay["observations"]["reported_presence"] == "unknown"
                for bay in result["physical_bays"]
            )
        )
        self.assertFalse(result["items"])

    def test_empty_or_missing_state_does_not_remove_documented_bay(self):
        payloads = fixture_payloads()
        a = next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/A")
        a["state"]["empty"] = True
        result = collect(payloads)
        self.assertEqual(
            result["physical_bays"][0]["observations"]["reported_presence"], "reported-empty"
        )
        a["state"].pop("empty")
        result = collect(payloads)
        self.assertEqual(result["physical_bays"][0]["observations"]["reported_presence"], "unknown")

    def test_misplaced_platform_observation_does_not_claim_bay_state(self):
        payloads = fixture_payloads()
        a = next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/A")
        a["state"]["parent"] = "Switch2"
        result = collect(payloads)
        self.assertEqual(result["physical_bays"][0]["observations"]["reported_presence"], "unknown")

    def test_power_inlet_uses_documented_connector_and_does_not_invent_ratings(self):
        asset = psu(collect())
        self.assertEqual(asset["device_serial"], "LAB93000001")
        self.assertEqual(asset["member"], 1)
        inlet = asset["power_ports"][0]
        self.assertEqual(inlet["name"], "Power Input")
        self.assertEqual(inlet["type"], "iec-60320-c16")
        for field in ("maximum_draw", "allocated_draw", "power_factor"):
            self.assertIsNone(inlet[field])
        self.assertNotIn("status", asset)

    def test_ntc_default_is_explicit_and_only_opted_in(self):
        strict = psu(collect())["power_ports"][0]
        inferred = psu(collect(use_ntc_defaults=True))["power_ports"][0]
        self.assertIsNone(strict["power_factor"])
        self.assertEqual(inferred["power_factor"], "0.95")
        self.assertEqual(inferred["source"]["inference"]["policy"], "ntc-power-factor-default")
        self.assertIsNone(inferred["maximum_draw"])

    def test_power_properties_remain_raw_without_unsupported_units_or_status_mapping(self):
        payloads = fixture_payloads()
        b = next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/B")
        b["platform-properties"] = {
            "platform-property": [
                {"name": "power-factor", "value": {"string": "88.4"}, "configurable": False},
                {"name": "input-power", "value": {"decimal": "158.50"}, "configurable": False},
                {"name": "sys-pwr", "value": {"uintsixfour": "0"}, "configurable": False},
            ]
        }
        b["state"]["status-desc"] = "status-desc-no-input"
        result = collect(payloads)
        asset = psu(result)
        properties = {prop["name"]: prop for prop in asset["observations"]["platform_properties"]}
        self.assertEqual(properties["power-factor"]["value"], {"string": "88.4"})
        self.assertIsNone(asset["power_ports"][0]["power_factor"])
        self.assertIsNone(asset["power_ports"][0]["allocated_draw"])
        self.assertIsNone(asset["power_ports"][0]["maximum_draw"])
        self.assertNotIn("status", asset)
        components.add_revisions(result, {"Cisco-IOS-XE-platform-oper": "2025-03-01"})
        self.assertEqual(properties["power-factor"]["source"]["revision"], "2025-03-01")

    def test_malformed_optional_properties_preserve_serialized_inventory_and_report_context(self):
        malformed = (
            [],
            {"platform-property": [None]},
            {"platform-property": [{"name": []}]},
            {"platform-property": [{"name": "input-power", "value": "158.5"}]},
            {"platform-property": [{"name": "input-power", "value": {"decimal": "bad"}}]},
            {"platform-property": [{"name": "sys-pwr", "value": {"uintsixfour": "-1"}}]},
            {
                "platform-property": [
                    {"name": "sys-pwr", "value": {"uintsixfour": "0"}, "configurable": "false"}
                ]
            },
            {
                "platform-property": [
                    {"name": "sys-pwr", "value": {"uintsixfour": "0"}},
                    {"name": "sys-pwr", "value": {"uintsixfour": "1"}},
                ]
            },
        )
        for properties in malformed:
            with self.subTest(properties=properties):
                payloads = fixture_payloads()
                b = next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/B")
                b["platform-properties"] = properties
                result = collect(payloads)
                self.assertEqual(psu(result)["serial"], "LABPSUB0001")
                self.assertEqual(len(result["physical_bays"]), 2)
                self.assertEqual(psu(result)["observations"]["platform_properties"], [])
                errors = [
                    row
                    for row in result["unresolved"]
                    if row["reason"].startswith("Optional operational property skipped:")
                ]
                self.assertTrue(errors)
                self.assertTrue(all(row["name"] == "PowerSupply1/B" for row in errors))
                self.assertIsNone(psu(result)["power_ports"][0]["power_factor"])

    def test_valid_optional_properties_survive_other_malformed_operational_rows(self):
        payloads = fixture_payloads()
        b = next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/B")
        b["platform-properties"] = {
            "platform-property": [
                {"name": "power-factor", "value": {"string": "88.4"}},
                {"name": "input-power", "value": {"decimal": {"bad": "structure"}}},
            ]
        }
        result = collect(payloads)
        properties = psu(result)["observations"]["platform_properties"]
        self.assertEqual([prop["name"] for prop in properties], ["power-factor"])
        self.assertEqual(properties[0]["value"], {"string": "88.4"})
        self.assertTrue(any(row.get("property") == "input-power" for row in result["unresolved"]))

    def test_two_members_have_independent_bays_and_verified_asset_owners(self):
        payloads = fixture_payloads()
        stack = second_member(payloads)
        inventory(payloads).reverse()
        platform(payloads).reverse()
        result = collect(payloads, stack=stack)
        self.assertEqual(
            [bay["key"] for bay in result["physical_bays"]],
            ["psu:1/A", "psu:1/B", "psu:2/A", "psu:2/B"],
        )
        self.assertEqual(
            {item["key"]: item["device_serial"] for item in result["items"]},
            {"psu:1/B": "LAB93000001", "psu:2/A": "LAB93000002"},
        )
        self.assertTrue(any(row.get("serial") == "LABUPLINK001" for row in result["unresolved"]))

    def test_missing_member_platform_root_defers_asset_but_preserves_documented_bays(self):
        payloads = fixture_payloads()
        stack = second_member(payloads)
        platform(payloads)[:] = [part for part in platform(payloads) if part["cname"] != "Switch2"]
        result = collect(payloads, stack=stack)
        self.assertEqual(len(result["physical_bays"]), 4)
        self.assertEqual([item["key"] for item in result["items"]], ["psu:1/B"])
        self.assertTrue(any(row.get("serial") == "LABPSU2A" for row in result["unresolved"]))

    def test_contradictory_stack_owner_identity_and_position_block_collection(self):
        for field, value in (("serial", "WRONG"), ("model", "C9300-48T"), ("position", 3)):
            with self.subTest(field=field):
                payloads = fixture_payloads()
                stack = second_member(payloads)
                stack["members"][0][field] = value
                with self.assertRaises(components.ComponentDiscoveryError):
                    collect(payloads, stack=stack)

    def test_exact_profiles_accept_documented_parts_without_model_suffix_guessing(self):
        for model, connector in profiles.PSU_CONNECTORS.items():
            with self.subTest(model=model):
                self.assertEqual(profiles.power_port(model)["type"], connector)
                self.assertTrue(any(model in parts for parts in profiles.FAMILY_PSUS.values()))
        self.assertFalse(profiles.supported_psu("C9300LM-48U-4Y", "PWR-C1-1100WAC-P"))
        self.assertTrue(profiles.supported_psu("C9300LM-48U-4Y", "PWR-C6-1KWAC"))
        self.assertTrue(profiles.supported_psu("C9300X-48HX", "PWR-C1-1900WHV-T"))
        self.assertIsNone(profiles.family_for_chassis("C9300-48UXM-M"))
        self.assertIsNone(profiles.family_for_chassis("C9300-48UXM-UNKNOWN"))

    def test_unknown_chassis_or_psu_does_not_invent_module_type(self):
        payloads = fixture_payloads()
        for row in inventory(payloads):
            if row.get("hw-type") == "hw-type-pem":
                row["part-number"] = "UNKNOWN-PSU"
        next(row for row in platform(payloads) if row["cname"] == "PowerSupply1/B")["state"][
            "part-no"
        ] = "UNKNOWN-PSU"
        result = collect(payloads)
        self.assertEqual(len(result["physical_bays"]), 2)
        self.assertFalse(any(item["kind"] == "power-supply" for item in result["items"]))
        self.assertTrue(any(row.get("model") == "UNKNOWN-PSU" for row in result["unresolved"]))


if __name__ == "__main__":
    unittest.main()
