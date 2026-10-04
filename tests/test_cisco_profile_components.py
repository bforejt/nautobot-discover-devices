"""Documented uplinks still require independent serialized placement evidence.

These are constructed source regressions, not additional live hardware captures.
The original structured slot-1 convention is used explicitly in each source.
"""

import json
import unittest
from copy import deepcopy

from tests._loader import fixture, load
from tests.test_cisco_components import inventory, platform
from tests.test_cisco_iosxe import FixtureClient, fixture_payloads

cisco = load("adapters.cisco_iosxe")
components = load("adapters.cisco_components")


def documented_module_payloads(chassis, pid, family, count, *, optical=False):
    """Retain independent chassis, serialized module and explicit interface rows."""
    payloads = fixture_payloads()
    chassis_row = next(row for row in inventory(payloads) if row["hw-type"] == "hw-type-chassis")
    chassis_row["part-number"] = chassis
    root = next(row for row in platform(payloads) if row["cname"] == "Switch1")
    root["state"]["part-no"] = chassis
    module = next(row for row in inventory(payloads) if row["hw-type"] == "hw-type-pim")
    module["part-number"] = pid
    placed = next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1")
    placed["state"].update({"part-no": pid, "type": "comp-module"})
    rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"]
    prototype = deepcopy(next(row for row in rows if row["name"] == "GigabitEthernet1/1/1"))
    rows[:] = [row for row in rows if "1/1/" not in row["name"]]
    rows.extend(
        {**deepcopy(prototype), "name": f"{family}1/1/{port}"} for port in range(1, count + 1)
    )
    if optical:
        optic = fixture("iosxe_transceiver_inventory.json")
        optic["hardware_inventory"]["dev-name"] = f"{family}1/1/1"
        optic["platform_component"]["cname"] = f"{family}1/1/1"
        inventory(payloads).append(optic["hardware_inventory"])
        platform(payloads).append(optic["platform_component"])
    return payloads


def uplink_items(discovery):
    return {
        row["key"]: row
        for row in discovery["components"]["items"]
        if row["kind"] in ("network-module", "transceiver")
    }


class DocumentedComponentProfileTests(unittest.TestCase):
    def test_documented_uplink_families_create_assets_only_for_observed_ports(self):
        cases = (
            ("C9300-24T", "C9300-NM-4G", "GigabitEthernet", 4, "1000base-x-sfp"),
            ("C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8, "10gbase-x-sfpp"),
            ("C9300-24P", "C9300-NM-2Q", "FortyGigabitEthernet", 2, "40gbase-x-qsfpp"),
            ("C9300-48P", "C9300-NM-2Y", "TwentyFiveGigE", 2, "25gbase-x-sfp28"),
            ("C9300-24T", "C9300-NM-4M", "TenGigabitEthernet", 4, "10gbase-t"),
            ("C9300X-24Y", "C9300X-NM-2C", "HundredGigE", 2, "100gbase-x-qsfp28"),
            ("C9300X-24Y", "C9300X-NM-4C", "HundredGigE", 4, "100gbase-x-qsfp28"),
            ("C9300X-48HX", "C9300X-NM-8M", "TenGigabitEthernet", 8, "10gbase-t"),
            ("C9300X-48TX", "C9300X-NM-8Y", "TwentyFiveGigE", 8, "25gbase-x-sfp28"),
        )
        for chassis, pid, family, count, type_ in cases:
            with self.subTest(chassis=chassis, pid=pid):
                result = cisco.collect(
                    FixtureClient(documented_module_payloads(chassis, pid, family, count))
                )
                module = uplink_items(result)["uplink:1/1"]
                self.assertEqual(module["model"], pid)
                self.assertEqual(module["serial"], "LABUPLINK001")
                self.assertEqual(module["device_serial"], "LAB93000001")
                self.assertEqual(module["chassis_model"], chassis)
                self.assertEqual(
                    module["interfaces"],
                    sorted(f"{family}1/1/{port}" for port in range(1, count + 1)),
                )
                self.assertTrue(module["source"]["ownership"]["hardware_documents"])
                observed = {row["name"]: row for row in result["interfaces"]}
                for name in module["interfaces"]:
                    self.assertEqual(observed[name]["type"], type_)
                self.assertNotIn("interface_templates", module)
                self.assertEqual(json.loads(json.dumps(result)), result)

    def test_optics_follow_a_serial_verified_sfp_sfp28_or_qsfp_parent(self):
        for pid, family, count, type_ in (
            ("C9300-NM-8X", "TenGigabitEthernet", 8, "10gbase-x-sfpp"),
            ("C9300-NM-2Y", "TwentyFiveGigE", 2, "25gbase-x-sfp28"),
            ("C9300-NM-2Q", "FortyGigabitEthernet", 2, "40gbase-x-qsfpp"),
        ):
            with self.subTest(pid=pid):
                payloads = documented_module_payloads(
                    "C9300-48UXM", pid, family, count, optical=True
                )
                result = cisco.collect(FixtureClient(payloads))
                optic = uplink_items(result)["transceiver:1/1/1"]
                self.assertEqual(optic["parent_key"], "uplink:1/1")
                self.assertEqual(optic["source"]["ownership"]["parent_serial"], "LABUPLINK001")
                self.assertEqual(optic["source"]["ownership"]["parent_model"], pid)
                self.assertEqual(optic["source"]["ownership"]["physical_type"], type_)
                self.assertEqual(optic["bay"]["name"], f"Transceiver {family}1/1/1")
                self.assertEqual(optic["interfaces"], [])
                self.assertEqual(optic["manufacturer"], "CISCO-EQUIV")
                self.assertEqual(json.loads(json.dumps(result)), result)

    def test_copper_uplink_does_not_establish_a_transceiver_cage(self):
        result = cisco.collect(
            FixtureClient(
                documented_module_payloads(
                    "C9300-24T", "C9300-NM-4M", "TenGigabitEthernet", 4, optical=True
                )
            )
        )
        self.assertEqual(set(uplink_items(result)), {"uplink:1/1"})
        self.assertTrue(
            any(
                row.get("serial") == "LABOPTIC001" and "copper" in row["reason"]
                for row in result["components"]["unresolved"]
            )
        )

    def test_both_identity_sources_accept_documented_long_and_short_port_aliases(self):
        for chassis, pid, canonical_family, count, alias in (
            ("C9300-48UXM", "C9300-NM-2Y", "TwentyFiveGigE", 2, "TwentyFiveGigabitEthernet"),
            ("C9300-48UXM", "C9300-NM-2Y", "TwentyFiveGigE", 2, "Twe"),
            ("C9300X-24Y", "C9300X-NM-2C", "HundredGigE", 2, "HundredGigabitEthernet"),
            ("C9300X-24Y", "C9300X-NM-2C", "HundredGigE", 2, "Hu"),
        ):
            with self.subTest(pid=pid, alias=alias):
                payloads = documented_module_payloads(
                    chassis, pid, canonical_family, count, optical=True
                )
                optic_hardware = next(
                    row for row in inventory(payloads) if row["hw-type"] == "hw-type-transceiver"
                )
                optic_platform = next(
                    row for row in platform(payloads) if row["cname"] == f"{canonical_family}1/1/1"
                )
                optic_hardware["dev-name"] = f"{alias}1/1/1"
                optic_platform["cname"] = f"{alias}1/1/1"
                optic = uplink_items(cisco.collect(FixtureClient(payloads)))["transceiver:1/1/1"]
                self.assertEqual(
                    optic["source"]["ownership"]["interface"], f"{canonical_family}1/1/1"
                )
                self.assertEqual(optic["observations"]["name"], f"{alias}1/1/1")
                self.assertEqual(optic["source"]["identity"]["interface_name"], f"{alias}1/1/1")
                optic_platform["cname"] = f"{alias}1/1/2"
                with self.assertRaisesRegex(
                    cisco.DiscoveryError, "different hardware and platform ports"
                ):
                    cisco.collect(FixtureClient(payloads))

    def test_long_alias_at_expected_port_still_rejects_a_contradictory_serial(self):
        payloads = documented_module_payloads(
            "C9300X-24Y", "C9300X-NM-2C", "HundredGigE", 2, optical=True
        )
        optic_platform = next(
            row for row in platform(payloads) if row["cname"] == "HundredGigE1/1/1"
        )
        optic_platform["cname"] = "HundredGigabitEthernet1/1/1"
        optic_platform["state"]["serial-no"] = "DIFFERENT-OPTIC-SERIAL"
        with self.assertRaisesRegex(cisco.DiscoveryError, "identities disagree at a reviewed port"):
            cisco.collect(FixtureClient(payloads))

    def test_hxn_disabled_uplink_ports_cannot_be_owned_or_contain_discovered_optics(self):
        payloads = documented_module_payloads(
            "C9300X-48HXN", "C9300X-NM-8Y", "TwentyFiveGigE", 8, optical=True
        )
        for port in (7, 8):
            with self.subTest(port=port):
                optic_hardware = next(
                    row for row in inventory(payloads) if row["hw-type"] == "hw-type-transceiver"
                )
                optic_platform = next(
                    row
                    for row in platform(payloads)
                    if row["state"].get("serial-no", "").strip() == "LABOPTIC001"
                )
                optic_hardware["dev-name"] = f"TwentyFiveGigE1/1/{port}"
                optic_platform["cname"] = f"TwentyFiveGigE1/1/{port}"
                result = cisco.collect(FixtureClient(payloads))
                module = uplink_items(result)["uplink:1/1"]
                self.assertEqual(
                    module["interfaces"], [f"TwentyFiveGigE1/1/{number}" for number in range(1, 7)]
                )
                self.assertNotIn("transceiver:1/1/7", uplink_items(result))
                self.assertNotIn("transceiver:1/1/8", uplink_items(result))
                self.assertFalse(
                    any(
                        row.get("component_key") == "uplink:1/1"
                        for row in result["components"]["unresolved"]
                    )
                )

    def test_new_module_does_not_inherit_the_lab_comp_port_quirk(self):
        payloads = documented_module_payloads(
            "C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8, optical=True
        )
        next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1")["state"][
            "type"
        ] = "comp-port"
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(uplink_items(result), {})
        self.assertTrue(
            any(
                row.get("serial") == "LABUPLINK001" and "classification" in row["reason"]
                for row in result["components"]["unresolved"]
            )
        )

    def test_generalized_module_still_requires_identity_parent_and_slot_evidence(self):
        for field, value in (
            ("parent", "Switch2"),
            ("location", "1/0/2/1"),
            ("empty", True),
            ("removable", False),
        ):
            with self.subTest(field=field):
                payloads = documented_module_payloads(
                    "C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8, optical=True
                )
                next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1")[
                    "state"
                ][field] = value
                self.assertEqual(uplink_items(cisco.collect(FixtureClient(payloads))), {})
        for field, value in (("serial-no", "OTHER-SERIAL"), ("part-no", "C9300-NM-2Y")):
            with self.subTest(field=field):
                payloads = documented_module_payloads(
                    "C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8
                )
                next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1")[
                    "state"
                ][field] = value
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_missing_module_or_optic_serial_does_not_create_assets(self):
        for kind in ("hw-type-pim", "hw-type-transceiver"):
            with self.subTest(kind=kind):
                payloads = documented_module_payloads(
                    "C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8, optical=True
                )
                next(row for row in inventory(payloads) if row["hw-type"] == kind).pop(
                    "serial-number"
                )
                result = uplink_items(cisco.collect(FixtureClient(payloads)))
                self.assertNotIn("transceiver:1/1/1", result)
                self.assertEqual("uplink:1/1" in result, kind == "hw-type-transceiver")

    def test_wrong_module_classification_blocks_collection(self):
        for value in ("hw-type-pem", "hw-type-transceiver", "hw-type-dram"):
            with self.subTest(value=value):
                payloads = documented_module_payloads(
                    "C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8
                )
                next(row for row in inventory(payloads) if row["hw-type"] == "hw-type-pim")[
                    "hw-type"
                ] = value
                with self.assertRaisesRegex(
                    cisco.DiscoveryError, "contradictory hardware classification"
                ):
                    cisco.collect(FixtureClient(payloads))

    def test_c9500_capability_does_not_establish_unreviewed_component_placement(self):
        payloads = documented_module_payloads(
            "C9500-16X", "C9500-NM-8X", "TenGigabitEthernet", 8, optical=True
        )
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(uplink_items(result), {})
        observed = next(
            row for row in result["interfaces"] if row["name"] == "TenGigabitEthernet1/1/1"
        )
        self.assertEqual(observed["type"], "10gbase-x-sfpp")
        unresolved = {row.get("serial") for row in result["components"]["unresolved"]}
        self.assertIn("LABUPLINK001", unresolved)
        self.assertIn("LABOPTIC001", unresolved)

    def test_wrong_capability_and_breakout_names_do_not_become_module_children(self):
        payloads = documented_module_payloads(
            "C9300-48UXM", "C9300-NM-8X", "TenGigabitEthernet", 8, optical=True
        )
        discovered = cisco.collect(FixtureClient(payloads))
        port = next(
            row for row in discovered["interfaces"] if row["name"] == "TenGigabitEthernet1/1/1"
        )
        port["type"] = "1000base-x-sfp"
        discovered["interfaces"].append({**deepcopy(port), "name": "TenGigabitEthernet1/1/1:1"})
        result = components.collect(
            FixtureClient(payloads),
            inventory(payloads),
            chassis_model="C9300-48UXM",
            chassis_serial="LAB93000001",
            member=1,
            interfaces=discovered["interfaces"],
            warnings=[],
        )
        module = next(row for row in result["items"] if row["kind"] == "network-module")
        self.assertEqual(len(module["interfaces"]), 7)
        self.assertNotIn("TenGigabitEthernet1/1/1", module["interfaces"])
        self.assertFalse(any(row["kind"] == "transceiver" for row in result["items"]))


if __name__ == "__main__":
    unittest.main()
