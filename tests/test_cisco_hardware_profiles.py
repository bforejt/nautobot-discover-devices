"""Physical classification requires exact hardware evidence, independent of link speed."""

import json
import unittest
from copy import deepcopy
from unittest.mock import patch

from tests._loader import load

profiles = load("adapters.cisco_hardware_profiles")
hardware = load("adapters.cisco_hardware")
cisco = load("adapters.cisco_iosxe")


def module(pid, serial="SYNTHETIC-MODULE"):
    return {
        "hw-type": "hw-type-pim",
        "part-number": pid,
        "serial-number": serial,
        "dev-name": "Switch 1 FRU Uplink Module 1",
    }


class HardwareLibrarySafetyTests(unittest.TestCase):
    def test_installed_module_must_be_unique_compatible_and_explicit(self):
        name = "TenGigabitEthernet1/1/1"
        for inventory in (
            [],
            [module("UNKNOWN-MODULE")],
            [module("C9300-NM-8X")],
            [module("C9500-NM-8X"), module("UNKNOWN-MODULE")],
            [module("C9500-NM-8X"), module("C9500-NM-8X", "SECOND-SERIAL")],
        ):
            with self.subTest(inventory=inventory):
                self.assertIsNone(hardware.interface_type(name, "C9500-16X", 1, inventory)[0])
        capability = hardware.interface_capability(name, "C9500-16X", 1, [module("C9500-NM-8X")])
        self.assertEqual(capability["type"], "10gbase-x-sfpp")
        self.assertEqual(capability["installed_module"]["serial"], "SYNTHETIC-MODULE")
        self.assertTrue(capability["documents"])

    def test_exact_ordering_alias_evidence_survives_port_classification(self):
        capability = profiles.port_capability("TwentyFiveGigE1/0/1", "C9500-48Y4C-A", 1)
        self.assertTrue(any("nb-06-cat9500" in url for url in capability["documents"]))
        self.assertEqual(capability["model"], "C9500-48Y4C-A")

    def test_documented_long_families_join_the_native_names(self):
        self.assertEqual(
            cisco.canonical_interface_name("TwentyFiveGigabitEthernet1/1/1"),
            "TwentyFiveGigE1/1/1",
        )
        self.assertEqual(
            cisco.canonical_interface_name("HundredGigabitEthernet1/0/1"),
            "HundredGigE1/0/1",
        )

    def test_profile_consumers_cannot_modify_catalog(self):
        baseline = deepcopy(profiles.CHASSIS_PROFILES)
        profile = profiles.chassis_profile("C9500-48Y4C")
        profile["fixed_ports"][0]["type"] = "other"
        profile["network_modules"] = ("UNKNOWN",)
        capability = profiles.port_capability("TwentyFiveGigE1/0/1", "C9500-48Y4C", 1)
        capability["type"] = "other"
        self.assertEqual(profiles.CHASSIS_PROFILES, baseline)
        self.assertEqual(
            hardware.interface_type("TwentyFiveGigE1/0/1", "C9500-48Y4C", 1, [])[0],
            "25gbase-x-sfp28",
        )

    def test_ambiguous_regions_do_not_drive_type(self):
        profile = profiles.chassis_profile("C9500-48Y4C")
        profile["fixed_ports"] += (deepcopy(profile["fixed_ports"][0]),)
        with patch.dict(profiles.CHASSIS_PROFILES, {"C9500-48Y4C": profile}):
            self.assertIsNone(profiles.port_capability("TwentyFiveGigE1/0/1", "C9500-48Y4C", 1))

    def test_unknown_pid_and_wrong_owner_cannot_acquire_capability(self):
        for pid, name, member in (
            ("C9500-48Y4C-UNREVIEWED", "TwentyFiveGigE1/0/1", 1),
            ("C9500-48Y4C", "TwentyFiveGigE2/0/1", 1),
            ("C9500-48Y4C", "TwentyFiveGigE1/0/1.10", 1),
            ("C9500-48Y4C", "TwentyFiveGigE1/0/1", True),
        ):
            with self.subTest(pid=pid, name=name, member=member):
                self.assertIsNone(profiles.port_capability(name, pid, member))

    def test_named_logical_interfaces_remain_independent_of_chassis_library(self):
        for name, expected in (
            ("Vlan12", "virtual"),
            ("Loopback1", "virtual"),
            ("Port-channel3", "lag"),
        ):
            self.assertEqual(hardware.interface_type(name, "UNKNOWN-CHASSIS", 1, [])[0], expected)

    def test_operational_speed_and_absent_ports_do_not_define_physical_type(self):
        rows = []
        for name, oper in (
            ("TwentyFiveGigE1/0/1", "if-oper-state-ready"),
            ("HundredGigE1/0/49", "if-oper-state-down"),
            ("HundredGigE1/0/50", "if-oper-state-not-present"),
        ):
            rows.append(
                {
                    "name": name,
                    "interface-type": "iana-iftype-ethernet-csmacd",
                    "admin-status": "if-state-up",
                    "oper-status": oper,
                    "speed": 1_000_000_000,
                    "ether-state": {"negotiated-port-speed": "speed-1gb"},
                }
            )
        facts, excluded = cisco._interfaces(
            {"Cisco-IOS-XE-interfaces-oper:interfaces": {"interface": rows}},
            "C9500-48Y4C",
            1,
            [],
            [],
        )
        by_name = {fact["name"]: fact for fact in facts}
        self.assertEqual(by_name["TwentyFiveGigE1/0/1"]["type"], "25gbase-x-sfp28")
        self.assertEqual(by_name["TwentyFiveGigE1/0/1"]["speed"], 1_000_000)
        self.assertEqual(by_name["HundredGigE1/0/49"]["type"], "100gbase-x-qsfp28")
        self.assertIsNone(by_name["HundredGigE1/0/49"]["speed"])
        self.assertEqual([row["name"] for row in excluded], ["HundredGigE1/0/50"])
        evidence = by_name["HundredGigE1/0/49"]["hardware_profile"]
        self.assertEqual(evidence["model"], "C9500-48Y4C")
        self.assertTrue(evidence["profile"] and evidence["documents"] and evidence["section"])
        self.assertEqual(json.loads(json.dumps(facts)), facts)

    def test_high_speed_native_names_are_canonical_and_in_scoped_configuration(self):
        layer2 = load("adapters.cisco_layer2")
        ipam = load("adapters.cisco_ipam")
        for short, long in (
            ("Fif1/0/1", "FiftyGigabitEthernet1/0/1"),
            ("FiftyGigE1/0/1", "FiftyGigabitEthernet1/0/1"),
            ("Fou1/0/31", "FourHundredGigE1/0/31"),
        ):
            self.assertEqual(cisco.canonical_interface_name(short), long)
            family = long.split("1/")[0]
            self.assertIn(family + "(", cisco.LAG_FIELDS)
            self.assertIn(family + "(", layer2.NATIVE_FIELDS)
            self.assertIn(family + "(", ipam.INTERFACE_FIELDS)
