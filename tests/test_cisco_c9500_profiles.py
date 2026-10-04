"""Published Catalyst 9500 physical capabilities and conservative boundaries."""

import unittest

from tests._loader import load

profiles = load("adapters.cisco_c9500_profiles")
CHASSIS_PROFILES = profiles.CHASSIS_PROFILES
NETWORK_MODULE_PROFILES = profiles.NETWORK_MODULE_PROFILES
interface_type = load("adapters.cisco_hardware").interface_type


class Catalyst9500ProfileTests(unittest.TestCase):
    def test_traditional_fixed_cages(self):
        for pid, family, last, type_ in (
            ("C9500-12Q", "FortyGigabitEthernet", 12, "40gbase-x-qsfpp"),
            ("C9500-24Q", "FortyGigabitEthernet", 24, "40gbase-x-qsfpp"),
            ("C9500-16X", "TenGigabitEthernet", 16, "10gbase-x-sfpp"),
            ("C9500-40X", "TenGigabitEthernet", 40, "10gbase-x-sfpp"),
        ):
            with self.subTest(pid=pid):
                for port in (1, last):
                    self.assertEqual(interface_type(f"{family}2/0/{port}", pid, 2, [])[0], type_)
                self.assertIsNone(interface_type(f"{family}2/0/{last + 1}", pid, 2, [])[0])
                self.assertIsNone(interface_type(f"{family}2/0/0", pid, 2, [])[0])
                self.assertIsNone(interface_type(f"{family}1/0/1", pid, 2, [])[0])

    def test_high_performance_fixed_uplink_numbering(self):
        for pid, count in (("C9500-24Y4C", 24), ("C9500-48Y4C", 48)):
            with self.subTest(pid=pid):
                self.assertEqual(
                    interface_type(f"TwentyFiveGigE1/0/{count}", pid, 1, [])[0],
                    "25gbase-x-sfp28",
                )
                self.assertIsNone(interface_type(f"TwentyFiveGigE1/0/{count + 1}", pid, 1, [])[0])
                for port in (count + 1, count + 4):
                    self.assertEqual(
                        interface_type(f"HundredGigE1/0/{port}", pid, 1, [])[0],
                        "100gbase-x-qsfp28",
                    )
                self.assertIsNone(interface_type(f"HundredGigE1/0/{count}", pid, 1, [])[0])
                self.assertIsNone(interface_type(f"HundredGigE1/0/{count + 5}", pid, 1, [])[0])
                self.assertIsNone(interface_type("HundredGigE1/1/1", pid, 1, [])[0])

    def test_32c_native_port_is_qsfp28_when_family_reports_100g(self):
        for port in (1, 32):
            self.assertEqual(
                interface_type(f"HundredGigE1/0/{port}", "C9500-32C", 1, [])[0],
                "100gbase-x-qsfp28",
            )
        self.assertIsNone(interface_type("HundredGigE1/0/33", "C9500-32C", 1, [])[0])
        self.assertIsNone(interface_type("FortyGigabitEthernet1/0/1", "C9500-32C", 1, [])[0])

    def test_32qc_aliases_are_deferred_until_active_mode_is_known(self):
        self.assertEqual(CHASSIS_PROFILES["C9500-32QC"]["fixed_ports"], ())
        self.assertIn("paired 40G", CHASSIS_PROFILES["C9500-32QC"]["deferred_reason"])
        for family, port in (
            ("FortyGigabitEthernet", 1),
            ("FortyGigabitEthernet", 32),
            ("HundredGigE", 33),
            ("HundredGigE", 48),
        ):
            self.assertIsNone(interface_type(f"{family}1/0/{port}", "C9500-32QC", 1, [])[0])

    def test_9500x_28c8d_physical_positions_include_middle_400g_cages(self):
        pid = "C9500X-28C8D"
        for port in (1, 14, 23, 36):
            self.assertEqual(
                interface_type(f"HundredGigE1/0/{port}", pid, 1, [])[0], "100gbase-x-qsfp28"
            )
        for port in (15, 22):
            self.assertEqual(
                interface_type(f"FourHundredGigE1/0/{port}", pid, 1, [])[0], "400gbase-x-qsfpdd"
            )
            self.assertIsNone(interface_type(f"HundredGigE1/0/{port}", pid, 1, [])[0])
        for port in (14, 23):
            self.assertIsNone(interface_type(f"FourHundredGigE1/0/{port}", pid, 1, [])[0])

    def test_9500x_60l4d_sfp56_numbering_is_not_a_continuous_1_to_60_range(self):
        pid = "C9500X-60L4D"
        for port in (1, 30, 35, 64):
            self.assertEqual(
                interface_type(f"FiftyGigabitEthernet1/0/{port}", pid, 1, [])[0], "50gbase-x-sfp56"
            )
        for port in (31, 34):
            self.assertEqual(
                interface_type(f"FourHundredGigE1/0/{port}", pid, 1, [])[0], "400gbase-x-qsfpdd"
            )
            self.assertIsNone(interface_type(f"FiftyGigabitEthernet1/0/{port}", pid, 1, [])[0])
        self.assertIsNone(interface_type("FiftyGigabitEthernet1/0/65", pid, 1, [])[0])

    def test_breakout_lanes_and_alternative_native_families_do_not_gain_cage_types(self):
        cases = (
            ("C9500-12Q", "TenGigabitEthernet1/0/1"),
            ("C9500-24Q", "TenGigabitEthernet1/0/96"),
            ("C9500-32C", "HundredGigE1/0/1/1"),
            ("C9500X-28C8D", "HundredGigE1/0/1/1"),
            ("C9500X-60L4D", "FourHundredGigE1/0/31/1"),
            ("C9500-24Y4C", "TenGigabitEthernet1/0/1"),
            ("C9500-40X", "GigabitEthernet1/0/1"),
        )
        for pid, name in cases:
            with self.subTest(pid=pid, name=name):
                self.assertIsNone(interface_type(name, pid, 1, [])[0])

    def test_documented_bundle_does_not_imply_an_installed_uplink_module(self):
        for pid in ("C9500-16X-2Q", "C9500-40X-2Q", "C9500-24X", "C9500-48X"):
            with self.subTest(pid=pid):
                self.assertEqual(
                    interface_type("TenGigabitEthernet1/0/1", pid, 1, [])[0], "10gbase-x-sfpp"
                )
                self.assertIsNone(interface_type("TenGigabitEthernet1/1/1", pid, 1, [])[0])
                self.assertIsNone(interface_type("FortyGigabitEthernet1/1/1", pid, 1, [])[0])

    def test_exact_license_aliases_keep_fixed_chassis_capabilities(self):
        for pid in ("C9500-48Y4C-A", "C9500-48Y4C-E"):
            self.assertEqual(
                interface_type("TwentyFiveGigE1/0/48", pid, 1, [])[0], "25gbase-x-sfp28"
            )
        for pid in ("C9500-48Y4C-UNKNOWN", "C9500X-60L4D-A", "C9500-NM-8X"):
            self.assertNotIn(pid, CHASSIS_PROFILES)
            self.assertIsNone(interface_type("TwentyFiveGigE1/0/1", pid, 1, [])[0])

    def test_management_port_is_documented_for_all_exact_profiles(self):
        for pid, profile in CHASSIS_PROFILES.items():
            with self.subTest(pid=pid):
                self.assertEqual(profile["management"]["name"], "GigabitEthernet0/0")
                self.assertEqual(interface_type("GigabitEthernet0/0", pid, 1, [])[0], "1000base-t")

    def test_optional_modules_require_present_inventory_and_compatible_chassis(self):
        for module, family, last, type_ in (
            ("C9500-NM-8X", "TenGigabitEthernet", 8, "10gbase-x-sfpp"),
            ("C9500-NM-2Q", "FortyGigabitEthernet", 2, "40gbase-x-qsfpp"),
        ):
            inventory = [
                {
                    "name": "Switch 1 FRU Uplink Module 1",
                    "hw-type": "hw-type-pim",
                    "part-number": module,
                }
            ]
            with self.subTest(module=module):
                for pid in ("C9500-16X", "C9500-40X"):
                    for port in (1, last):
                        self.assertEqual(
                            interface_type(f"{family}1/1/{port}", pid, 1, inventory)[0], type_
                        )
                    self.assertIsNone(
                        interface_type(f"{family}1/1/{last + 1}", pid, 1, inventory)[0]
                    )
                    self.assertIsNone(interface_type(f"{family}1/1/1", pid, 1, [])[0])
                for pid in ("C9500-12Q", "C9500-32C", "C9500-48Y4C", "C9500X-28C8D"):
                    self.assertIsNone(interface_type(f"{family}1/1/1", pid, 1, inventory)[0])

    def test_module_inventory_ambiguity_and_breakout_aliases_remain_unresolved(self):
        inventory = [{"hw-type": "hw-type-pim", "part-number": "C9500-NM-2Q"}]
        self.assertIsNone(interface_type("TenGigabitEthernet1/1/1", "C9500-16X", 1, inventory)[0])
        self.assertIsNone(
            interface_type("FortyGigabitEthernet1/1/1", "C9500-16X", 1, inventory * 2)[0]
        )
        self.assertIsNone(interface_type("FortyGigabitEthernet2/1/1", "C9500-16X", 1, inventory)[0])

    def test_every_mapping_keeps_primary_documentation_and_no_positional_guess(self):
        for pid, profile in CHASSIS_PROFILES.items():
            with self.subTest(pid=pid):
                self.assertTrue(profile["documents"])
                for region in (*profile["fixed_ports"], profile["management"]):
                    self.assertTrue(region["documents"])
                    self.assertTrue(region["section"])
                    self.assertTrue(
                        all(url.startswith("https://www.cisco.com/") for url in region["documents"])
                    )
        for module, profile in NETWORK_MODULE_PROFILES.items():
            with self.subTest(module=module):
                self.assertIsNone(profile["component_placement"])
                self.assertEqual({region["slot"] for region in profile["ports"]}, {1})


if __name__ == "__main__":
    unittest.main()
