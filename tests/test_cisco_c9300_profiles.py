"""Physical port mapping regressions for documented 9300 hardware regions."""

import unittest

from tests._loader import load

profiles = load("adapters.cisco_c9300_profiles")
hardware = load("adapters.cisco_hardware")
hardware_profiles = load("adapters.cisco_hardware_profiles")
interface_capability = hardware.interface_capability
interface_type = hardware.interface_type
chassis_profile = hardware_profiles.chassis_profile
module_profile = hardware_profiles.module_profile
port_capability = hardware_profiles.port_capability


def inventory(pid):
    return [{"hw-type": "hw-type-pim", "part-number": pid, "serial-number": "UPLINK-001"}]


class Catalyst9300ProfilesTest(unittest.TestCase):
    def test_exact_chassis_identities_do_not_accept_ordering_or_cloud_suffixes(self):
        self.assertEqual(len(profiles.CHASSIS_PROFILES), 40)
        for model in ("C9300-48T-E", "C9300X-48HX-M", "C9300-UNKNOWN", "c9300-48t"):
            with self.subTest(model=model):
                self.assertIsNone(chassis_profile(model))
                self.assertIsNone(interface_type("GigabitEthernet1/0/1", model, 1, [])[0])

    def test_copper_and_fiber_gigabit_ports_are_distinguished_by_exact_chassis(self):
        for model, expected in (
            ("C9300-24T", "1000base-t"),
            ("C9300-24P", "1000base-t"),
            ("C9300-24S", "1000base-x-sfp"),
        ):
            with self.subTest(model=model):
                self.assertEqual(interface_type("GigabitEthernet3/0/24", model, 3, [])[0], expected)
                self.assertIsNone(interface_type("GigabitEthernet3/0/25", model, 3, [])[0])
                self.assertIsNone(interface_type("GigabitEthernet3/0/24", model, 2, [])[0])

    def test_lab_mixed_capability_regions_and_descriptions_are_preserved(self):
        self.assertEqual(
            interface_type("TwoGigabitEthernet1/0/36", "C9300-48UXM", 1, []),
            ("2.5gbase-t", "C9300-48UXM fixed copper ports 1-36"),
        )
        self.assertEqual(
            interface_type("TenGigabitEthernet1/0/37", "C9300-48UXM", 1, []),
            ("10gbase-t", "C9300-48UXM fixed copper ports 37-48"),
        )
        for name in ("TenGigabitEthernet1/0/36", "TwoGigabitEthernet1/0/37"):
            self.assertIsNone(interface_type(name, "C9300-48UXM", 1, [])[0])

    def test_published_all_five_gigabit_chassis_does_not_use_copied_mixed_port_bullets(self):
        for port in (1, 36, 37, 48):
            name = f"FiveGigabitEthernet2/0/{port}"
            row = interface_capability(name, "C9300-48UN", 2, [])
            self.assertEqual(row["type"], "5gbase-t")
            self.assertIn(profiles.ARCHITECTURE_URL, row["documents"])
        for name in ("TwoGigabitEthernet2/0/1", "TenGigabitEthernet2/0/48"):
            self.assertIsNone(interface_type(name, "C9300-48UN", 2, [])[0])

    def test_48uxg_uses_documented_nonoverlapping_mixed_ranges(self):
        for model in ("C9300L-48UXG-4X", "C9300L-48UXG-2Q"):
            with self.subTest(model=model):
                self.assertEqual(
                    interface_type("GigabitEthernet1/0/36", model, 1, [])[0], "1000base-t"
                )
                self.assertEqual(
                    interface_type("TenGigabitEthernet1/0/37", model, 1, [])[0], "10gbase-t"
                )
                self.assertIsNone(interface_type("GigabitEthernet1/0/37", model, 1, [])[0])
                self.assertIsNone(interface_type("TenGigabitEthernet1/0/36", model, 1, [])[0])

    def test_ambiguous_mixed_downlinks_defer_while_known_uplinks_remain_eligible(self):
        for model, unresolved in (
            ("C9300L-24UXG-4X", "TenGigabitEthernet1/0/17"),
            ("C9300L-24UXG-2Q", "GigabitEthernet1/0/16"),
            ("C9300LM-48UX-4Y", "TenGigabitEthernet1/0/41"),
            ("C9300X-48HXN", "FiveGigabitEthernet1/0/1"),
        ):
            with self.subTest(model=model):
                result = interface_type(unresolved, model, 1, [])
                self.assertIsNone(result[0])
                self.assertIn("unresolved", result[1])
                self.assertEqual(
                    interface_type("GigabitEthernet0/0", model, 1, [])[0], "1000base-t"
                )
        self.assertEqual(
            interface_type("TwentyFiveGigE1/1/4", "C9300LM-48UX-4Y", 1, [])[0],
            "25gbase-x-sfp28",
        )

    def test_fixed_uplink_cage_does_not_require_a_removable_module_identity(self):
        for model, name, expected in (
            ("C9300L-48P-4G", "GigabitEthernet1/1/4", "1000base-x-sfp"),
            ("C9300L-24T-4X", "TenGigabitEthernet1/1/4", "10gbase-x-sfpp"),
            ("C9300L-24UXG-2Q", "FortyGigabitEthernet1/1/2", "40gbase-x-qsfpp"),
            ("C9300LM-48U-4Y", "TwentyFiveGigE1/1/4", "25gbase-x-sfp28"),
        ):
            with self.subTest(model=model):
                self.assertEqual(interface_type(name, model, 1, [])[0], expected)
                self.assertIsNone(module_profile(model, "C9300-NM-8X"))

    def test_modular_uplink_requires_installed_unique_compatible_identity(self):
        name = "TenGigabitEthernet1/1/8"
        model = "C9300-48P"
        self.assertIsNone(interface_type(name, model, 1, [])[0])
        self.assertIsNone(interface_type(name, model, 1, inventory("C9300-NM-4G"))[0])
        self.assertIsNone(interface_type(name, model, 1, inventory("C9300-NM-8X") * 2)[0])
        row = interface_capability(name, model, 1, inventory("C9300-NM-8X"))
        self.assertEqual(row["type"], "10gbase-x-sfpp")
        self.assertEqual(row["installed_module"]["serial"], "UPLINK-001")
        self.assertIsNone(
            interface_type("GigabitEthernet1/1/1", model, 1, inventory("C9300-NM-8X"))[0]
        )

    def test_module_families_do_not_turn_inactive_or_breakout_aliases_into_cages(self):
        for model, pid, good_name, expected, bad_names in (
            (
                "C9300-48T",
                "C9300-NM-4G",
                "GigabitEthernet1/1/4",
                "1000base-x-sfp",
                ("TenGigabitEthernet1/1/1", "GigabitEthernet1/1/5"),
            ),
            (
                "C9300-24UX",
                "C9300-NM-2Q",
                "FortyGigabitEthernet1/1/2",
                "40gbase-x-qsfpp",
                ("TenGigabitEthernet1/1/1", "FortyGigabitEthernet1/1/3"),
            ),
            (
                "C9300-48U",
                "C9300-NM-2Y",
                "TwentyFiveGigE1/1/2",
                "25gbase-x-sfp28",
                ("TenGigabitEthernet1/1/1", "TwentyFiveGigE1/1/3"),
            ),
            (
                "C9300X-48HX",
                "C9300X-NM-4C",
                "HundredGigE1/1/4",
                "100gbase-x-qsfp28",
                ("FortyGigabitEthernet1/1/1", "HundredGigE1/1/1/1", "TenGigabitEthernet1/1/1"),
            ),
        ):
            with self.subTest(pid=pid):
                self.assertEqual(interface_type(good_name, model, 1, inventory(pid))[0], expected)
                for name in bad_names:
                    self.assertIsNone(interface_type(name, model, 1, inventory(pid))[0])

    def test_x_module_compatibility_and_hxn_disabled_ports_remain_bounded(self):
        for model in ("C9300X-24Y", "C9300X-48HX", "C9300X-48TX"):
            self.assertIsNotNone(module_profile(model, "C9300X-NM-4C"))
        for model in ("C9300-48UXM", "C9300X-12Y", "C9300X-24HX", "C9300X-48HXN"):
            self.assertIsNone(module_profile(model, "C9300X-NM-4C"))
        self.assertIsNotNone(module_profile("C9300X-48HXN", "C9300X-NM-2C"))
        self.assertIsNone(module_profile("C9300X-48HX", "C9300-NM-8X"))

    def test_hxn_module_region_override_blocks_permanently_disabled_ports(self):
        for pid, family, expected in (
            ("C9300X-NM-8M", "TenGigabitEthernet", "10gbase-t"),
            ("C9300X-NM-8Y", "TwentyFiveGigE", "25gbase-x-sfp28"),
        ):
            with self.subTest(pid=pid):
                resolved = module_profile("C9300X-48HXN", pid)
                self.assertEqual(resolved["ports"][0]["last"], 6)
                self.assertIn(profiles.OVERVIEW_URL, resolved["ports"][0]["documents"])
                self.assertEqual(module_profile("C9300X-48HX", pid)["ports"][0]["last"], 8)
                for port in (1, 6):
                    self.assertEqual(
                        interface_type(f"{family}3/1/{port}", "C9300X-48HXN", 3, inventory(pid))[0],
                        expected,
                    )
                for port in (0, 7, 8):
                    self.assertIsNone(
                        interface_type(f"{family}3/1/{port}", "C9300X-48HXN", 3, inventory(pid))[0]
                    )

    def test_lab_3850_module_preserves_description_and_limited_compatibility(self):
        self.assertEqual(
            interface_type("GigabitEthernet1/1/4", "C9300-48UXM", 1, inventory("C3850-NM-4-1G")),
            ("1000base-x-sfp", "Installed C3850-NM-4-1G 4x1G SFP uplink module"),
        )
        self.assertIsNone(module_profile("C9300-48T", "C3850-NM-4-1G"))

    def test_profile_provenance_and_consumer_copies_are_independent(self):
        for model, profile in profiles.CHASSIS_PROFILES.items():
            with self.subTest(model=model):
                self.assertTrue(profile["documents"])
                for region in profile["fixed_ports"]:
                    self.assertTrue(region["documents"])
                    self.assertTrue(region["section"])
                    self.assertLessEqual(region["first"], region["last"])
                for pid in profile["network_modules"]:
                    self.assertIn(pid, profiles.NETWORK_MODULE_PROFILES)
        row = port_capability("TenGigabitEthernet1/0/1", "C9300X-48HX", 1)
        row["description"] = "Local edit"
        self.assertNotEqual(
            port_capability("TenGigabitEthernet1/0/1", "C9300X-48HX", 1)["description"],
            "Local edit",
        )


if __name__ == "__main__":
    unittest.main()
