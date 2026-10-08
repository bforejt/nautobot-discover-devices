"""Full-roster AP identity, independent admission, and reviewed native replacements."""

import unittest
from copy import deepcopy

from tests._loader import load

reconcile = load("reconcile_wireless")
policy_module = load("wireless_policy")


def uid(number):
    return "00000000-0000-4000-8000-%012d" % number


CONTROLLER, DEVICE, MANUFACTURER, PLATFORM = (uid(index) for index in range(1, 5))
ROLE, STATUS, GROUP, LOCATION, OTHER_LOCATION, TYPE = (uid(index) for index in range(5, 11))
MAC = "00:11:22:33:44:55"


def ap(serial="SERIAL1", name="AP1", **values):
    return {
        "serial": serial,
        "name": name,
        "model": "C9130AXI-B",
        "wtp_mac": "00:11:22:33:44:50",
        "ethernet_mac": MAC,
        "software_version": "17.12.4.12",
        "state": "registered",
        "tags": {"site": "REMOTE"},
        "location_label": "Remote Building",
        "floor_label": "2",
        "ethernet_interfaces": [],
        "errors": [],
        "warnings": [],
        "provenance": {"path": "capwap-data"},
        **values,
    }


def snapshot(*aps):
    return {
        "contract": "cisco-9800-snapshot-v1",
        "adapter": "cisco_9800",
        "controller_id": CONTROLLER,
        "source": {"verified": True},
        "complete": True,
        "aps": list(aps),
    }


def existing(**values):
    return {
        "id": DEVICE,
        "serial": "SERIAL1",
        "name": "operator-alias",
        "model": "C9130AXI-B",
        "manufacturer_id": MANUFACTURER,
        "manufacturer_name": "Cisco",
        "device_type_id": TYPE,
        "platform_id": PLATFORM,
        "software_version": "17.15.1.1",
        "software_version_id": uid(11),
        "location_id": OTHER_LOCATION,
        "controller_managed_device_group_id": GROUP,
        "interfaces": [],
        **values,
    }


def inventory(*devices):
    return {
        "supported": True,
        "devices": list(devices),
        "software_versions": [],
        "device_types": [{"id": TYPE, "model": "C9130AXI-B", "manufacturer_id": MANUFACTURER}],
        "locations": [{"id": LOCATION}, {"id": OTHER_LOCATION}],
    }


def admission(**values):
    raw = {
        "manufacturer": MANUFACTURER,
        "platform": PLATFORM,
        "role": ROLE,
        "status": STATUS,
        "managed_group": GROUP,
        "naming": "reported",
        "locations": [{"match": {"site_tag": "REMOTE"}, "location": LOCATION}],
        **values,
    }
    return policy_module.normalize_wireless_policy(
        raw,
        lambda kind, identifier: {
            "id": identifier,
            "controller_id": CONTROLLER,
            "name": "Cisco" if kind == "manufacturer" else kind,
        },
        controller_id=CONTROLLER,
    )


def partial():
    return policy_module.normalize_wireless_policy({}, None, controller_id=CONTROLLER)


class WirelessReconcileTests(unittest.TestCase):
    def build(self, source=None, native=None, policy=None):
        return reconcile.build_wireless_plan(
            source or snapshot(ap()), native or inventory(existing()), policy or admission()
        )

    def test_existing_serial_identity_preserves_alias_and_replaces_location_and_downgrades(self):
        plan = self.build()
        row = plan["aps"][0]
        self.assertEqual(row["device_id"], DEVICE)
        self.assertEqual(row["outcome"], "eligible")
        self.assertEqual(
            {change["field"] for change in row["updates"]},
            {
                "location_id",
                "software_version_id",
            },
        )
        self.assertEqual(row["software"]["version"], "17.12.4.12")
        self.assertEqual(row["software"]["platform_id"], PLATFORM)
        self.assertEqual(plan["summary"]["software_updates"], 1)

    def test_existing_software_updates_need_no_new_admission_metadata_or_location(self):
        row = self.build(policy=partial())["aps"][0]
        self.assertEqual(row["outcome"], "eligible")
        self.assertEqual(row["updates"][0]["field"], "software_version_id")
        self.assertTrue(row["unresolved"])

    def test_missing_reported_name_does_not_block_existing_location_and_software(self):
        row = self.build(source=snapshot(ap(name=None)))["aps"][0]
        self.assertEqual(row["device_id"], DEVICE)
        self.assertEqual(row["outcome"], "eligible")
        self.assertEqual(
            {change["field"] for change in row["updates"]},
            {
                "location_id",
                "software_version_id",
            },
        )
        self.assertTrue(row["warnings"])

    def test_missing_reported_name_defers_only_blank_native_name_domain(self):
        row = self.build(source=snapshot(ap(name=None)), native=inventory(existing(name="")))[
            "aps"
        ][0]
        self.assertEqual(row["outcome"], "eligible")
        self.assertNotIn("name", [change["field"] for change in row["updates"]])
        self.assertTrue(row["unresolved"])

    def test_missing_reported_name_defers_new_ap_admission(self):
        row = self.build(source=snapshot(ap(name=None)), native=inventory())["aps"][0]
        self.assertEqual(row["outcome"], "unresolved")
        self.assertIs(row["create"], False)
        self.assertTrue(any("reported AP name" in reason for reason in row["unresolved"]))

    def test_existing_software_only_recognizes_cisco_systems_inc_label(self):
        row = self.build(
            native=inventory(existing(manufacturer_name="Cisco Systems, Inc.")), policy=partial()
        )["aps"][0]
        self.assertEqual(row["outcome"], "eligible")

    def test_native_serial_whitespace_resolves_same_asset_without_rewriting_identity(self):
        row = self.build(native=inventory(existing(serial=" SERIAL1 ")))["aps"][0]
        self.assertEqual(row["device_id"], DEVICE)
        self.assertIs(row["create"], False)
        self.assertNotIn("serial", [change["field"] for change in row["updates"]])

    def test_download_is_current_but_disconnected_and_historical_states_are_not(self):
        row = self.build(source=snapshot(ap(state="downloading")), native=inventory())["aps"][0]
        self.assertIs(row["create"], True)
        for state in (None, "ap-down", "ap-up", "unregistered", "unknown", []):
            row = self.build(source=snapshot(ap(state=state)), native=inventory())["aps"][0]
            self.assertEqual(row["outcome"], "failed")
            self.assertIs(row["create"], False)

    def test_reported_wtp_identity_is_required_without_synthesizing_mac(self):
        row = self.build(source=snapshot(ap(wtp_mac=None)))["aps"][0]
        self.assertEqual(row["outcome"], "failed")

    def test_unknown_software_and_location_preserve_populated_fields(self):
        row = self.build(source=snapshot(ap(software_version=None)), policy=partial())["aps"][0]
        self.assertEqual(row["updates"], [])
        self.assertIsNone(row["software"])

    def test_exact_ap_version_reuses_own_platform_catalog(self):
        native = inventory(existing())
        native["software_versions"] = [
            {"id": uid(12), "platform_id": PLATFORM, "version": "17.12.4.12"},
            {"id": uid(13), "platform_id": GROUP, "version": "17.12.4.12"},
        ]
        row = self.build(native=native)["aps"][0]
        self.assertEqual(row["software"]["existing_id"], uid(12))
        self.assertIs(row["software"]["create"], False)

    def test_unknown_software_formats_remain_unresolved(self):
        for value in (False, 1712, "Cisco IOS XE 17.12.4", "", "17.12.4\n", "17.bad.a"):
            row = self.build(source=snapshot(ap(software_version=value)))["aps"][0]
            self.assertIsNone(row["software"])

    def test_missing_own_platform_does_not_copy_controller_platform(self):
        row = self.build(native=inventory(existing(platform_id=None)))["aps"][0]
        self.assertIsNone(row["software"])

    def test_duplicate_exact_software_catalog_is_unresolved_without_blocking_location(self):
        native = inventory(existing())
        native["software_versions"] = [
            {"id": uid(index), "platform_id": PLATFORM, "version": "17.12.4.12"}
            for index in (12, 13)
        ]
        row = self.build(native=native)["aps"][0]
        self.assertIsNone(row["software"])
        self.assertEqual(row["updates"][0]["field"], "location_id")

    def test_new_ap_created_with_explicit_remote_location_and_manager(self):
        row = self.build(native=inventory())["aps"][0]
        self.assertIs(row["create"], True)
        self.assertEqual(row["device"]["location_id"], LOCATION)
        self.assertEqual(row["device"]["controller_managed_device_group_id"], GROUP)
        self.assertEqual(row["device"]["name"], "AP1")

    def test_new_ap_missing_admission_or_exact_type_stays_unresolved(self):
        for native, policy in (
            (inventory(), partial()),
            ({**inventory(), "device_types": []}, admission()),
        ):
            row = self.build(native=native, policy=policy)["aps"][0]
            self.assertIs(row["create"], False)
            self.assertEqual(row["outcome"], "unresolved")

    def test_name_match_never_claims_blank_serial_device_or_replacement_hardware(self):
        for serial in ("", "REPLACED"):
            row = self.build(native=inventory(existing(name="AP1", serial=serial)))["aps"][0]
            self.assertEqual(row["outcome"], "failed")
            self.assertIsNone(row["device_id"])

    def test_blank_serial_binding_requires_live_native_mac_and_reported_join(self):
        native = inventory(
            existing(serial="", interfaces=[{"id": uid(14), "name": "Gi0", "mac_address": MAC}])
        )
        policy = admission()
        policy["identity_bindings"] = [
            {"serial": "SERIAL1", "device": {"id": DEVICE}, "ethernet_mac": MAC}
        ]
        row = self.build(native=native, policy=policy)["aps"][0]
        self.assertEqual(row["device_id"], DEVICE)
        self.assertIn("serial", [change["field"] for change in row["updates"]])
        native["devices"][0]["interfaces"] = []
        row = self.build(native=native, policy=policy)["aps"][0]
        self.assertEqual(row["outcome"], "failed")

    def test_explicit_binding_cannot_override_a_different_native_serial_claim(self):
        policy = admission()
        policy["identity_bindings"] = [
            {
                "serial": "SERIAL1",
                "device": {"id": uid(99)},
                "ethernet_mac": MAC,
            }
        ]
        row = self.build(policy=policy)["aps"][0]
        self.assertEqual(row["outcome"], "failed")
        self.assertEqual(row["updates"], [])

    def test_duplicate_normalized_binding_claims_block_before_any_ap_plan(self):
        policy = admission()
        policy["identity_bindings"] = [
            {"serial": serial, "device": {"id": uid(99)}, "ethernet_mac": MAC}
            for serial in ("SERIAL1", "SERIAL2")
        ]
        plan = self.build(policy=policy)
        self.assertTrue(plan["errors"])
        self.assertEqual(plan["aps"], [])

    def test_duplicate_roster_identities_fail_only_affected_aps(self):
        for duplicate in (
            ap(),
            ap(serial="SERIAL2", name="AP2"),
            ap(
                serial="SERIAL2",
                name="AP1",
                wtp_mac="00:11:22:33:55:50",
                ethernet_mac="00:11:22:33:55:55",
            ),
        ):
            independent = ap(
                serial="SERIAL3",
                name="AP3",
                wtp_mac="00:11:22:33:66:50",
                ethernet_mac="00:11:22:33:66:55",
            )
            plan = self.build(source=snapshot(ap(), duplicate, independent), native=inventory())
            self.assertEqual(
                [row["outcome"] for row in plan["aps"]], ["failed", "failed", "eligible"]
            )

    def test_cross_role_mac_claims_are_also_duplicate_physical_identity(self):
        other = ap(serial="SERIAL2", name="AP2", wtp_mac=MAC, ethernet_mac="00:11:22:33:55:55")
        plan = self.build(source=snapshot(ap(), other))
        self.assertTrue(all(row["outcome"] == "failed" for row in plan["aps"]))

    def test_native_serial_duplicates_or_wrong_manufacturer_model_block_candidate(self):
        for devices in (
            (existing(), existing(id=uid(99))),
            (existing(model="C9120AXI-B"),),
            (existing(manufacturer_id=uid(99)),),
        ):
            row = self.build(native=inventory(*devices))["aps"][0]
            self.assertEqual(row["outcome"], "failed")
            self.assertEqual(row["updates"], [])

    def test_existing_software_only_still_requires_compatible_cisco_manufacturer(self):
        row = self.build(native=inventory(existing(manufacturer_name="Acme")), policy=partial())[
            "aps"
        ][0]
        self.assertEqual(row["outcome"], "failed")

    def test_conflicting_location_rules_preserve_location_and_allow_software(self):
        policy = admission(
            locations=[
                {"match": {"serial": "SERIAL1"}, "location": LOCATION},
                {"match": {"site_tag": "REMOTE"}, "location": OTHER_LOCATION},
            ]
        )
        row = self.build(policy=policy)["aps"][0]
        self.assertEqual([change["field"] for change in row["updates"]], ["software_version_id"])
        self.assertIn("Conflicting explicit Location mappings", row["unresolved"])
        self.assertIs(self.build(native=inventory(), policy=policy)["aps"][0]["create"], False)

    def test_group_difference_is_reported_and_existing_primary_is_preserved(self):
        row = self.build(native=inventory(existing(controller_managed_device_group_id=uid(99))))[
            "aps"
        ][0]
        self.assertTrue(any("configured controller" in warning for warning in row["warnings"]))
        self.assertNotIn(
            "controller_managed_device_group_id", [item["field"] for item in row["updates"]]
        )

    def test_ethernet_create_requires_policy_admin_state_not_link_state(self):
        ethernet = {
            "name": "GigabitEthernet0",
            "physical_ethernet": True,
            "mac_address": MAC,
            "oper_status": "up",
        }
        source = snapshot(ap(ethernet_interfaces=[ethernet]))
        self.assertEqual(self.build(source=source)["aps"][0]["interface_creates"], [])
        row = self.build(source=source, policy=admission(ethernet_enabled=False))["aps"][0]
        self.assertIs(row["interface_creates"][0]["enabled"], False)
        self.assertEqual(row["interface_creates"][0]["type"], "other")

    def test_existing_interface_populated_values_are_preserved(self):
        native = inventory(
            existing(
                interfaces=[
                    {
                        "id": uid(14),
                        "name": "GigabitEthernet0",
                        "type": "1000base-t",
                        "enabled": True,
                        "mac_address": MAC,
                    }
                ]
            )
        )
        source = snapshot(
            ap(
                ethernet_interfaces=[
                    {
                        "name": "GigabitEthernet0",
                        "physical_ethernet": True,
                        "mac_address": "00:11:22:33:77:55",
                    }
                ]
            )
        )
        row = self.build(source=source, native=native, policy=admission(ethernet_enabled=False))[
            "aps"
        ][0]
        self.assertEqual(row["interface_updates"], [])

    def test_failed_or_incomplete_roster_blocks_all_plans(self):
        for field, value in (
            ("complete", False),
            ("source", {"verified": False}),
            ("aps", None),
            ("errors", ["read failed"]),
            ("controller_id", "guess"),
            ("adapter", "cisco_iosxe"),
            ("source", {"verified": True, "controller_id": uid(99)}),
        ):
            source = snapshot(ap())
            source[field] = value
            plan = self.build(source=source)
            self.assertTrue(plan["errors"])
            self.assertEqual(plan["aps"], [])

    def test_empty_roster_has_no_deletes_and_no_changes(self):
        plan = self.build(source=snapshot())
        self.assertEqual(plan["aps"], [])
        self.assertEqual(plan["summary"]["observed"], 0)
        self.assertFalse(plan["errors"])

    def test_unchanged_repeat_has_no_work(self):
        row = self.build(
            native=inventory(existing(location_id=LOCATION, software_version="17.12.4.12"))
        )["aps"][0]
        self.assertEqual(row["outcome"], "unchanged")
        self.assertEqual(row["updates"], [])
        self.assertIsNone(row["software"])

    def test_missing_location_affects_only_new_ap_and_other_ap_proceeds(self):
        other = ap(
            serial="SERIAL2",
            name="AP2",
            wtp_mac="00:11:22:33:55:50",
            ethernet_mac="00:11:22:33:55:55",
            tags={"site": "UNKNOWN"},
        )
        plan = self.build(source=snapshot(ap(), other), native=inventory())
        self.assertEqual([row["outcome"] for row in plan["aps"]], ["eligible", "unresolved"])

    def test_planning_does_not_mutate_snapshot_native_or_policy(self):
        source, native, policy = snapshot(ap()), inventory(existing()), admission()
        original = deepcopy((source, native, policy))
        self.build(source=source, native=native, policy=policy)
        self.assertEqual((source, native, policy), original)


if __name__ == "__main__":
    unittest.main()
