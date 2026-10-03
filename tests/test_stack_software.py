"""Per-chassis software evidence and Platform-scoped native catalogs."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_stack_reconcile import applied_stack, observed_stack, stack_inventory

cisco = load("adapters.cisco_iosxe")
planner = load("reconcile_stack")
reconcile = load("reconcile")


def software_stack():
    observed = observed_stack()
    for member in observed["stack"]["members"]:
        member["software_version"] = "17.12.8"
        member["sources"]["software_version"] = {
            "module": "Cisco-IOS-XE-install-oper",
            "path": cisco.INSTALL_PATH,
            "chassis": member["position"],
            "install_rows": [
                {
                    "chassis": member["position"],
                    "fru": "fru-rp",
                    "current": "install-version-state-provisioned-committed",
                    "version": "17.12.08.0.1234",
                    "release": "17.12.8",
                }
            ],
        }
    return observed


def software_inventory():
    before = stack_inventory()
    version = {"id": "release-1", "version": "17.12.8", "platform_id": "platform-1"}
    before["software_versions"] = [deepcopy(version)]
    before["stack"]["software_versions"] = [version]
    return before


def existing_member(before, *, platform="platform-1", software=None):
    member = {
        **deepcopy(before["stack"]["selected"]),
        "id": "device-2",
        "name": "operator-member",
        "serial": "LAB93000002",
        "platform_id": platform,
        "software_version": software,
    }
    before["stack"]["devices"].append(member)
    return member


class StackSoftwareTests(unittest.TestCase):
    def test_new_member_reuses_selected_platform_release_with_exact_member_evidence(self):
        observed, before = software_stack(), software_inventory()
        original = deepcopy(before)
        plan = planner.plan_stack(observed, before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["summary"]["stack_member_software_assigned"], 1)
        self.assertEqual(
            plan["software_versions"],
            [
                {
                    "key": "platform-1:17.12.08",
                    "platform_id": "platform-1",
                    "version": "17.12.08",
                    "existing_id": "release-1",
                    "create": False,
                }
            ],
        )
        selected, member = plan["members"]
        self.assertIsNone(selected["software_version_key"])
        self.assertEqual(member["software_version_key"], "platform-1:17.12.08")
        self.assertEqual(member["software_source"]["install_rows"][0]["chassis"], 2)
        self.assertEqual(before, original)

    def test_existing_member_uses_own_platform_and_fills_blank_software(self):
        before = software_inventory()
        row = existing_member(before, platform="operator-platform")
        plan = planner.plan_stack(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["software_versions"][0]["platform_id"], "operator-platform")
        self.assertTrue(plan["software_versions"][0]["create"])
        member = plan["members"][1]
        self.assertEqual(member["existing_id"], row["id"])
        self.assertEqual(member["platform_id"], "operator-platform")
        self.assertEqual(
            [change for change in member["changes"] if change["field"] == "software_version"],
            [{"field": "software_version", "before": None, "after": "17.12.08"}],
        )
        self.assertFalse(any(change["field"] == "platform" for change in member["changes"]))

    def test_existing_platform_catalog_reuses_normalized_release(self):
        before = software_inventory()
        existing_member(before, platform="operator-platform")
        before["stack"]["software_versions"].append(
            {"id": "operator-version", "platform_id": "operator-platform", "version": "17.12.08"}
        )
        spec = planner.plan_stack(software_stack(), before)["software_versions"][0]
        self.assertFalse(spec["create"])
        self.assertEqual(spec["existing_id"], "operator-version")

    def test_populated_conflicting_software_is_preserved(self):
        before = software_inventory()
        existing_member(before, software="17.9.4")
        plan = planner.plan_stack(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["software_versions"], [])
        self.assertEqual(plan["summary"]["stack_member_software_assigned"], 0)
        self.assertEqual(plan["conflicts"][0]["field"], "software_version")
        self.assertFalse(
            any(change["field"] == "software_version" for change in plan["members"][1]["changes"])
        )

    def test_missing_member_platform_defers_only_software(self):
        before = software_inventory()
        existing_member(before, platform=None)
        plan = planner.plan_stack(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["software_versions"], [])
        self.assertTrue(plan["members"][1]["changes"])
        self.assertTrue(any("assign its Platform" in warning for warning in plan["warnings"]))

    def test_incompatible_existing_platform_driver_defers_software_and_preserves_platform(self):
        before = software_inventory()
        before["stack"]["selected"]["platform_network_driver"] = "cisco_ios"
        row = existing_member(before, platform="arista-platform")
        row["platform_network_driver"] = "arista_eos"
        plan = planner.plan_stack(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["software_versions"], [])
        self.assertEqual(plan["conflicts"][0]["field"], "platform")
        self.assertEqual(row["platform_id"], "arista-platform")

    def test_supported_ios_xe_driver_aliases_use_each_members_own_platform(self):
        for selected_driver, member_driver in (
            ("cisco_ios", "cisco_iosxe"),
            ("cisco_iosxe", "cisco_ios"),
        ):
            with self.subTest(selected=selected_driver, member=member_driver):
                before = software_inventory()
                before["stack"]["selected"]["platform_network_driver"] = selected_driver
                row = existing_member(before, platform="operator-platform")
                row["platform_network_driver"] = member_driver
                plan = planner.plan_stack(software_stack(), before)
                self.assertFalse(plan["errors"])
                self.assertFalse(plan["conflicts"])
                self.assertEqual(plan["summary"]["stack_member_software_assigned"], 1)
                self.assertEqual(plan["software_versions"][0]["platform_id"], "operator-platform")

    def test_blank_selected_driver_cannot_hide_an_explicit_non_cisco_member_driver(self):
        before = software_inventory()
        before["stack"]["selected"]["platform_network_driver"] = ""
        row = existing_member(before, platform="arista-platform")
        row["platform_network_driver"] = "arista_eos"
        plan = planner.plan_stack(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(plan["software_versions"], [])
        self.assertEqual(plan["conflicts"][0]["field"], "platform")
        self.assertEqual(plan["summary"]["stack_member_software_assigned"], 0)

    def test_blank_member_driver_preserves_operator_platform_and_fills_software(self):
        before = software_inventory()
        before["stack"]["selected"]["platform_network_driver"] = "cisco_iosxe"
        row = existing_member(before, platform="operator-platform")
        row["platform_network_driver"] = ""
        plan = planner.plan_stack(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["conflicts"])
        self.assertEqual(plan["software_versions"][0]["platform_id"], "operator-platform")
        self.assertEqual(plan["summary"]["stack_member_software_assigned"], 1)

    def test_missing_or_mismatched_member_install_evidence_cannot_assign_release(self):
        for mutation in (
            "no-source",
            "empty-rows",
            "wrong-chassis",
            "wrong-release",
            "no-release",
            "present-image",
            "wrong-fru",
            "unknown-extension",
            "wrong-raw-version",
        ):
            with self.subTest(mutation=mutation):
                observed = software_stack()
                member = observed["stack"]["members"][1]
                source = member["sources"]["software_version"]
                if mutation == "no-source":
                    member["sources"].pop("software_version")
                elif mutation == "empty-rows":
                    source["install_rows"] = []
                elif mutation == "wrong-chassis":
                    source["install_rows"][0]["chassis"] = 1
                elif mutation == "wrong-release":
                    source["install_rows"][0]["release"] = "17.18.4"
                elif mutation == "no-release":
                    member.pop("software_version")
                elif mutation == "present-image":
                    source["install_rows"][0]["current"] = "install-version-state-present"
                elif mutation == "wrong-fru":
                    source["install_rows"][0]["fru"] = "fru-pim"
                elif mutation == "unknown-extension":
                    source["install_rows"][0]["version-extension"] = "engineering"
                else:
                    source["install_rows"][0]["version"] = "17.18.04.0.1234"
                plan = planner.plan_stack(observed, software_inventory())
                self.assertFalse(plan["errors"])
                self.assertEqual(plan["software_versions"], [])
                self.assertTrue(plan["warnings"])

    def test_ambiguous_platform_release_catalog_blocks_assignment(self):
        before = software_inventory()
        before["stack"]["software_versions"].append(
            {"id": "duplicate", "platform_id": "platform-1", "version": "17.12.08"}
        )
        plan = planner.plan_stack(software_stack(), before)
        self.assertTrue(plan["errors"])
        self.assertEqual(plan["software_versions"], [])

    def test_repeat_preserves_member_assignment_without_catalog_changes(self):
        before = software_inventory()
        observed = software_stack()
        first = planner.plan_stack(observed, before)
        after = applied_stack(first, before)
        after["stack"]["devices"][1]["software_version"] = "17.12.8"
        second = planner.plan_stack(observed, after)
        self.assertFalse(second["errors"])
        self.assertEqual(second["software_versions"], [])
        self.assertTrue(all(value == 0 for value in second["summary"].values()))

    def test_selected_and_new_member_share_catalog_key_when_selected_software_blank(self):
        before = software_inventory()
        for row in (before["device"], before["stack"]["selected"], before["stack"]["devices"][0]):
            row["software_version"] = None
        before["software_versions"] = []
        before["stack"]["software_versions"] = []
        plan = reconcile.build_plan(software_stack(), before)
        self.assertFalse(plan["errors"])
        self.assertEqual(
            plan["software_version"]["key"], plan["stack"]["software_versions"][0]["key"]
        )
        self.assertTrue(plan["software_version"]["create"])


if __name__ == "__main__":
    unittest.main()
