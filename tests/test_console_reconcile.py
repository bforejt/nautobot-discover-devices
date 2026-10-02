"""Console connector identity, provenance and idempotency regressions."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_reconcile import discovery, inventory

console = load("reconcile_console")
reconcile = load("reconcile")


def profile():
    return {
        "method": "reviewed-hardware-profile",
        "profile": console.PROFILE,
        "model": console.MODEL,
        "member": 1,
        "documents": [sorted(console.DOCUMENTS)[0]],
    }


def observed_consoles():
    observed = discovery()
    observed["interfaces"] = []
    observed["console_ports"] = {
        "schema_version": 1,
        "items": [
            {
                "key": "console:rj45",
                "name": "Console RJ45",
                "type": "rj-45",
                "label": None,
                "description": "Rear serial console",
                "source": profile(),
            },
            {
                "key": "console:usb",
                "name": "Console USB",
                "type": "usb-mini-b",
                "label": None,
                "description": "Front USB console",
                "source": profile(),
            },
        ],
        "unresolved": [],
        "observations": {"console_line": {"first": "0"}},
    }
    return observed


def console_inventory():
    before = inventory()
    before["console_inventory"] = {"supported": True, "ports": [], "templates": []}
    return before


def apply_console_snapshot(plan, before):
    after = deepcopy(before)
    rows = after["console_inventory"]["ports"]
    for index, row in enumerate(plan["creates"]):
        rows.append({"id": "created-%s" % index, "module_id": None, "cable_id": None, **row})
    for row in plan["updates"]:
        port = next(port for port in rows if port["id"] == row["id"])
        for change in row["changes"]:
            port[change["field"]] = change["after"]
    return after


class ConsoleReconciliationTests(unittest.TestCase):
    def test_documented_connectors_create_then_repeat_without_changes(self):
        before = console_inventory()
        observed = observed_consoles()
        first = console.plan_console_ports(observed, before)
        self.assertFalse(first["errors"])
        self.assertEqual(first["summary"]["console_ports_created"], 2)
        self.assertEqual({row["type"] for row in first["creates"]}, {"rj-45", "usb-mini-b"})
        self.assertTrue(all(row["label"] is None for row in first["creates"]))
        after = apply_console_snapshot(first, before)
        second = console.plan_console_ports(observed, after)
        self.assertEqual(second["creates"], [])
        self.assertEqual(second["updates"], [])
        self.assertFalse(second["conflicts"])
        self.assertEqual(first["observations"], observed["console_ports"]["observations"])

    def test_unique_native_connector_adopts_manual_name_and_preserves_uuid_cable(self):
        before = console_inventory()
        before["console_inventory"]["ports"] = [
            {
                "id": "manual-rj45",
                "name": "Con0",
                "type": "rj-45",
                "description": "",
                "label": "Operator label",
                "module_id": None,
                "cable_id": "cable-1",
            },
        ]
        copy = deepcopy(before)
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertEqual(before, copy)
        self.assertEqual(plan["updates"][0]["id"], "manual-rj45")
        self.assertEqual(plan["updates"][0]["name"], "Con0")
        self.assertEqual(
            [change["field"] for change in plan["updates"][0]["changes"]], ["description"]
        )
        after = apply_console_snapshot(plan, before)
        port = after["console_inventory"]["ports"][0]
        self.assertEqual(port["cable_id"], "cable-1")
        self.assertEqual(port["label"], "Operator label")
        self.assertEqual(port["name"], "Con0")

    def test_unique_template_names_are_used_without_writing_templates(self):
        before = console_inventory()
        before["console_inventory"]["templates"] = [
            {"name": "con", "type": "rj-45", "label": "Manual template"},
            {"name": "usb", "type": "usb-mini-b"},
        ]
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertEqual({row["name"] for row in plan["creates"]}, {"con", "usb"})
        self.assertTrue(all(row["label"] is None for row in plan["creates"]))
        self.assertNotIn("template_updates", plan)

    def test_named_unknown_connector_type_is_filled(self):
        before = console_inventory()
        before["console_inventory"]["ports"] = [
            {"id": "console-1", "name": "Console RJ45", "type": "", "module_id": None}
        ]
        plan = console.plan_console_ports(observed_consoles(), before)
        changes = {row["field"]: row["after"] for row in plan["updates"][0]["changes"]}
        self.assertEqual(changes["type"], "rj-45")
        self.assertEqual(len(plan["creates"]), 1)

    def test_manual_populated_type_description_and_label_are_preserved(self):
        before = console_inventory()
        before["console_inventory"]["ports"] = [
            {
                "id": "console-1",
                "name": "Console RJ45",
                "type": "de-9",
                "label": "Manual",
                "description": "Manual",
                "module_id": None,
            }
        ]
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertFalse(plan["updates"])
        self.assertEqual(plan["conflicts"][0]["field"], "type")
        self.assertEqual(len(plan["unresolved"]), 1)
        self.assertEqual([row["type"] for row in plan["creates"]], ["usb-mini-b"])
        before["console_inventory"]["ports"][0]["type"] = "rj-45"
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertFalse(plan["updates"])
        self.assertEqual({row["field"] for row in plan["conflicts"]}, {"description"})

    def test_multiple_existing_connectors_are_not_guessed_or_duplicated(self):
        before = console_inventory()
        before["console_inventory"]["ports"] = [
            {"id": "one", "name": "con1", "type": "rj-45"},
            {"id": "two", "name": "con2", "type": "rj-45"},
        ]
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertTrue(plan["errors"])
        self.assertFalse(plan["updates"])
        self.assertEqual([row["type"] for row in plan["creates"]], ["usb-mini-b"])

    def test_module_connector_is_never_reattached(self):
        before = console_inventory()
        before["console_inventory"]["ports"] = [
            {"id": "module-console", "name": "Con", "type": "rj-45", "module_id": "module-1"}
        ]
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertFalse(plan["updates"])
        self.assertEqual([row["type"] for row in plan["creates"]], ["usb-mini-b"])
        self.assertEqual(plan["conflicts"][0]["field"], "module_id")

    def test_unidentified_existing_ports_prevent_duplicate_connectors(self):
        before = console_inventory()
        before["console_inventory"]["ports"] = [{"id": "unknown", "name": "con", "type": "other"}]
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertEqual(plan["creates"], [])
        self.assertEqual(plan["summary"]["unresolved_console_ports"], 2)

    def test_multiple_template_candidates_are_ambiguous(self):
        before = console_inventory()
        before["console_inventory"]["templates"] = [
            {"name": "one", "type": "rj-45"},
            {"name": "two", "type": "rj-45"},
        ]
        plan = console.plan_console_ports(observed_consoles(), before)
        self.assertTrue(plan["errors"])
        self.assertEqual([row["type"] for row in plan["creates"]], ["usb-mini-b"])

    def test_invalid_schema_profile_connector_or_duplicates_block_apply(self):
        baseline = observed_consoles()
        cases = []
        for field, value in (
            ("method", "guess"),
            ("profile", "other"),
            ("model", "C9300-24T"),
            ("member", True),
            ("member", 2),
            ("documents", [{}]),
        ):
            observed = deepcopy(baseline)
            observed["console_ports"]["items"][0]["source"][field] = value
            cases.append(observed)
        observed = deepcopy(baseline)
        observed["console_ports"]["items"][0]["type"] = "usb-a"
        cases.append(observed)
        observed = deepcopy(baseline)
        observed["console_ports"]["items"].append(observed["console_ports"]["items"][0])
        cases.append(observed)
        observed = deepcopy(baseline)
        observed["console_ports"]["schema_version"] = True
        cases.append(observed)
        for observed in cases:
            with self.subTest(observed=observed):
                plan = reconcile.build_plan(observed, console_inventory())
                self.assertTrue(plan["errors"])
                self.assertTrue(plan["summary"]["blocked"])

    def test_missing_old_schema_or_inventory_support_performs_no_console_writes(self):
        plan = reconcile.build_plan(discovery(), inventory())
        self.assertEqual(plan["console_ports"]["creates"], [])
        self.assertEqual(plan["summary"]["console_ports_created"], 0)
        plan = console.plan_console_ports(observed_consoles(), inventory())
        self.assertFalse(plan["creates"])
        self.assertEqual(len(plan["unresolved"]), 2)
        self.assertTrue(plan["warnings"])


if __name__ == "__main__":
    unittest.main()
