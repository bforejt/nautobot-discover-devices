"""Physical stack consoles preserve independent member identities and cables."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_cisco_iosxe import FixtureClient
from tests.test_cisco_stack_components import stack_component_payloads
from tests.test_stack_reconcile import applied_stack, stack_inventory

cisco = load("adapters.cisco_iosxe")
console = load("reconcile_console")
stack = load("reconcile_stack")


def observed():
    return cisco.collect(FixtureClient(stack_component_payloads()))


def inventory():
    result = stack_inventory()
    result["console_inventory"] = {"supported": True, "ports": [], "templates": []}
    return result


class StackConsoleTests(unittest.TestCase):
    def test_each_physical_member_has_its_own_documented_connectors(self):
        facts, before = observed(), inventory()
        plan = console.plan_console_ports(facts, before, stack_plan=stack.plan_stack(facts, before))
        self.assertFalse(plan["errors"])
        self.assertEqual(len(plan["creates"]), 4)
        self.assertEqual(
            {(row["device_serial"], row["type"]) for row in plan["creates"]},
            {
                (serial, type_)
                for serial in ("LAB93000001", "LAB93000002")
                for type_ in ("rj-45", "usb-mini-b")
            },
        )
        self.assertEqual({row["member_position"] for row in plan["creates"]}, {1, 2})
        self.assertNotIn("console_line", facts["console_ports"]["observations"])
        self.assertFalse(any(row.get("mgmt_only") for row in facts["interfaces"]))

    def test_same_named_connectors_adopt_only_the_correct_member_and_repeat(self):
        facts, before = observed(), inventory()
        first = stack.plan_stack(facts, before)
        after = applied_stack(first, before)
        members = {row["serial"]: row for row in after["stack"]["devices"]}
        original = []
        for serial, member in members.items():
            for type_ in ("rj-45", "usb-mini-b"):
                original.append(
                    {
                        "id": serial + type_,
                        "name": "Operator " + type_,
                        "type": type_,
                        "device_id": member["id"],
                        "module_id": None,
                        "label": "Preserved",
                        "description": "Manual",
                        "cable_id": serial + "cable",
                    }
                )
        after["console_inventory"]["ports"] = original
        stable = deepcopy(after)
        plan = console.plan_console_ports(facts, after, stack_plan=stack.plan_stack(facts, after))
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["creates"])
        self.assertFalse(plan["updates"])
        self.assertEqual(after, stable)

    def test_unknown_or_conflicting_owner_cannot_create_connectors(self):
        for field, value in (
            ("device_serial", "OTHER"),
            ("member", 2),
            ("chassis_model", "C9300-24T"),
        ):
            with self.subTest(field=field):
                facts, before = observed(), inventory()
                validated = stack.plan_stack(facts, before)
                facts["console_ports"]["items"][0][field] = value
                plan = console.plan_console_ports(facts, before, stack_plan=validated)
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["creates"])

    def test_stack_plan_required_and_foreign_member_port_cannot_be_adopted(self):
        facts, before = observed(), inventory()
        self.assertTrue(console.plan_console_ports(facts, before)["errors"])
        before["console_inventory"]["ports"] = [
            {
                "id": "foreign",
                "name": "Console RJ45",
                "type": "de-9",
                "device_id": "foreign-device",
                "module_id": None,
            }
        ]
        plan = console.plan_console_ports(facts, before, stack_plan=stack.plan_stack(facts, before))
        self.assertFalse(plan["errors"])
        self.assertEqual(len(plan["creates"]), 4)
        self.assertFalse(plan["conflicts"])

    def test_collector_defers_unknown_chassis_without_applying_other_member_profile(self):
        facts = observed()
        source = deepcopy(facts["stack"])
        source["members"][1]["model"] = "C9300-24T"
        result = cisco.cisco_access_ports.collect_stack_consoles(source)
        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(result["unresolved"][0]["member"], 2)
        self.assertEqual({row["device_serial"] for row in result["items"]}, {"LAB93000001"})

    def test_collector_rejects_ambiguous_or_unproven_member_identity(self):
        for mutation in ("duplicate", "identity", "membership", "position", "state"):
            with self.subTest(mutation=mutation):
                source = deepcopy(observed()["stack"])
                owner = source["members"][1]
                if mutation == "duplicate":
                    owner["serial"] = source["members"][0]["serial"]
                elif mutation in ("identity", "membership"):
                    owner["sources"].pop(mutation)
                elif mutation == "position":
                    owner["position"] = True
                else:
                    owner["state"] = "state-provisioned"
                with self.assertRaises(ValueError):
                    cisco.cisco_access_ports.collect_stack_consoles(source)
