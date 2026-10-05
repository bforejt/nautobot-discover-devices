"""Logical interface provenance, conservative native mapping and preservation."""

import json
import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

from tests._loader import load

logical = load("adapters.panos_logical")
planner = load("reconcile_panos_interfaces")
FIXTURES = Path(__file__).parent / "fixtures"


def facts(xml=None):
    return logical.parse_logical_interfaces(
        xml or (FIXTURES / "panos_ipam_network.xml").read_text()
    )


def inventory(member_type="virtual"):
    return {
        "device": {"id": "device-id", "name": "panos-lab"},
        "interfaces": [
            {
                "id": name,
                "name": name,
                "type": member_type if name == "ethernet1/5" else "virtual",
                "device_id": "device-id",
                "module_id": None,
                "enabled": True,
            }
            for name in ("ethernet1/1", "ethernet1/2", "ethernet1/5")
        ],
        "unsupported_interface_fields": [],
        "panos_interface_inventory": {
            "supported": True,
            "capabilities": {
                "types": ["virtual", "lag", "tunnel"],
                "parent_interface": True,
                "lag": True,
            },
            "interfaces": [],
        },
    }


def observe(configuration=None):
    return {"adapter": "panos", "logical_interfaces": configuration or facts()}


def apply_pure(existing, plan):
    for create in plan["creates"]:
        existing["interfaces"].append(
            {**deepcopy(create), "id": create["name"], "device_id": "device-id", "module_id": None}
        )
    for update in plan["updates"]:
        row = next(row for row in existing["interfaces"] if row["name"] == update["name"])
        for change in update["changes"]:
            row[change["field"]] = change["after"]
    for assignment in plan["parents"] + plan["lag_assignments"]:
        rows = existing["panos_interface_inventory"]["interfaces"]
        row = next((row for row in rows if row["name"] == assignment["name"]), None)
        if row is None:
            row = {"name": assignment["name"]}
            rows.append(row)
        field = "parent_interface" if "parent_name" in assignment else "lag"
        target = assignment.get("parent_name", assignment.get("lag_name"))
        row[field + "_id"] = target
        row[field + "_name"] = target


class PanosLogicalTests(unittest.TestCase):
    def plan(self, observed=None, existing=None, interface_plan=None, identity=True):
        return planner.plan_panos_interfaces(
            observed or observe(),
            existing or inventory(),
            interface_plan,
            identity_verified=identity,
        )

    def test_exact_logical_kinds_and_direct_parents(self):
        rows = {row["name"]: row for row in facts()["interfaces"]}
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows["ethernet1/1.100"]["parent_name"], "ethernet1/1")
        self.assertEqual(rows["ethernet1/2.101"]["mode"], "layer2")
        self.assertEqual(rows["ae1.200"]["parent_name"], "ae1")
        self.assertEqual(rows["ae1"]["type"], "lag")
        self.assertEqual(rows["tunnel.1"]["type"], "tunnel")
        self.assertTrue(all(row["enabled"] is True for row in rows.values()))
        self.assertTrue(logical.validate_logical_interfaces(facts()))

    def test_live_xml_logicals_are_instantiated_independent_of_tunnel_status(self):
        data = facts((FIXTURES / "panos_ipam_live_network.xml").read_text())
        self.assertEqual(
            [(row["name"], row["enabled"]) for row in data["interfaces"]],
            [("loopback.1", True), ("tunnel.1", True)],
        )
        self.assertTrue(
            all(
                row["source"]["administrative_semantics"] == logical.ADMIN_SEMANTICS
                for row in data["interfaces"]
            )
        )

    def test_unknown_administrative_control_is_not_assumed_enabled(self):
        xml = (
            (FIXTURES / "panos_ipam_live_network.xml")
            .read_text()
            .replace('<entry name="tunnel.1">', '<entry name="tunnel.1"><disabled>yes</disabled>')
        )
        data = facts(xml)
        self.assertIsNone(
            next(row for row in data["interfaces"] if row["name"] == "tunnel.1")["enabled"]
        )
        plan = self.plan(observe(data))
        self.assertEqual([row["name"] for row in plan["creates"]], ["loopback.1"])

    def test_explicit_scalars_only_and_no_default_mtu_tag(self):
        xml = (
            (FIXTURES / "panos_ipam_network.xml")
            .read_text()
            .replace(
                '<entry name="ethernet1/1.100">',
                '<entry name="ethernet1/1.100"><comment>Transit</comment>'
                "<mtu>1600</mtu><tag>100</tag>",
            )
        )
        row = next(row for row in facts(xml)["interfaces"] if row["name"] == "ethernet1/1.100")
        self.assertEqual((row["description"], row["mtu"], row["tag"]), ("Transit", 1600, 100))
        untouched = next(row for row in facts()["interfaces"] if row["name"] == "tunnel.1")
        self.assertIsNone(untouched["mtu"])
        self.assertIsNone(untouched["tag"])

    def test_secret_and_unrelated_network_branches_are_discarded(self):
        xml = (
            (FIXTURES / "panos_ipam_network.xml")
            .read_text()
            .replace(
                "</network>",
                '<ike><gateway><entry name="private"><authentication><pre-shared-key>'
                "<key>PRIVATE</key></pre-shared-key></authentication>"
                "</entry></gateway></ike></network>",
            )
        )
        self.assertNotIn("PRIVATE", json.dumps(facts(xml)))
        self.assertNotIn("authentication", json.dumps(facts(xml)))

    def test_empty_optional_comment_is_unknown_without_inventing_description(self):
        xml = (
            (FIXTURES / "panos_ipam_live_network.xml")
            .read_text()
            .replace('<entry name="tunnel.1">', '<entry name="tunnel.1"><comment/>')
        )
        row = next(row for row in facts(xml)["interfaces"] if row["name"] == "tunnel.1")
        self.assertIsNone(row["description"])
        self.assertTrue(logical.validate_logical_interfaces(facts(xml)))

    def test_scalar_error_status_attributes_structure_and_empty_numbers_are_rejected(self):
        original = (FIXTURES / "panos_ipam_live_network.xml").read_text()
        for scalar in (
            '<mtu status="error">1500</mtu>',
            '<comment unsupported="scope">Untrusted</comment>',
            "<comment><value>Nested</value></comment>",
            "<mtu/>",
            "<mtu>" + "1" * 5000 + "</mtu>",
        ):
            with self.subTest(scalar=scalar[:25]), self.assertRaises(logical.DiscoveryError):
                facts(
                    original.replace('<entry name="tunnel.1">', '<entry name="tunnel.1">' + scalar)
                )

    def test_future_admin_control_family_is_unresolved(self):
        xml = (
            (FIXTURES / "panos_ipam_live_network.xml")
            .read_text()
            .replace(
                '<entry name="tunnel.1">',
                '<entry name="tunnel.1"><admin-enabled>no</admin-enabled>',
            )
        )
        data = facts(xml)
        self.assertTrue(logical.validate_logical_interfaces(data))
        row = next(row for row in data["interfaces"] if row["name"] == "tunnel.1")
        self.assertIsNone(row["enabled"])

    def test_duplicate_scalar_duplicate_identity_error_and_conflicting_mode_fail(self):
        original = (FIXTURES / "panos_ipam_live_network.xml").read_text()
        response = ET.fromstring(original)
        ET.SubElement(
            response.find('result/network/interface/ethernet/entry[@name="ethernet1/2"]'), "layer2"
        )
        variants = [
            original.replace(
                '<entry name="loopback.1">',
                '<entry name="loopback.1"><comment>A</comment><comment>B</comment>',
            ),
            original.replace(
                '<entry name="tunnel.1">', '<entry name="tunnel.1"><error>PRIVATE</error>'
            ),
            ET.tostring(response, encoding="unicode"),
        ]
        for xml in variants:
            with self.subTest(xml=xml[-25:]), self.assertRaises(logical.DiscoveryError):
                facts(xml)

    def test_invalid_parent_and_integer_values_fail_without_echoing_input(self):
        original = (FIXTURES / "panos_ipam_network.xml").read_text()
        for replacement in (
            '<entry name="ethernet1/7.100">',
            '<entry name="ethernet1/1.100"><mtu>0</mtu>',
            '<entry name="ethernet1/1.100"><tag>4095</tag>',
        ):
            with self.subTest(replacement=replacement), self.assertRaises(logical.DiscoveryError):
                facts(original.replace('<entry name="ethernet1/1.100">', replacement))

    def test_provenance_tamper_is_a_plan_error(self):
        for field, value in (
            ("type", "1000base-t"),
            ("enabled", False),
            ("parent_name", "ethernet1/9"),
        ):
            data = facts()
            data["interfaces"][0][field] = value
            self.assertFalse(logical.validate_logical_interfaces(data))
            self.assertTrue(self.plan(observe(data))["errors"])
        data = facts()
        data["memberships"][0]["lag_name"] = "ae99"
        self.assertFalse(logical.validate_logical_interfaces(data))

    def test_pure_creation_and_relationships_preserve_inputs(self):
        observed, existing = observe(), inventory()
        before = deepcopy((observed, existing))
        plan = self.plan(observed, existing)
        self.assertEqual(len(plan["creates"]), 6)
        self.assertEqual(len(plan["parents"]), 3)
        self.assertFalse(plan["lag_assignments"])
        self.assertIn("virtual vNICs", plan["unresolved"][0]["reason"])
        self.assertEqual((observed, existing), before)
        json.dumps(plan)

    def test_repeat_has_zero_native_changes(self):
        existing = inventory("1000base-t")
        first = self.plan(existing=existing)
        apply_pure(existing, first)
        repeat = self.plan(existing=existing)
        self.assertFalse(
            any(repeat[key] for key in ("creates", "updates", "parents", "lag_assignments"))
        )
        self.assertFalse(repeat["conflicts"])

    def test_native_physical_member_uses_explicit_aggregation_target(self):
        plan = self.plan(existing=inventory("1000base-t"))
        self.assertEqual(
            [(row["name"], row["lag_name"]) for row in plan["lag_assignments"]],
            [("ethernet1/5", "ae1")],
        )

    def test_identity_and_capability_gates_prevent_writes(self):
        self.assertFalse(self.plan(identity=False)["creates"])
        for key in ("supported",):
            existing = inventory()
            existing["panos_interface_inventory"][key] = False
            self.assertFalse(self.plan(existing=existing)["creates"])
        existing = inventory()
        existing["panos_interface_inventory"]["capabilities"]["types"] = ["virtual"]
        self.assertNotIn(
            "tunnel.1", [row["name"] for row in self.plan(existing=existing)["creates"]]
        )

    def test_absent_parent_field_and_missing_parent_are_report_only(self):
        existing = inventory()
        existing["panos_interface_inventory"]["capabilities"]["parent_interface"] = False
        self.assertFalse(self.plan(existing=existing)["parents"])
        existing = inventory()
        existing["interfaces"] = [
            row for row in existing["interfaces"] if row["name"] != "ethernet1/1"
        ]
        plan = self.plan(existing=existing)
        self.assertNotIn("ethernet1/1.100", [row["name"] for row in plan["parents"]])
        self.assertTrue(
            any("Direct configured parent" in row["reason"] for row in plan["unresolved"])
        )

    def test_prospective_base_parent_resolves_before_ipam(self):
        existing = inventory()
        existing["interfaces"] = [
            row for row in existing["interfaces"] if row["name"] != "ethernet1/1"
        ]
        plan = self.plan(
            existing=existing,
            interface_plan={
                "interface_creates": [{"name": "ethernet1/1", "type": "virtual", "enabled": True}]
            },
        )
        self.assertIn("ethernet1/1.100", [row["name"] for row in plan["parents"]])

    def test_populated_false_mtu_and_description_are_preserved(self):
        existing = inventory()
        row = {
            "id": "loopback.1",
            "name": "loopback.1",
            "type": "virtual",
            "device_id": "device-id",
            "module_id": None,
            "enabled": False,
            "mtu": 1700,
            "description": "Intent",
        }
        existing["interfaces"].append(row)
        data = facts()
        logical_row = next(row for row in data["interfaces"] if row["name"] == "loopback.1")
        evidence = deepcopy(logical_row["source"]["evidence"])
        evidence.update(comment="Observed", mtu="1500")
        data["interfaces"][data["interfaces"].index(logical_row)] = logical.canonical_row(evidence)
        plan = self.plan(observe(data), existing)
        self.assertFalse(plan["updates"])
        self.assertEqual(
            {row["field"] for row in plan["conflicts"]}, {"enabled", "mtu", "description"}
        )
        self.assertIs(existing["interfaces"][-1]["enabled"], False)

    def test_blank_optional_fields_fill_without_type_or_vlan_reassignment(self):
        existing = inventory()
        existing["interfaces"].append(
            {
                "id": "loopback.1",
                "name": "loopback.1",
                "type": "virtual",
                "device_id": "device-id",
                "module_id": None,
                "enabled": True,
                "description": "",
                "mtu": None,
            }
        )
        data = facts()
        index = next(i for i, row in enumerate(data["interfaces"]) if row["name"] == "loopback.1")
        evidence = deepcopy(data["interfaces"][index]["source"]["evidence"])
        evidence.update(comment="Observed", mtu="1500")
        data["interfaces"][index] = logical.canonical_row(evidence)
        plan = self.plan(observe(data), existing)
        self.assertEqual(
            [row["field"] for row in plan["updates"][0]["changes"]], ["description", "mtu"]
        )
        self.assertNotIn("tag", plan["creates"][0])

    def test_populated_parent_and_lag_assignments_are_preserved(self):
        existing = inventory("1000base-t")
        existing["panos_interface_inventory"]["interfaces"] = [
            {
                "name": "ethernet1/1.100",
                "parent_interface_id": "other",
                "parent_interface_name": "ethernet1/9",
            },
            {"name": "ethernet1/5", "lag_id": "other", "lag_name": "ae9"},
        ]
        plan = self.plan(existing=existing)
        self.assertNotIn("ethernet1/1.100", [row["name"] for row in plan["parents"]])
        self.assertFalse(plan["lag_assignments"])
        self.assertEqual({row["field"] for row in plan["conflicts"]}, {"parent_interface", "lag"})

    def test_module_ownership_and_conflicting_type_block_native_logical_changes(self):
        existing = inventory()
        existing["interfaces"].append(
            {
                "id": "loopback.1",
                "name": "loopback.1",
                "type": "1000base-t",
                "device_id": "device-id",
                "module_id": None,
            }
        )
        plan = self.plan(existing=existing)
        self.assertEqual(plan["conflicts"][0]["field"], "type")
        existing["interfaces"][-1].update(type="virtual", module_id="module-id")
        plan = self.plan(existing=existing)
        self.assertFalse(plan["updates"])
        self.assertTrue(any("directly owned" in row["reason"] for row in plan["unresolved"]))


if __name__ == "__main__":
    unittest.main()
