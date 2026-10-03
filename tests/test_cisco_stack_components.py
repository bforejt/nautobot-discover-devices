"""Physical stack-member uplinks and nested SFPs use corroborated owners."""

import unittest
from copy import deepcopy

from tests._loader import fixture, load
from tests.test_cisco_components import inventory, platform
from tests.test_cisco_iosxe import FixtureClient
from tests.test_cisco_stack import nodes, stack_payloads

cisco = load("adapters.cisco_iosxe")
components = load("adapters.cisco_components")


def stack_component_payloads():
    """Extend sanitized structured fixtures with an uplink and SFP per member."""
    payloads = stack_payloads()
    root = deepcopy(next(row for row in platform(payloads) if row["cname"] == "Switch1"))
    root["cname"] = "Switch2"
    root["state"].update({"serial-no": "LAB93000002", "parent": "Switch2", "location": "2/0/0/0"})
    platform(payloads).append(root)
    module = deepcopy(next(row for row in inventory(payloads) if row["hw-type"] == "hw-type-pim"))
    module.update(
        {
            "dev-name": "Switch 2 FRU Uplink Module 1",
            "serial-number": "LABUPLINK002",
            "hw-dev-index": 9001,
        }
    )
    inventory(payloads).append(module)
    part = deepcopy(next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1"))
    part["cname"] = "FRUUplinkModule2/1"
    part["state"].update(
        {"serial-no": "LABUPLINK002", "parent": "Switch2", "location": "2/0/1/1", "id": "900"}
    )
    platform(payloads).append(part)
    interfaces = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
        "interface"
    ]
    interfaces.extend(
        {**deepcopy(row), "name": row["name"].replace("GigabitEthernet1/1/", "GigabitEthernet2/1/")}
        for row in list(interfaces)
        if row["name"].startswith("GigabitEthernet1/1/")
    )
    for member in (1, 2):
        optic = fixture("iosxe_transceiver_inventory.json")
        optic["hardware_inventory"].update(
            {
                "dev-name": "Gi%d/1/1" % member,
                "serial-number": "LABOPTIC00%d" % member,
                "hw-dev-index": 8000 + member,
            }
        )
        optic["platform_component"]["cname"] = "GigabitEthernet%d/1/1" % member
        optic["platform_component"]["state"].update(
            {
                "serial-no": "LABOPTIC00%d" % member,
                "parent": "Switch%d" % member,
                "location": "%d/0/1/1" % member,
                "id": str(10000 + member),
            }
        )
        inventory(payloads).append(optic["hardware_inventory"])
        platform(payloads).append(optic["platform_component"])
    return payloads


def network_items(result):
    return {
        item["key"]: item
        for item in result["components"]["items"]
        if item["kind"] in ("network-module", "transceiver")
    }


class StackComponentCollectionTests(unittest.TestCase):
    def test_each_module_and_sfp_belongs_to_its_serial_matched_physical_member(self):
        result = cisco.collect(FixtureClient(stack_component_payloads()))
        items = network_items(result)
        self.assertEqual(
            set(items), {"uplink:1/1", "uplink:2/1", "transceiver:1/1/1", "transceiver:2/1/1"}
        )
        self.assertEqual(result["stack"]["active_position"], 2)
        for member in (1, 2):
            with self.subTest(member=member):
                uplink = items["uplink:%d/1" % member]
                optic = items["transceiver:%d/1/1" % member]
                for item in (uplink, optic):
                    self.assertEqual(item["device_serial"], "LAB9300000%d" % member)
                    self.assertEqual(item["member"], member)
                    self.assertEqual(item["chassis_model"], "C9300-48UXM")
                    self.assertEqual(item["source"]["ownership"]["member"], member)
                    self.assertEqual(item["source"]["ownership"]["chassis_model"], "C9300-48UXM")
                    self.assertEqual(item["source"]["membership"]["chassis_number"], member)
                    self.assertIn("documentation", item["source"]["ownership"])
                self.assertEqual(uplink["serial"], "LABUPLINK00%d" % member)
                self.assertEqual(
                    uplink["interfaces"],
                    ["GigabitEthernet%d/1/%d" % (member, p) for p in range(1, 5)],
                )
                self.assertEqual(optic["parent_key"], uplink["key"])
                self.assertEqual(optic["source"]["ownership"]["parent_serial"], uplink["serial"])
                self.assertEqual(optic["serial"], "LABOPTIC00%d" % member)
                self.assertEqual(optic["bay"]["label"], "GigabitEthernet%d/1/1" % member)
        self.assertFalse(
            any(
                row.get("serial") in {"LABUPLINK001", "LABUPLINK002", "LABOPTIC001", "LABOPTIC002"}
                for row in result["components"]["unresolved"]
            )
        )

    def test_input_order_and_active_role_do_not_change_physical_component_owners(self):
        payloads = stack_component_payloads()
        expected = network_items(cisco.collect(FixtureClient(payloads)))
        inventory(payloads).reverse()
        platform(payloads).reverse()
        nodes(payloads).reverse()
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(network_items(result), expected)
        for row in nodes(payloads):
            row["role"] = "role-active" if row["chassis-number"] == 1 else "role-member"
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(result["stack"]["active_position"], 1)
        self.assertEqual(
            {key: row["device_serial"] for key, row in network_items(result).items()},
            {key: row["device_serial"] for key, row in expected.items()},
        )

    def test_unverified_module_member_does_not_inherit_a_platform_parent(self):
        payloads = stack_component_payloads()
        module = next(
            row for row in inventory(payloads) if row.get("serial-number") == "LABUPLINK002"
        )
        module["dev-name"] = "Switch 3 FRU Uplink Module 1"
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(set(network_items(result)), {"uplink:1/1", "transceiver:1/1/1"})
        unresolved = result["components"]["unresolved"]
        self.assertEqual(sum(row.get("serial") == "LABUPLINK002" for row in unresolved), 1)
        self.assertEqual(sum(row.get("serial") == "LABOPTIC002" for row in unresolved), 1)

    def test_missing_member_root_defers_only_that_member_and_preserves_its_bays(self):
        payloads = stack_component_payloads()
        platform(payloads)[:] = [row for row in platform(payloads) if row["cname"] != "Switch2"]
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(set(network_items(result)), {"uplink:1/1", "transceiver:1/1/1"})
        self.assertEqual(len(result["components"]["physical_bays"]), 4)
        unresolved = result["components"]["unresolved"]
        for serial in ("LABUPLINK002", "LABOPTIC002"):
            self.assertEqual(sum(row.get("serial") == serial for row in unresolved), 1)

    def test_another_chassis_model_does_not_inherit_the_reviewed_active_member_profile(self):
        payloads = stack_component_payloads()
        next(row for row in inventory(payloads) if row.get("dev-name") == "Switch 2")[
            "part-number"
        ] = "C9300-24T"
        next(row for row in platform(payloads) if row["cname"] == "Switch2")["state"]["part-no"] = (
            "C9300-24T"
        )
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(set(network_items(result)), {"uplink:1/1", "transceiver:1/1/1"})
        self.assertEqual(
            sum(row.get("serial") == "LABUPLINK002" for row in result["components"]["unresolved"]),
            1,
        )

    def test_member_location_and_parent_must_match_without_slot_guesses(self):
        for field, value in (("location", "2/0/2/1"), ("parent", "Switch1")):
            with self.subTest(field=field):
                payloads = stack_component_payloads()
                next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule2/1")[
                    "state"
                ][field] = value
                result = cisco.collect(FixtureClient(payloads))
                self.assertEqual(set(network_items(result)), {"uplink:1/1", "transceiver:1/1/1"})

    def test_same_serialized_module_cannot_name_another_members_platform_bay(self):
        payloads = stack_component_payloads()
        platform(payloads)[:] = [
            row for row in platform(payloads) if row["cname"] != "FRUUplinkModule2/1"
        ]
        next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1")["cname"] = (
            "FRUUplinkModule2/1"
        )
        with self.assertRaisesRegex(cisco.DiscoveryError, "different hardware and platform bays"):
            cisco.collect(FixtureClient(payloads))

    def test_duplicate_module_or_sfp_identity_across_members_blocks_discovery(self):
        for kind, serial1, serial2 in (
            ("network-module", "LABUPLINK001", "LABUPLINK002"),
            ("transceiver", "LABOPTIC001", "LABOPTIC002"),
        ):
            with self.subTest(kind=kind):
                payloads = stack_component_payloads()
                next(row for row in inventory(payloads) if row.get("serial-number") == serial2)[
                    "serial-number"
                ] = serial1
                with self.assertRaisesRegex(cisco.DiscoveryError, "multiple inventory entries"):
                    cisco.collect(FixtureClient(payloads))

    def test_down_member_sfp_is_eligible_but_a_missing_port_is_not_invented(self):
        payloads = stack_component_payloads()
        interfaces = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        port = next(row for row in interfaces if row["name"] == "GigabitEthernet2/1/1")
        port["oper-status"] = "if-oper-state-lower-layer-down"
        self.assertIn("transceiver:2/1/1", network_items(cisco.collect(FixtureClient(payloads))))
        port["oper-status"] = "if-oper-state-not-present"
        result = cisco.collect(FixtureClient(payloads))
        self.assertNotIn("transceiver:2/1/1", network_items(result))
        self.assertEqual(len(network_items(result)["uplink:2/1"]["interfaces"]), 3)
        self.assertTrue(
            any(
                row.get("component_key") == "uplink:2/1"
                and row.get("interfaces") == ["GigabitEthernet2/1/1"]
                for row in result["components"]["unresolved"]
            )
        )

    def test_stack_interface_owner_disagreement_cannot_establish_an_sfp_association(self):
        payloads = stack_component_payloads()
        discovery = cisco.collect(FixtureClient(payloads))
        next(row for row in discovery["interfaces"] if row["name"] == "GigabitEthernet2/1/1")[
            "stack_member"
        ] = 1
        result = components.collect(
            FixtureClient(payloads),
            inventory(payloads),
            chassis_model=discovery["identity"]["model"],
            chassis_serial=discovery["identity"]["serial"],
            member=2,
            interfaces=discovery["interfaces"],
            warnings=[],
            stack=discovery["stack"],
        )
        self.assertFalse(any(row["key"] == "transceiver:2/1/1" for row in result["items"]))
        self.assertTrue(any(row.get("serial") == "LABOPTIC002" for row in result["unresolved"]))


if __name__ == "__main__":
    unittest.main()
