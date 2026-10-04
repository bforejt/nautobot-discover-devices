"""End-to-end RESTCONF-shaped discovery stays useful without product profiles."""

import json
import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_cisco_components import inventory, platform, transceiver_payloads
from tests.test_cisco_iosxe import FixtureClient

cisco = load("adapters.cisco_iosxe")


def unlisted_payloads():
    """Construct reported facts, without claiming a live capture of new hardware."""
    payloads = transceiver_payloads()
    hardware = inventory(payloads)
    parts = platform(payloads)
    hardware[:] = [row for row in hardware if row.get("dev-name") != "c93xx Stack"]
    parts[:] = [row for row in parts if row["cname"] != "c93xx Stack"]
    chassis = next(row for row in hardware if row["hw-type"] == "hw-type-chassis")
    chassis["part-number"] = "UNLISTED-CHASSIS-PID"
    root = next(row for row in parts if row["cname"] == "Switch1")
    root["state"]["part-no"] = chassis["part-number"]
    for row in payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
        "interface"
    ]:
        if cisco.canonical_interface_name(row["name"]).startswith(cisco.LAG_INTERFACE_FAMILIES):
            row["interface-type"] = "iana-iftype-ethernet-csmacd"
    for hw_type, platform_name, pid, platform_type in (
        ("hw-type-pim", "FRUUplinkModule1/1", "UNLISTED-UPLINK", "comp-module"),
        ("hw-type-pem", "PowerSupply1/B", "UNLISTED-PSU", "comp-power-supply"),
        ("hw-type-transceiver", "GigabitEthernet1/1/1", "UNLISTED-BIDI", "comp-transceiver"),
    ):
        row = next(row for row in hardware if row["hw-type"] == hw_type)
        row["part-number"] = pid
        part = next(row for row in parts if row["cname"] == platform_name)
        part["state"].update(
            {"part-no": pid, "type": platform_type, "mfg-name": "Reported OEM", "removable": True}
        )
        if hw_type == "hw-type-transceiver":
            part["state"]["parent"] = "FRUUplinkModule1/1"
    return payloads


class GenericCollectionTests(unittest.TestCase):
    def test_unlisted_chassis_and_pids_keep_known_facts_without_capability_maps(self):
        result = cisco.collect(FixtureClient(unlisted_payloads()))
        self.assertEqual(result["identity"]["model"], "UNLISTED-CHASSIS-PID")
        ethernet = [row for row in result["interfaces"] if row.get("physical_ethernet")]
        self.assertEqual(len(ethernet), 53)
        self.assertTrue(all(row["type"] is None for row in ethernet))
        self.assertTrue(all("hardware_profile" not in row for row in ethernet))
        items = {row["model"]: row for row in result["components"]["items"]}
        self.assertEqual(set(items), {"UNLISTED-UPLINK", "UNLISTED-PSU", "UNLISTED-BIDI"})
        self.assertEqual(items["UNLISTED-BIDI"]["parent_key"], items["UNLISTED-UPLINK"]["key"])
        self.assertTrue(all(row["manufacturer"] == "Reported OEM" for row in items.values()))
        self.assertTrue(all(row["interfaces"] == [] for row in items.values()))
        self.assertTrue(all(not row.get("power_ports") for row in items.values()))
        self.assertTrue(all(row["bay"]["label"] == "" for row in items.values()))
        self.assertEqual(len(result["components"]["identities"]), 3)
        self.assertTrue(
            all(
                row["source"]["manufacturer"]["revision"] == "2023-03-01"
                for row in result["components"]["identities"]
            )
        )
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_unavailable_containment_retains_identity_without_inventing_a_module(self):
        payloads = unlisted_payloads()
        part = next(row for row in platform(payloads) if row["cname"] == "FRUUplinkModule1/1")
        part["state"]["parent"] = "UNREPORTED-PARENT"
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertEqual(len(result["identities"]), 3)
        self.assertEqual([row["model"] for row in result["items"]], ["UNLISTED-PSU"])
        unresolved = {row["model"]: row for row in result["unresolved"] if row.get("serial")}
        self.assertIn("UNLISTED-UPLINK", unresolved)
        self.assertIn("UNLISTED-BIDI", unresolved)
        self.assertNotIn("no reviewed component profile", unresolved["UNLISTED-UPLINK"]["reason"])

    def test_missing_manufacturer_does_not_assume_cisco_from_platform_or_pid(self):
        payloads = unlisted_payloads()
        for part in platform(payloads):
            part["state"].pop("mfg-name", None)
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertEqual(result["identities"], [])
        self.assertEqual(result["items"], [])
        self.assertTrue(any("manufacturer" in row["reason"] for row in result["unresolved"]))

    def test_optic_identity_survives_but_logical_or_breakout_names_cannot_claim_a_cage(self):
        for name in (
            "TenGigabitEthernet1/1/1.123",
            "TenGigabitEthernet1/1/1/2",
            "UnclassifiedInterface1/1/1",
        ):
            with self.subTest(name=name):
                payloads = unlisted_payloads()
                optic = next(
                    row for row in inventory(payloads) if row["hw-type"] == "hw-type-transceiver"
                )
                optic["dev-name"] = name
                part = next(
                    row for row in platform(payloads) if row["state"]["part-no"] == "UNLISTED-BIDI"
                )
                part["cname"] = name
                rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
                    "interface"
                ]
                prototype = next(row for row in rows if row["name"] == "GigabitEthernet1/1/1")
                rows.append({**deepcopy(prototype), "name": name})
                result = cisco.collect(FixtureClient(payloads))["components"]
                self.assertTrue(
                    any(row["model"] == "UNLISTED-BIDI" for row in result["identities"])
                )
                self.assertFalse(any(row["model"] == "UNLISTED-BIDI" for row in result["items"]))
                self.assertTrue(
                    any(row.get("model") == "UNLISTED-BIDI" for row in result["unresolved"])
                )
