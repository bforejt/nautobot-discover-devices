"""Serialized identity, placement and ownership regressions for the lab profile."""

import unittest
from copy import deepcopy

from tests._loader import fixture, load
from tests.test_cisco_iosxe import FixtureClient, fixture_payloads

cisco = load("adapters.cisco_iosxe")
components = load("adapters.cisco_components")


def inventory(payloads):
    return payloads[cisco.HARDWARE_PATH]["Cisco-IOS-XE-device-hardware-oper:device-hardware-data"][
        "device-hardware"
    ]["device-inventory"]


def platform(payloads):
    return payloads[components.PLATFORM_PATH]["Cisco-IOS-XE-platform-oper:components"]["component"]


def transceiver_payloads():
    """Add the sanitized live transceiver leaves to the existing lab fixtures."""
    payloads = fixture_payloads()
    optic = fixture("iosxe_transceiver_inventory.json")
    inventory(payloads).append(optic["hardware_inventory"])
    platform(payloads).append(optic["platform_component"])
    return payloads


class CiscoComponentTests(unittest.TestCase):
    def test_transceiver_explicit_identity_manufacturer_and_nested_port_are_captured(self):
        client = FixtureClient(transceiver_payloads())
        result = cisco.collect(client)["components"]
        self.assertEqual(len(result["items"]), 3)
        optic = next(row for row in result["items"] if row["kind"] == "transceiver")
        self.assertEqual(optic["key"], "transceiver:1/1/1")
        self.assertEqual(optic["manufacturer"], "CISCO-EQUIV")
        self.assertEqual(optic["model"], "GLC-SX-MM")
        self.assertEqual(optic["part_number"], "GLC-SX-MM")
        self.assertEqual(optic["serial"], "LABOPTIC001")
        self.assertEqual(optic["hardware_revision"], "V03")
        self.assertEqual(optic["parent_key"], "uplink:1/1")
        self.assertEqual(optic["device_serial"], "LAB93000001")
        self.assertEqual(optic["member"], 1)
        self.assertEqual(optic["chassis_model"], "C9300-48UXM")
        self.assertEqual(optic["interfaces"], [])
        self.assertEqual(
            optic["bay"],
            {"name": "SFP GigabitEthernet1/1/1", "position": "1", "label": "GigabitEthernet1/1/1"},
        )
        self.assertEqual(optic["observations"]["platform_type"], "comp-port")
        self.assertFalse(optic["observations"]["removable"])
        self.assertFalse(optic["observations"]["empty"])
        self.assertEqual(optic["source"]["identity"]["inventory_index"], 700)
        self.assertEqual(optic["source"]["placement"]["profile"], components.TRANSCEIVER_PROFILE)
        self.assertEqual(optic["source"]["manufacturer"]["value"], "CISCO-EQUIV")
        self.assertEqual(optic["source"]["manufacturer"]["field"], "state/mfg-name")
        self.assertEqual(optic["source"]["manufacturer"]["revision"], "2023-03-01")
        self.assertEqual(optic["source"]["ownership"]["interface"], "GigabitEthernet1/1/1")
        self.assertEqual(optic["source"]["ownership"]["parent_serial"], "LABUPLINK001")
        self.assertTrue(any("mfg-name" in path for path in client.requests))
        self.assertFalse(any(row.get("serial") == "LABOPTIC001" for row in result["unresolved"]))

    def test_transceiver_collection_is_independent_of_inventory_order_and_ntc_flag(self):
        expected = cisco.collect(FixtureClient(transceiver_payloads()))["components"]
        payloads = transceiver_payloads()
        inventory(payloads).reverse()
        platform(payloads).reverse()
        for ntc_defaults in (False, True):
            with self.subTest(ntc_defaults=ntc_defaults):
                result = cisco.collect(FixtureClient(payloads), use_ntc_defaults=ntc_defaults)
                self.assertEqual(
                    [
                        item
                        for item in result["components"]["items"]
                        if item["kind"] != "power-supply"
                    ],
                    [item for item in expected["items"] if item["kind"] != "power-supply"],
                )
                self.assertEqual(result["components"]["physical_bays"], expected["physical_bays"])
                self.assertEqual(result["components"]["unresolved"], expected["unresolved"])

    def test_transceiver_pid_and_manufacturer_are_explicit_and_not_catalog_guesses(self):
        payloads = transceiver_payloads()
        inventory(payloads)[-1]["part-number"] = "VENDOR-EXPLICIT-PID  "
        platform(payloads)[-1]["state"]["part-no"] = "VENDOR-EXPLICIT-PID"
        platform(payloads)[-1]["state"]["mfg-name"] = "Actual OEM  "
        result = cisco.collect(FixtureClient(payloads))["components"]
        optic = next(row for row in result["items"] if row["kind"] == "transceiver")
        self.assertEqual(optic["model"], "VENDOR-EXPLICIT-PID")
        self.assertEqual(optic["manufacturer"], "Actual OEM")
        self.assertEqual(optic["source"]["manufacturer"]["value"], "Actual OEM")

    def test_missing_transceiver_manufacturer_or_identity_is_unresolved(self):
        for target, field, value in (
            ("platform", "mfg-name", None),
            ("platform", "mfg-name", "   "),
            ("platform", "mfg-name", "NULL"),
            ("hardware", "part-number", None),
            ("hardware", "serial-number", None),
            ("hardware", "hw-class", None),
            ("hardware", "field-replaceable", None),
        ):
            with self.subTest(target=target, field=field, value=value):
                payloads = transceiver_payloads()
                row = (
                    platform(payloads)[-1]["state"]
                    if target == "platform"
                    else inventory(payloads)[-1]
                )
                if value is None:
                    row.pop(field)
                else:
                    row[field] = value
                result = cisco.collect(FixtureClient(payloads))["components"]
                self.assertEqual(len(result["items"]), 2)
                self.assertTrue(
                    any(row.get("hw_type") == "hw-type-transceiver" for row in result["unresolved"])
                )

    def test_unreviewed_transceiver_placement_stays_unresolved(self):
        for target, field, value in (
            ("hardware", "dev-name", "Gi1/0/1"),
            ("hardware", "dev-name", "Gi1/1/5"),
            ("hardware", "dev-name", "Gi2/1/1"),
            ("platform", "parent", "Switch2"),
            ("platform", "location", "1/0/1/2"),
            ("platform", "type", "comp-transceiver"),
            ("platform", "empty", True),
            ("platform", "removable", True),
            ("platform", "empty", None),
            ("platform", "removable", None),
        ):
            with self.subTest(target=target, field=field, value=value):
                payloads = transceiver_payloads()
                row = (
                    platform(payloads)[-1]["state"]
                    if target == "platform"
                    else inventory(payloads)[-1]
                )
                if value is None:
                    row.pop(field)
                else:
                    row[field] = value
                result = cisco.collect(FixtureClient(payloads))["components"]
                self.assertEqual(len(result["items"]), 2)
                self.assertTrue(
                    any(row.get("hw_type") == "hw-type-transceiver" for row in result["unresolved"])
                )

    def test_transceiver_does_not_require_link_up_but_requires_observed_parent_port(self):
        payloads = transceiver_payloads()
        rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        target = next(row for row in rows if row["name"] == "GigabitEthernet1/1/1")
        target["oper-status"] = "if-oper-state-lower-layer-down"
        self.assertEqual(len(cisco.collect(FixtureClient(payloads))["components"]["items"]), 3)
        target["oper-status"] = "if-oper-state-not-present"
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertEqual(len(result["items"]), 2)
        self.assertTrue(
            any("eligible observed interface" in row["reason"] for row in result["unresolved"])
        )

    def test_transceiver_missing_or_unresolved_uplink_parent_is_not_created(self):
        for remove in (True, False):
            with self.subTest(remove=remove):
                payloads = transceiver_payloads()
                if remove:
                    inventory(payloads).pop(1)
                    platform(payloads).pop(2)
                else:
                    platform(payloads)[2]["state"]["parent"] = "Switch2"
                result = cisco.collect(FixtureClient(payloads))["components"]
                self.assertEqual([row["key"] for row in result["items"]], ["psu:1/B"])
                self.assertTrue(
                    any("parent uplink module" in row["reason"] for row in result["unresolved"])
                )

    def test_contradictory_transceiver_hardware_classification_blocks_collection(self):
        for field, value in (
            ("hw-class", "hw-class-logical"),
            ("field-replaceable", False),
            ("field-replaceable", "true"),
        ):
            with self.subTest(field=field, value=value):
                payloads = transceiver_payloads()
                inventory(payloads)[-1][field] = value
                with self.assertRaisesRegex(
                    cisco.DiscoveryError, "contradictory hardware classification"
                ):
                    cisco.collect(FixtureClient(payloads))

    def test_transceiver_contradictory_identity_or_interface_names_block_collection(self):
        for field, value in (
            ("serial-no", "WRONG-SERIAL"),
            ("part-no", "WRONG-PID"),
            ("cname", "GigabitEthernet1/1/2"),
        ):
            with self.subTest(field=field):
                payloads = transceiver_payloads()
                target = (
                    platform(payloads)[-1] if field == "cname" else platform(payloads)[-1]["state"]
                )
                target[field] = value
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_duplicate_transceiver_identity_in_either_source_blocks_collection(self):
        for target in ("hardware", "platform"):
            with self.subTest(target=target):
                payloads = transceiver_payloads()
                rows = inventory(payloads) if target == "hardware" else platform(payloads)
                duplicate = deepcopy(rows[-1])
                if target == "hardware":
                    duplicate["hw-dev-index"] = 999
                else:
                    duplicate["cname"] = "GigabitEthernet1/1/2"
                rows.append(duplicate)
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_reviewed_identity_and_placement_produce_exact_two_serialized_items(self):
        result = cisco.collect(FixtureClient())["components"]
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual([part["key"] for part in result["items"]], ["psu:1/B", "uplink:1/1"])
        parts = {part["key"]: part for part in result["items"]}
        uplink, psu = parts["uplink:1/1"], parts["psu:1/B"]
        self.assertEqual(uplink["kind"], "network-module")
        self.assertEqual(uplink["model"], "C3850-NM-4-1G")
        self.assertEqual(uplink["serial"], "LABUPLINK001")
        self.assertEqual(uplink["hardware_revision"], "V01")
        self.assertEqual(uplink["device_serial"], "LAB93000001")
        self.assertEqual(uplink["member"], 1)
        self.assertEqual(uplink["chassis_model"], "C9300-48UXM")
        self.assertEqual(
            uplink["bay"], {"name": "Uplink Module 1", "position": "1", "label": "Uplink Module 1"}
        )
        self.assertEqual(
            uplink["interfaces"], ["GigabitEthernet1/1/%d" % port for port in range(1, 5)]
        )
        self.assertEqual(uplink["observations"]["platform_type"], "comp-port")
        self.assertEqual(psu["kind"], "power-supply")
        self.assertEqual(psu["model"], "PWR-C1-1100WAC-P")
        self.assertEqual(psu["bay"]["position"], "PSU-B")
        self.assertEqual(psu["interfaces"], [])
        for part in parts.values():
            self.assertEqual(part["manufacturer"], "Cisco")
            self.assertEqual(part["part_number"], part["model"])
            self.assertIsNone(part["parent_key"])
            self.assertEqual(part["source"]["placement"]["revision"], "2023-03-01")
            self.assertEqual(part["source"]["ownership"]["method"], "reviewed-profile")

    def test_flat_and_platform_indexes_are_evidence_and_never_identity_joins(self):
        payloads = fixture_payloads()
        for offset, row in enumerate(inventory(payloads)):
            row["hw-dev-index"] = 9000 + offset
        for offset, row in enumerate(platform(payloads)):
            row["state"]["id"] = str(50000 + offset)
        parts = cisco.collect(FixtureClient(payloads))["components"]["items"]
        self.assertEqual(len(parts), 2)
        self.assertTrue(
            all(part["source"]["identity"]["inventory_index"] >= 9000 for part in parts)
        )

    def test_known_stack_alias_is_excluded_without_global_serial_deduplication(self):
        payloads = fixture_payloads()
        inventory(payloads).append(
            {
                "hw-type": "hw-type-transceiver",
                "hw-dev-index": 20,
                "part-number": "UNREVIEWED-OPTIC",
                "serial-number": "LAB93000001",
                "dev-name": "An individually reported optic",
                "field-replaceable": True,
            }
        )
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertTrue(any(row.get("name") == "c93xx Stack" for row in result["excluded"]))
        self.assertTrue(
            any(
                row.get("model") == "UNREVIEWED-OPTIC" and row.get("serial") == "LAB93000001"
                for row in result["unresolved"]
            )
        )
        self.assertEqual(len(result["items"]), 2)

    def test_inexact_stack_alias_remains_unresolved(self):
        payloads = fixture_payloads()
        inventory(payloads)[3]["field-replaceable"] = True
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertTrue(
            any(
                row.get("name") == "c93xx Stack" and row.get("hw_type") == "hw-type-emmc"
                for row in result["unresolved"]
            )
        )

    def test_psu_a_and_fans_are_unresolved_and_are_not_declared_vacant(self):
        result = cisco.collect(FixtureClient())["components"]
        names = {row.get("name") for row in result["unresolved"]}
        self.assertEqual(names, {"PowerSupply1/A", "Fan1/1", "Fan1/2", "Fan1/3"})
        psu = next(row for row in result["unresolved"] if row["name"] == "PowerSupply1/A")
        self.assertIsNone(psu["serial"])
        self.assertFalse(psu["empty"])
        self.assertEqual(psu["status_description"], "status-desc-no-input")
        self.assertIn("not inferred", psu["reason"])

    def test_platform_read_failure_retains_serialized_identity_as_unresolved(self):
        class UnavailableClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(components.PLATFORM_PATH):
                    raise cisco.RestconfError("unavailable", status_code=404)
                return super().get(path, **kwargs)

        result = cisco.collect(UnavailableClient())
        self.assertEqual(result["components"]["items"], [])
        self.assertEqual(
            {row["serial"] for row in result["components"]["unresolved"]},
            {"LABUPLINK001", "LABPSUB0001"},
        )
        self.assertEqual(len(result["interfaces"]), 58)
        self.assertTrue(
            any("placement source unavailable" in warning for warning in result["warnings"])
        )

    def test_platform_filter_retry_keeps_only_relevant_structured_fields(self):
        class FilterClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(components.PLATFORM_PATH + "?fields="):
                    self.requests.append(path)
                    raise cisco.RestconfError("filter unsupported", status_code=400)
                return super().get(path, **kwargs)

        payloads = fixture_payloads()
        platform(payloads)[2]["unrelated-field"] = "DO_NOT_RETAIN"
        client = FilterClient(payloads)
        result = cisco.collect(client)
        self.assertIn(components.PLATFORM_PATH, client.requests)
        self.assertEqual(len(result["components"]["items"]), 2)
        self.assertNotIn("DO_NOT_RETAIN", str(result))

    def test_unknown_serialized_part_is_visible_and_does_not_create_item(self):
        payloads = fixture_payloads()
        inventory(payloads)[1]["part-number"] = "NEW-UPLINK-MODEL"
        platform(payloads)[2]["state"]["part-no"] = "NEW-UPLINK-MODEL"
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertEqual([row["key"] for row in result["items"]], ["psu:1/B"])
        self.assertTrue(any(row.get("model") == "NEW-UPLINK-MODEL" for row in result["unresolved"]))

    def test_unknown_platform_only_serialized_part_is_visible(self):
        payloads = fixture_payloads()
        platform(payloads).append(
            {
                "cname": "FuturePart",
                "state": {
                    "type": "comp-fru",
                    "part-no": "NEW-PART",
                    "serial-no": "NEW-SERIAL",
                    "parent": "Switch1",
                    "location": "other",
                    "empty": False,
                    "removable": True,
                },
            }
        )
        result = cisco.collect(FixtureClient(payloads))["components"]
        self.assertTrue(any(row.get("serial") == "NEW-SERIAL" for row in result["unresolved"]))

    def test_unreviewed_parent_or_location_is_unresolved(self):
        for key, value in (("parent", "Switch2"), ("location", "other")):
            with self.subTest(key=key):
                payloads = fixture_payloads()
                platform(payloads)[2]["state"][key] = value
                result = cisco.collect(FixtureClient(payloads))["components"]
                self.assertEqual([row["key"] for row in result["items"]], ["psu:1/B"])
                self.assertTrue(
                    any(row.get("serial") == "LABUPLINK001" for row in result["unresolved"])
                )

    def test_contradictory_identity_or_class_blocks_collection(self):
        for target, key, value in (
            ("platform", "serial-no", "WRONG-SERIAL"),
            ("platform", "part-no", "WRONG-PID"),
            ("hardware", "hw-type", "hw-type-pem"),
        ):
            with self.subTest(target=target, key=key):
                payloads = fixture_payloads()
                row = (
                    platform(payloads)[2]["state"]
                    if target == "platform"
                    else inventory(payloads)[1]
                )
                row[key] = value
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_ambiguous_serialized_identity_blocks_collection(self):
        for source in ("hardware", "platform"):
            with self.subTest(source=source):
                payloads = fixture_payloads()
                if source == "hardware":
                    duplicate = deepcopy(inventory(payloads)[1])
                    duplicate["hw-dev-index"] = 99
                    inventory(payloads).append(duplicate)
                else:
                    duplicate = deepcopy(platform(payloads)[2])
                    duplicate["cname"] = "DuplicateUplink"
                    platform(payloads).append(duplicate)
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_missing_module_interface_remains_unresolved_without_fabrication(self):
        payloads = fixture_payloads()
        rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        next(row for row in rows if row["name"] == "GigabitEthernet1/1/4")["oper-status"] = (
            "if-oper-state-not-present"
        )
        result = cisco.collect(FixtureClient(payloads))["components"]
        uplink = next(row for row in result["items"] if row["key"] == "uplink:1/1")
        self.assertEqual(len(uplink["interfaces"]), 3)
        self.assertTrue(
            any(row.get("interfaces") == ["GigabitEthernet1/1/4"] for row in result["unresolved"])
        )

    def test_malformed_identity_types_and_platform_state_block_collection(self):
        for source in ("serial", "state", "empty"):
            with self.subTest(source=source):
                payloads = fixture_payloads()
                if source == "serial":
                    inventory(payloads)[1]["serial-number"] = {"unexpected": "object"}
                elif source == "state":
                    platform(payloads)[2]["state"] = []
                else:
                    platform(payloads)[2]["state"]["empty"] = "false"
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_worker_cancellation_is_not_swallowed(self):
        class InterruptedClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(components.PLATFORM_PATH):
                    raise RuntimeError("worker interrupted")
                return super().get(path, **kwargs)

        with self.assertRaisesRegex(RuntimeError, "worker interrupted"):
            cisco.collect(InterruptedClient())


if __name__ == "__main__":
    unittest.main()
