"""Structured IOS XE identity and interface collection regressions."""

import unittest
from copy import deepcopy

from tests._loader import fixture, load

cisco = load("adapters.cisco_iosxe")


class FixtureClient:
    """GET-only fake that accepts filtered requests without network access."""

    def __init__(self, payloads=None):
        self.payloads = payloads if payloads is not None else fixture_payloads()
        self.requests = []
        self.trace = []

    def get(self, path, **kwargs):
        self.requests.append(path)
        self.trace.append({"path": path, "status": 200, "tls_mode": "default", "error": None})
        return deepcopy(self.payloads.get(path.split("?", 1)[0]))


def fixture_payloads():
    return {
        cisco.HOSTNAME_PATH: fixture("iosxe_hostname.json"),
        cisco.HARDWARE_PATH: fixture("iosxe_hardware.json"),
        cisco.INSTALL_PATH: fixture("iosxe_install.json"),
        cisco.INTERFACES_PATH: fixture("iosxe_interfaces.json"),
        cisco.NATIVE_INTERFACES_PATH: fixture("iosxe_native_lag_memberships.json"),
        cisco.cisco_layer2.GLOBAL_PATH: {"Cisco-IOS-XE-native:vlan": {}},
        cisco.cisco_layer2.VLAN_PATH: fixture("iosxe_vlan_database.json"),
        cisco.cisco_components.PLATFORM_PATH: fixture("iosxe_platform_components.json"),
        cisco.YANG_LIBRARY_PATH: fixture("iosxe_yang_library.json"),
    }


class CiscoCollectionTests(unittest.TestCase):
    def test_connector_uses_explicit_physical_rj45_media_even_when_down(self):
        for oper in (
            "if-oper-state-ready",
            "if-oper-state-lower-layer-down",
            "if-oper-state-no-pass",
        ):
            with self.subTest(oper=oper):
                values = fixture_payloads()
                row = next(
                    row
                    for row in values[cisco.INTERFACES_PATH][
                        "Cisco-IOS-XE-interfaces-oper:interfaces"
                    ]["interface"]
                    if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/1"
                )
                row.update({"interface-type": "iana-iftype-ethernet-csmacd", "oper-status": oper})
                row["ether-state"]["media-type"] = "ether-media-type-rj45"
                result = cisco.collect(FixtureClient(values))
                port = next(
                    row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/1"
                )
                self.assertEqual(port["port_type"], "8p8c")
                self.assertTrue(
                    result["evidence"]["sources"]["interface_fields"]["connector_references"]
                )

    def test_generic_absent_and_auto_media_do_not_establish_a_connector(self):
        for media in (
            None,
            "rj45",
            "ether-media-type-none",
            "ether-media-type-auto-select",
            "ether-media-type-sfp",
        ):
            with self.subTest(media=media):
                values = fixture_payloads()
                row = next(
                    row
                    for row in values[cisco.INTERFACES_PATH][
                        "Cisco-IOS-XE-interfaces-oper:interfaces"
                    ]["interface"]
                    if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/1"
                )
                row["interface-type"] = "iana-iftype-ethernet-csmacd"
                row["ether-state"]["media-type"] = media
                result = cisco.collect(FixtureClient(values))
                port = next(
                    row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/1"
                )
                self.assertIsNone(port["port_type"])

    def test_virtual_interface_and_unclassified_interface_do_not_get_physical_connectors(self):
        for name, raw_type in (
            ("Vlan2", "iana-iftype-ethernet-csmacd"),
            ("TwoGigabitEthernet1/0/1", None),
        ):
            with self.subTest(name=name, raw_type=raw_type):
                values = fixture_payloads()
                row = next(
                    row
                    for row in values[cisco.INTERFACES_PATH][
                        "Cisco-IOS-XE-interfaces-oper:interfaces"
                    ]["interface"]
                    if cisco.canonical_interface_name(row["name"]) == name
                )
                row["interface-type"] = raw_type
                row["ether-state"]["media-type"] = "ether-media-type-rj45"
                port = next(
                    row
                    for row in cisco.collect(FixtureClient(values))["interfaces"]
                    if row["name"] == name
                )
                self.assertIsNone(port["port_type"])

    def test_ready_speed_is_written_and_corroborated_duplex_remains_observation(self):
        payloads = fixture_payloads()
        row = next(
            row
            for row in payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
                "interface"
            ]
            if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/1"
        )
        row.update(
            {
                "oper-status": "if-oper-state-ready",
                "speed": "2500000000",
                "interface-type": "iana-iftype-ethernet-csmacd",
            }
        )
        row["ether-state"].update(
            {"negotiated-duplex-mode": "full-duplex", "auto-negotiate": False}
        )
        row["ether-stats"] = {
            "dot3-counters": {"dot3-error-counters-v2": {"dot3-duplex-status": "3"}}
        }
        result = cisco.collect(FixtureClient(payloads))
        collected = next(
            row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet1/0/1"
        )
        self.assertEqual(collected["speed"], 2500000)
        self.assertIsNone(collected["duplex"])
        self.assertEqual(collected["observations"]["corroborated_operational_duplex"], "full")
        self.assertEqual(collected["type"], "2.5gbase-t")
        self.assertFalse(collected["observations"]["auto_negotiate"])
        self.assertIn(
            "rfc3635", result["evidence"]["sources"]["interface_fields"]["duplex_reference"]
        )

    def test_down_nominal_speed_and_stale_mac_duplex_remain_observations(self):
        payloads = fixture_payloads()
        row = next(
            row
            for row in payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
                "interface"
            ]
            if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/1"
        )
        row.update(
            {
                "oper-status": "if-oper-state-lower-layer-down",
                "speed": "2500000000",
                "interface-type": "iana-iftype-ethernet-csmacd",
            }
        )
        row["ether-state"]["negotiated-duplex-mode"] = "full-duplex"
        row["ether-stats"] = {
            "dot3-counters": {"dot3-error-counters-v2": {"dot3-duplex-status": "3"}}
        }
        collected = next(
            row
            for row in cisco.collect(FixtureClient(payloads))["interfaces"]
            if row["name"] == "TwoGigabitEthernet1/0/1"
        )
        self.assertIsNone(collected["speed"])
        self.assertIsNone(collected["duplex"])
        self.assertEqual(collected["observations"]["reported_speed_bps"], 2500000000)

    def test_duplex_observation_requires_agreeing_mac_status_and_reviewed_copper_type(self):
        for raw_name, mac_status, expected in (
            ("Tw1/0/1", "2", None),
            ("Tw1/0/1", "1", None),
            ("Gi1/1/1", "3", None),
        ):
            with self.subTest(name=raw_name, mac_status=mac_status):
                payloads = fixture_payloads()
                row = next(
                    row
                    for row in payloads[cisco.INTERFACES_PATH][
                        "Cisco-IOS-XE-interfaces-oper:interfaces"
                    ]["interface"]
                    if cisco.canonical_interface_name(row["name"])
                    == cisco.canonical_interface_name(raw_name)
                )
                row.update(
                    {
                        "oper-status": "if-oper-state-ready",
                        "speed": "1000000000",
                        "interface-type": "iana-iftype-ethernet-csmacd",
                    }
                )
                row["ether-state"]["negotiated-duplex-mode"] = "full-duplex"
                row["ether-stats"] = {
                    "dot3-counters": {"dot3-error-counters-v2": {"dot3-duplex-status": mac_status}}
                }
                collected = next(
                    row
                    for row in cisco.collect(FixtureClient(payloads))["interfaces"]
                    if row["name"] == cisco.canonical_interface_name(raw_name)
                )
                self.assertIsNone(collected["duplex"])
                self.assertEqual(
                    collected["observations"]["corroborated_operational_duplex"], expected
                )
                self.assertEqual(collected["speed"], 1000000)

    def test_virtual_nominal_bandwidth_and_invalid_speed_do_not_fill_operational_speed(self):
        for raw_name, speed in (
            ("Vlan2", "1000000000"),
            ("Tw1/0/1", True),
            ("Tw1/0/1", "2500000001"),
            ("Tw1/0/1", "speed-auto"),
            ("Tw1/0/1", "0"),
        ):
            with self.subTest(name=raw_name, speed=speed):
                payloads = fixture_payloads()
                row = next(
                    row
                    for row in payloads[cisco.INTERFACES_PATH][
                        "Cisco-IOS-XE-interfaces-oper:interfaces"
                    ]["interface"]
                    if cisco.canonical_interface_name(row["name"])
                    == cisco.canonical_interface_name(raw_name)
                )
                row.update(
                    {
                        "oper-status": "if-oper-state-ready",
                        "speed": speed,
                        "interface-type": "iana-iftype-propvirtual"
                        if raw_name.startswith("Vlan")
                        else "iana-iftype-ethernet-csmacd",
                    }
                )
                collected = next(
                    row
                    for row in cisco.collect(FixtureClient(payloads))["interfaces"]
                    if row["name"] == cisco.canonical_interface_name(raw_name)
                )
                self.assertIsNone(collected["speed"])

    def test_identity_comes_from_explicit_structured_leaves(self):
        result = cisco.collect(FixtureClient())
        self.assertEqual(
            result["identity"],
            {
                "hostname": "example-9300",
                "serial": "LAB93000001",
                "model": "C9300-48UXM",
                "software_version": "17.12.08",
            },
        )
        self.assertEqual(result["adapter"], "cisco_iosxe")
        self.assertEqual(result["schema_version"], 1)

    def test_absent_aliases_and_internal_application_port_are_excluded(self):
        result = cisco.collect(FixtureClient())
        self.assertEqual(len(result["interfaces"]), 58)
        self.assertEqual(len(result["excluded_interfaces"]), 13)
        included = {row["name"] for row in result["interfaces"]}
        excluded = {row["name"] for row in result["excluded_interfaces"]}
        self.assertNotIn("AppGigabitEthernet1/0/1", included)
        self.assertIn("AppGigabitEthernet1/0/1", excluded)
        self.assertIn("FortyGigabitEthernet1/1/1", excluded)
        self.assertIn("GigabitEthernet0/0", included)
        self.assertIn("Vlan2", included)
        self.assertIn("Port-channel1", included)
        self.assertTrue(all(row["reason"] for row in result["excluded_interfaces"]))

    def test_physical_type_uses_chassis_capability_not_negotiated_speed(self):
        result = cisco.collect(FixtureClient())
        rows = {row["name"]: row for row in result["interfaces"]}
        # Every synthetic interface negotiates 1G, including these multigig copper ports.
        self.assertEqual(rows["TwoGigabitEthernet1/0/1"]["type"], "2.5gbase-t")
        self.assertEqual(rows["TwoGigabitEthernet1/0/36"]["type"], "2.5gbase-t")
        self.assertEqual(rows["TenGigabitEthernet1/0/37"]["type"], "10gbase-t")
        self.assertEqual(rows["TenGigabitEthernet1/0/48"]["type"], "10gbase-t")
        self.assertEqual(rows["GigabitEthernet1/1/1"]["type"], "1000base-x-sfp")
        self.assertEqual(rows["GigabitEthernet0/0"]["type"], "1000base-t")
        self.assertEqual(rows["Port-channel1"]["type"], "lag")
        self.assertEqual(rows["Vlan2"]["type"], "virtual")
        self.assertTrue(rows["TwoGigabitEthernet1/0/1"]["type_source"])

    def test_present_disconnected_ports_and_admin_down_ports_remain(self):
        result = cisco.collect(FixtureClient())
        rows = {row["name"]: row for row in result["interfaces"]}
        self.assertIn("TwoGigabitEthernet1/0/2", rows)
        self.assertFalse(rows["GigabitEthernet0/0"]["enabled"])
        self.assertEqual(rows["GigabitEthernet1/1/1"]["description"], "Example uplink")
        self.assertEqual(rows["GigabitEthernet1/1/1"]["mtu"], 1500)
        self.assertTrue(rows["GigabitEthernet1/1/1"]["mac_address"].startswith("02:"))

    def test_unknown_chassis_keeps_physical_type_unknown(self):
        payloads = fixture_payloads()
        inventory = payloads[cisco.HARDWARE_PATH][
            "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
        ]["device-hardware"]["device-inventory"]
        inventory[0]["part-number"] = "UNKNOWN-MODEL"
        payloads[cisco.cisco_components.PLATFORM_PATH]["Cisco-IOS-XE-platform-oper:components"][
            "component"
        ][0]["state"]["part-no"] = "UNKNOWN-MODEL"
        result = cisco.collect(FixtureClient(payloads))
        rows = {row["name"]: row for row in result["interfaces"]}
        self.assertIsNone(rows["TwoGigabitEthernet1/0/1"]["type"])
        self.assertEqual(rows["Vlan2"]["type"], "virtual")

    def test_uncommitted_active_install_takes_precedence_over_old_committed(self):
        payloads = fixture_payloads()
        location = payloads[cisco.INSTALL_PATH][
            "Cisco-IOS-XE-install-oper:install-location-information"
        ][0]
        location["install-version-info"].append(
            {
                "version": "17.15.06.0.999",
                "current": "install-version-state-provisioned-uncommitted",
            }
        )
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(result["identity"]["software_version"], "17.15.06")

    def test_multiple_chassis_fail_instead_of_guessing_stack_identity(self):
        payloads = fixture_payloads()
        inventory = payloads[cisco.HARDWARE_PATH][
            "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
        ]["device-hardware"]["device-inventory"]
        inventory.append({**inventory[0], "hw-dev-index": 2, "serial-number": "LAB93000002"})
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_missing_install_data_does_not_parse_prose_banner(self):
        payloads = fixture_payloads()
        payloads[cisco.INSTALL_PATH] = None
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_optional_yang_library_gap_is_visible_but_not_fatal(self):
        payloads = fixture_payloads()
        payloads[cisco.YANG_LIBRARY_PATH] = None
        result = cisco.collect(FixtureClient(payloads))
        self.assertTrue(result["warnings"])
        self.assertEqual(len(result["interfaces"]), 58)

    def test_rejected_fields_filter_retries_same_structured_endpoint(self):
        class FilterClient(FixtureClient):
            def get(self, path, **kwargs):
                if "?fields=" in path and path.split("?", 1)[0] in (
                    cisco.INSTALL_PATH,
                    cisco.INTERFACES_PATH,
                ):
                    self.requests.append(path)
                    self.trace.append({"path": path, "status": 400})
                    raise cisco.RestconfError("filter unsupported", status_code=400)
                return super().get(path, **kwargs)

        client = FilterClient()
        result = cisco.collect(client)
        self.assertEqual(len(result["interfaces"]), 58)
        for path in (cisco.INSTALL_PATH, cisco.INTERFACES_PATH):
            self.assertIn(path, client.requests)
            self.assertTrue(
                any(request.startswith(path + "?fields=") for request in client.requests)
            )
        self.assertTrue(any("400" in warning for warning in result["warnings"]))

    def test_duplicate_canonical_interface_names_are_rejected(self):
        payloads = fixture_payloads()
        rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        rows.append(
            {"name": "Po1", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready"}
        )
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_ambiguous_provisioned_install_versions_are_rejected(self):
        payloads = fixture_payloads()
        versions = payloads[cisco.INSTALL_PATH][
            "Cisco-IOS-XE-install-oper:install-location-information"
        ][0]["install-version-info"]
        versions.append({**versions[0], "version": "17.15.06.0.999"})
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_old_software_release_is_rejected(self):
        payloads = fixture_payloads()
        payloads[cisco.INSTALL_PATH]["Cisco-IOS-XE-install-oper:install-location-information"][0][
            "install-version-info"
        ][0]["version"] = "17.06.08.0.999"
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_numeric_install_extension_remains_evidence_not_release(self):
        payloads = fixture_payloads()
        payloads[cisco.INSTALL_PATH]["Cisco-IOS-XE-install-oper:install-location-information"][0][
            "install-version-info"
        ][0]["version-extension"] = "1784423960"
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(result["identity"]["software_version"], "17.12.08")
        self.assertIn("1784423960", str(result["evidence"]["install"]))

    def test_unreviewed_install_extension_fails_explicitly(self):
        payloads = fixture_payloads()
        payloads[cisco.INSTALL_PATH]["Cisco-IOS-XE-install-oper:install-location-information"][0][
            "install-version-info"
        ][0]["version-extension"] = "special-image"
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_other_member_is_rejected_when_present_and_excluded_when_absent(self):
        payloads = fixture_payloads()
        rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        rows.append(
            {"name": "Gi2/0/1", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready"}
        )
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))
        rows[-1]["oper-status"] = "if-oper-state-not-present"
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(len(result["interfaces"]), 58)
        self.assertIn(
            "GigabitEthernet2/0/1", {row["name"] for row in result["excluded_interfaces"]}
        )

    def test_collection_records_structured_request_and_module_evidence(self):
        client = FixtureClient()
        result = cisco.collect(client)
        self.assertTrue(client.requests)
        self.assertTrue(all(path.startswith("/data/") for path in client.requests))
        self.assertTrue(result["evidence"]["requests"])
        self.assertIn("2023-11-01", str(result["evidence"]["modules"]))

    def test_configured_lag_members_keep_disconnected_ports_and_source_evidence(self):
        client = FixtureClient()
        result = cisco.collect(client)
        self.assertEqual(
            [(row["member"], row["lag"]) for row in result["lag_memberships"]],
            [
                ("TwoGigabitEthernet1/0/22", "Port-channel1"),
                ("TwoGigabitEthernet1/0/23", "Port-channel1"),
            ],
        )
        observed = {row["name"]: row for row in result["interfaces"]}
        for row in result["lag_memberships"]:
            self.assertEqual(row["source"]["mode"], "active")
            self.assertEqual(row["source"]["module"], "Cisco-IOS-XE-ethernet")
            self.assertEqual(row["source"]["revision"], "2023-07-01")
            self.assertIn("channel-group/number", row["source"]["field"])
            self.assertEqual(
                observed[row["member"]]["observations"]["oper_status"],
                "if-oper-state-lower-layer-down",
            )
        request = next(
            path for path in client.requests if path.startswith(cisco.NATIVE_INTERFACES_PATH)
        )
        for family in cisco.LAG_INTERFACE_FAMILIES:
            self.assertIn(
                family + "(name;Cisco-IOS-XE-ethernet:channel-group(number;mode))", request
            )

    def test_all_configured_aggregation_modes_use_the_same_membership_mapping(self):
        for mode in ("active", "passive", "on", "auto", "desirable", None):
            with self.subTest(mode=mode):
                payloads = fixture_payloads()
                rows = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"][
                    "TwoGigabitEthernet"
                ]
                for row in rows[1:]:
                    group = row["Cisco-IOS-XE-ethernet:channel-group"]
                    if mode is None:
                        group.pop("mode")
                    else:
                        group["mode"] = mode
                result = cisco.collect(FixtureClient(payloads))
                self.assertEqual(len(result["lag_memberships"]), 2)
                self.assertTrue(
                    all(row["source"]["mode"] == mode for row in result["lag_memberships"])
                )

    def test_native_lag_filter_400_retries_json_without_retaining_unrelated_data(self):
        class FilterClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(cisco.NATIVE_INTERFACES_PATH + "?fields="):
                    self.requests.append(path)
                    raise cisco.RestconfError("filter unsupported", status_code=400)
                return super().get(path, **kwargs)

        payloads = fixture_payloads()
        row = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"][
            "TwoGigabitEthernet"
        ][1]
        row["unrelated-sensitive-field"] = "DO_NOT_RETAIN"
        client = FilterClient(payloads)
        result = cisco.collect(client)
        self.assertIn(cisco.NATIVE_INTERFACES_PATH, client.requests)
        self.assertEqual(len(result["lag_memberships"]), 2)
        self.assertNotIn("DO_NOT_RETAIN", str(result))
        self.assertTrue(any("400" in warning for warning in result["warnings"]))

    def test_native_lag_read_failure_is_visible_and_does_not_fabricate_members(self):
        class UnavailableClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(cisco.NATIVE_INTERFACES_PATH):
                    raise cisco.RestconfError("not served", status_code=404)
                return super().get(path, **kwargs)

        result = cisco.collect(UnavailableClient())
        self.assertEqual(result["lag_memberships"], [])
        self.assertEqual(len(result["interfaces"]), 58)
        self.assertTrue(
            any(
                "Configured LAG membership source unavailable" in warning
                for warning in result["warnings"]
            )
        )

    def test_native_configuration_without_channel_groups_has_no_memberships(self):
        payloads = fixture_payloads()
        rows = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"][
            "TwoGigabitEthernet"
        ]
        for row in rows:
            row.pop("Cisco-IOS-XE-ethernet:channel-group", None)
        self.assertEqual(cisco.collect(FixtureClient(payloads))["lag_memberships"], [])

    def test_malformed_group_numbers_modes_and_shapes_block_collection(self):
        for group in (
            None,
            [],
            "1",
            {},
            {"number": True},
            {"number": 0},
            {"number": 513},
            {"number": "1"},
            {"number": 1, "mode": "unknown"},
        ):
            with self.subTest(group=group):
                payloads = fixture_payloads()
                rows = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"][
                    "TwoGigabitEthernet"
                ]
                rows[1]["Cisco-IOS-XE-ethernet:channel-group"] = group
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_duplicate_configured_member_is_rejected(self):
        payloads = fixture_payloads()
        rows = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"][
            "TwoGigabitEthernet"
        ]
        rows.append(deepcopy(rows[1]))
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(FixtureClient(payloads))

    def test_absent_member_is_omitted_and_missing_member_is_reported(self):
        payloads = fixture_payloads()
        rows = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"][
            "TenGigabitEthernet"
        ]
        rows.extend(
            [
                {"name": "1/1/1", "Cisco-IOS-XE-ethernet:channel-group": {"number": 1}},
                {"name": "1/0/99", "Cisco-IOS-XE-ethernet:channel-group": {"number": 1}},
            ]
        )
        result = cisco.collect(FixtureClient(payloads))
        members = {row["member"] for row in result["lag_memberships"]}
        self.assertNotIn("TenGigabitEthernet1/1/1", members)
        self.assertIn("TenGigabitEthernet1/0/99", members)
        self.assertTrue(any("TenGigabitEthernet1/1/1" in warning for warning in result["warnings"]))
        self.assertTrue(
            any("TenGigabitEthernet1/0/99" in warning for warning in result["warnings"])
        )

    def test_native_lag_worker_cancellation_is_not_swallowed(self):
        class InterruptedClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(cisco.NATIVE_INTERFACES_PATH):
                    raise RuntimeError("worker interrupted")
                return super().get(path, **kwargs)

        with self.assertRaisesRegex(RuntimeError, "worker interrupted"):
            cisco.collect(InterruptedClient())

    def test_canonical_interface_and_version_matching(self):
        for short, full in (
            ("Gi1/0/1", "GigabitEthernet1/0/1"),
            ("Te1/0/37", "TenGigabitEthernet1/0/37"),
            ("Po1", "Port-channel1"),
            ("Vl2", "Vlan2"),
        ):
            with self.subTest(short=short):
                self.assertEqual(
                    cisco.canonical_interface_name(short), cisco.canonical_interface_name(full)
                )
        self.assertEqual(cisco.canonical_software_version("17.12.8a"), "17.12.08a")
        self.assertEqual(cisco.canonical_software_version("17.12.08.0.770"), "17.12.08")


if __name__ == "__main__":
    unittest.main()
