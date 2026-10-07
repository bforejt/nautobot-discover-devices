"""Provisional 9800 source contract on copied, synthetic testsuite fixtures.

No fixture in this file constitutes a captured live controller payload.
"""

import unittest
from copy import deepcopy

from tests._loader import fixture, load

wlc = load("adapters.cisco_9800")
transport = load("transport_restconf")
POLICY = {"kind": "logical", "expected_hostname": "fixture-wlc"}


def payloads():
    return {
        wlc.HOSTNAME_PATH: {"Cisco-IOS-XE-native:hostname": "fixture-wlc"},
        wlc.HARDWARE_PATH: fixture("wlc_device_hardware_9800.json"),
        wlc.YANG_LIBRARY_PATH: {
            "ietf-yang-library:modules-state": {
                "module": [
                    {"name": "Cisco-IOS-XE-native", "revision": "2023-07-01"},
                    {"name": wlc.AP_MODULE, "revision": "2023-07-01"},
                    {"name": wlc.JOIN_MODULE, "revision": "2023-07-01"},
                    {"name": wlc.AP_CFG_MODULE, "revision": "2022-11-01"},
                ]
            }
        },
        wlc.CAPWAP_PATH: fixture("wlc_capwap_data.json"),
        wlc.MAC_MAP_PATH: fixture("wlc_ap_name_mac_map.json"),
        wlc.ETHERNET_PATH: fixture("wlc_ethernet_if_stats.json"),
        wlc.CDP_PATH: fixture("wlc_cdp_cache_data.json"),
        wlc.LLDP_PATH: fixture("wlc_lldp_neigh.json"),
        wlc.JOIN_PATH: fixture("wlc_ap_join_stats.json"),
        wlc.RADIO_PATH: fixture("wlc_radio_oper_data.json"),
        wlc.AP_TAG_PATH: fixture("wlc_ap_tags.json"),
    }


class FixtureClient:
    """One JSON response per requested resource, never a direct AP transport."""

    def __init__(self, values=None):
        self.payloads = values if values is not None else payloads()
        self.requests = []

    def get(self, path, **kwargs):
        self.requests.append(path)
        value = self.payloads.get(path, self.payloads.get(path.split("?", 1)[0]))
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value(path)
        return deepcopy(value)


def collect(client=None, policy=None, **kwargs):
    return wlc.collect(
        client or FixtureClient(),
        controller_id="controller-uuid",
        source_policy=policy if policy is not None else POLICY,
        **kwargs,
    )


def roster(values):
    return values[wlc.CAPWAP_PATH][wlc.AP_MODULE + ":capwap-data"]


class SourceIdentityTests(unittest.TestCase):
    def test_logical_source_is_verified_without_a_fabricated_chassis_serial(self):
        snapshot = collect()
        self.assertEqual(snapshot["contract"], wlc.CONTRACT)
        self.assertTrue(snapshot["source"]["verified"])
        self.assertEqual(snapshot["source"]["hostname"], "fixture-wlc")
        self.assertIsNone(snapshot["source"]["serial"])
        self.assertEqual(snapshot["source"]["reported_serial"], "9ABCDEF0123")
        self.assertEqual(snapshot["source"]["module_revisions"][wlc.AP_MODULE], "2023-07-01")

    def test_logical_source_can_leave_hardware_unresolved(self):
        values = payloads()
        values[wlc.HARDWARE_PATH] = None
        snapshot = collect(FixtureClient(values))
        self.assertTrue(snapshot["source"]["verified"])
        self.assertIsNone(snapshot["source"]["model"])
        self.assertIsNone(snapshot["source"]["serial"])
        hardware = next(row for row in snapshot["resources"] if row["path"] == wlc.HARDWARE_PATH)
        self.assertFalse(hardware["complete"])

    def test_physical_source_requires_exact_chassis_serial_and_model(self):
        values = payloads()
        chassis = values[wlc.HARDWARE_PATH][
            "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
        ]["device-hardware"]["device-inventory"][0]
        chassis["part-number"] = "C9800-40-K9"
        policy = {
            "kind": "physical",
            "expected_model": "C9800-40-K9",
            "expected_serial": "9ABCDEF0123",
        }
        self.assertEqual(collect(FixtureClient(values), policy)["source"]["serial"], "9ABCDEF0123")
        policy["expected_serial"] = "OTHER"
        client = FixtureClient(values)
        with self.assertRaisesRegex(wlc.DiscoveryError, "serial"):
            collect(client, policy)
        self.assertFalse(any("capwap-data" in path for path in client.requests))

    def test_source_policy_is_validated_before_io(self):
        for policy in ({}, {"kind": "logical"}, {"kind": "physical", "expected_model": "C9800"}):
            with self.subTest(policy=policy):
                client = FixtureClient()
                with self.assertRaises(wlc.DiscoveryError):
                    collect(client, policy)
                self.assertEqual(client.requests, [])

    def test_wrong_hostname_and_unadvertised_wireless_module_block_the_roster(self):
        for change in ("hostname", "module", "revision", "imported"):
            with self.subTest(change=change):
                values = payloads()
                modules = values[wlc.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]["module"]
                if change == "hostname":
                    values[wlc.HOSTNAME_PATH] = {"Cisco-IOS-XE-native:hostname": "another-wlc"}
                elif change == "module":
                    modules[:] = []
                elif change == "revision":
                    modules[1]["revision"] = "2023-99-01"
                else:
                    modules[1]["conformance-type"] = "import"
                client = FixtureClient(values)
                with self.assertRaises(wlc.DiscoveryError):
                    collect(client)
                self.assertFalse(any("capwap-data" in path for path in client.requests))

    def test_virtual_controller_cannot_use_the_physical_chassis_contract(self):
        with self.assertRaisesRegex(wlc.DiscoveryError, "logical"):
            collect(
                policy={
                    "kind": "physical",
                    "expected_model": "C9800-CL-K9",
                    "expected_serial": "9ABCDEF0123",
                }
            )


class RosterTests(unittest.TestCase):
    def test_full_roster_preserves_exact_ap_versions_and_downloading_state(self):
        client = FixtureClient()
        snapshot = collect(client)
        self.assertTrue(snapshot["complete"])
        self.assertEqual(len(snapshot["aps"]), 3)
        east, _, lobby = snapshot["aps"]
        self.assertEqual(east["serial"], "FGL0000AB01")
        self.assertEqual(east["software_version"], "17.12.4.42")
        self.assertEqual(east["wtp_mac"], "00:11:22:33:44:00")
        self.assertEqual(east["ethernet_mac"], "00:11:22:33:44:01")
        self.assertEqual(east["floor_label"], "3")
        self.assertEqual(east["tags"]["site"], "ST-HQ-3F")
        self.assertEqual(lobby["state"], "downloading")
        self.assertEqual(lobby["software_version"], "17.9.5.47")
        self.assertEqual(lobby["errors"], [])
        self.assertIsNone(lobby["location_label"])
        for path in (wlc.CAPWAP_PATH, wlc.MAC_MAP_PATH):
            self.assertEqual(
                sum(request.split("?", 1)[0] == path for request in client.requests), 1
            )
        self.assertFalse(any("client-oper" in path or "wlan" in path for path in client.requests))

    def test_duplicate_names_and_physical_claims_survive_for_the_planner(self):
        values = payloads()
        roster(values)[1]["name"] = roster(values)[0]["name"]
        roster(values).append(deepcopy(roster(values)[0]))
        snapshot = collect(FixtureClient(values))
        self.assertEqual(len(snapshot["aps"]), 4)
        self.assertEqual(sum(ap["name"] == "AP-3F-EAST-01" for ap in snapshot["aps"]), 3)

    def test_explicit_empty_roster_is_valid(self):
        values = payloads()
        values[wlc.CAPWAP_PATH] = {wlc.AP_MODULE + ":capwap-data": []}
        values[wlc.MAC_MAP_PATH] = {wlc.AP_MODULE + ":ap-name-mac-map": []}
        snapshot = collect(FixtureClient(values))
        self.assertTrue(snapshot["complete"])
        self.assertEqual(snapshot["aps"], [])
        self.assertEqual(len(snapshot["join_history"]), 3)

    def test_unknown_and_malformed_rosters_are_not_empty_fleets(self):
        for bad in (
            None,
            {},
            {"wrong:capwap-data": []},
            {wlc.AP_MODULE + ":capwap-data": {}},
            {wlc.AP_MODULE + ":capwap-data": [None]},
        ):
            with self.subTest(bad=bad):
                values = payloads()
                values[wlc.CAPWAP_PATH] = bad
                with self.assertRaisesRegex(wlc.DiscoveryError, "Required capwap-data"):
                    collect(FixtureClient(values))

    def test_known_parent_wrapper_is_supported(self):
        values = payloads()
        values[wlc.CAPWAP_PATH] = {
            wlc.AP_MODULE + ":access-point-oper-data": {"capwap-data": roster(values)}
        }
        self.assertEqual(len(collect(FixtureClient(values))["aps"]), 3)

    def test_required_mapping_failure_is_a_failed_controller_snapshot(self):
        values = payloads()
        values[wlc.MAC_MAP_PATH] = transport.RestconfError("HTTP 500", status_code=500)
        with self.assertRaisesRegex(wlc.DiscoveryError, "Required ap-name-mac-map"):
            collect(FixtureClient(values))

    def test_roster_limits_never_return_a_truncated_complete_fleet(self):
        with self.assertRaisesRegex(wlc.DiscoveryError, "incomplete"):
            collect(max_aps=2)
        for invalid in (True, 0, -1, 1.5):
            with self.subTest(invalid=invalid):
                client = FixtureClient()
                with self.assertRaises(wlc.DiscoveryError):
                    collect(client, max_aps=invalid)
                self.assertEqual(client.requests, [])

    def test_unsupported_states_do_not_become_joined_because_history_says_so(self):
        for state in (None, "ap-down", "unregistered", "invented"):
            with self.subTest(state=state):
                values = payloads()
                roster(values)[0]["ap-state"]["ap-operation-state"] = state
                snapshot = collect(FixtureClient(values))
                self.assertTrue(snapshot["aps"][0]["errors"])
                self.assertEqual(len(snapshot["aps"]), 3)
        self.assertNotIn("AP-OLD-04", {ap["name"] for ap in collect()["aps"]})

    def test_bad_identity_and_scalar_types_remain_unresolved(self):
        values = payloads()
        first = roster(values)[0]
        first["wtp-mac"] = "garbage"
        first["device-detail"]["static-info"]["board-data"]["wtp-serial-num"] = 123
        first["ap-location"]["floor"] = True
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertIsNone(ap["serial"])
        self.assertIsNone(ap["wtp_mac"])
        self.assertIsNone(ap["floor_label"])
        self.assertTrue(ap["errors"])

    def test_conflicting_reported_mac_mapping_defers_only_affected_ap(self):
        values = payloads()
        maps = values[wlc.MAC_MAP_PATH][wlc.AP_MODULE + ":ap-name-mac-map"]
        conflict = deepcopy(maps[0])
        conflict["eth-mac"] = "00:11:22:33:44:ff"
        maps.append(conflict)
        snapshot = collect(FixtureClient(values))
        self.assertIn("Contradictory", " ".join(snapshot["aps"][0]["errors"]))
        self.assertEqual(snapshot["aps"][1]["errors"], [])

    def test_invalid_ethernet_claim_does_not_disappear_beside_a_valid_mapping(self):
        values = payloads()
        maps = values[wlc.MAC_MAP_PATH][wlc.AP_MODULE + ":ap-name-mac-map"]
        maps.append({**maps[0], "eth-mac": "invalid"})
        snapshot = collect(FixtureClient(values))
        self.assertIn("invalid Ethernet", " ".join(snapshot["aps"][0]["errors"]))
        self.assertEqual(snapshot["aps"][1]["errors"], [])

    def test_exact_mac_spelling_is_canonicalized_without_arithmetic(self):
        values = payloads()
        roster(values)[0]["wtp-mac"] = "0011.2233.4400"
        maps = values[wlc.MAC_MAP_PATH][wlc.AP_MODULE + ":ap-name-mac-map"]
        maps[0]["eth-mac"] = "00-11-22-33-44-01"
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertEqual(ap["wtp_mac"], "00:11:22:33:44:00")
        self.assertEqual(ap["ethernet_mac"], "00:11:22:33:44:01")
        self.assertEqual(ap["errors"], [])


class OptionalAndFilterTests(unittest.TestCase):
    def test_radios_and_configured_tags_are_separate_report_only_observations(self):
        snapshot = collect()
        east, west, lobby = snapshot["aps"]
        self.assertEqual(len(east["radios"]), 3)
        self.assertEqual(len(west["radios"]), 2)
        self.assertEqual(lobby["radios"], [])
        self.assertEqual(east["radios"][0]["slot_id"], 0)
        self.assertEqual(east["radios"][0]["channel_number"], 6)
        self.assertEqual(east["radios"][0]["bands"][0]["power_dbm"], 14)
        self.assertEqual(len(west["radios"][1]["bands"]), 2)
        self.assertIn("report-only", east["radios"][0]["write_policy"])
        self.assertEqual(east["configured_tags"][0]["site"], "ST-HQ-3F")
        self.assertEqual(
            east["configured_tags"][0]["provenance"]["semantics"], "configuration-intent"
        )
        self.assertEqual(west["configured_tags"], [])
        self.assertEqual(len(snapshot["aps"]), 3)

    def test_optional_unadvertised_modules_are_recorded_without_probes(self):
        values = payloads()
        modules = values[wlc.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]["module"]
        modules[:] = [
            row for row in modules if row["name"] not in (wlc.JOIN_MODULE, wlc.AP_CFG_MODULE)
        ]
        client = FixtureClient(values)
        snapshot = collect(client)
        self.assertFalse(any(path.split("?", 1)[0] == wlc.JOIN_PATH for path in client.requests))
        self.assertFalse(any(path.split("?", 1)[0] == wlc.AP_TAG_PATH for path in client.requests))
        self.assertEqual(sum(row["status"] == "not-advertised" for row in snapshot["resources"]), 2)
        self.assertEqual(snapshot["aps"][0]["software_version"], "17.12.4.42")

    def test_signed_radio_power_and_duplicate_slot_claims_are_retained(self):
        values = payloads()
        radios = values[wlc.RADIO_PATH][wlc.AP_MODULE + ":radio-oper-data"]
        radios[0]["radio-band-info"][0]["phy-tx-pwr-lvl-cfg"]["cfg-data"][
            "curr-tx-power-in-dbm"
        ] = -3
        radios.append(deepcopy(radios[0]))
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertEqual(len(ap["radios"]), 4)
        self.assertEqual(ap["radios"][0]["bands"][0]["power_dbm"], -3)
        self.assertEqual(ap["radios"][3]["slot_id"], 0)

    def test_invalid_radio_slot_and_power_do_not_get_defaults(self):
        values = payloads()
        radios = values[wlc.RADIO_PATH][wlc.AP_MODULE + ":radio-oper-data"]
        radios[0]["radio-slot-id"] = True
        radios[1]["radio-band-info"][0]["phy-tx-pwr-lvl-cfg"]["cfg-data"][
            "curr-tx-power-in-dbm"
        ] = "junk"
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertEqual(len(ap["radios"]), 2)
        self.assertIsNone(ap["radios"][0]["bands"][0]["power_dbm"])
        self.assertEqual(ap["errors"], [])

    def test_only_explicit_filter_rejection_has_one_unfiltered_retry(self):
        values = payloads()

        def answer(path):
            if "?fields=" in path:
                raise transport.RestconfError(
                    "fields unsupported", status_code=400, filter_rejected=True
                )
            return payloads()[wlc.CAPWAP_PATH]

        values[wlc.CAPWAP_PATH] = answer
        client = FixtureClient(values)
        snapshot = collect(client)
        self.assertEqual(client.requests.count(wlc.CAPWAP_PATH), 1)
        resource = next(row for row in snapshot["resources"] if row["path"] == wlc.CAPWAP_PATH)
        self.assertTrue(resource["filter_retry"])
        values[wlc.CAPWAP_PATH] = transport.RestconfError("HTTP 400", status_code=400)
        client = FixtureClient(values)
        with self.assertRaises(wlc.DiscoveryError):
            collect(client)
        self.assertEqual(client.requests.count(wlc.CAPWAP_PATH), 0)

    def test_optional_failures_preserve_independent_identity_and_software(self):
        values = payloads()
        for path in (wlc.ETHERNET_PATH, wlc.CDP_PATH, wlc.LLDP_PATH, wlc.JOIN_PATH):
            values[path] = transport.RestconfError("HTTP 500", status_code=500)
        snapshot = collect(FixtureClient(values))
        self.assertEqual(snapshot["aps"][0]["software_version"], "17.12.4.42")
        self.assertEqual(snapshot["aps"][0]["errors"], [])
        self.assertEqual(snapshot["aps"][0]["ethernet_interfaces"], [])
        self.assertEqual(snapshot["aps"][0]["attachments"], [])
        self.assertEqual(sum(not row["complete"] for row in snapshot["resources"]), 4)

    def test_ethernet_port_mac_needs_an_explicit_unique_ethernet_identity_join(self):
        values = payloads()
        ethernet = values[wlc.ETHERNET_PATH][wlc.AP_MODULE + ":ethernet-if-stats"]
        ethernet[0].update({"wtp-mac": "00:11:22:33:44:01", "duplex": 1})
        ap = collect(FixtureClient(values))["aps"][0]
        port = ap["ethernet_interfaces"][0]
        self.assertTrue(port["physical_ethernet"])
        self.assertEqual(port["mac_address"], "00:11:22:33:44:01")
        self.assertEqual(port["negotiated_speed_mbps"], 1000)
        self.assertIsNone(port["speed"])
        self.assertIsNone(port["admin_state"])
        self.assertIsNone(port["capability"])
        ethernet.append({**ethernet[0], "if-name": "GigabitEthernet1", "if-index": 1})
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertTrue(all(port["mac_address"] is None for port in ap["ethernet_interfaces"]))

    def test_bad_numeric_and_boolean_observations_do_not_invent_zero_or_false(self):
        values = payloads()
        ethernet = values[wlc.ETHERNET_PATH][wlc.AP_MODULE + ":ethernet-if-stats"]
        ethernet[0].update({"link-speed": True, "if-index": 1.5})
        joins = values[wlc.JOIN_PATH][wlc.JOIN_MODULE + ":ap-join-stats"]
        joins[0]["ap-join-info"]["is-joined"] = "junk"
        snapshot = collect(FixtureClient(values))
        port = snapshot["aps"][0]["ethernet_interfaces"][0]
        self.assertIsNone(port["negotiated_speed_mbps"])
        self.assertIsNone(port["if_index"])
        self.assertIsNone(snapshot["join_history"][0]["joined"])

    def test_cdp_freshness_and_all_neighbors_are_retained_without_selecting_first(self):
        values = payloads()
        cdp = values[wlc.CDP_PATH][wlc.AP_MODULE + ":cdp-cache-data"]
        cdp[0].update(
            {"mac-addr": "00:11:22:33:44:00", "last-updated-time": "2026-09-24T13:55:00Z"}
        )
        cdp.append(
            {**cdp[0], "cdp-cache-device-id": "SECOND-SWITCH", "cdp-cache-device-port": "Gi1/0/2"}
        )
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertEqual(len(ap["attachments"]), 3)
        self.assertEqual(ap["attachments"][0]["last_updated_at"], "2026-09-24T13:55:00Z")
        self.assertEqual(ap["attachments"][0]["provenance"]["semantics"], "cached-unspecified")
        self.assertEqual(ap["attachments"][2]["neighbor_mac"], "aa:aa:aa:00:00:01")

    def test_cdp_radio_primary_key_is_an_explicit_join_without_ap_name(self):
        values = payloads()
        cdp = values[wlc.CDP_PATH][wlc.AP_MODULE + ":cdp-cache-data"]
        cdp[0]["mac-addr"] = cdp[0].pop("wtp-mac-addr")
        cdp[0].pop("ap-name")
        ap = collect(FixtureClient(values))["aps"][0]
        self.assertEqual(ap["attachments"][0]["protocol"], "cdp")
        self.assertEqual(ap["attachments"][0]["wtp_mac"], ap["wtp_mac"])


if __name__ == "__main__":
    unittest.main()
