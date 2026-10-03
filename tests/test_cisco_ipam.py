"""Static IPAM evidence must be complete, scoped and joined to core identity."""

import json
import unittest
from copy import deepcopy
from unittest.mock import patch

import requests

from tests._loader import fixture, load

ipam = load("adapters.cisco_ipam")
cisco = load("adapters.cisco_iosxe")
RestconfError = load("transport_restconf").RestconfError
RestconfClient = load("transport_restconf").RestconfClient

ELIGIBLE_NAMES = (
    "GigabitEthernet0/0",
    "GigabitEthernet1/0/1",
    "GigabitEthernet2/0/1",
    "Loopback0",
    "Port-channel1",
    "Port-channel1.99",
    "Vlan2",
    "Vlan3",
    "Vlan4",
)
EXCLUDED = [
    {"name": "TenGigabitEthernet1/1/1", "reason": "Device reports if-oper-state-not-present"},
    {"name": "AppGigabitEthernet1/0/1", "reason": "Internal application-hosting interface"},
]


class FixtureClient:
    def __init__(self, payloads=None):
        self.payloads = deepcopy(payloads or fixture("iosxe_ipam_configured.json"))
        self.requests = []
        self.trace = []

    def get(self, path, **kwargs):
        self.requests.append((path, kwargs))
        key = {
            ipam.INTERFACES_PATH: "interfaces",
            ipam.VRF_PATH: "vrfs",
            ipam.LEGACY_VRF_PATH: "legacy_vrfs",
        }[path.split("?", 1)[0]]
        value = self.payloads[key]
        self.trace.append(
            {"path": path, "status": value.status_code if isinstance(value, RestconfError) else 200}
        )
        if isinstance(value, BaseException):
            raise value
        return deepcopy(value)


def collect(payloads=None, **kwargs):
    return ipam.collect(
        FixtureClient(payloads),
        [{"name": name} for name in ELIGIBLE_NAMES],
        canonical_name=cisco.canonical_interface_name,
        excluded_interfaces=EXCLUDED,
        revisions={ipam.MODULE: "2025-07-01"},
        **kwargs,
    )


def rows(values):
    return values["interfaces"]["Cisco-IOS-XE-native:interface"]


class IpamCollectionTests(unittest.TestCase):
    def test_live_1718_projection_validates_core_exclusions_and_configured_addresses(self):
        values = fixture("iosxe_ipam_live_1718.json")
        core = fixture("iosxe_interfaces.json")["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        eligible, excluded = [], []
        for row in core:
            name = cisco.canonical_interface_name(row["name"])
            if row["oper-status"] == "if-oper-state-not-present" or name.startswith(
                "AppGigabitEthernet"
            ):
                excluded.append({"name": name, "reason": "Mandatory core exclusion"})
            else:
                eligible.append({"name": name})
        result = ipam.collect(
            FixtureClient(values),
            eligible,
            canonical_name=cisco.canonical_interface_name,
            excluded_interfaces=excluded,
        )
        facts = {row["name"]: row for row in result["interfaces"]}
        self.assertEqual(len(facts), 58)
        self.assertEqual(len(result["excluded"]), 13)
        self.assertEqual(facts["Vlan3"]["ipv4"][0]["address"], "192.0.2.2")
        self.assertEqual(facts["Vlan4"]["ipv4"][0]["address"], "198.51.100.2")
        self.assertEqual(facts["Vlan2"]["ipv4"], [])
        self.assertEqual(facts["GigabitEthernet0/0"]["vrf"], "Mgmt-vrf")
        self.assertEqual(result["sources"][-1]["status"], "available")

    def test_static_families_primary_secondary_and_disconnected_configuration(self):
        result = collect()
        interfaces = {row["name"]: row for row in result["interfaces"]}
        self.assertEqual(set(interfaces), set(ELIGIBLE_NAMES))
        self.assertEqual(interfaces["GigabitEthernet0/0"]["vrf"], "Mgmt-vrf")
        self.assertEqual(interfaces["GigabitEthernet0/0"]["ipv4"], [])
        self.assertEqual(interfaces["GigabitEthernet2/0/1"]["vrf"], "CORP")
        self.assertEqual(interfaces["Port-channel1.99"]["vrf"], "CORP")
        self.assertEqual(
            interfaces["GigabitEthernet1/0/1"]["ipv4"],
            [
                {
                    "address": "192.0.2.2",
                    "mask": "255.255.255.252",
                    "prefix_length": 30,
                    "secondary": False,
                    "method": "configured-static",
                },
                {
                    "address": "198.51.100.6",
                    "mask": "255.255.255.252",
                    "prefix_length": 30,
                    "secondary": True,
                    "method": "configured-static",
                },
            ],
        )
        self.assertEqual(interfaces["Loopback0"]["ipv4"][0]["prefix_length"], 32)
        self.assertEqual(interfaces["Port-channel1"]["ipv4"][0]["prefix_length"], 31)
        self.assertEqual(interfaces["Vlan3"]["ipv4"][0]["address"], "192.0.2.2")
        self.assertTrue(all(source["complete"] for source in result["sources"]))
        self.assertTrue(all(source["status"] == "available" for source in result["sources"]))
        self.assertTrue(
            all(row["source"]["revision"] == "2025-07-01" for row in result["interfaces"])
        )

    def test_unused_named_vrfs_are_retained_without_name_or_rd_inference(self):
        result = collect()
        vrfs = {row["name"]: row for row in result["vrfs"]}
        self.assertEqual(set(vrfs), {"Mgmt-vrf", "CORP", "UNUSED"})
        self.assertIsNone(vrfs["Mgmt-vrf"]["rd"])
        self.assertEqual(vrfs["CORP"]["rd"], "65000:20")
        self.assertEqual(vrfs["UNUSED"]["address_families"], ["ipv4"])
        self.assertIsNone(
            next(row for row in result["interfaces"] if row["name"] == "Loopback0")["vrf"]
        )

    def test_excluded_alias_and_internal_interface_remain_observation_only(self):
        result = collect()
        self.assertEqual(
            {row["name"] for row in result["excluded"]}, {row["name"] for row in EXCLUDED}
        )
        self.assertFalse(
            {row["name"] for row in result["excluded"]}
            & {row["name"] for row in result["interfaces"]}
        )
        self.assertTrue(all(row["reason"] for row in result["excluded"]))

    def test_dynamic_and_ipv6_are_observations_with_no_fabricated_addresses(self):
        result = collect()
        facts = {row["name"]: row for row in result["interfaces"]}
        self.assertEqual(facts["Vlan2"]["ipv4"], [])
        self.assertEqual(facts["Vlan2"]["addressing"]["ipv4_method"], "dhcp")
        self.assertEqual(facts["Vlan4"]["ipv4"], [])
        self.assertEqual(
            facts["Vlan4"]["ipv6"],
            [
                {
                    "configured_prefix": "2001:db8:4::2/64",
                    "method": "configured",
                    "eui_64": False,
                    "anycast": False,
                }
            ],
        )
        self.assertEqual({row["name"] for row in result["unresolved"]}, {"Vlan2", "Vlan4"})

    def test_unnumbered_and_negotiated_cannot_become_static_addresses(self):
        for method in ("unnumbered", "negotiated"):
            with self.subTest(method=method):
                values = fixture("iosxe_ipam_configured.json")
                rows(values)["Vlan"][1]["ip"] = (
                    {"unnumbered": "Loopback0"}
                    if method == "unnumbered"
                    else {"address": {"negotiated": [None]}}
                )
                result = collect(values)
                fact = next(row for row in result["interfaces"] if row["name"] == "Vlan3")
                self.assertEqual(fact["ipv4"], [])
                self.assertEqual(fact["addressing"]["ipv4_method"], method)

    def test_legacy_vrf_definition_and_structured_forwarding_word_are_supported(self):
        values = fixture("iosxe_ipam_configured.json")
        values["legacy_vrfs"] = {"Cisco-IOS-XE-native:vrf": [{"name": "LEGACY", "rd": "65000:99"}]}
        rows(values)["Vlan"][1]["ip"]["vrf"] = {"forwarding": {"word": "LEGACY"}}
        result = collect(values)
        self.assertEqual(
            next(row for row in result["interfaces"] if row["name"] == "Vlan3")["vrf"], "LEGACY"
        )
        self.assertEqual(
            next(row for row in result["vrfs"] if row["name"] == "LEGACY")["rd"], "65000:99"
        )

    def test_unknown_names_duplicates_and_vrf_joins_invalidate_the_whole_interface_source(self):
        for mutation in (
            "unknown-interface",
            "unknown-vrf",
            "duplicate-interface",
            "foreign-leaf",
            "qualified-collision",
            "symbolic-forwarding",
            "duplicate-vrf-reference",
        ):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                row = rows(values)["GigabitEthernet"][0]
                if mutation == "unknown-interface":
                    row["name"] = "7/0/999"
                elif mutation == "unknown-vrf":
                    row["vrf"]["forwarding"] = "unreported-vrf"
                elif mutation == "duplicate-interface":
                    rows(values)["GigabitEthernet"].append(deepcopy(row))
                elif mutation == "foreign-leaf":
                    row["vrf"]["foreign:forwarding"] = row["vrf"].pop("forwarding")
                elif mutation == "qualified-collision":
                    row[ipam.MODULE + ":name"] = row["name"]
                elif mutation == "symbolic-forwarding":
                    row.pop("vrf")
                    row["ip"] = {"vrf": {"forwarding": {"mgmtVrf": [None]}}}
                else:
                    row["ip-vrf"] = {"ip": {"vrf": {"forwarding": "Mgmt-vrf"}}}
                result = collect(values)
                self.assertEqual(result["interfaces"], [])
                self.assertEqual(result["excluded"], [])
                self.assertEqual(result["sources"][-1]["status"], "invalid")
                self.assertEqual(len(result["vrfs"]), 3)

    def test_malformed_excluded_rows_cannot_bypass_source_validation(self):
        values = fixture("iosxe_ipam_configured.json")
        rows(values)["TenGigabitEthernet"][0]["ip"] = {
            "address": {"primary": {"address": "not-an-ip", "mask": "255.255.255.0"}}
        }
        self.assertEqual(collect(values)["interfaces"], [])

    def test_ipv4_invalid_masks_sentinels_types_duplicate_hosts_and_secondary_flags(self):
        for mutation in (
            "noncontiguous-mask",
            "prefix-instead-of-mask",
            "zero-address",
            "multicast",
            "string-primary",
            "duplicate-host",
            "missing-secondary-flag",
            "mixed-methods",
        ):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                address = rows(values)["GigabitEthernet"][1]["ip"]["address"]
                if mutation == "noncontiguous-mask":
                    address["primary"]["mask"] = "255.0.255.0"
                elif mutation == "prefix-instead-of-mask":
                    address["primary"]["mask"] = "30"
                elif mutation == "zero-address":
                    address["primary"]["address"] = "0.0.0.0"
                elif mutation == "multicast":
                    address["primary"]["address"] = "224.0.0.1"
                elif mutation == "string-primary":
                    address["primary"] = "192.0.2.2/30"
                elif mutation == "duplicate-host":
                    address["secondary"][0]["address"] = address["primary"]["address"]
                elif mutation == "missing-secondary-flag":
                    address["secondary"][0].pop("secondary")
                else:
                    address["dhcp"] = {}
                result = collect(values)
                self.assertEqual(result["interfaces"], [])
                self.assertFalse(result["sources"][-1]["complete"])

    def test_numeric_interface_keys_require_the_yang_integer_type(self):
        for family, key in (
            ("Vlan", True),
            ("Vlan", "3"),
            ("Vlan", 4095),
            ("Loopback", -1),
            ("Port-channel", 513),
        ):
            with self.subTest(family=family, key=key):
                values = fixture("iosxe_ipam_configured.json")
                rows(values)[family][0]["name"] = key
                self.assertEqual(collect(values)["interfaces"], [])

    def test_duplicate_or_foreign_vrf_definitions_cannot_establish_identity(self):
        for mutation in ("duplicate-modern", "duplicate-across-sources", "foreign-rd"):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                definitions = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"]
                if mutation == "duplicate-modern":
                    definitions.append(deepcopy(definitions[0]))
                elif mutation == "duplicate-across-sources":
                    values["legacy_vrfs"]["Cisco-IOS-XE-native:vrf"] = [{"name": "CORP"}]
                else:
                    definitions[1]["foreign:rd"] = definitions[1].pop("rd")
                result = collect(values)
                self.assertEqual(result["vrfs"], [])
                self.assertEqual(result["interfaces"], [])
                self.assertTrue(result["unresolved"])

    def test_filtered_read_failures_never_retry_full_native_configuration(self):
        for status, expected in (
            (400, "unavailable"),
            (404, "unsupported"),
            (501, "unsupported"),
            (503, "unavailable"),
            (200, "invalid"),
            (None, "unavailable"),
        ):
            with self.subTest(status=status):
                values = fixture("iosxe_ipam_configured.json")
                values["interfaces"] = RestconfError("sensitive body omitted", status_code=status)
                client = FixtureClient(values)
                result = ipam.collect(
                    client,
                    [{"name": name} for name in ELIGIBLE_NAMES],
                    canonical_name=cisco.canonical_interface_name,
                    excluded_interfaces=EXCLUDED,
                )
                self.assertEqual(result["interfaces"], [])
                self.assertEqual(result["sources"][-1]["status"], expected)
                self.assertEqual(len(client.requests), 3)
                self.assertTrue(all("?fields=" in path for path, _kwargs in client.requests))
                self.assertTrue(
                    all(
                        kwargs == {"timeout": ipam.READ_TIMEOUT}
                        for _path, kwargs in client.requests
                    )
                )
                self.assertNotIn("sensitive", str(result))

    def test_empty_vrf_subtree_http_204_is_valid_absence(self):
        class EmptyLegacyClient(FixtureClient):
            def get(self, path, **kwargs):
                if path.startswith(ipam.LEGACY_VRF_PATH + "?"):
                    self.requests.append((path, kwargs))
                    self.trace.append({"path": path, "status": 204})
                    return None
                return super().get(path, **kwargs)

        result = ipam.collect(
            EmptyLegacyClient(),
            [{"name": name} for name in ELIGIBLE_NAMES],
            canonical_name=cisco.canonical_interface_name,
            excluded_interfaces=EXCLUDED,
        )
        source = next(
            source for source in result["sources"] if source["path"] == ipam.LEGACY_VRF_PATH
        )
        self.assertEqual(source["http_status"], 204)
        self.assertEqual(source["status"], "available")
        self.assertTrue(source["complete"])
        self.assertFalse(
            any(row["source"]["path"] == ipam.LEGACY_VRF_PATH for row in result["unresolved"])
        )
        self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))

    def test_real_transport_204_empty_objects_establish_only_vrf_absence(self):
        raw = fixture("iosxe_ipam_configured.json")
        # With no configured VRFs, the management interface has no named
        # membership. This leaves default-table static data independently valid.
        for family in raw["interfaces"]["Cisco-IOS-XE-native:interface"].values():
            rows = family if isinstance(family, list) else family["Port-channel"]
            for row in rows:
                row.pop("vrf", None)
                row.pop("ip-vrf", None)
        for empty_path in (ipam.VRF_PATH, ipam.LEGACY_VRF_PATH, ipam.INTERFACES_PATH):
            with self.subTest(empty_path=empty_path):
                with RestconfClient("switch.example.test", "test-user", "test-password") as client:
                    payloads = {
                        ipam.VRF_PATH: {"Cisco-IOS-XE-native:vrf": {}},
                        ipam.LEGACY_VRF_PATH: raw["legacy_vrfs"],
                        ipam.INTERFACES_PATH: raw["interfaces"],
                    }

                    def response(url, *, empty_response_path=empty_path, values=payloads, **kwargs):
                        path = url.removeprefix(client.base).split("?", 1)[0]
                        reply = requests.Response()
                        reply.status_code = 204 if path == empty_response_path else 200
                        reply.headers["Content-Type"] = "application/yang-data+json"
                        reply._content = (
                            b""
                            if path == empty_response_path
                            else json.dumps(values[path]).encode()
                        )
                        return reply

                    with patch.object(client.session, "get", side_effect=response) as get:
                        result = ipam.collect(
                            client,
                            [{"name": name} for name in ELIGIBLE_NAMES],
                            canonical_name=cisco.canonical_interface_name,
                            excluded_interfaces=EXCLUDED,
                        )
                    source = next(
                        source for source in result["sources"] if source["path"] == empty_path
                    )
                    self.assertEqual(source["http_status"], 204)
                    self.assertEqual(len(client.trace), 3)
                    self.assertEqual(get.call_count, 3)
                    self.assertTrue(all("?fields=" in call.args[0] for call in get.call_args_list))
                    if empty_path == ipam.INTERFACES_PATH:
                        self.assertFalse(source["complete"])
                        self.assertEqual(source["status"], "unavailable")
                        self.assertEqual(result["interfaces"], [])
                        self.assertEqual(result["unresolved"][0]["source"]["path"], empty_path)
                    else:
                        self.assertTrue(source["complete"])
                        self.assertEqual(source["status"], "available")
                        self.assertEqual(result["vrfs"], [])
                        self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))
                        self.assertFalse(
                            any(row["source"]["path"] == empty_path for row in result["unresolved"])
                        )

    def test_programming_errors_and_cancellation_are_not_optional_failures(self):
        for error in (KeyError("bug"), RuntimeError("bug"), ValueError("bug"), KeyboardInterrupt()):
            values = fixture("iosxe_ipam_configured.json")
            values["interfaces"] = error
            with self.assertRaises(type(error)):
                collect(values)

    def test_invalid_input_identities_fail_before_reads(self):
        client = FixtureClient()
        for interfaces, excluded in (
            ([{"name": "Gi0/0"}], []),
            ([{"name": "GigabitEthernet0/0"}] * 2, []),
            (
                [{"name": "GigabitEthernet0/0"}],
                [{"name": "GigabitEthernet0/0", "reason": "absent"}],
            ),
        ):
            with self.subTest(interfaces=interfaces, excluded=excluded):
                with self.assertRaises(ipam.IpamDiscoveryError):
                    ipam.collect(
                        client,
                        interfaces,
                        canonical_name=cisco.canonical_interface_name,
                        excluded_interfaces=excluded,
                    )
        self.assertEqual(client.requests, [])


if __name__ == "__main__":
    unittest.main()
