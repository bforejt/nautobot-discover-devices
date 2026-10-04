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
        if path.endswith("?fields=" + ipam.ROUTE_TARGET_FIELDS):
            key = "route_targets" if "route_targets" in self.payloads else key
        elif path.endswith("?fields=" + ipam.LEGACY_ROUTE_TARGET_FIELDS):
            key = "legacy_route_targets" if "legacy_route_targets" in self.payloads else key
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

    def test_dynamic_observed_and_literal_ipv6_is_eligible_without_fabricated_addresses(self):
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
        self.assertEqual({row["name"] for row in result["unresolved"]}, {"Vlan2"})

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

    def test_static_ipv6_and_named_generated_forms_keep_independent_ipv4_evidence(self):
        values = fixture("iosxe_ipam_configured.json")
        row = rows(values)["Vlan"][1]
        row["ipv6"] = {
            "address": {
                "prefix-list": [
                    {"prefix": "2001:0DB8:3::2/64"},
                    {"prefix": "fd00:3::2/127"},
                    {"prefix": "2001:db8:4::/64", "eui-64": [None]},
                    {"prefix": "2001:db8:5::2/64", "anycast": [None]},
                ],
                "prefix-name": [{"name": "DELEGATED", "ipv6-prefix": ["::2/64"]}],
                "link-local-address-container": {"address": "fe80::2", "link-local": [None]},
                "dhcp": {},
                "autoconfig": {},
            }
        }
        result = collect(values)
        fact = next(row for row in result["interfaces"] if row["name"] == "Vlan3")
        self.assertEqual(fact["ipv4"][0]["address"], "192.0.2.2")
        self.assertEqual(fact["ipv6"][0]["configured_prefix"], "2001:db8:3::2/64")
        self.assertEqual(fact["ipv6"][1]["configured_prefix"], "fd00:3::2/127")
        self.assertTrue(fact["ipv6"][2]["eui_64"])
        self.assertTrue(fact["ipv6"][3]["anycast"])
        self.assertEqual(fact["ipv6"][4]["method"], "configured-link-local")
        self.assertEqual(fact["ipv6"][5]["method"], "configured-named-prefix")
        self.assertEqual(fact["addressing"]["ipv6_methods"], {"dhcp": True, "autoconfig": True})
        notices = [row for row in result["unresolved"] if row.get("name") == "Vlan3"]
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["reason"], "DHCP/SLAAC IPv6 is observation-only")
        self.assertTrue(result["sources"][-1]["complete"])

    def test_complete_empty_route_target_policy_is_distinct_from_unavailable(self):
        result = collect()
        for row in result["vrfs"]:
            facts = row["route_targets"]
            self.assertEqual(facts["status"], "available")
            self.assertEqual(facts["import"], [])
            self.assertEqual(facts["export"], [])
            self.assertTrue(facts["source"]["complete"])
            self.assertEqual(facts["source"]["requested_fields"], ipam.ROUTE_TARGET_FIELDS)

    def test_modern_literal_targets_canonicalize_asn_ip_and_both_explicit_directions(self):
        values = fixture("iosxe_ipam_configured.json")
        definition = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
        definition["route-target"] = {
            "import": [
                {"asn-ip": "65000:20"},
                {"asn-ip": "1.10:23"},
                {"asn-ip": "192.0.2.1:77"},
            ],
            "export": [{"asn-ip": "65000:20"}, {"asn-ip": "65546:24"}],
        }
        result = collect(values)
        targets = next(row for row in result["vrfs"] if row["name"] == "CORP")["route_targets"]
        self.assertEqual(targets["status"], "available")
        self.assertEqual(targets["import"], ["192.0.2.1:77", "65000:20", "65546:23"])
        self.assertEqual(targets["export"], ["65000:20", "65546:24"])
        self.assertEqual(
            targets["address_family_policies"]["ipv4"], targets["address_family_policies"]["ipv6"]
        )

    def test_legacy_both_targets_preserve_import_and_export_direction(self):
        values = fixture("iosxe_ipam_configured.json")
        values["legacy_vrfs"] = {
            "Cisco-IOS-XE-native:vrf": [
                {
                    "name": "LEGACY",
                    "rd": "65000:99",
                    "route-target": [
                        {"direction": "both", "target": "65000:99"},
                        {"direction": "import", "target": "192.0.2.1:22"},
                        {"direction": "export", "target": "65000:100"},
                    ],
                }
            ]
        }
        targets = next(row for row in collect(values)["vrfs"] if row["name"] == "LEGACY")[
            "route_targets"
        ]
        self.assertEqual(targets["status"], "available")
        self.assertEqual(targets["import"], ["192.0.2.1:22", "65000:99"])
        self.assertEqual(targets["export"], ["65000:100", "65000:99"])
        self.assertEqual(targets["source"]["requested_fields"], ipam.LEGACY_ROUTE_TARGET_FIELDS)

    def test_identical_address_family_targets_use_reviewed_without_stitching_lists(self):
        values = fixture("iosxe_ipam_configured.json")
        definition = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
        for family in ("ipv4", "ipv6"):
            definition["address-family"][family]["route-target"] = {
                "import-route-target": {"without-stitching": [{"asn-ip": "65000:20"}]},
                "export-route-target": {"without-stitching": [{"asn-ip": "65000:21"}]},
            }
        targets = next(row for row in collect(values)["vrfs"] if row["name"] == "CORP")[
            "route_targets"
        ]
        self.assertEqual(targets["status"], "available")
        self.assertEqual(targets["import"], ["65000:20"])
        self.assertEqual(targets["export"], ["65000:21"])

    def test_family_differences_and_mixed_policy_cannot_be_flattened(self):
        for mutation in ("different-target", "missing-family-target", "mixed-common-target"):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                definition = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
                definition["address-family"]["ipv4"]["route-target"] = {
                    "import-route-target": {"without-stitching": [{"asn-ip": "65000:20"}]}
                }
                if mutation == "different-target":
                    definition["address-family"]["ipv6"]["route-target"] = {
                        "import-route-target": {"without-stitching": [{"asn-ip": "65000:21"}]}
                    }
                elif mutation == "mixed-common-target":
                    definition["route-target"] = {"import": [{"asn-ip": "65000:22"}]}
                result = collect(values)
                targets = next(row for row in result["vrfs"] if row["name"] == "CORP")[
                    "route_targets"
                ]
                self.assertEqual(targets["status"], "unresolved")
                self.assertEqual(targets["import"], [])
                self.assertEqual(targets["export"], [])
                self.assertTrue(result["interfaces"])

    def test_parallel_obsolete_and_current_af_representations_require_same_canonical_targets(self):
        for direction in ("import", "export"):
            for match in (True, False):
                with self.subTest(direction=direction, match=match):
                    values = fixture("iosxe_ipam_configured.json")
                    definition = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
                    for family in ("ipv4", "ipv6"):
                        definition["address-family"][family]["route-target"] = {
                            direction: [{"asn-ip": "65000:20"}],
                            direction + "-route-target": {
                                "without-stitching": [
                                    {"asn-ip": "065000:020" if match else "65000:21"}
                                ]
                            },
                        }
                    result = collect(values)
                    targets = next(row for row in result["vrfs"] if row["name"] == "CORP")[
                        "route_targets"
                    ]
                    if match:
                        self.assertEqual(targets["status"], "available")
                        self.assertEqual(targets[direction], ["65000:20"])
                    else:
                        self.assertEqual(targets["status"], "unresolved")
                        self.assertIn("representations differ", targets["reason"])
                        self.assertEqual(targets["import"], [])
                        self.assertEqual(targets["export"], [])
                        evidence = targets["configuration"]["address-family"]["ipv4"][
                            "route-target"
                        ]
                        self.assertEqual(evidence[direction][0]["asn-ip"], "65000:20")
                        self.assertEqual(
                            evidence[direction + "-route-target"]["without-stitching"][0]["asn-ip"],
                            "65000:21",
                        )
                    self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))

    def test_stitching_auto_unknown_and_invalid_encoded_targets_are_unresolved(self):
        for policy in (
            {"import": [{"asn-ip": "65000:20", "stitching": [None]}]},
            {"import": [{"asn-ip": "auto"}]},
            {"import": [{"asn-ip": "65000:4294967296"}]},
            {"import": [{"asn-ip": "65536:65536"}]},
            {"import": [{"asn-ip": "192.0.2.1:65536"}]},
            {"import": [{"asn-ip": "0.65000:20"}]},
            {"import": [{"asn-ip": "65000:20"}, {"asn-ip": "065000:020"}]},
            {"both": [{"asn-ip": "65000:20"}]},
        ):
            with self.subTest(policy=policy):
                values = fixture("iosxe_ipam_configured.json")
                values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]["route-target"] = policy
                result = collect(values)
                targets = next(row for row in result["vrfs"] if row["name"] == "CORP")[
                    "route_targets"
                ]
                self.assertEqual(targets["status"], "unresolved")
                self.assertEqual(targets["import"], [])
                self.assertEqual(targets["export"], [])
                self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))

    def test_af_stitching_and_vnid_do_not_create_plain_targets(self):
        for mutation in ("stitching", "vnid"):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                definition = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
                if mutation == "stitching":
                    definition["address-family"]["ipv4"]["route-target"] = {
                        "import-route-target": {
                            "with-stitching": [{"asn-ip": "65000:20", "stitching": [None]}]
                        }
                    }
                else:
                    definition["vnid"] = [{"vnid-value": 12345}]
                result = collect(values)
                self.assertEqual(
                    next(row for row in result["vrfs"] if row["name"] == "CORP")["route_targets"][
                        "status"
                    ],
                    "unresolved",
                )
                self.assertTrue(result["interfaces"])

    def test_incomplete_route_target_identity_or_family_projection_keeps_ipam_facts(self):
        for mutation in ("missing-vrf", "duplicate-vrf", "missing-family", "empty"):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                values["route_targets"] = deepcopy(values["vrfs"])
                definitions = values["route_targets"]["Cisco-IOS-XE-native:vrf"]["definition"]
                if mutation == "missing-vrf":
                    definitions.pop()
                elif mutation == "duplicate-vrf":
                    definitions.append(deepcopy(definitions[0]))
                elif mutation == "missing-family":
                    definitions[1]["address-family"].pop("ipv6")
                else:
                    values["route_targets"] = {"Cisco-IOS-XE-native:vrf": {}}
                result = collect(values)
                self.assertEqual(len(result["vrfs"]), 3)
                self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))
                targets = next(row for row in result["vrfs"] if row["name"] == "CORP")[
                    "route_targets"
                ]
                self.assertEqual(targets["status"], "unresolved")

    def test_optional_route_target_filter_failure_does_not_retry_or_erase_known_ips_vrfs(self):
        for status in (400, 404, 503):
            with self.subTest(status=status):
                values = fixture("iosxe_ipam_configured.json")
                values["route_targets"] = RestconfError("secret omitted", status_code=status)
                client = FixtureClient(values)
                result = ipam.collect(
                    client,
                    [{"name": name} for name in ELIGIBLE_NAMES],
                    canonical_name=cisco.canonical_interface_name,
                    excluded_interfaces=EXCLUDED,
                )
                self.assertEqual(len(result["vrfs"]), 3)
                self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))
                self.assertTrue(
                    all(row["route_targets"]["status"] == "unavailable" for row in result["vrfs"])
                )
                self.assertEqual(len(client.requests), 5)
                self.assertTrue(all("?fields=" in path for path, _kwargs in client.requests))
                self.assertNotIn("secret", str(result))

    def test_malformed_optional_target_values_defer_without_recursive_evidence_parse_failure(self):
        for mutation in ("null-target", "null-family", "null-families", "invalid-container"):
            with self.subTest(mutation=mutation):
                values = fixture("iosxe_ipam_configured.json")
                values["route_targets"] = deepcopy(values["vrfs"])
                definition = values["route_targets"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
                if mutation == "null-target":
                    definition["route-target"] = None
                elif mutation == "null-family":
                    definition["address-family"]["ipv4"] = None
                elif mutation == "null-families":
                    definition["address-family"] = None
                else:
                    definition["address-family"]["ipv4"] = "invalid"
                result = collect(values)
                self.assertEqual(len(result["vrfs"]), 3)
                self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))
                targets = next(row for row in result["vrfs"] if row["name"] == "CORP")[
                    "route_targets"
                ]
                self.assertEqual(targets["status"], "unresolved")
                self.assertEqual(targets["import"], [])
                self.assertEqual(targets["export"], [])

    def test_exact_reviewed_1791_native_schema_omits_known_absent_optional_vrf_fields(self):
        class Reviewed1791Client(FixtureClient):
            def get(self, path, **kwargs):
                if "rd-auto" in path or "vnid" in path:
                    raise RestconfError("Requested field is not in this schema", status_code=400)
                return super().get(path, **kwargs)

        values = fixture("iosxe_ipam_configured.json")
        values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]["route-target"] = {
            "import": [{"asn-ip": "65000:20"}]
        }
        client = Reviewed1791Client(values)
        result = ipam.collect(
            client,
            [{"name": name} for name in ELIGIBLE_NAMES],
            canonical_name=cisco.canonical_interface_name,
            excluded_interfaces=EXCLUDED,
            revisions={ipam.MODULE: "2022-07-01"},
        )
        self.assertEqual(len(result["vrfs"]), 3)
        self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))
        targets = next(row for row in result["vrfs"] if row["name"] == "CORP")["route_targets"]
        self.assertEqual(targets["status"], "available")
        self.assertEqual(targets["import"], ["65000:20"])
        self.assertEqual(targets["source"]["schema_profile"], "iosxe-1791-native-vrf-2022-07-01")
        self.assertIn("definition/vnid", targets["source"]["known_absent_fields"])
        self.assertEqual(len(client.requests), 5)
        self.assertFalse(any("rd-auto" in path or "vnid" in path for path, _kw in client.requests))

    def test_unknown_schema_revisions_do_not_inherit_known_absent_vrf_field_profile(self):
        for revision in (None, "2022-11-01", "2025-07-01"):
            with self.subTest(revision=revision):
                client = FixtureClient()
                result = ipam.collect(
                    client,
                    [{"name": name} for name in ELIGIBLE_NAMES],
                    canonical_name=cisco.canonical_interface_name,
                    excluded_interfaces=EXCLUDED,
                    revisions={ipam.MODULE: revision} if revision else None,
                )
                self.assertTrue(any("rd-auto" in path for path, _kw in client.requests))
                self.assertTrue(any("vnid" in path for path, _kw in client.requests))
                self.assertTrue(all("schema_profile" not in row for row in result["sources"]))

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

    def test_legacy_ipv4_forwarding_or_definition_cannot_establish_native_ipv6_vrf(self):
        for binding in ("legacy-forwarding", "legacy-ip-vrf", "legacy-definition"):
            with self.subTest(binding=binding):
                values = fixture("iosxe_ipam_configured.json")
                row = rows(values)["Vlan"][1]
                row["ipv6"] = {"address": {"prefix-list": [{"prefix": "2001:db8:3::2/64"}]}}
                if binding == "legacy-forwarding":
                    row["ip"]["vrf"] = {"forwarding": {"word": "CORP"}}
                elif binding == "legacy-ip-vrf":
                    row["ip-vrf"] = {"ip": {"vrf": {"forwarding": "CORP"}}}
                else:
                    values["legacy_vrfs"] = {
                        "Cisco-IOS-XE-native:vrf": [{"name": "LEGACY", "rd": "65000:99"}]
                    }
                    row["vrf"] = {"forwarding": "LEGACY"}
                result = collect(values)
                fact = next(row for row in result["interfaces"] if row["name"] == "Vlan3")
                self.assertEqual(fact["ipv4"][0]["address"], "192.0.2.2")
                self.assertEqual(fact["ipv6"][0]["configured_prefix"], "2001:db8:3::2/64")
                self.assertEqual(fact["addressing"]["ipv6_vrf_scope"], "unresolved-legacy-vrf")
                self.assertEqual(fact["ipv6_routing"]["status"], "unresolved")
                self.assertTrue(fact["ipv6_routing"]["source"]["complete"])
                self.assertTrue(fact["ipv6_routing"]["vrf_source"]["complete"])
                self.assertEqual(
                    fact["vrf"], "LEGACY" if binding == "legacy-definition" else "CORP"
                )

    def test_modern_vrf_binding_and_default_table_do_not_inherit_legacy_ipv6_deferral(self):
        result = collect()
        for name in ("Vlan4", "Vlan3"):
            fact = next(row for row in result["interfaces"] if row["name"] == name)
            self.assertNotIn("ipv6_vrf_scope", fact["addressing"])
            self.assertNotIn("ipv6_routing", fact)

    def test_complete_modern_vrf_without_ipv6_family_preserves_core_ipv4_and_ipv6_observation(self):
        values = fixture("iosxe_ipam_configured.json")
        definition = values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]
        definition["address-family"].pop("ipv6")
        rows(values)["Vlan"][2]["ip"] = {
            "address": {"primary": {"address": "10.40.0.2", "mask": "255.255.255.0"}}
        }
        result = collect(values)
        self.assertEqual(len(result["interfaces"]), len(ELIGIBLE_NAMES))
        fact = next(row for row in result["interfaces"] if row["name"] == "Vlan4")
        self.assertEqual(fact["ipv4"][0]["address"], "10.40.0.2")
        self.assertEqual(fact["ipv6"][0]["configured_prefix"], "2001:db8:4::2/64")
        self.assertEqual(fact["vrf"], "CORP")
        self.assertEqual(fact["addressing"]["ipv6_vrf_scope"], "unresolved-inactive-vrf-family")
        self.assertEqual(fact["ipv6_routing"]["binding"], "inactive-modern-vrf-family")
        self.assertTrue(fact["ipv6_routing"]["source"]["complete"])
        self.assertTrue(fact["ipv6_routing"]["vrf_source"]["complete"])
        self.assertEqual(result["sources"][-1]["status"], "available")

    def test_absent_modern_ipv6_family_does_not_claim_unresolved_ipv6_when_not_configured(self):
        values = fixture("iosxe_ipam_configured.json")
        values["vrfs"]["Cisco-IOS-XE-native:vrf"]["definition"][1]["address-family"].pop("ipv6")
        result = collect(values)
        fact = next(row for row in result["interfaces"] if row["name"] == "GigabitEthernet2/0/1")
        self.assertTrue(fact["ipv4"])
        self.assertEqual(fact["ipv6"], [])
        self.assertNotIn("ipv6_vrf_scope", fact["addressing"])

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
                self.assertEqual(len(client.requests), 5)
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
                    self.assertEqual(len(client.trace), 5)
                    self.assertEqual(get.call_count, 5)
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
