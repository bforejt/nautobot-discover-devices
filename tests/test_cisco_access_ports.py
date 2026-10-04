"""Physical access ports are confirmed hardware facts, separate from settings."""

import unittest
from copy import deepcopy

from tests._loader import fixture, load

access = load("adapters.cisco_access_ports")
RestconfError = load("transport_restconf").RestconfError


def management_interface(**overrides):
    return {
        "name": access.MANAGEMENT_INTERFACE,
        "type": "1000base-t",
        "type_source": "C9300-48UXM dedicated 1G copper management port",
        "enabled": False,
        "observations": {"oper_status": "if-oper-state-no-pass"},
        **overrides,
    }


class FakeClient:
    def __init__(self, updates=None):
        raw = fixture("iosxe_access_ports.json")
        self.payloads = {
            access.CONSOLE_PATH: raw["console_config"],
            access.MANAGEMENT_PATH: raw["management_config"],
            access.MANAGEMENT_OPER_PATH: raw["management_oper"],
            access.VRF_PATH: raw["vrf_config"],
        }
        self.payloads.update(updates or {})
        self.requests = []

    def get(self, path):
        self.requests.append(path)
        value = self.payloads[path.split("?", 1)[0]]
        if isinstance(value, BaseException):
            raise value
        return deepcopy(value)


def collect(client=None, interfaces=None, **kwargs):
    if interfaces is None:
        interfaces = [management_interface()]
    return access.collect(
        client or FakeClient(),
        interfaces,
        model=kwargs.get("model", access.MODEL),
        member=kwargs.get("member", 1),
    )


def native_row():
    return fixture("iosxe_access_ports.json")["management_config"][
        "Cisco-IOS-XE-native:GigabitEthernet"
    ][0]


class AccessPortCollectionTests(unittest.TestCase):
    def test_reviewed_profile_has_two_physical_connectors_and_confirmed_management(self):
        interfaces = [management_interface(), {"name": "Vlan2", "type": "virtual"}]
        console, management = collect(interfaces=interfaces)
        self.assertEqual(console["schema_version"], 1)
        self.assertEqual(
            [(item["key"], item["name"], item["type"], item["label"]) for item in console["items"]],
            [
                ("console:rj45", "Console RJ45", "rj-45", None),
                ("console:usb", "Console USB", "usb-mini-b", None),
            ],
        )
        for item in console["items"]:
            self.assertEqual(item["source"]["method"], "reviewed-hardware-profile")
            self.assertEqual(item["source"]["model"], access.MODEL)
            self.assertEqual(item["source"]["shared_logical_console"], "0")
            self.assertIn("Discovery-standardized", item["source"]["name_origin"])
            self.assertTrue(item["source"]["documents"])
        self.assertTrue(interfaces[0]["mgmt_only"])
        self.assertEqual(interfaces[0]["mgmt_only_source"]["value"], True)
        self.assertNotIn("mgmt_only", interfaces[1])
        self.assertEqual(management["interfaces"][0]["vrf"], "Mgmt-vrf")
        self.assertEqual(management["interfaces"][0]["ipv4"], [])
        self.assertEqual(management["interfaces"][0]["ipv6"], [])

    def test_consistent_explicit_console_speed_reports_one_baud(self):
        for extra in ({}, {"rxspeed": 9600, "txspeed": 9600}):
            with self.subTest(extra=extra):
                payload = {"console": [{"first": "0", "speed": 9600, **extra}]}
                console, _management = collect(FakeClient({access.CONSOLE_PATH: payload}))
                self.assertEqual(console["observations"]["console_line"]["baudrate"], 9600)

    def test_unreviewed_pid_member_or_boolean_member_never_inherits_hardware_profile(self):
        for kwargs in ({"model": "C9300-48P"}, {"member": 2}, {"member": True}, {"member": "1"}):
            with self.subTest(kwargs=kwargs):
                client = FakeClient()
                interfaces = [management_interface()]
                console, management = collect(client, interfaces, **kwargs)
                self.assertEqual(console["items"], [])
                self.assertEqual(management["interfaces"], [])
                self.assertTrue(console["unresolved"])
                self.assertNotIn("mgmt_only", interfaces[0])
                self.assertEqual(client.requests, [])

    def test_management_requires_an_unambiguous_observed_reviewed_port(self):
        for interfaces in (
            [],
            [management_interface(type="other")],
            [management_interface(type_source="operator template")],
            [management_interface(name="Vlan2")],
            [management_interface(), management_interface()],
        ):
            with self.subTest(interfaces=interfaces):
                console, management = collect(interfaces=deepcopy(interfaces))
                self.assertEqual(len(console["items"]), 2)
                self.assertEqual(management["interfaces"], [])
                self.assertTrue(management["unresolved"])
                self.assertTrue(all("mgmt_only" not in row for row in interfaces))

    def test_all_optional_queries_are_scoped_and_exclude_authentication_fields(self):
        client = FakeClient()
        collect(client)
        self.assertEqual(len(client.requests), 4)
        self.assertTrue(all("?fields=" in path for path in client.requests))
        self.assertEqual(
            next(path for path in client.requests if path.startswith(access.CONSOLE_PATH)),
            access.CONSOLE_PATH + "?fields=" + access.CONSOLE_FIELDS,
        )
        self.assertFalse(any("password" in path or "login" in path for path in client.requests))

    def test_optional_failure_never_masks_confirmed_inventory_or_retries_unfiltered(self):
        for status in (400, 403, 404, None):
            with self.subTest(status=status):
                client = FakeClient(
                    {
                        path: RestconfError("sensitive provider body", status)
                        for path in FakeClient().payloads
                    }
                )
                interfaces = [management_interface()]
                console, management = collect(client, interfaces)
                self.assertEqual(len(console["items"]), 2)
                self.assertTrue(interfaces[0]["mgmt_only"])
                self.assertEqual(len(console["unresolved"]), 1)
                self.assertEqual(len(management["unresolved"]), 3)
                self.assertEqual(management["interfaces"], [])
                self.assertEqual(len(client.requests), 4)
                self.assertNotIn("sensitive", str((console, management)))

    def test_cancellation_and_programming_errors_propagate(self):
        for error in (KeyboardInterrupt(), RuntimeError("implementation error")):
            with self.subTest(error=error):
                with self.assertRaises(type(error)):
                    collect(FakeClient({access.CONSOLE_PATH: error}))

    def test_malformed_or_missing_optional_sources_leave_confirmed_ports(self):
        for payload in (None, [], {}, {"Cisco-IOS-XE-native:console": None}):
            with self.subTest(payload=payload):
                console, _ = collect(FakeClient({access.CONSOLE_PATH: payload}))
                self.assertEqual(len(console["items"]), 2)
                self.assertNotIn("console_line", console["observations"])
                self.assertEqual(len(console["unresolved"]), 1)

    def test_console_omitted_speed_does_not_claim_factory_baud_or_active_connector(self):
        console, _ = collect()
        line = console["observations"]["console_line"]
        self.assertEqual(line["first"], "0")
        self.assertEqual(line["stopbits"], "1")
        self.assertIsNone(line["baudrate"])
        self.assertIsNone(line["media-type"])
        self.assertTrue(all("speed" not in item for item in console["items"]))

    def test_explicit_console_terminal_settings_stay_logical_line_observations(self):
        payload = {
            "Cisco-IOS-XE-native:console": [
                {
                    "first": "0",
                    "speed": 115200,
                    "rxspeed": 9600,
                    "txspeed": 19200,
                    "stopbits": "1.5",
                    "databits": {"set-to-8": [None]},
                    "parity": {"none": [None]},
                    "media-type": {"rj45": [None]},
                    "password": {"secret": "must not be copied"},
                }
            ]
        }
        console, _ = collect(FakeClient({access.CONSOLE_PATH: payload}))
        line = console["observations"]["console_line"]
        self.assertIsNone(line["baudrate"])
        self.assertEqual(line["databits"], "set-to-8")
        self.assertEqual(line["parity"], "none")
        self.assertEqual(line["media-type"], "rj45")
        self.assertNotIn("password", str(console))
        self.assertTrue(all("speed" not in item for item in console["items"]))

    def test_static_ipv4_preserves_configured_mask_and_secondary_role(self):
        row = native_row()
        row["ip"] = {
            "address": {
                "primary": {"address": "192.0.2.10", "mask": "255.255.255.0"},
                "secondary": [
                    {"address": "198.51.100.10", "mask": "255.255.255.128", "secondary": [None]}
                ],
            }
        }
        _, management = collect(
            FakeClient({access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}})
        )
        addresses = management["interfaces"][0]["ipv4"]
        self.assertEqual(
            [(v["address"], v["prefix_length"], v["secondary"]) for v in addresses],
            [("192.0.2.10", 24, False), ("198.51.100.10", 25, True)],
        )
        self.assertIn("Namespace", management["writes_deferred_reason"])

    def test_dhcp_and_negotiated_are_methods_without_fabricated_ip_addresses(self):
        for method, value in (("dhcp", {}), ("negotiated", [None])):
            with self.subTest(method=method):
                row = native_row()
                row["ip"] = {"address": {method: value}}
                _, management = collect(
                    FakeClient(
                        {access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}}
                    )
                )
                self.assertEqual(management["interfaces"][0]["ipv4"], [])
                self.assertEqual(management["interfaces"][0]["addressing"]["ipv4_method"], method)

    def test_invalid_mask_or_missing_address_evidence_does_not_propose_ip_facts(self):
        for address in (
            {"primary": {"address": "192.0.2.10"}},
            {"primary": {"address": "0.0.0.0", "mask": "0.0.0.0"}},
            {"primary": {"address": "192.0.2.10", "mask": "255.0.255.0"}},
            {"primary": {"address": "192.0.2.10", "mask": "0.0.0.255"}},
            {"dhcp": {}, "primary": {"address": "192.0.2.10", "mask": "255.255.255.0"}},
            {"secondary": [{"address": "192.0.2.10", "mask": "255.255.255.0"}]},
        ):
            with self.subTest(address=address):
                row = native_row()
                row["ip"] = {"address": address}
                interfaces = [management_interface()]
                _, management = collect(
                    FakeClient(
                        {access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}}
                    ),
                    interfaces,
                )
                self.assertEqual(management["interfaces"], [])
                self.assertTrue(management["unresolved"])
                self.assertTrue(interfaces[0]["mgmt_only"])

    def test_configured_ipv6_prefixes_eui64_and_linklocal_are_not_derived_host_masks(self):
        row = native_row()
        row["ipv6"] = {
            "address": {
                "prefix-list": [
                    {"prefix": "2001:db8:1::10/64"},
                    {"prefix": "2001:db8:2::/64", "eui-64": [None]},
                ],
                "link-local-address": [{"address": "fe80::10", "link-local": [None]}],
                "autoconfig": {},
            }
        }
        _, management = collect(
            FakeClient({access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}})
        )
        addresses = management["interfaces"][0]["ipv6"]
        self.assertEqual(addresses[0]["configured_prefix"], "2001:db8:1::10/64")
        self.assertTrue(addresses[1]["eui_64"])
        self.assertNotIn("address", addresses[1])
        self.assertEqual(addresses[2]["address"], "fe80::10")
        self.assertNotIn("prefix_length", addresses[2])
        self.assertTrue(management["interfaces"][0]["addressing"]["ipv6_methods"]["autoconfig"])

    def test_missing_ipv6_prefix_length_is_not_assumed_to_be_128(self):
        row = native_row()
        row["ipv6"] = {"address": {"prefix-list": [{"prefix": "2001:db8::10"}]}}
        _, management = collect(
            FakeClient({access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}})
        )
        self.assertEqual(management["interfaces"], [])
        self.assertTrue(management["unresolved"])

    def test_present_null_does_not_claim_missing_configuration(self):
        for field, value in (
            ("vrf", None),
            ("ip", {"address": None}),
            ("ipv6", {"address": {"prefix-list": None}}),
        ):
            with self.subTest(field=field, value=value):
                row = native_row()
                row[field] = value
                _, management = collect(
                    FakeClient(
                        {access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}}
                    )
                )
                self.assertEqual(management["interfaces"], [])
                self.assertTrue(management["unresolved"])

    def test_named_ipv6_prefix_does_not_discard_known_literal_or_ipv4_configuration(self):
        row = native_row()
        row["ip"] = {"address": {"primary": {"address": "192.0.2.2", "mask": "255.255.255.0"}}}
        row["ipv6"] = {
            "address": {
                "prefix-list": [{"prefix": "2001:0DB8::2/64"}],
                "prefix-name": [{"name": "EXAMPLE", "ipv6-prefix": ["::2/64"]}],
            }
        }
        _, management = collect(
            FakeClient({access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}})
        )
        facts = management["interfaces"][0]
        self.assertEqual(facts["ipv4"][0]["address"], "192.0.2.2")
        self.assertEqual(facts["ipv6"][0]["configured_prefix"], "2001:db8::2/64")
        self.assertEqual(facts["ipv6"][1]["method"], "configured-named-prefix")
        self.assertEqual(facts["ipv6"][1]["prefix_name"], "EXAMPLE")
        self.assertNotIn("configured_prefix", facts["ipv6"][1])

    def test_1718_linklocal_container_retains_scope_without_inventing_mask(self):
        row = native_row()
        row["ipv6"] = {
            "address": {
                "link-local-address-container": {"address": "fe80::2", "link-local": [None]}
            }
        }
        _, management = collect(
            FakeClient({access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}})
        )
        self.assertEqual(
            management["interfaces"][0]["ipv6"],
            [{"address": "fe80::2", "method": "configured-link-local"}],
        )

    def test_malformed_ipv6_addresses_duplicates_and_linklocal_scope_cannot_drive_writes(self):
        values = (
            {"prefix-list": [{"prefix": "ff02::1/64"}]},
            {"prefix-list": [{"prefix": "2001:db8::1%eth0/64"}]},
            {"prefix-list": [{"prefix": "2001:db8::1/64"}] * 2},
            {"link-local-address-container": {"address": "2001:db8::2", "link-local": [None]}},
            {"link-local-address-container": {"address": "fe80::2"}},
            {
                "link-local-address": [{"address": "fe80::2", "link-local": [None]}],
                "link-local-address-container": {"address": "fe80::2", "link-local": [None]},
            },
        )
        for value in values:
            with self.subTest(value=value):
                row = native_row()
                row["ipv6"] = {"address": value}
                _, management = collect(
                    FakeClient(
                        {access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]}}
                    )
                )
                self.assertEqual(management["interfaces"], [])
                self.assertTrue(management["unresolved"])

    def test_operational_unavailable_values_are_retained_as_observations_only(self):
        _, management = collect()
        self.assertEqual(management["observations"]["operational"]["ipv4"], "0.0.0.0")
        self.assertEqual(management["observations"]["operational"]["ipv4-subnet-mask"], "0.0.0.0")
        self.assertEqual(management["interfaces"][0]["ipv4"], [])
        self.assertNotIn("primary_ip", management)

    def test_vrf_definition_matches_actual_configured_name_without_a_default_name(self):
        row = native_row()
        row["vrf"]["forwarding"] = "OOB-EXAMPLE"
        vrfs = {
            "Cisco-IOS-XE-native:vrf": {
                "definition": [
                    {"name": "Mgmt-vrf", "address-family": {"ipv4": {}}},
                    {
                        "name": "OOB-EXAMPLE",
                        "rd": "64512:123",
                        "address-family": {"ipv4": {}, "ipv6": {}},
                    },
                ]
            }
        }
        _, management = collect(
            FakeClient(
                {
                    access.MANAGEMENT_PATH: {"Cisco-IOS-XE-native:GigabitEthernet": [row]},
                    access.VRF_PATH: vrfs,
                }
            )
        )
        self.assertEqual(management["interfaces"][0]["vrf"], "OOB-EXAMPLE")
        self.assertEqual(
            management["observations"]["vrf_configuration"]["definitions"],
            [{"name": "OOB-EXAMPLE", "rd": "64512:123", "address_families": ["ipv4", "ipv6"]}],
        )

    def test_ambiguous_identity_or_wrong_yang_namespace_remains_unresolved(self):
        for payload in (
            {"bad-module:console": [{"first": "0"}]},
            {"console": [{"first": "0"}], "Cisco-IOS-XE-native:console": [{"first": "0"}]},
            {"console": [{"first": "1", "speed": 9600}]},
            {"console": [{"first": "0"}, {"first": "0"}]},
        ):
            with self.subTest(payload=payload):
                console, _ = collect(FakeClient({access.CONSOLE_PATH: payload}))
                self.assertEqual(len(console["items"]), 2)
                self.assertNotIn("console_line", console["observations"])
                self.assertTrue(console["unresolved"])

    def test_revisions_annotate_existing_safe_sources_without_more_queries(self):
        interfaces = [management_interface()]
        client = FakeClient()
        console, management = collect(client, interfaces)
        requests = list(client.requests)
        access.add_revisions(
            console,
            management,
            interfaces,
            {
                "Cisco-IOS-XE-device-hardware-oper": "2023-01-01",
                "Cisco-IOS-XE-native": "2023-07-01",
                "Cisco-IOS-XE-interfaces-oper": "2023-07-01",
            },
        )
        self.assertEqual(console["items"][0]["source"]["revision"], "2023-01-01")
        self.assertEqual(interfaces[0]["mgmt_only_source"]["revision"], "2023-01-01")
        self.assertEqual(management["interfaces"][0]["source"]["revision"], "2023-07-01")
        self.assertEqual(client.requests, requests)


if __name__ == "__main__":
    unittest.main()
