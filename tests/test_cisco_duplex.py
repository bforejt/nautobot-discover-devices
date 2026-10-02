"""Configured copper duplex is independent of negotiated duplex and link state."""

import unittest
from copy import deepcopy

from tests._loader import load

duplex = load("adapters.cisco_duplex")
cisco = load("adapters.cisco_iosxe")


class Client:
    def __init__(self, payload, error=None):
        self.payload, self.error = payload, error
        self.requests = []

    def get(self, path):
        self.requests.append(path)
        if self.error:
            raise duplex.RestconfError(
                "Untrusted response body is not retained", status_code=self.error
            )
        return deepcopy(self.payload)


def native(*rows, family="TwoGigabitEthernet"):
    return {"Cisco-IOS-XE-native:interface": {family: list(rows)}}


def interface(name="TwoGigabitEthernet1/0/1", type_="2.5gbase-t"):
    return {
        "name": name,
        "type": type_,
        "duplex": None,
        "observations": {
            "oper_status": "if-oper-state-lower-layer-down",
            "negotiated_duplex": "full-duplex",
            "auto_negotiate": False,
        },
    }


class ConfiguredDuplexTests(unittest.TestCase):
    def collect(self, payload=None, interfaces=None, **kwargs):
        warnings = []
        rows = interfaces if interfaces is not None else [interface()]
        client = kwargs.pop(
            "client", Client(payload if payload is not None else native({"name": "1/0/1"}))
        )
        result = duplex.collect(
            client,
            rows,
            model=kwargs.pop("model", "C9300-48UXM"),
            software_version=kwargs.pop("version", "17.12.08"),
            member=kwargs.pop("member", 1),
            canonical_name=cisco.canonical_interface_name,
            warnings=warnings,
            **kwargs,
        )
        return result, rows, warnings, client

    def test_down_port_complete_config_default_is_auto_not_negotiated_full(self):
        result, rows, warnings, client = self.collect()
        self.assertEqual(rows[0]["duplex"], "auto")
        self.assertEqual(rows[0]["observations"]["negotiated_duplex"], "full-duplex")
        source = rows[0]["duplex_source"]
        self.assertEqual(source["basis"], "documented-default")
        self.assertTrue(source["complete"])
        self.assertEqual(source["defaults"]["model"], "C9300-48UXM")
        self.assertEqual(source["defaults"]["software_family"], "17.12")
        self.assertTrue(all("17-12" in url for url in source["defaults"]["documents"]))
        self.assertEqual(result["unresolved"], [])
        self.assertEqual(warnings, [])
        self.assertEqual(client.requests, [duplex.NATIVE_PATH + "?fields=" + duplex.NATIVE_FIELDS])

    def test_explicit_configured_values_do_not_require_default_profile_or_up_link(self):
        for value in ("auto", "full", "half"):
            with self.subTest(value=value):
                result, rows, _, _ = self.collect(
                    native({"name": "1/0/47", "duplex": value}, family="TenGigabitEthernet"),
                    [interface("TenGigabitEthernet1/0/47", "10gbase-t")],
                    model="reviewed-other-hardware",
                    version="17.15.06",
                )
                self.assertEqual(rows[0]["duplex"], value)
                self.assertEqual(rows[0]["duplex_source"]["basis"], "explicit")
                self.assertNotIn("defaults", rows[0]["duplex_source"])
                self.assertEqual(result["unresolved"], [])

    def test_management_gigabit_has_reviewed_default_on_member1(self):
        _, rows, _, _ = self.collect(
            native({"name": "0/0"}, family="GigabitEthernet"),
            [interface("GigabitEthernet0/0", "1000base-t")],
            version="17.9.06",
        )
        self.assertEqual(rows[0]["duplex"], "auto")
        self.assertTrue(
            all("17-9" in url for url in rows[0]["duplex_source"]["defaults"]["documents"])
        )

    def test_defaults_require_reviewed_model_release_member_and_exact_port_capability(self):
        for kwargs in (
            {"model": "C9300-24T"},
            {"version": "17.15.06"},
            {"version": None},
            {"member": 2},
            {"member": True},
        ):
            with self.subTest(kwargs=kwargs):
                result, rows, _, _ = self.collect(**kwargs)
                self.assertIsNone(rows[0]["duplex"])
                self.assertEqual(len(result["unresolved"]), 1)
        for name, type_, family, suffix in (
            ("TenGigabitEthernet1/0/47", "10gbase-t", "TenGigabitEthernet", "1/0/47"),
            ("TwoGigabitEthernet2/0/1", "2.5gbase-t", "TwoGigabitEthernet", "2/0/1"),
            ("TwoGigabitEthernet1/0/37", "2.5gbase-t", "TwoGigabitEthernet", "1/0/37"),
            ("TwoGigabitEthernet1/0/1", "1000base-t", "TwoGigabitEthernet", "1/0/1"),
            ("GigabitEthernet1/1/1", "1000base-t", "GigabitEthernet", "1/1/1"),
        ):
            with self.subTest(name=name, type_=type_):
                _, rows, _, _ = self.collect(
                    native({"name": suffix}, family=family), [interface(name, type_)]
                )
                self.assertIsNone(rows[0]["duplex"])

    def test_only_supported_normalized_copper_types_get_explicit_settings(self):
        for type_ in ("100base-tx", "1000base-t", "2.5gbase-t", "5gbase-t", "10gbase-t"):
            with self.subTest(type_=type_):
                _, rows, _, _ = self.collect(
                    native({"name": "1/0/1", "duplex": "full"}), [interface(type_=type_)]
                )
                self.assertEqual(rows[0]["duplex"], "full")
        for type_ in (
            None,
            "other",
            "virtual",
            "lag",
            "1000base-x-sfp",
            "10gbase-x-sfpp",
            "ieee802.11ac",
        ):
            with self.subTest(type_=type_):
                result, rows, _, _ = self.collect(
                    native({"name": "1/0/1", "duplex": "full"}), [interface(type_=type_)]
                )
                self.assertIsNone(rows[0]["duplex"])
                self.assertEqual(result["interfaces"], [])

    def test_unavailable_incomplete_and_missing_rows_do_not_establish_defaults(self):
        for payload in (
            {},
            {"wrong-envelope": {}},
            {"Cisco-IOS-XE-native:interface": {}},
            native({"name": "1/0/2"}),
        ):
            with self.subTest(payload=payload):
                result, rows, _, _ = self.collect(client=Client(payload))
                self.assertIsNone(rows[0]["duplex"])
                self.assertEqual(len(result["unresolved"]), 1)
        result, rows, warnings, _ = self.collect(client=Client(None, error=404))
        self.assertIsNone(rows[0]["duplex"])
        self.assertFalse(result["source"]["complete"])
        self.assertEqual(len(warnings), 1)
        self.assertNotIn("Untrusted", str(warnings))

    def test_filter400_retries_same_endpoint_without_retaining_unrelated_data(self):
        class Filter(Client):
            def get(self, path):
                if "?fields=" in path:
                    self.requests.append(path)
                    raise duplex.RestconfError("filter rejected", status_code=400)
                return super().get(path)

        result, rows, warnings, client = self.collect(
            client=Filter(native({"name": "1/0/1", "unrelated-secret": "DO-NOT-RETAIN"}))
        )
        self.assertEqual(rows[0]["duplex"], "auto")
        self.assertEqual(result["source"]["request"], duplex.NATIVE_PATH)
        self.assertEqual(client.requests[-1], duplex.NATIVE_PATH)
        self.assertEqual(len(warnings), 1)
        self.assertNotIn("DO-NOT-RETAIN", str(result) + str(rows))

    def test_malformed_native_objects_and_values_block_collection(self):
        for payload in (
            {"Cisco-IOS-XE-native:interface": []},
            {"Cisco-IOS-XE-native:interface": {"TwoGigabitEthernet": None}},
            {"Cisco-IOS-XE-native:interface": {"TwoGigabitEthernet": {"name": "1/0/1"}}},
            {"Cisco-IOS-XE-native:interface": {"TwoGigabitEthernet": ["unstructured"]}},
            native({"name": True}),
            native({"name": "Tw1/0/1"}),
            native({"name": "1/0/1", "duplex": "full-duplex"}),
            native({"name": "1/0/1", "duplex": None}),
            native({"name": "1/0/1", "duplex": True}),
            native({"name": "1/0/1", "duplex": {"auto": True}}),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(duplex.DuplexDiscoveryError):
                    self.collect(payload)

    def test_namespace_or_canonical_identity_ambiguity_blocks_collection(self):
        for payload in (
            {"interface": {}, "Cisco-IOS-XE-native:interface": {}},
            {
                "Cisco-IOS-XE-native:interface": {
                    "TwoGigabitEthernet": [],
                    "other:TwoGigabitEthernet": [],
                }
            },
            native({"name": "1/0/1", "other:name": "1/0/1"}),
            native({"name": "1/0/1", "duplex": "auto", "other:duplex": "auto"}),
            native({"name": "1/0/1"}, {"name": "1/0/1"}),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(duplex.DuplexDiscoveryError):
                    self.collect(payload)
        with self.assertRaises(duplex.DuplexDiscoveryError):
            self.collect(interfaces=[interface(), interface()])

    def test_revision_is_added_to_both_report_and_interface_provenance(self):
        result, rows, _, _ = self.collect()
        duplex.add_revisions(result, {"Cisco-IOS-XE-ethernet": "2023-07-01"})
        self.assertEqual(result["source"]["revision"], "2023-07-01")
        self.assertEqual(rows[0]["duplex_source"]["revision"], "2023-07-01")

    def test_qualified_ethernet_augmentation_is_requested_and_parsed(self):
        _, rows, _, client = self.collect(
            native({"name": "1/0/1", "Cisco-IOS-XE-ethernet:duplex": "full"})
        )
        self.assertEqual(rows[0]["duplex"], "full")
        self.assertEqual(rows[0]["duplex_source"]["module"], "Cisco-IOS-XE-ethernet")
        self.assertIn("Cisco-IOS-XE-ethernet:duplex", client.requests[0])

    def test_expected_native_namespaces_are_accepted_with_ethernet_duplex(self):
        payload = {
            "Cisco-IOS-XE-native:interface": {
                "Cisco-IOS-XE-native:TwoGigabitEthernet": [
                    {
                        "Cisco-IOS-XE-native:name": "1/0/1",
                        "Cisco-IOS-XE-ethernet:duplex": "full",
                    }
                ]
            }
        }
        _, rows, _, _ = self.collect(payload)
        self.assertEqual(rows[0]["duplex"], "full")
        self.assertEqual(rows[0]["duplex_source"]["basis"], "explicit")

    def test_unexpected_namespaces_cannot_supply_values_or_trigger_defaults(self):
        for payload in (
            {"other:interface": {"TwoGigabitEthernet": [{"name": "1/0/1"}]}},
            {"interface": {"other:TwoGigabitEthernet": [{"name": "1/0/1"}]}},
            native({"other:name": "1/0/1"}),
            native({"name": "1/0/1", "other:duplex": "full"}),
            native({"name": "1/0/1", "Cisco-IOS-XE-native:duplex": "full"}),
            native({"name": "1/0/1", "other:duplex": None}),
        ):
            with self.subTest(payload=payload):
                rows = [interface()]
                with self.assertRaisesRegex(
                    duplex.DuplexDiscoveryError, "unexpected YANG namespace"
                ):
                    self.collect(payload, rows)
                self.assertIsNone(rows[0]["duplex"])
                self.assertNotIn("duplex_source", rows[0])


if __name__ == "__main__":
    unittest.main()
