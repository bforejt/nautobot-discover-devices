"""Explicit mappings require scoped existing objects and never infer targets."""

import json
import unittest
from unittest.mock import Mock

from tests._loader import load

policy = load("panos_ipam_policy")


class PanosIpamPolicyTests(unittest.TestCase):
    def setUp(self):
        self.resolver = Mock(side_effect=self.resolve)

    def resolve(self, kind, identifier, namespace_id):
        if kind == "namespace":
            return {"id": "ns-" + identifier, "name": identifier, "private_field": "discard"}
        return {"id": "vrf-" + identifier, "name": identifier, "namespace_id": namespace_id}

    def row(self, **values):
        return {
            "vsys": "vsys1",
            "virtual_router": "router-a",
            "namespace": "Lab",
            "vrf": None,
            **values,
        }

    def normalize(self, rows, **options):
        return policy.normalize_panos_ipam_policy(json.dumps(rows), self.resolver, **options)

    def test_blank_mapping_is_report_only_without_resolver_reads(self):
        self.assertIsNone(policy.normalize_panos_ipam_policy("\n", self.resolver))
        self.resolver.assert_not_called()

    def test_global_routing_requires_explicit_null_and_retains_exact_source_scope(self):
        result = self.normalize([self.row()])
        binding = result["panos_routing_domains"][0]
        self.assertEqual(binding["virtual_router"], "router-a")
        self.assertIsNone(binding["vrf"])
        self.assertEqual(binding["namespace"], {"id": "ns-Lab", "name": "Lab"})
        self.assertFalse(result["group_user_vrfs"])
        self.assertNotIn("discard", str(result))

    def test_named_vrf_is_resolved_inside_selected_namespace(self):
        result = self.normalize([self.row(vrf="Selected VRF")])
        self.resolver.assert_any_call("vrf", "Selected VRF", "ns-Lab")
        self.assertEqual(result["panos_routing_domains"][0]["vrf"]["name"], "Selected VRF")

    def test_source_labels_are_opaque_within_the_reviewed_source_bound(self):
        name = "Routing domain " + "x" * 500
        result = self.normalize([self.row(virtual_router=name)])
        self.assertEqual(result["panos_routing_domains"][0]["virtual_router"], name)
        with self.assertRaises(ValueError):
            self.normalize([self.row(virtual_router="x" * 1025)])

    def test_multiple_domains_are_sorted_without_namespace_fallback(self):
        result = self.normalize([self.row(vsys="vsys2", namespace="B"), self.row(namespace="A")])
        self.assertEqual(
            [row["vsys"] for row in result["panos_routing_domains"]], ["vsys1", "vsys2"]
        )
        self.assertEqual(
            [row["namespace"]["name"] for row in result["panos_routing_domains"]], ["A", "B"]
        )

    def test_missing_vrf_does_not_implicitly_select_global_routing(self):
        row = self.row()
        del row["vrf"]
        with self.assertRaises(ValueError):
            self.normalize([row])
        self.resolver.assert_not_called()

    def test_repeated_scope_and_json_keys_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "repeat"):
            self.normalize([self.row(), self.row(namespace="Other")])
        raw = '[{"vsys":"vsys1","vsys":"vsys2","virtual_router":"a","namespace":"Lab","vrf":null}]'
        with self.assertRaisesRegex(ValueError, "duplicate"):
            policy.normalize_panos_ipam_policy(raw, self.resolver)

    def test_invalid_structure_and_identifier_are_not_resolved(self):
        for rows in (
            None,
            {},
            [],
            [None],
            [self.row(namespace=True)],
            [self.row(vsys=" vsys1")],
            [self.row(extra="unsupported")],
        ):
            self.resolver.reset_mock()
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.normalize(rows)
            self.resolver.assert_not_called()
        for raw in (True, None, "[invalid", "x" * (1024 * 1024 + 1)):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(ValueError):
                policy.normalize_panos_ipam_policy(raw, self.resolver)

    def test_cross_namespace_vrf_and_missing_existing_target_are_rejected(self):
        for response in (None, {"id": "vrf-1", "name": "VRF", "namespace_id": "other"}):
            self.resolver.side_effect = [self.resolve("namespace", "Lab", None), response]
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.normalize([self.row(vrf="VRF")])

    def test_prefix_creation_and_location_are_explicit_policy(self):
        result = self.normalize([self.row()], create_missing_prefixes=False, location={"id": "loc"})
        self.assertFalse(result["create_missing_prefixes"])
        self.assertEqual(result["location"], {"id": "loc"})
        with self.assertRaises(ValueError):
            self.normalize([self.row()], create_missing_prefixes="true")


if __name__ == "__main__":
    unittest.main()
