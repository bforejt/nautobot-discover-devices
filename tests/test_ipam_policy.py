"""Operator Namespace routing rules never depend on inferred naming conventions."""

import unittest
from types import SimpleNamespace

from tests._loader import load

policy = load("ipam_policy")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.default = SimpleNamespace(pk="default-id", name="Any label")
        self.override = SimpleNamespace(pk="override-id", name="Another label")

    def test_blank_default_keeps_existing_job_report_only(self):
        self.assertIsNone(policy.normalize_ipam_policy(None))

    def test_override_union_is_explicit_and_names_do_not_define_purpose(self):
        result = policy.normalize_ipam_policy(
            self.default,
            self.override,
            override_networks="100.64.0.0/10\n198.51.100.0/24\n100.64.0.0/10",
        )
        self.assertEqual(result["default_namespace"]["id"], "default-id")
        self.assertTrue(result["override_rfc1918"])
        self.assertEqual(result["override_networks"], ["100.64.0.0/10", "198.51.100.0/24"])
        self.assertFalse(result["group_user_vrfs"])
        self.assertEqual(result["local_vrf_names"], ["Mgmt-vrf"])

    def test_same_namespace_is_supported(self):
        result = policy.normalize_ipam_policy(self.default, self.default)
        self.assertEqual(result["default_namespace"], result["override_namespace"])

    def test_unchecked_rfc1918_leaves_manual_exceptions(self):
        result = policy.normalize_ipam_policy(
            self.default,
            self.override,
            override_rfc1918=False,
            override_networks="100.64.0.0/10",
            local_vrf_names="Mgmt-vrf\nPRIVATE\nMgmt-vrf",
            group_user_vrfs=True,
        )
        self.assertFalse(result["override_rfc1918"])
        self.assertEqual(result["local_vrf_names"], ["Mgmt-vrf", "PRIVATE"])

    def test_invalid_inputs_fail_before_inventory_or_transport(self):
        for networks in (
            "192.0.2.1/24",
            "192.0.2.0",
            "2001:db8::1/64",
            "2001:db8::",
            "not-a-network",
        ):
            with self.subTest(networks=networks), self.assertRaises(ValueError):
                policy.normalize_ipam_policy(
                    self.default,
                    self.override,
                    override_networks=networks,
                )
        with self.assertRaises(ValueError):
            policy.normalize_ipam_policy(self.default, override_networks="100.64.0.0/10")
        with self.assertRaises(ValueError):
            policy.normalize_ipam_policy(None, self.override)
        for key in ("override_rfc1918", "create_missing_prefixes", "group_user_vrfs"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.normalize_ipam_policy(self.default, **{key: "true"})

    def test_manual_override_accepts_both_families_without_implicit_ula_policy(self):
        result = policy.normalize_ipam_policy(
            self.default,
            self.override,
            override_networks="fd00::/8, 100.64.0.0/10\n2001:DB8::/32\n2001:db8::/32",
        )
        self.assertEqual(
            result["override_networks"], ["100.64.0.0/10", "2001:db8::/32", "fd00::/8"]
        )
        self.assertTrue(result["override_rfc1918"])
