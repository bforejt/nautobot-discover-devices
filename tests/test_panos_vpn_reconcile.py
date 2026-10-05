"""Native VPN planning from applied configuration, without optional ORM imports."""

import copy
import json
import unittest

from tests._loader import FIXTURES, load

planner = load("reconcile_panos_vpn")
configuration = load("adapters.panos_vpn_config")


def observed():
    return {
        "adapter": "panos",
        "observations": {
            "vpn": {
                "configuration": configuration.parse_vpn_configuration(
                    (FIXTURES / "panos_vpn_applied_network.xml").read_text()
                ),
                "runtime": {"ipsec_sas": [{"name": "unrelated:colon:peer", "state": "up"}]},
            }
        },
    }


def inventory():
    namespace = {"id": "namespace-id", "name": "Explicit"}
    choices = {
        "encryption_algorithm": ["AES-128-CBC", "AES-256-CBC", "3DES"],
        "integrity_algorithm": ["SHA1", "SHA256"],
        "dh_group": ["2", "14"],
    }
    row = {
        "tunnel": "lab-ipsec",
        "vpn_name": "Selected VPN",
        "tunnel_name": "Selected Tunnel",
        "profile_name": "Selected Profile",
        "status": {"id": "status-id", "name": "Active"},
        **{
            key: namespace
            for key in (
                "local_namespace",
                "remote_namespace",
                "local_protected_namespace",
                "remote_protected_namespace",
            )
        },
    }
    return {
        "device": {"id": "device-id", "name": "Selected Device"},
        "panos_vpn_inventory": {
            "supported": True,
            "policy": {"contract": "panos-vpn-policy-v1", "tunnels": [row]},
            "capabilities": {
                "VPNPhase1Policy": {
                    "choices": {**choices, "ike_version": ["IKEv1", "IKEv2"]},
                    "collections": ["encryption_algorithm", "integrity_algorithm", "dh_group"],
                },
                "VPNPhase2Policy": {
                    "choices": {**choices, "pfs_group": ["2", "14"]},
                    "collections": ["encryption_algorithm", "integrity_algorithm", "pfs_group"],
                },
                "VPN": {"fields": ["name", "vpn_profile", "service_type"]},
            },
            "catalog": {
                name: [{"id": "profile-id", "name": "Selected Profile"}]
                if name == "VPNProfile"
                else []
                for name in planner.MODELS
            },
            "interfaces": [
                {"id": "source-id", "name": "ethernet1/1", "device_id": "device-id"},
                {"id": "tunnel-id", "name": "tunnel.1", "device_id": "device-id"},
            ],
            "ip_addresses": [
                {
                    "id": "local-ip",
                    "host": "198.18.101.1",
                    "mask_length": 29,
                    "namespace_id": "namespace-id",
                },
                {
                    "id": "remote-ip",
                    "host": "198.18.101.3",
                    "mask_length": 29,
                    "namespace_id": "namespace-id",
                },
            ],
            "ip_assignments": [{"interface_id": "source-id", "ip_address_id": "local-ip"}],
            "prefixes": [
                {"id": "local-prefix", "prefix": "10.255.101.1/32", "namespace_id": "namespace-id"},
                {
                    "id": "remote-prefix",
                    "prefix": "10.255.103.1/32",
                    "namespace_id": "namespace-id",
                },
            ],
        },
    }


class PanosVpnReconcileTests(unittest.TestCase):
    def test_applied_catalog_and_explicit_endpoints_are_planned_without_mutation(self):
        discovery, existing = observed(), inventory()
        before = copy.deepcopy((discovery, existing))
        plan = planner.plan_panos_vpn(discovery, existing)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["unresolved"])
        self.assertEqual(plan["summary"]["vpn_objects_created"], 6)
        self.assertEqual(len(plan["assignments"]), 2)
        self.assertEqual(len(plan["prefix_assignments"]), 2)
        phase1 = next(row for row in plan["catalog"] if row["model"] == "VPNPhase1Policy")
        self.assertEqual(phase1["values"]["lifetime_seconds"], 28800)
        self.assertEqual(phase1["values"]["ike_version"], "IKEv2")
        remote = next(row for row in plan["catalog"] if row["name"].startswith("ip:"))
        self.assertNotIn("device", remote["relations"])
        self.assertNotIn("source_fqdn", remote["values"])
        self.assertEqual((discovery, existing), before)
        self.assertNotIn("unrelated:colon:peer", json.dumps(plan))

    def test_missing_optional_models_remain_report_only(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["supported"] = False
        plan = planner.plan_panos_vpn(observed(), existing)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["catalog"])
        self.assertEqual(plan["summary"]["unresolved_vpn"], 1)

    def test_no_policy_is_report_only(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["policy"] = None
        self.assertFalse(planner.plan_panos_vpn(observed(), existing)["catalog"])

    def test_missing_profile_does_not_guess_behavior_booleans(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["catalog"]["VPNProfile"] = []
        plan = planner.plan_panos_vpn(observed(), existing)
        self.assertFalse(plan["errors"])
        self.assertTrue(any("required keepalive" in row["reason"] for row in plan["unresolved"]))
        self.assertFalse(any(row["model"] == "VPNProfile" for row in plan["catalog"]))
        self.assertFalse(plan["assignments"])
        self.assertTrue(any(row["model"] == "VPNTunnel" for row in plan["catalog"]))
        self.assertTrue(all("vpn_profile" not in row["relations"] for row in plan["catalog"]))

    def test_exact_local_mask_and_assignment_are_required(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["ip_addresses"][0]["mask_length"] = 32
        plan = planner.plan_panos_vpn(observed(), existing)
        self.assertFalse(any(row["name"].startswith("local:") for row in plan["catalog"]))
        self.assertTrue(plan["unresolved"])

    def test_multiple_tunnels_keep_independent_endpoints_on_one_verified_wan(self):
        discovery, existing = observed(), inventory()
        tunnel = copy.deepcopy(
            discovery["observations"]["vpn"]["configuration"]["ipsec_tunnels"][0]
        )
        tunnel.update(name="second-ipsec", tunnel_interface="tunnel.2")
        discovery["observations"]["vpn"]["configuration"]["ipsec_tunnels"].append(tunnel)
        mapping = copy.deepcopy(existing["panos_vpn_inventory"]["policy"]["tunnels"][0])
        mapping.update(tunnel="second-ipsec", vpn_name="Second VPN", tunnel_name="Second Tunnel")
        existing["panos_vpn_inventory"]["policy"]["tunnels"].append(mapping)
        existing["panos_vpn_inventory"]["interfaces"].append(
            {"id": "second-tunnel-id", "name": "tunnel.2", "device_id": "device-id"}
        )
        plan = planner.plan_panos_vpn(discovery, existing)
        self.assertFalse(plan["errors"])
        second = next(
            row
            for row in plan["catalog"]
            if row["model"] == "VPNTunnel" and row["name"] == "Second Tunnel"
        )
        self.assertIn("endpoint_a", second["relations"])
        locals_ = [row for row in plan["catalog"] if row["name"].startswith("local:")]
        self.assertEqual(len(locals_), 2)
        self.assertEqual(
            {row["relations"]["tunnel_interface"]["id"] for row in locals_},
            {"tunnel-id", "second-tunnel-id"},
        )
        self.assertTrue(all("source_interface" not in row["relations"] for row in locals_))
        self.assertTrue(
            all(row["source_binding"]["source_interface_id"] == "source-id" for row in locals_)
        )
        self.assertFalse(plan["unresolved"])

    def test_no_pfs_is_exactly_empty_array_and_group14_is_preserved(self):
        discovery = observed()
        profile = next(
            row
            for row in discovery["observations"]["vpn"]["configuration"]["ipsec_crypto_profiles"]
            if row["name"] == "lab-ipsec-profile"
        )
        for source, expected in (("no-pfs", []), ("group14", ["14"])):
            profile["dh_group"] = source
            plan = planner.plan_panos_vpn(discovery, inventory())
            phase2 = next(row for row in plan["catalog"] if row["model"] == "VPNPhase2Policy")
            self.assertEqual(phase2["values"]["pfs_group"], expected)

    def test_native_scalar_algorithms_accept_only_one_explicit_value(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["capabilities"]["VPNPhase1Policy"]["collections"] = []
        plan = planner.plan_panos_vpn(observed(), existing)
        phase1 = next(row for row in plan["catalog"] if row["model"] == "VPNPhase1Policy")
        self.assertEqual(phase1["values"]["encryption_algorithm"], "AES-256-CBC")
        discovery = observed()
        profile = next(
            row
            for row in discovery["observations"]["vpn"]["configuration"]["ike_crypto_profiles"]
            if row["name"] == "lab-ike-profile"
        )
        profile["encryption"] = ["aes-128-cbc", "aes-256-cbc"]
        plan = planner.plan_panos_vpn(discovery, existing)
        self.assertFalse(plan["catalog"])
        self.assertTrue(plan["unresolved"])

    def test_crypto_lists_preserve_applied_order(self):
        discovery = observed()
        profile = next(
            row
            for row in discovery["observations"]["vpn"]["configuration"]["ike_crypto_profiles"]
            if row["name"] == "lab-ike-profile"
        )
        profile["encryption"] = ["3des", "aes-128-cbc", "aes-256-cbc"]
        plan = planner.plan_panos_vpn(discovery, inventory())
        phase1 = next(row for row in plan["catalog"] if row["model"] == "VPNPhase1Policy")
        self.assertEqual(
            phase1["values"]["encryption_algorithm"], ["3DES", "AES-128-CBC", "AES-256-CBC"]
        )

    def test_unknown_algorithm_defers_tunnel_without_guessing(self):
        discovery = observed()
        profile = next(
            row
            for row in discovery["observations"]["vpn"]["configuration"]["ike_crypto_profiles"]
            if row["name"] == "lab-ike-profile"
        )
        profile["encryption"] = ["future-encryption"]
        plan = planner.plan_panos_vpn(discovery, inventory())
        self.assertFalse(plan["catalog"])
        self.assertTrue(plan["unresolved"])

    def test_missing_local_ip_assignment_defers_only_endpoint(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["ip_assignments"] = []
        plan = planner.plan_panos_vpn(observed(), existing)
        tunnel = next(row for row in plan["catalog"] if row["model"] == "VPNTunnel")
        self.assertNotIn("endpoint_a", tunnel["relations"])
        self.assertIn("endpoint_z", tunnel["relations"])
        self.assertTrue(plan["unresolved"])

    def test_namespace_does_not_fall_back_from_matching_host(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["policy"]["tunnels"][0]["remote_namespace"] = None
        plan = planner.plan_panos_vpn(observed(), existing)
        self.assertFalse(any(row["name"].startswith("ip:") for row in plan["catalog"]))

    def test_missing_status_keeps_independent_catalog(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["policy"]["tunnels"][0]["status"] = None
        plan = planner.plan_panos_vpn(observed(), existing)
        self.assertTrue(any(row["model"] == "VPN" for row in plan["catalog"]))
        self.assertFalse(any(row["model"] == "VPNTunnel" for row in plan["catalog"]))

    def test_foreign_tunnel_interface_ownership_is_preserved(self):
        existing = inventory()
        existing["panos_vpn_inventory"]["catalog"]["VPNTunnelEndpoint"] = [
            {
                "id": "foreign-endpoint",
                "source_interface_id": "foreign-interface",
                "tunnel_interface_id": "tunnel-id",
                "device_id": "foreign-device",
            }
        ]
        plan = planner.plan_panos_vpn(observed(), existing)
        tunnel = next(row for row in plan["catalog"] if row["model"] == "VPNTunnel")
        self.assertNotIn("endpoint_a", tunnel["relations"])
        self.assertTrue(plan["unresolved"])

    def test_restricted_selectors_do_not_become_whole_prefixes(self):
        discovery = observed()
        discovery["observations"]["vpn"]["configuration"]["ipsec_tunnels"][0]["auto_key"][
            "selectors_ipv4"
        ][0]["protocol"]["kind"] = "tcp"
        plan = planner.plan_panos_vpn(discovery, inventory())
        self.assertFalse(plan["prefix_assignments"])
        self.assertTrue(plan["unresolved"])

    def test_unsupported_multi_gateway_version_and_mode_remain_unresolved(self):
        for mode in ("manual", "multi-gateway", "version"):
            discovery = observed()
            config = discovery["observations"]["vpn"]["configuration"]
            if mode == "manual":
                config["ipsec_tunnels"][0]["mode"] = "manual-key"
            elif mode == "multi-gateway":
                config["ipsec_tunnels"][0]["auto_key"]["ike_gateways"] += ["other"]
            else:
                config["ike_gateways"][0]["protocol"]["version"] = "ikev2-preferred"
            plan = planner.plan_panos_vpn(discovery, inventory())
            self.assertFalse(plan["catalog"])
            self.assertTrue(plan["unresolved"])

    def test_tampered_provenance_blocks_native_plan(self):
        discovery = observed()
        discovery["observations"]["vpn"]["configuration"]["sources"]["ipsec_tunnels"]["command"] = (
            "unreviewed"
        )
        self.assertTrue(planner.plan_panos_vpn(discovery, inventory())["errors"])


if __name__ == "__main__":
    unittest.main()
