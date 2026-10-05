"""Prospective Interface ownership and combined IPAM graph regressions."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_ipam_reconcile import address, discovery, fact, inventory, ip, prefix

ipam = load("reconcile_ipam")


def prospective():
    return {
        "interface_creates": [{"name": "ethernet1/1", "type": "virtual", "enabled": True}],
        "interface_updates": [],
    }


def owned_inventory(*, persisted=False):
    existing = inventory()
    existing["interfaces"] = (
        [{"id": "selected-interface", "name": "ethernet1/1", "vrf_id": None}] if persisted else []
    )
    existing["ipam_inventory"]["prefixes"] = [prefix()]
    existing["ipam_inventory"]["ip_addresses"] = [ip()]
    return existing


def plan(existing, interface_plan=None):
    return ipam.plan_ipam(
        discovery(fact("ethernet1/1", addresses=[address()])),
        existing,
        interface_plan or prospective(),
        canonical_name=lambda name: name,
    )


class IpamOwnershipGuardTests(unittest.TestCase):
    def test_new_device_interface_does_not_adopt_a_vm_interface_assignment(self):
        existing = owned_inventory()
        existing["ipam_inventory"]["ip_assignments"] = [
            {
                "id": "foreign-vm-assignment",
                "ip_address_id": "ip-1",
                "interface_id": None,
                "interface_device_id": None,
                "vm_interface_id": "unrelated-vm-interface",
                "is_secondary": False,
            }
        ]
        before = deepcopy(existing)
        proposed = plan(existing)
        self.assertFalse(proposed["errors"])
        self.assertFalse(proposed["ip_addresses"])
        self.assertFalse(proposed["ip_assignments"])
        self.assertTrue(
            any("assigned elsewhere" in row["reason"] for row in proposed["unresolved"])
        )
        self.assertEqual(existing, before)

    def test_unknown_null_device_assignment_is_not_prospective_local_ownership(self):
        existing = owned_inventory()
        existing["ipam_inventory"]["ip_assignments"] = [
            {
                "id": "unresolved-owner",
                "ip_address_id": "ip-1",
                "interface_id": None,
                "interface_device_id": None,
                "vm_interface_id": None,
                "is_secondary": False,
            }
        ]
        proposed = plan(existing)
        self.assertFalse(proposed["ip_addresses"])
        self.assertFalse(proposed["ip_assignments"])
        self.assertTrue(
            any("assigned elsewhere" in row["reason"] for row in proposed["unresolved"])
        )

    def test_persisted_exact_selected_interface_assignment_remains_local(self):
        existing = owned_inventory(persisted=True)
        existing["ipam_inventory"]["ip_assignments"] = [
            {
                "id": "selected-assignment",
                "ip_address_id": "ip-1",
                "interface_id": "selected-interface",
                "interface_device_id": "device-1",
                "vm_interface_id": None,
                "is_secondary": False,
            }
        ]
        proposed = plan(existing, {"interface_creates": [], "interface_updates": []})
        self.assertFalse(proposed["errors"])
        self.assertFalse(proposed["unresolved"])
        self.assertEqual(proposed["ip_addresses"][0]["id"], "ip-1")
        self.assertFalse(proposed["ip_addresses"][0]["create"])
        self.assertFalse(proposed["ip_assignments"])

    def test_existing_local_assignment_does_not_hide_a_second_vm_owner(self):
        existing = owned_inventory(persisted=True)
        existing["ipam_inventory"]["ip_assignments"] = [
            {
                "id": "selected-assignment",
                "ip_address_id": "ip-1",
                "interface_id": "selected-interface",
                "interface_device_id": "device-1",
                "vm_interface_id": None,
                "is_secondary": False,
            },
            {
                "id": "foreign-vm-assignment",
                "ip_address_id": "ip-1",
                "interface_id": None,
                "interface_device_id": None,
                "vm_interface_id": "vm-interface",
                "is_secondary": False,
            },
        ]
        proposed = plan(existing, {"interface_creates": [], "interface_updates": []})
        self.assertFalse(proposed["ip_addresses"])
        self.assertTrue(
            any("assigned elsewhere" in row["reason"] for row in proposed["unresolved"])
        )

    def test_combined_management_and_routed_graph_uses_closest_staged_prefix(self):
        existing = inventory()
        existing["interfaces"] = [
            {"id": "routed", "name": "ethernet1/1", "vrf_id": None},
            {"id": "management", "name": "Management Interface", "vrf_id": None},
        ]
        existing["ipam_inventory"]["policy"].update(
            default_namespace={"id": "same", "name": "Same"},
            override_namespace=None,
            override_rfc1918=False,
        )
        interfaces = {"interface_creates": [], "interface_updates": []}
        combined = discovery(
            fact("ethernet1/1", addresses=[address("10.0.1.5", 16)]),
            fact("Management Interface", addresses=[address("10.0.1.10", 24)]),
        )
        untouched = deepcopy((combined, existing, interfaces))
        proposed = ipam.plan_ipam(
            combined,
            existing,
            interfaces,
            canonical_name=lambda name: name,
        )
        self.assertFalse(proposed["errors"])
        self.assertFalse(proposed["unresolved"])
        self.assertEqual((combined, existing, interfaces), untouched)
        prefixes = {row["key"]: row for row in proposed["prefixes"]}
        addresses = {row["host"]: row for row in proposed["ip_addresses"]}
        self.assertEqual(prefixes[addresses["10.0.1.5"]["parent_key"]]["prefix"], "10.0.1.0/24")
        self.assertEqual(prefixes[addresses["10.0.1.10"]["parent_key"]]["prefix"], "10.0.1.0/24")
        narrow = next(row for row in prefixes.values() if row["prefix"] == "10.0.1.0/24")
        self.assertEqual(prefixes[narrow["parent_key"]]["prefix"], "10.0.0.0/16")
        self.assertEqual(len(proposed["ip_assignments"]), 2)

    def test_reviewed_logical_creates_receive_panos_addresses_in_first_plan(self):
        from pathlib import Path

        from tests.test_panos_ipam_reconcile import existing, raw_discovery

        logical_parser = load("adapters.panos_logical")
        logical_planner = load("reconcile_panos_interfaces")
        panos_ipam = load("reconcile_panos_ipam")
        observed = raw_discovery()
        observed["logical_interfaces"] = logical_parser.parse_logical_interfaces(
            (Path(__file__).with_name("fixtures") / "panos_ipam_network.xml").read_text()
        )
        before = existing(observed)
        before["device"] = {"id": "device-1", "name": "panos-lab"}
        before["interfaces"] = [
            {**row, "device_id": "device-1", "module_id": None, "type": "virtual", "enabled": True}
            for row in before["interfaces"]
            if row["name"].startswith("ethernet") and "." not in row["name"]
        ]
        before["panos_interface_inventory"] = {
            "supported": True,
            "capabilities": {
                "types": ["virtual", "lag", "tunnel"],
                "parent_interface": True,
                "lag": True,
            },
            "interfaces": [],
        }
        logical = logical_planner.plan_panos_interfaces(observed, before, identity_verified=True)
        self.assertFalse(logical["errors"])
        self.assertEqual(len(logical["creates"]), 6)
        interface_plan = {
            "interface_creates": logical["creates"],
            "interface_updates": logical["updates"],
        }
        untouched = deepcopy((observed, before, interface_plan))
        proposed = panos_ipam.plan_panos_ipam(observed, before, interface_plan)
        self.assertFalse(proposed["errors"])
        self.assertFalse(proposed["unresolved"])
        self.assertEqual(
            {row["name"] for row in proposed["ip_assignments"]},
            {"ethernet1/1", "ethernet1/1.100", "ae1", "ae1.200", "loopback.1", "tunnel.1"},
        )
        self.assertEqual(proposed["summary"]["ip_addresses_created"], 12)
        self.assertEqual((observed, before, interface_plan), untouched)

    def test_unreviewed_logical_create_does_not_unlock_panos_ipam(self):
        from tests.test_panos_ipam_reconcile import existing, raw_discovery

        panos_ipam = load("reconcile_panos_ipam")
        observed = raw_discovery()
        before = existing(observed)
        before["interfaces"] = [row for row in before["interfaces"] if row["name"] != "tunnel.1"]
        proposed = panos_ipam.plan_panos_ipam(
            observed,
            before,
            {
                "interface_creates": [{"name": "tunnel.1", "type": "tunnel", "enabled": True}],
                "interface_updates": [],
            },
        )
        self.assertFalse(proposed["errors"])
        self.assertNotIn("tunnel.1", {row["name"] for row in proposed["ip_assignments"]})
        self.assertTrue(
            any(
                row.get("name") == "tunnel.1" and "Interface" in row["reason"]
                for row in proposed["unresolved"]
            )
        )


if __name__ == "__main__":
    unittest.main()
