"""Reciprocal Palo HA identities and native shared-address ownership evidence."""

import json
import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

from tests._loader import load
from tests.test_panos_ha_policy import GROUP, PEER, SELECTED, VM_UUID, resolve, selections
from tests.test_panos_ipam_reconcile import existing, raw_discovery

ha_parser = load("adapters.panos_ha")
panos = load("adapters.panos")
ha_policy = load("panos_ha_policy")
planner = load("reconcile_panos_ha")
ipam_planner = load("reconcile_panos_ipam")
ssh = load("transport_ssh")
FIXTURES = Path(__file__).parent / "fixtures"
SELECTED_VM_UUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def discovery(peer=False):
    result = raw_discovery()
    identifier = VM_UUID if peer else SELECTED_VM_UUID
    xml = ET.fromstring((FIXTURES / "panos_vm_system_info.xml").read_text())
    xml.find("result/system/vm-uuid").text = identifier
    identity, system = panos.parse_system_info(ET.tostring(xml, encoding="unicode"))
    result["identity"] = identity
    result["sources"] = {"identity": {"command": ssh.SYSTEM_INFO, "path": "result/system"}}
    result["identity_binding"] = {
        "contract": "panos-vm-identity-v1",
        "system_command": ssh.SYSTEM_INFO,
        "system_path": "result/system",
        "expected_uuid": identifier,
        "observed_uuid": identifier,
        "model": "PA-VM",
        "family": "vm",
        "vm_mode": "KVM",
    }
    result["observations"]["system"] = system
    config = ET.fromstring((FIXTURES / "panos_ha_configured.xml").read_text())
    if peer:
        config.find("result/deviceconfig/high-availability/group/peer-ip").text = "198.18.100.1"
        config.find(
            "result/deviceconfig/high-availability/interface/ha1/ip-address"
        ).text = "198.18.100.2"
        config.find(
            "result/deviceconfig/high-availability/group/election-option/device-priority"
        ).text = "110"
    result["observations"]["ha"] = {
        "configuration": ha_parser.parse_ha_configuration(ET.tostring(config, encoding="unicode")),
        "runtime": ha_parser.parse_ha_state(
            (FIXTURES / ("panos_ha_passive.xml" if peer else "panos_ha_active.xml")).read_text()
        ),
    }
    return result


def paired():
    result = discovery()
    policy = ha_policy.normalize_panos_ha_policy(
        json.dumps(selections()), resolve, selected_device_id=SELECTED
    )
    result["ha_pair"] = {
        "contract": "panos-ha-pair-v1",
        "policy": policy,
        "peer_discovery": discovery(True),
    }
    before = existing(result)
    before["device"] = {"id": SELECTED, "model": "PA-VM"}
    before["ha_inventory"] = {
        "supported": True,
        "policy": deepcopy(policy),
        "group": {"id": GROUP, "name": "Existing explicit HA group", "failover_strategy": ""},
        "group_member_ids": [],
        "devices": [
            {
                "id": SELECTED,
                "name": "Selected",
                "model": "PA-VM",
                "serial": "",
                "manufacturer_name": "Palo Alto Networks",
                "platform_network_driver": "paloalto_panos",
                "platform_name": "PAN-OS",
                "device_redundancy_group_id": None,
                "device_redundancy_group_priority": None,
            },
            {
                "id": PEER,
                "name": "Peer",
                "model": "PA-VM",
                "serial": "",
                "manufacturer_name": "Palo Alto Networks",
                "platform_network_driver": "paloalto_panos",
                "platform_name": "PAN-OS",
                "device_redundancy_group_id": None,
                "device_redundancy_group_priority": None,
            },
        ],
        "peer_interfaces": [
            {"id": "peer-" + row["name"], "name": row["name"], "device_id": PEER, "vrf_id": None}
            for row in result["ipam"]["interfaces"]
        ],
    }
    return result, before


class PanosHaReconcileTests(unittest.TestCase):
    def test_reciprocal_identity_membership_priority_and_shared_addresses_are_pure(self):
        observed, before = paired()
        unchanged = deepcopy((observed, before))
        plan = planner.plan_panos_ha(observed, before, identity_verified=True)
        self.assertFalse(plan["errors"])
        self.assertFalse(plan["unresolved"])
        self.assertEqual(plan["summary"]["ha_groups_updated"], 1)
        self.assertEqual(plan["summary"]["ha_devices_updated"], 2)
        self.assertEqual(plan["summary"]["ha_shared_addresses_reviewed"], 12)
        self.assertEqual(
            {row["interface_name"] for row in plan["sharing"]["addresses"]},
            {row["name"] for row in observed["ipam"]["interfaces"]},
        )
        self.assertEqual((observed, before), unchanged)
        json.dumps(plan)
        for row in before["ha_inventory"]["devices"]:
            row["device_redundancy_group_id"] = GROUP
            row["device_redundancy_group_priority"] = 100 if row["id"] == SELECTED else 110
        before["ha_inventory"]["group"]["failover_strategy"] = "active-passive"
        before["ha_inventory"]["group_member_ids"] = [SELECTED, PEER]
        repeated = planner.plan_panos_ha(observed, before, identity_verified=True)
        self.assertFalse(repeated["errors"])
        self.assertEqual(repeated["group_updates"], [])
        self.assertEqual(repeated["device_updates"], [])

    def test_unverified_identity_or_absent_native_capability_never_plans_writes(self):
        observed, before = paired()
        plan = planner.plan_panos_ha(observed, before)
        self.assertTrue(plan["unresolved"])
        self.assertFalse(plan["device_updates"])
        before["ha_inventory"]["supported"] = False
        plan = planner.plan_panos_ha(observed, before, identity_verified=True)
        self.assertFalse(plan["sharing"])
        self.assertTrue(plan["unresolved"])

    def test_wrong_uuid_group_link_mode_role_sync_or_provenance_fails_closed(self):
        mutations = (
            lambda observed, before: observed["ha_pair"]["peer_discovery"]["observations"][
                "system"
            ].update({"vm-uuid": SELECTED_VM_UUID}),
            lambda observed, before: observed["ha_pair"]["peer_discovery"]["observations"]["ha"][
                "configuration"
            ].update({"group_id": 43}),
            lambda observed, before: observed["ha_pair"]["peer_discovery"]["observations"]["ha"][
                "runtime"
            ]["links"]["ha1"].update({"peer_mac": "02:00:00:00:00:ee"}),
            lambda observed, before: observed["ha_pair"]["peer_discovery"]["observations"]["ha"][
                "runtime"
            ]["local"].update({"role": "active"}),
            lambda observed, before: observed["ha_pair"]["peer_discovery"]["observations"]["ha"][
                "runtime"
            ]["synchronization"].update({"running_config_status": "not synchronized"}),
            lambda observed, before: observed["observations"]["ha"]["configuration"].update(
                {"mode": "active-active"}
            ),
            lambda observed, before: observed["observations"]["ha"]["configuration"]["source"][
                "fields"
            ]["enabled"].update({"path": "guessed/path"}),
            lambda observed, before: before["ha_inventory"].update(
                {"group_member_ids": ["unexpected third device"]}
            ),
            lambda observed, before: observed["ha_pair"]["peer_discovery"]["sources"][
                "identity"
            ].update({"command": "show something else"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                observed, before = paired()
                mutate(observed, before)
                plan = planner.plan_panos_ha(observed, before, identity_verified=True)
                self.assertTrue(plan["errors"])
                self.assertFalse(plan["group_updates"])
                self.assertFalse(plan["device_updates"])
                self.assertIsNone(plan["sharing"])

    def test_populated_other_group_intent_preserves_both_devices_and_blocks_sharing(self):
        observed, before = paired()
        before["ha_inventory"]["devices"][1]["device_redundancy_group_id"] = "another-group"
        plan = planner.plan_panos_ha(observed, before, identity_verified=True)
        self.assertFalse(plan["errors"])
        self.assertTrue(plan["conflicts"])
        self.assertFalse(plan["device_updates"])
        self.assertFalse(plan["group_updates"])
        self.assertIsNone(plan["sharing"])

    def test_populated_other_priority_intent_blocks_shared_ownership(self):
        observed, before = paired()
        before["ha_inventory"]["devices"][1]["device_redundancy_group_priority"] = 99
        plan = planner.plan_panos_ha(observed, before, identity_verified=True)
        self.assertFalse(plan["errors"])
        self.assertTrue(plan["conflicts"])
        self.assertFalse(plan["device_updates"])
        self.assertFalse(plan["group_updates"])
        self.assertIsNone(plan["sharing"])

    def test_absent_peer_interface_or_changed_shared_address_does_not_authorize_host(self):
        for variant in ("missing", "address", "vrf"):
            with self.subTest(variant=variant):
                observed, before = paired()
                if variant == "missing":
                    before["ha_inventory"]["peer_interfaces"] = [
                        row
                        for row in before["ha_inventory"]["peer_interfaces"]
                        if row["name"] != "ethernet1/1"
                    ]
                elif variant == "address":
                    xml = (
                        (FIXTURES / "panos_ipam_network.xml")
                        .read_text()
                        .replace("192.0.2.1/24", "192.0.2.2/24")
                    )
                    observed["ha_pair"]["peer_discovery"]["ipam"] = raw_discovery(xml)["ipam"]
                else:
                    next(
                        row
                        for row in before["ha_inventory"]["peer_interfaces"]
                        if row["name"] == "ethernet1/1"
                    )["vrf_id"] = "other-vrf"
                plan = planner.plan_panos_ha(observed, before, identity_verified=True)
                self.assertFalse(plan["errors"])
                self.assertTrue(plan["unresolved"])
                self.assertNotIn(
                    "ethernet1/1", {row["interface_name"] for row in plan["sharing"]["addresses"]}
                )

    def test_native_ipam_requires_the_recomputed_sharing_proof_and_preserves_other_foreign_owners(
        self,
    ):
        observed, before = paired()
        ha_plan = planner.plan_panos_ha(observed, before, identity_verified=True)
        no_policy = ipam_planner.plan_panos_ipam(observed, before)
        self.assertEqual(no_policy["summary"]["ip_addresses_created"], 0)
        first = ipam_planner.plan_panos_ipam(observed, before, ha_plan=ha_plan)
        self.assertFalse(first["errors"])
        self.assertEqual(first["summary"]["ip_addresses_created"], 12)
        forged = deepcopy(ha_plan)
        forged["sharing"]["addresses"][0]["peer_interface_id"] = "another-device-interface"
        refused = ipam_planner.plan_panos_ipam(observed, before, ha_plan=forged)
        self.assertTrue(refused["errors"])
        self.assertEqual(refused["summary"]["ip_addresses_created"], 0)
