"""Operator-selected existing PAN-OS HA identity, without ORM or transport."""

import json
import unittest

from tests._loader import load

policy = load("panos_ha_policy")
SELECTED = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
GROUP = "33333333-3333-3333-3333-333333333333"
VM_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def selections():
    return {"peer_device": PEER, "peer_vm_uuid": VM_UUID, "redundancy_group": GROUP}


def resolve(kind, identifier):
    if kind == "device" and identifier == PEER:
        return {"id": PEER, "name": "Existing explicit peer", "model": "PA-VM"}
    if kind == "redundancy_group" and identifier == GROUP:
        return {"id": GROUP, "name": "Existing explicit HA group", "failover_strategy": ""}
    return None


class PanosHaPolicyTests(unittest.TestCase):
    def test_explicit_peer_uuid_and_existing_group_are_normalized(self):
        result = policy.normalize_panos_ha_policy(
            json.dumps(selections()), resolve, selected_device_id=SELECTED
        )
        self.assertEqual(result["contract"], "panos-ha-policy-v1")
        self.assertEqual(result["peer_vm_uuid"], VM_UUID)
        self.assertEqual(result["peer_device"]["id"], PEER)
        self.assertEqual(result["redundancy_group"]["id"], GROUP)
        json.dumps(result)

    def test_blank_is_report_only_without_native_lookups(self):
        def forbidden(*args):
            raise AssertionError("Blank selection must not resolve native objects")

        self.assertIsNone(
            policy.normalize_panos_ha_policy(" ", forbidden, selected_device_id=SELECTED)
        )

    def test_required_uuid_selection_cannot_guess_names_or_addresses(self):
        for field, value in (
            ("peer_device", "panos-peer"),
            ("peer_device", "192.0.2.102"),
            ("redundancy_group", "HA group"),
            ("peer_vm_uuid", "unknown"),
            ("peer_vm_uuid", "00000000-0000-0000-0000-000000000000"),
            ("peer_device", SELECTED),
            ("peer_vm_uuid", 7),
        ):
            with self.subTest(field=field, value=value):
                row = selections()
                row[field] = value
                with self.assertRaises(ValueError):
                    policy.normalize_panos_ha_policy(
                        json.dumps(row), resolve, selected_device_id=SELECTED
                    )

    def test_missing_or_extra_fields_duplicate_json_and_oversized_input_fail(self):
        rows = [
            "[]",
            "{}",
            json.dumps({**selections(), "guess": True}),
            '{"peer_device":"'
            + PEER
            + '","peer_device":"'
            + PEER
            + '","peer_vm_uuid":"'
            + VM_UUID
            + '","redundancy_group":"'
            + GROUP
            + '"}',
            " " * (64 * 1024 + 1),
        ]
        for text in rows:
            with self.subTest(text=text[:80]):
                with self.assertRaises(ValueError):
                    policy.normalize_panos_ha_policy(text, resolve, selected_device_id=SELECTED)

    def test_existing_objects_and_compatible_native_strategy_are_mandatory(self):
        for altered in (
            lambda kind, identifier: None,
            lambda kind, identifier: {**resolve(kind, identifier), "model": "other"}
            if kind == "device"
            else resolve(kind, identifier),
            lambda kind, identifier: {
                **resolve(kind, identifier),
                "failover_strategy": "active-active",
            }
            if kind == "redundancy_group"
            else resolve(kind, identifier),
        ):
            with self.assertRaises(ValueError):
                policy.normalize_panos_ha_policy(
                    json.dumps(selections()), altered, selected_device_id=SELECTED
                )
