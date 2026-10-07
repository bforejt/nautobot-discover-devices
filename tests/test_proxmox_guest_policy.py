"""Explicit UUID mappings resolve only existing Hosted On schema and Devices."""

import json
import unittest
from copy import deepcopy
from unittest.mock import Mock

from tests._loader import load

policy = load("proxmox_guest_policy")
HOST = "00000001-0000-4000-8000-000000000001"
GUEST = "00000002-0000-4000-8000-000000000002"
VM = "00000003-0000-4000-8000-000000000003"
RELATIONSHIP = {
    "id": "6295555f-c43f-4a18-b9d1-ec91c0ee2eef",
    "key": "hosted_on",
    "type": "one-to-many",
    "source_type": "dcim.device",
    "destination_type": "dcim.device",
}


class ProxmoxGuestPolicyTests(unittest.TestCase):
    def setUp(self):
        self.resolver = Mock(
            side_effect=lambda kind, identifier: (
                deepcopy(RELATIONSHIP)
                if kind == "relationship"
                else {"id": identifier, "name": "VNF"}
            )
        )

    def normalize(self, value):
        return policy.normalize_proxmox_guest_policy(value, self.resolver, selected_device_id=HOST)

    def test_blank_and_empty_inputs_keep_guest_inventory_report_only(self):
        for value in (None, "", " ", "[]"):
            self.assertIsNone(self.normalize(value))
        self.resolver.assert_not_called()

    def test_exact_existing_relationship_and_guest_uuid_are_resolved(self):
        result = self.normalize(json.dumps([{"vm_uuid": VM.upper(), "device": GUEST.upper()}]))
        self.assertEqual(
            result,
            {
                "contract": "proxmox-guest-policy-v1",
                "host_device_id": HOST,
                "relationship": RELATIONSHIP,
                "mappings": [{"vm_uuid": VM, "device": {"id": GUEST, "name": "VNF"}}],
            },
        )
        self.assertEqual(self.resolver.call_args_list[0].args, ("relationship", "hosted_on"))
        self.assertEqual(self.resolver.call_args_list[1].args, ("device", GUEST))

    def test_invalid_shapes_do_not_resolve_inventory(self):
        for value in (
            False,
            104,
            [],
            "invalid-json",
            "{}",
            "[null]",
            "[{}]",
            json.dumps([{"vm_uuid": VM, "device": GUEST, "name": "guess"}]),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.normalize(value)
        self.resolver.assert_not_called()

    def test_names_registration_ids_and_sentinel_uuid_are_not_device_identity(self):
        for value in (
            "vnf-name",
            "vm-104",
            104,
            VM.replace("-", ""),
            "{" + VM + "}",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ):
            for field in ("vm_uuid", "device"):
                row = {"vm_uuid": VM, "device": GUEST, field: value}
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.normalize(json.dumps([row]))
        self.resolver.assert_not_called()

    def test_duplicate_vm_device_and_host_as_guest_are_rejected_before_resolution(self):
        cases = (
            [{"vm_uuid": VM, "device": GUEST}] * 2,
            [{"vm_uuid": VM, "device": GUEST}, {"vm_uuid": HOST, "device": GUEST}],
            [{"vm_uuid": VM, "device": GUEST}, {"vm_uuid": VM, "device": VM}],
            [{"vm_uuid": VM, "device": HOST}],
        )
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.normalize(json.dumps(rows))
        self.resolver.assert_not_called()

    def test_changed_relationship_scope_or_cardinality_is_rejected(self):
        for field, value in (
            ("id", "not-a-uuid"),
            ("key", "another"),
            ("type", "many-to-many"),
            ("source_type", "virtualization.virtualmachine"),
            ("destination_type", "ipam.ipaddress"),
        ):
            changed = {**RELATIONSHIP, field: value}
            self.resolver.side_effect = lambda kind, identifier, changed=changed: changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.normalize(json.dumps([{"vm_uuid": VM, "device": GUEST}]))

    def test_guest_lookup_must_return_the_explicit_existing_uuid(self):
        self.resolver.side_effect = lambda kind, identifier: (
            RELATIONSHIP if kind == "relationship" else {"id": HOST, "name": "Wrong Device"}
        )
        with self.assertRaises(ValueError):
            self.normalize(json.dumps([{"vm_uuid": VM, "device": GUEST}]))

    def test_invalid_selected_host_and_read_budget_stop_before_resolution(self):
        with self.assertRaises(ValueError):
            policy.normalize_proxmox_guest_policy(
                json.dumps([{"vm_uuid": VM, "device": GUEST}]),
                self.resolver,
                selected_device_id="host-name",
            )
        with self.assertRaises(ValueError):
            self.normalize(json.dumps([{"vm_uuid": VM, "device": GUEST}] * 4097))
        self.resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
