"""Hosted On links require explicit QEMU UUIDs and complete local evidence."""

import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_proxmox import GUEST_UUID, NODE, Client, inventory
from tests.test_proxmox_guest_policy import GUEST, HOST, RELATIONSHIP

proxmox = load("adapters.proxmox")
planner = load("reconcile_proxmox_guests")
ASSOCIATION = "00000004-0000-4000-8000-000000000004"
OTHER_HOST = "00000005-0000-4000-8000-000000000005"


def source(raw=None):
    observed = proxmox.collect(Client(raw), expected_node=NODE)
    observed["guest_policy"] = {
        "contract": "proxmox-guest-policy-v1",
        "host_device_id": HOST,
        "relationship": deepcopy(RELATIONSHIP),
        "mappings": [{"vm_uuid": GUEST_UUID, "device": {"id": GUEST, "name": "VNF"}}],
    }
    return observed


def existing():
    return {
        "device": {"id": HOST},
        "proxmox_guest_inventory": {
            "supported": True,
            "relationship": {**RELATIONSHIP, "source_filter": None, "destination_filter": None},
            "devices": [{"id": GUEST, "name": "VNF"}],
            "associations": [],
        },
    }


def association(**changes):
    return {
        "id": ASSOCIATION,
        "relationship_id": RELATIONSHIP["id"],
        "source_type": "dcim.device",
        "source_id": HOST,
        "destination_type": "dcim.device",
        "destination_id": GUEST,
        **changes,
    }


def plan(observed=None, before=None):
    return planner.plan_proxmox_guests(
        source() if observed is None else observed,
        existing() if before is None else before,
        identity_verified=True,
    )


class ProxmoxGuestPlannerTests(unittest.TestCase):
    def test_registered_stopped_qemu_fills_one_association_without_mutating_inputs(self):
        observed, before = source(), existing()
        unchanged = deepcopy((observed, before))
        result = plan(observed, before)
        self.assertFalse(result["errors"])
        self.assertEqual(
            result["creates"],
            [
                {
                    "relationship_id": RELATIONSHIP["id"],
                    "source_type": "dcim.device",
                    "source_id": HOST,
                    "destination_type": "dcim.device",
                    "destination_id": GUEST,
                    "vm_uuid": GUEST_UUID,
                    "kind": "qemu",
                    "vmid": inventory()["guests"][0]["vmid"],
                    "node": NODE,
                }
            ],
        )
        self.assertEqual(result["summary"]["hosted_on_created"], 1)
        self.assertEqual((observed, before), unchanged)

    def test_running_guest_and_documented_false_template_default_are_eligible(self):
        raw = inventory()
        raw["api"]["qemu"][0].update(status="running")
        raw["api"]["qemu"][0].pop("template")
        raw["guests"][0]["summary"] = deepcopy(raw["api"]["qemu"][0])
        raw["guests"][0]["status"]["status"] = "running"
        result = plan(source(raw))
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["creates"]), 1)

    def test_unrelated_pending_capacity_and_device_settings_do_not_choose_ownership(self):
        raw = inventory()
        raw["guests"][0]["config"]["memory"] = 8192
        raw["guests"][0]["pending"] = [
            {"key": "memory", "value": 4096, "pending": 8192},
            {"key": "net0", "value": raw["guests"][0]["current_config"]["net0"], "delete": 1},
        ]
        observed = source(raw)
        result = plan(observed)
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["creates"]), 1)
        self.assertEqual(observed["observations"]["guests"][0]["config"]["memory"], 8192)

    def test_lxc_remains_report_only_even_with_uuid_name_and_vmid_spoofs(self):
        raw = inventory()
        raw["api"]["lxc"] = raw["api"]["qemu"]
        raw["api"]["qemu"] = []
        raw["guests"][0]["kind"] = "lxc"
        raw["ssh"]["host"]["guest_registry"]["ids"]["100"]["type"] = "lxc"
        raw["guests"][0]["config"]["hostname"] = "VNF"
        raw["guests"][0]["current_config"]["hostname"] = "VNF"
        result = plan(source(raw))
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])

    def test_successful_permission_filtered_guest_lists_do_not_prove_complete_ownership(self):
        for parent_grant in (0, 1):
            raw = inventory()
            raw["api"]["permissions"]["/vms"]["VM.Audit"] = parent_grant
            raw["ssh"]["host"]["guest_registry"]["ids"]["101"] = {
                "node": NODE,
                "type": "qemu",
                "version": 1,
            }
            with (
                self.subTest(parent_grant=parent_grant),
                self.assertRaisesRegex(proxmox.DiscoveryError, "authoritative local registrations"),
            ):
                source(raw)

    def test_exact_authoritative_registry_proves_coverage_without_parent_propagation(self):
        raw = inventory()
        raw["api"]["permissions"]["/vms"]["VM.Audit"] = 0
        observed = source(raw)
        self.assertIs(observed["source"]["inventory"]["completeness"]["guests"], True)
        result = plan(observed)
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["creates"]), 1)

    def test_existing_exact_ownership_preserves_its_uuid_and_repeat_has_no_writes(self):
        before = existing()
        before["proxmox_guest_inventory"]["associations"] = [association()]
        result = plan(before=before)
        self.assertEqual(result["creates"], [])
        self.assertEqual(result["preserved"], [association()])
        self.assertEqual(result["summary"]["hosted_on_preserved"], 1)
        self.assertFalse(result["errors"])

    def test_foreign_typed_duplicate_or_identityless_ownership_blocks_reparenting(self):
        for rows in (
            [association(source_id=OTHER_HOST)],
            [association(source_type="virtualization.virtualmachine")],
            [association(destination_type="ipam.ipaddress")],
            [association(), association(id=OTHER_HOST)],
            [association(id=None)],
        ):
            before = existing()
            before["proxmox_guest_inventory"]["associations"] = rows
            with self.subTest(rows=rows):
                result = plan(before=before)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])
                self.assertEqual(before["proxmox_guest_inventory"]["associations"], rows)

    def test_missing_guest_definition_or_native_capability_blocks(self):
        for mutate in (
            lambda before: before["proxmox_guest_inventory"].update(devices=[]),
            lambda before: before["proxmox_guest_inventory"]["devices"].append(
                deepcopy(before["proxmox_guest_inventory"]["devices"][0])
            ),
            lambda before: before["proxmox_guest_inventory"].update(supported=False),
            lambda before: before["proxmox_guest_inventory"].update(relationship=None),
            lambda before: before["proxmox_guest_inventory"]["relationship"].update(id=OTHER_HOST),
            lambda before: before["proxmox_guest_inventory"]["relationship"].update(
                type="many-to-many"
            ),
            lambda before: before["proxmox_guest_inventory"]["relationship"].update(
                source_type="virtualization.virtualmachine"
            ),
        ):
            before = existing()
            mutate(before)
            with self.subTest(mutation=mutate):
                result = plan(before=before)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_uuid_kind_node_registration_template_and_live_status_gate_links(self):
        mutations = (
            lambda raw: raw["guests"].clear(),
            lambda raw: raw["guests"][0]["current_config"].update(smbios1="uuid=" + OTHER_HOST),
            lambda raw: raw["guests"][0]["current_config"].pop("smbios1"),
            lambda raw: raw["guests"][0].update(kind="lxc"),
            lambda raw: raw["guests"][0].update(node="foreign-node"),
            lambda raw: raw["guests"][0].update(vmid=99),
            lambda raw: raw["guests"][0].update(vmid=True),
            lambda raw: raw["guests"][0]["current_config"].update(template=1),
            lambda raw: raw["guests"][0]["config"].update(template=1),
            lambda raw: raw["guests"][0]["summary"].update(template="0"),
            lambda raw: raw["guests"][0]["status"].update(status="unknown"),
            lambda raw: raw["guests"][0]["status"].update(node="foreign-node"),
            lambda raw: raw["guests"][0]["status"].update(vmid=999999998),
            lambda raw: raw["guests"][0]["status"].update(lock="migrate"),
            lambda raw: raw["guests"][0]["current_config"].update(lock="clone"),
            lambda raw: raw["api"]["qemu"].clear(),
            lambda raw: raw["api"]["qemu"].append(deepcopy(raw["api"]["qemu"][0])),
            lambda raw: raw["guests"].append(deepcopy(raw["guests"][0])),
            lambda raw: raw["completeness"].update(guests="permission-scoped"),
        )
        for mutate in mutations:
            observed = source()
            mutate(observed["source"]["inventory"])
            with self.subTest(mutation=mutate):
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_same_bios_uuid_on_distinct_vmid_is_ambiguous(self):
        observed = source()
        raw = observed["source"]["inventory"]
        guest = deepcopy(raw["guests"][0])
        guest["vmid"] += 1
        guest["summary"]["vmid"] = guest["vmid"]
        guest["status"]["vmid"] = guest["vmid"]
        raw["guests"].append(guest)
        raw["api"]["qemu"].append(deepcopy(guest["summary"]))
        result = plan(observed)
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])

    def test_pending_identity_mutations_deletions_and_unknown_pending_shape_block_links(self):
        for pending in (
            None,
            [None],
            [{"key": "smbios1", "pending": "uuid=" + OTHER_HOST}],
            [{"key": "smbios1", "delete": 1}],
            [{"key": "template", "pending": 1}],
            [{"key": "lock", "pending": "migrate"}],
            [{"key": "smbios1"}, {"key": "smbios1"}],
        ):
            observed = source()
            observed["source"]["inventory"]["guests"][0]["pending"] = pending
            with self.subTest(pending=pending):
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])
        observed = source()
        observed["source"]["inventory"]["guests"][0]["config"]["smbios1"] = "uuid=" + OTHER_HOST
        self.assertTrue(plan(observed)["errors"])

    def test_current_pending_identity_values_must_corroborate_both_config_reads(self):
        for rows in (
            [{"key": "smbios1", "value": "uuid=" + OTHER_HOST}],
            [{"key": "smbios1", "value": "uuid=" + GUEST_UUID + ",uuid=" + GUEST_UUID}],
            [{"key": "smbios1", "value": None}],
            [{"key": "smbios1"}],
            [{"key": "template", "value": 1}],
            [{"key": "template", "value": "0"}],
            [{"key": "lock", "value": "migrate"}],
        ):
            raw = inventory()
            raw["guests"][0]["pending"] = rows
            with self.subTest(rows=rows):
                result = plan(source(raw))
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])
        raw = inventory()
        raw["guests"][0]["pending"] = [
            {"key": "smbios1", "value": "uuid=" + GUEST_UUID},
            {"key": "template", "value": 0},
        ]
        result = plan(source(raw))
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["creates"]), 1)

    def test_sanitized_pending_uuid_values_keep_transition_presence(self):
        for pending in (None, "", "serial=SECRET", "uuid=" + GUEST_UUID + ",uuid=" + GUEST_UUID):
            raw = inventory()
            raw["guests"][0]["pending"] = [
                {"key": "smbios1", "value": "uuid=" + GUEST_UUID, "pending": pending}
            ]
            observed = source(raw)
            sanitized = observed["source"]["inventory"]["guests"][0]["pending"][0]
            with self.subTest(pending=pending):
                self.assertIn("pending", sanitized)
                self.assertNotIn("SECRET", repr(observed))
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_locks_and_template_flags_from_every_guest_view_block_links(self):
        for view in ("config", "current_config", "status", "summary"):
            raw = inventory()
            raw["guests"][0][view]["lock"] = "migrate"
            if view == "summary":
                raw["api"]["qemu"][0]["lock"] = "migrate"
            with self.subTest(view=view):
                result = plan(source(raw))
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])
        raw = inventory()
        raw["guests"][0]["status"]["template"] = 1
        result = plan(source(raw))
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])

    def test_opaque_qemu_arguments_keep_presence_and_cannot_override_uuid_ownership(self):
        for view in ("config", "current_config"):
            raw = inventory()
            raw["guests"][0][view]["args"] = "-smbios type=1,uuid=" + OTHER_HOST + ",serial=SECRET"
            observed = source(raw)
            with self.subTest(view=view):
                self.assertIs(observed["source"]["inventory"]["guests"][0][view]["args"], True)
                self.assertNotIn("SECRET", repr(observed))
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])
        for row in (
            {"key": "args", "value": "-uuid " + OTHER_HOST + " SECRET"},
            {"key": "args", "pending": "-uuid " + OTHER_HOST + " SECRET"},
            {"key": "args", "delete": 1},
        ):
            raw = inventory()
            raw["guests"][0]["pending"] = [row]
            observed = source(raw)
            with self.subTest(row=row):
                self.assertEqual(
                    observed["source"]["inventory"]["guests"][0]["pending"][0]["key"], "args"
                )
                self.assertNotIn("SECRET", repr(observed))
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_names_and_vmid_reuse_never_substitute_for_missing_bios_uuid(self):
        observed = source()
        guest = observed["source"]["inventory"]["guests"][0]
        guest["summary"]["name"] = "VNF"
        guest["current_config"].pop("smbios1")
        guest["config"].pop("smbios1")
        observed["observations"]["guests"] = [
            {"kind": "qemu", "vmid": guest["vmid"], "identity": {"guest_uuid": GUEST_UUID}}
        ]
        result = plan(observed)
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])

    def test_policy_duplicates_host_as_guest_and_wrong_host_contract_are_rejected(self):
        for mutate in (
            lambda policy: policy["mappings"].append(deepcopy(policy["mappings"][0])),
            lambda policy: policy["mappings"][0]["device"].update(id=HOST),
            lambda policy: policy.update(host_device_id=OTHER_HOST),
            lambda policy: policy["mappings"][0].update(vm_uuid="vm-name"),
            lambda policy: policy.update(contract="esxi-guest-policy-v1"),
        ):
            observed = source()
            mutate(observed["guest_policy"])
            with self.subTest(mutation=mutate):
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_unmapped_guests_and_other_adapters_do_not_require_relationships(self):
        observed = source()
        observed["guest_policy"] = None
        self.assertFalse(plan(observed, {"device": {"id": HOST}})["errors"])
        observed["adapter"] = "esxi"
        observed["guest_policy"] = source()["guest_policy"]
        self.assertEqual(plan(observed, {})["creates"], [])
        self.assertFalse(plan(observed, {})["errors"])

    def test_unverified_host_identity_and_unreviewed_source_contract_block_all_links(self):
        result = planner.plan_proxmox_guests(source(), existing(), identity_verified=False)
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])
        observed = source()
        observed["source"]["contract"] = "unreviewed-source"
        self.assertTrue(plan(observed)["errors"])

    def test_smbios_uuid_parser_rejects_duplicates_sentinels_and_wrapped_identity(self):
        self.assertEqual(planner.canonical_guest_uuid("uuid=" + GUEST_UUID.upper()), GUEST_UUID)
        self.assertEqual(
            planner.canonical_guest_uuid("manufacturer=TEVOT1ZP,uuid=" + GUEST_UUID), GUEST_UUID
        )
        for value in (
            None,
            GUEST_UUID,
            "uuid=" + GUEST_UUID + ",uuid=" + GUEST_UUID,
            "uuid={" + GUEST_UUID + "}",
            "uuid=" + GUEST_UUID.replace("-", ""),
            "uuid=00000000-0000-0000-0000-000000000000",
            "uuid=ffffffff-ffff-ffff-ffff-ffffffffffff",
            "uuid=" + GUEST_UUID + ",malformed",
            "uuid=" + GUEST_UUID + " ",
        ):
            with self.subTest(value=value):
                self.assertIsNone(planner.canonical_guest_uuid(value))


if __name__ == "__main__":
    unittest.main()
