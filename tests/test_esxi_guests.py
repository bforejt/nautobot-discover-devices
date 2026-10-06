"""Hosted On links require positive host-local BIOS UUID evidence and preserve ownership."""

import unittest
from copy import deepcopy
from types import SimpleNamespace

from tests._loader import load
from tests.test_esxi import GUEST_UUID, HOST_UUID, inventory
from tests.test_esxi_guest_policy import GUEST, HOST, RELATIONSHIP

esxi = load("adapters.esxi")
planner = load("reconcile_esxi_guests")
ASSOCIATION = "00000004-0000-4000-8000-000000000004"
OTHER_HOST = "00000005-0000-4000-8000-000000000005"


def source():
    observed = esxi.collect(SimpleNamespace(discovery=inventory), expected_host_uuid=HOST_UUID)
    observed["guest_policy"] = {
        "contract": "esxi-guest-policy-v1",
        "host_device_id": HOST,
        "relationship": deepcopy(RELATIONSHIP),
        "mappings": [{"vm_uuid": GUEST_UUID, "device": {"id": GUEST, "name": "VNF"}}],
    }
    return observed


def existing():
    return {
        "device": {"id": HOST},
        "esxi_guest_inventory": {
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


def plan(observed=None, before=None, **kwargs):
    return planner.plan_esxi_guests(
        source() if observed is None else observed,
        existing() if before is None else before,
        identity_verified=True,
        **kwargs,
    )


class EsxiGuestPlannerTests(unittest.TestCase):
    def test_registered_powered_off_guest_has_one_fill_only_association(self):
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
                }
            ],
        )
        self.assertEqual(result["summary"]["hosted_on_created"], 1)
        self.assertEqual((observed, before), unchanged)

    def test_existing_exact_ownership_keeps_its_uuid_and_repeat_proposes_no_writes(self):
        before = existing()
        before["esxi_guest_inventory"]["associations"] = [association()]
        result = plan(before=before)
        self.assertEqual(result["creates"], [])
        self.assertEqual(result["preserved"], [association()])
        self.assertEqual(result["summary"]["hosted_on_preserved"], 1)
        self.assertFalse(result["errors"])

    def test_existing_foreign_typed_or_duplicate_ownership_blocks_reparenting(self):
        for rows in (
            [association(source_id=OTHER_HOST)],
            [association(source_type="virtualization.virtualmachine")],
            [association(destination_type="ipam.ipaddress")],
            [association(), association(id=OTHER_HOST)],
        ):
            before = existing()
            before["esxi_guest_inventory"]["associations"] = rows
            with self.subTest(rows=rows):
                result = plan(before=before)
                self.assertTrue(result["errors"])
                self.assertTrue(result["conflicts"])
                self.assertEqual(result["creates"], [])
                self.assertEqual(before["esxi_guest_inventory"]["associations"], rows)

    def test_missing_guest_device_definition_or_native_capability_blocks(self):
        for mutate in (
            lambda before: before["esxi_guest_inventory"].update(devices=[]),
            lambda before: before["esxi_guest_inventory"].update(supported=False),
            lambda before: before["esxi_guest_inventory"].update(relationship=None),
            lambda before: before["esxi_guest_inventory"]["relationship"].update(id=OTHER_HOST),
            lambda before: before["esxi_guest_inventory"]["relationship"].update(
                type="many-to-many"
            ),
            lambda before: before["esxi_guest_inventory"]["relationship"].update(
                source_type="virtualization.virtualmachine"
            ),
        ):
            before = existing()
            mutate(before)
            with self.subTest(mutation=mutate):
                result = plan(before=before)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_raw_vm_host_template_registration_and_connection_evidence_gate_the_link(self):
        mutations = (
            lambda raw: raw["guests"].clear(),
            lambda raw: raw["guests"][0]["properties"].update({"config.uuid": HOST_UUID}),
            lambda raw: raw["guests"][0]["properties"].update({"config.uuid": None}),
            lambda raw: raw["guests"][0]["properties"].update({"config.template": True}),
            lambda raw: raw["guests"][0]["properties"].pop("config.template"),
            lambda raw: raw["guests"][0]["properties"].update({"runtime.host": None}),
            lambda raw: raw["guests"][0]["properties"].update(
                {"runtime.host": {"type": "HostSystem", "ref": "other-host"}}
            ),
            lambda raw: raw["guests"][0]["properties"].update(
                {"runtime.host": {"type": "VirtualMachine", "ref": "ha-host"}}
            ),
            lambda raw: raw["guests"][0]["properties"].update(
                {"runtime.connectionState": "inaccessible"}
            ),
            lambda raw: raw["host"]["properties"]["vm"].clear(),
            lambda raw: raw["host"]["properties"]["vm"].append(
                {"type": "VirtualMachine", "ref": "1"}
            ),
            lambda raw: raw["guests"].append(deepcopy(raw["guests"][0])),
        )
        for mutate in mutations:
            observed = source()
            mutate(observed["source"]["inventory"])
            with self.subTest(mutation=mutate):
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_same_guest_bios_uuid_on_distinct_registered_vms_is_ambiguous(self):
        observed = source()
        raw = observed["source"]["inventory"]
        raw["guests"].append({**deepcopy(raw["guests"][0]), "ref": "2"})
        raw["host"]["properties"]["vm"].append({"type": "VirtualMachine", "ref": "2"})
        result = plan(observed)
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])

    def test_normalized_guest_observations_cannot_choose_native_ownership(self):
        observed = source()
        observed["observations"]["guests"] = [{"identity": {"guest_uuid": HOST_UUID}}]
        self.assertFalse(plan(observed)["errors"])
        observed["source"]["inventory"]["guests"][0]["properties"]["config.uuid"] = HOST_UUID
        observed["observations"]["guests"] = [{"identity": {"guest_uuid": GUEST_UUID}}]
        self.assertTrue(plan(observed)["errors"])

    def test_policy_duplicate_native_device_and_host_as_guest_are_rejected(self):
        for mutate in (
            lambda policy: policy["mappings"].append(deepcopy(policy["mappings"][0])),
            lambda policy: policy["mappings"][0]["device"].update(id=HOST),
            lambda policy: policy.update(host_device_id=OTHER_HOST),
            lambda policy: policy["mappings"][0].update(vm_uuid="vm-name"),
            lambda policy: policy.update(contract="esxi-guessed-name-policy"),
        ):
            observed = source()
            mutate(observed["guest_policy"])
            with self.subTest(mutation=mutate):
                result = plan(observed)
                self.assertTrue(result["errors"])
                self.assertEqual(result["creates"], [])

    def test_unmapped_report_only_and_other_adapters_do_not_require_relationships(self):
        observed = source()
        observed["guest_policy"] = None
        self.assertFalse(plan(observed, {"device": {"id": HOST}})["errors"])
        observed["adapter"] = "panos"
        observed["guest_policy"] = source()["guest_policy"]
        self.assertFalse(plan(observed, {})["errors"])
        self.assertEqual(plan(observed, {})["creates"], [])

    def test_unverified_host_identity_and_altered_source_contract_block_all_links(self):
        result = planner.plan_esxi_guests(source(), existing(), identity_verified=False)
        self.assertTrue(result["errors"])
        self.assertEqual(result["creates"], [])
        observed = source()
        observed["source"]["contract"] = "unreviewed-source"
        self.assertTrue(plan(observed)["errors"])


if __name__ == "__main__":
    unittest.main()
