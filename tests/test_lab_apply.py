"""Lab apply guards detect preservation failures before a transaction commits."""

import unittest
from copy import deepcopy

from tools import lab_apply


class LabApplyPreservationTests(unittest.TestCase):
    def setUp(self):
        self.before = [
            {
                "id": "existing-uuid",
                "name": "ethernet1/1",
                "type": "other",
                "enabled": False,
                "mtu": 0,
                "description": "",
                "module_id": "owned-module",
                "last_updated": "before",
            }
        ]

    def test_only_a_planned_blank_fill_and_its_timestamp_are_allowed(self):
        after = deepcopy(self.before)
        after[0].update(description="Verified description", last_updated="after")
        lab_apply._preserved_rows(self.before, after, {"existing-uuid": {"description"}})

    def test_populated_false_zero_other_are_preserved_even_when_plan_allows_field(self):
        for field, value in (("enabled", True), ("mtu", 1500), ("type", "virtual")):
            with self.subTest(field=field):
                after = deepcopy(self.before)
                after[0][field] = value
                with self.assertRaisesRegex(AssertionError, "populated native field"):
                    lab_apply._preserved_rows(self.before, after, {"existing-uuid": {field}})

    def test_deletion_or_replacement_of_an_existing_uuid_is_refused(self):
        after = deepcopy(self.before)
        after[0]["id"] = "replacement-uuid"
        with self.assertRaisesRegex(AssertionError, "removed"):
            lab_apply._preserved_rows(self.before, after, {})

    def test_name_and_module_ownership_cannot_change_during_a_blank_fill(self):
        for field in ("name", "module_id"):
            with self.subTest(field=field):
                after = deepcopy(self.before)
                after[0][field] = "changed"
                with self.assertRaisesRegex(AssertionError, "preserved native field"):
                    lab_apply._preserved_rows(
                        self.before, after, {"existing-uuid": {"description"}}
                    )

    def test_repeat_without_changes_preserves_timestamps(self):
        after = deepcopy(self.before)
        after[0]["last_updated"] = "after"
        with self.assertRaisesRegex(AssertionError, "last_updated"):
            lab_apply._preserved_rows(self.before, after, {})

    def test_explicit_uuid_rejects_missing_invalid_and_sentinel_identity(self):
        for value in (
            None,
            "",
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lab_apply._uuid(value)
        self.assertEqual(
            lab_apply._uuid("B2AB2231-F1C1-4A45-9356-4190F49E6A84"),
            "b2ab2231-f1c1-4a45-9356-4190f49e6a84",
        )


if __name__ == "__main__":
    unittest.main()
