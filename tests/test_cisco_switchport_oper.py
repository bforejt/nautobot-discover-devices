"""Dedicated operational switchport source: applicability, exact joins and failures."""

import unittest
from copy import deepcopy

from tests._loader import load

switchport = load("adapters.cisco_switchport_oper")
cisco = load("adapters.cisco_iosxe")
RestconfError = load("transport_restconf").RestconfError


def port(name="Gi1/0/1", admin="admin-dyn-auto", oper="oper-stat-acc"):
    return {
        "if-name": name,
        "enabled": [None],
        "hardware-present": [None],
        "admin-mode": admin,
        "port-details": {
            "oper-mode": oper,
            "access-mode-id": 2,
            "access-mode-name": "LAB-DATA",
            "access-state": "acc-active",
            "trunk-nat-mode-id": 1,
            "trunk-nat-mode-name": "default",
            "trunk-nat-state": "trunk-nat-active",
            "voice-state": "voice-none",
            "agport-if-name": "",
            "trunk-vlan": [{"start-id": 1, "end-id": 4094}],
            "pruning-vlan": [{"start-id": 2, "end-id": 1001}],
        },
    }


def payload(rows):
    return {switchport.MODULE + ":switchport-oper-data": {"switchport-info": rows}}


class FakeClient:
    def __init__(self, response=None, errors=None, status=200):
        self.response = payload([port()]) if response is None else response
        self.errors = list(errors or [])
        self.status = status
        self.requests = []
        self.request_options = []
        self.trace = []

    def get(self, path, **kwargs):
        self.requests.append(path)
        self.request_options.append(kwargs)
        error = self.errors.pop(0) if self.errors else None
        self.trace.append({"path": path, "status": error.status_code if error else self.status})
        if error:
            raise error
        return deepcopy(self.response)


class SwitchportOperationalTests(unittest.TestCase):
    def collect(self, rows=None, client=None, revisions=True, interfaces=None):
        if client is None:
            client = FakeClient(payload(rows if rows is not None else [port()]))
        self.warnings = []
        result = switchport.collect(
            client,
            interfaces if interfaces is not None else [{"name": "GigabitEthernet1/0/1"}],
            canonical_name=cisco.canonical_interface_name,
            revisions={switchport.MODULE: "2024-03-01"} if revisions is True else revisions,
            warnings=self.warnings,
        )
        return result

    def assert_invalid(self, result):
        self.assertEqual(result["source"]["status"], "invalid")
        self.assertEqual(result["interfaces"], [])
        self.assertTrue(result["source"]["reason"])
        self.assertTrue(self.warnings)
        self.assertNotIn("secret-response-body", str(result) + str(self.warnings))

    def test_unknown_capability_probes_with_a_bound_and_does_not_invent_a_revision(self):
        client = FakeClient()
        result = self.collect(client=client, revisions=None)
        self.assertEqual(result["source"]["status"], "available")
        self.assertEqual(result["source"]["capability_status"], "unknown")
        self.assertTrue(result["source"]["probed_without_advertisement"])
        self.assertIsNone(result["source"]["revision"])
        self.assertEqual(result["interfaces"][0]["operational_mode"], "access")
        self.assertIsNone(result["interfaces"][0]["source"]["revision"])
        self.assertEqual(client.requests, [switchport.PATH + "?fields=" + switchport.FIELDS])
        self.assertEqual(client.request_options, [{"timeout": 15}])
        self.assertEqual(self.warnings, [])

    def test_known_module_absence_makes_no_request(self):
        client = FakeClient()
        result = self.collect(client=client, revisions={})
        self.assertEqual(result["source"]["status"], "not-advertised")
        self.assertEqual(result["source"]["capability_status"], "not-advertised")
        self.assertFalse(result["source"]["probed_without_advertisement"])
        self.assertEqual(result["interfaces"], [])
        self.assertEqual(client.requests, [])
        self.assertEqual(self.warnings, [])

    def test_advertised_module_reads_whole_meaningful_port_details(self):
        client = FakeClient()
        result = self.collect(client=client)
        self.assertEqual(client.requests, [switchport.PATH + "?fields=" + switchport.FIELDS])
        self.assertIn("port-details", switchport.FIELDS)
        self.assertEqual(result["source"]["status"], "available")
        self.assertEqual(result["source"]["revision"], "2024-03-01")
        self.assertEqual(result["source"]["capability_status"], "advertised")
        self.assertFalse(result["source"]["probed_without_advertisement"])
        self.assertEqual(result["source"]["http_status"], 200)
        self.assertEqual(result["schema_version"], 1)

    def test_actual_access_is_separate_from_dynamic_administrative_mode(self):
        result = self.collect()
        row = result["interfaces"][0]
        self.assertEqual(row["name"], "GigabitEthernet1/0/1")
        self.assertEqual(row["admin_mode"], "admin-dyn-auto")
        self.assertEqual(row["operational_mode"], "access")
        self.assertTrue(row["applicability"]["usable"])
        self.assertEqual(row["observations"], port())
        self.assertEqual(row["source"]["field"], "port-details/oper-mode")
        self.assertEqual(row["source"]["interface"], "Gi1/0/1")

    def test_all_ordinary_admin_modes_use_only_actual_oper_mode(self):
        for admin in sorted(switchport.ORDINARY_ADMIN):
            for oper, expected in switchport.OPERATIONAL_MODES.items():
                with self.subTest(admin=admin, oper=oper):
                    row = self.collect([port(admin=admin, oper=oper)])["interfaces"][0]
                    self.assertEqual(row["operational_mode"], expected)
                    self.assertEqual(row["admin_mode"], admin)

    def test_administrative_trunk_never_substitutes_for_unknown_oper_mode(self):
        for oper in (None, "oper-unknown", "oper-tunnel", "oper-pvlan-host", "future-enum"):
            with self.subTest(oper=oper):
                row = port(admin="admin-trunk", oper=oper)
                if oper is None:
                    del row["port-details"]["oper-mode"]
                actual = self.collect([row])["interfaces"][0]
                self.assertIsNone(actual["operational_mode"])
                self.assertFalse(actual["applicability"]["usable"])
                self.assertEqual(actual["observations"], row)

    def test_nonordinary_and_missing_admin_modes_cannot_acquire_mapping(self):
        for admin in (
            None,
            "admin-unknown",
            "admin-tunnel",
            "admin-multi",
            "admin-pvlan-host",
            "admin-loopback",
            "future-enum",
        ):
            with self.subTest(admin=admin):
                row = port(admin=admin, oper="oper-trunk")
                if admin is None:
                    del row["admin-mode"]
                actual = self.collect([row])["interfaces"][0]
                self.assertIsNone(actual["operational_mode"])
                self.assertFalse(actual["applicability"]["ordinary_admin"])

    def test_routed_and_missing_hardware_retain_observations_without_mapping(self):
        for absent in ("enabled", "hardware-present"):
            with self.subTest(absent=absent):
                row = port(oper="oper-trunk")
                del row[absent]
                actual = self.collect([row])["interfaces"][0]
                self.assertIsNone(actual["operational_mode"])
                self.assertFalse(actual["applicability"]["usable"])
                self.assertEqual(actual["observations"]["port-details"]["oper-mode"], "oper-trunk")
                self.assertIsNotNone(actual["applicability"]["reason"])

    def test_absent_port_details_is_an_unknown_current_mode(self):
        row = port()
        del row["port-details"]
        actual = self.collect([row])["interfaces"][0]
        self.assertIsNone(actual["operational_mode"])
        self.assertEqual(actual["observations"], row)

    def test_voice_private_vlan_and_bundle_guards_are_retained_unmodified(self):
        row = port()
        row["port-details"].update(
            {
                "voice-state": "voice-active",
                "voice-id": 20,
                "voice-name": "LAB-VOICE",
                "access-state": "acc-pvlan-primary",
                "agport-if-name": "Po1",
                "is-agport-suspend": True,
            }
        )
        actual = self.collect([row])["interfaces"][0]
        self.assertEqual(actual["observations"]["port-details"], row["port-details"])
        self.assertNotIn("untagged_vid", actual)
        self.assertNotIn("tagged_vids", actual)

    def test_matching_module_qualified_leaves_and_enums_are_accepted(self):
        row = port()
        row["admin-mode"] = switchport.MODULE + ":admin-dyn-des"
        row["port-details"]["oper-mode"] = switchport.MODULE + ":oper-trunk"
        row["port-details"] = {
            switchport.MODULE + ":" + key: value for key, value in row["port-details"].items()
        }
        row = {switchport.MODULE + ":" + key: value for key, value in row.items()}
        actual = self.collect([row])["interfaces"][0]
        self.assertEqual(actual["operational_mode"], "trunk")
        self.assertEqual(actual["admin_mode"], switchport.MODULE + ":admin-dyn-des")

    def test_foreign_enum_namespace_never_acquires_a_mapping(self):
        for field in ("admin-mode", "oper-mode"):
            with self.subTest(field=field):
                row = port()
                if field == "admin-mode":
                    row[field] = "unrelated:admin-trunk"
                else:
                    row["port-details"][field] = "unrelated:oper-trunk"
                self.assertIsNone(self.collect([row])["interfaces"][0]["operational_mode"])

    def test_duplicate_canonical_source_names_and_unknown_endpoints_discard_source(self):
        for rows in ([port(), port("GigabitEthernet1/0/1")], [port("Gi1/0/2")], [port("")]):
            with self.subTest(rows=rows):
                self.assert_invalid(self.collect(rows))

    def test_ambiguous_or_invalid_eligible_interface_names_block(self):
        for interfaces in (
            [{"name": "Gi1/0/1"}, {"name": "GigabitEthernet1/0/1"}],
            [{"name": None}],
            ["Gi1/0/1"],
        ):
            with (
                self.subTest(interfaces=interfaces),
                self.assertRaises(switchport.SwitchportOperDiscoveryError),
            ):
                self.collect(interfaces=interfaces)

    def test_invalid_revision_arguments_remain_programming_contract_errors(self):
        for revisions in ([], "unknown", {switchport.MODULE: 15}, {switchport.MODULE: {}}):
            with (
                self.subTest(revisions=revisions),
                self.assertRaises(switchport.SwitchportOperDiscoveryError),
            ):
                self.collect(revisions=revisions)

    def test_duplicate_and_foreign_namespaced_leaves_discard_source(self):
        cases = []
        row = port()
        row[switchport.MODULE + ":if-name"] = "Gi1/0/1"
        cases.append(payload([row]))
        row = port()
        row["unrelated:enabled"] = row.pop("enabled")
        cases.append(payload([row]))
        row = port()
        row["port-details"]["unrelated:oper-mode"] = "oper-trunk"
        cases.append(payload([row]))
        cases.append({"unrelated:switchport-oper-data": {"switchport-info": [port()]}})
        for value in cases:
            with self.subTest(value=value):
                self.assert_invalid(self.collect(client=FakeClient(value)))

    def test_malformed_empty_leaves_discard_source_even_if_the_other_guard_is_missing(self):
        for name in ("enabled", "hardware-present"):
            for invalid in (True, False, None, [], {}, [False], [None, None]):
                with self.subTest(name=name, invalid=invalid):
                    row = port()
                    row[name] = invalid
                    row.pop("hardware-present" if name == "enabled" else "enabled")
                    self.assert_invalid(self.collect([row]))

    def test_malformed_container_list_and_scalar_shapes_discard_source(self):
        cases = [
            {},
            [],
            {switchport.MODULE + ":switchport-oper-data": []},
            {switchport.MODULE + ":switchport-oper-data": {"switchport-info": port()}},
            payload(["Gi1/0/1"]),
        ]
        for name, invalid in (("if-name", 1), ("admin-mode", True), ("port-details", [])):
            row = port()
            row[name] = invalid
            cases.append(payload([row]))
        for name, invalid in (
            ("oper-mode", []),
            ("voice-id", "20"),
            ("access-mode-id", True),
            ("is-agport-suspend", "true"),
            ("trunk-vlan", {}),
            ("trunk-vlan", [{"start-id": 20, "end-id": 1}]),
            ("pruning-vlan", [{"start-id": 1}]),
        ):
            row = port()
            row["port-details"][name] = invalid
            cases.append(payload([row]))
        for value in cases:
            with self.subTest(value=value):
                self.assert_invalid(self.collect(client=FakeClient(value)))

    def test_a_late_invalid_row_discards_every_earlier_fact_atomically(self):
        for advertised in (True, False):
            with self.subTest(advertised=advertised):
                invalid = port("secret-response-body")
                self.assert_invalid(
                    self.collect([port(), invalid], revisions=True if advertised else None)
                )

    def test_empty_structured_list_and_confirmed_204_are_available_empty_sources(self):
        for client in (FakeClient(payload([])), FakeClient({}, status=204)):
            with self.subTest(status=client.status):
                result = self.collect(client=client)
                self.assertEqual(result["interfaces"], [])
                self.assertEqual(result["source"]["status"], "available")

    def test_filtered_400_falls_back_to_same_endpoint_once(self):
        client = FakeClient(errors=[RestconfError("operator-safe", 400)])
        result = self.collect(client=client)
        self.assertEqual(
            client.requests, [switchport.PATH + "?fields=" + switchport.FIELDS, switchport.PATH]
        )
        self.assertEqual(result["interfaces"][0]["operational_mode"], "access")
        self.assertEqual(client.request_options, [{"timeout": 15}, {"timeout": 15}])
        self.assertEqual(len(self.warnings), 1)
        self.assertIn("HTTP 400", self.warnings[0])

    def test_optional_transport_failures_preserve_other_discovery_without_error_body(self):
        for status in (None, 200, 201, 299, 401, 403, 404, 501, 503):
            with self.subTest(status=status):
                client = FakeClient(errors=[RestconfError("secret-response-body", status)])
                result = self.collect(client=client)
                self.assertEqual(
                    result["source"]["status"],
                    "invalid"
                    if status is not None and 200 <= status < 300
                    else "unsupported"
                    if status in (404, 501)
                    else "unavailable",
                )
                if status is not None and 200 <= status < 300:
                    self.assert_invalid(result)
                self.assertEqual(result["interfaces"], [])
                self.assertEqual(len(client.requests), 1)
                self.assertEqual(len(self.warnings), 1)
                self.assertNotIn("secret-response-body", self.warnings[0])

    def test_unfiltered_fallback_failure_is_optional_and_not_retried_again(self):
        for status in (200, 503):
            with self.subTest(status=status):
                client = FakeClient(
                    errors=[RestconfError("filter", 400), RestconfError("secret", status)]
                )
                result = self.collect(client=client)
                self.assertEqual(
                    result["source"]["status"], "invalid" if status == 200 else "unavailable"
                )
                self.assertEqual(len(client.requests), 2)
                self.assertEqual(len(self.warnings), 2)
                self.assertNotIn("secret", str(result) + str(self.warnings))

    def test_cancellation_and_programming_failures_propagate(self):
        class CancelledClient:
            def get(self, path, **kwargs):
                raise RuntimeError("worker time limit")

        with self.assertRaisesRegex(RuntimeError, "worker time limit"):
            self.collect(client=CancelledClient())

        class BrokenClient:
            def get(self, path, **kwargs):
                raise TypeError("programming error")

        with self.assertRaisesRegex(TypeError, "programming error"):
            self.collect(client=BrokenClient(), revisions=None)

    def test_output_is_sorted_and_observations_do_not_alias_input(self):
        rows = [port("Gi1/0/2"), port("Gi1/0/1")]
        client = FakeClient(payload(rows))
        result = self.collect(client=client, interfaces=[{"name": "Gi1/0/1"}, {"name": "Gi1/0/2"}])
        self.assertEqual(
            [row["name"] for row in result["interfaces"]],
            ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"],
        )
        result["interfaces"][0]["observations"]["port-details"]["voice-state"] = "voice-active"
        self.assertEqual(
            client.response[switchport.MODULE + ":switchport-oper-data"]["switchport-info"][1][
                "port-details"
            ]["voice-state"],
            "voice-none",
        )


if __name__ == "__main__":
    unittest.main()
