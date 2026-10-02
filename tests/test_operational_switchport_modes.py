"""Actual negotiated mode joins configuration without relaxing VLAN safeguards."""

import unittest

from tests._loader import load
from tests.test_cisco_iosxe import FixtureClient, cisco
from tests.test_cisco_layer2 import native_row, payloads
from tests.test_vlan_reconcile import apply_to_snapshot

oper = load("adapters.cisco_switchport_oper")
planner = load("reconcile_vlans")
PORT = "TwoGigabitEthernet1/0/35"


def operational_values(mode="oper-dyn-acc", admin="admin-dyn-auto", *, ready=True):
    values = payloads()
    values[cisco.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]["module"].append(
        {"name": oper.MODULE, "revision": "2024-03-01"}
    )
    row = {
        "if-name": "Tw1/0/35",
        "enabled": [None],
        "hardware-present": [None],
        "admin-mode": admin,
        "port-details": {"oper-mode": mode, "voice-state": "voice-none"},
    }
    values[oper.PATH] = {oper.MODULE + ":switchport-oper-data": {"switchport-info": [row]}}
    if ready:
        next(
            row
            for row in values[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
                "interface"
            ]
            if cisco.canonical_interface_name(row["name"]) == PORT
        )["oper-status"] = "if-oper-state-ready"
    return values, row


def settings(discovery, name=PORT):
    return next(row for row in discovery["layer2"]["settings"] if row["name"] == name)


def bundle(discovery, name=PORT):
    return next((row for row in discovery["layer2"]["interfaces"] if row["name"] == name), None)


def inventory(discovery):
    return {
        "interfaces": [
            {
                "id": str(i),
                "name": row["name"],
                "type": row["type"],
                "mode": "",
                "untagged_vlan_id": None,
                "tagged_vlan_ids": [],
            }
            for i, row in enumerate(discovery["interfaces"])
        ],
        "vlan_inventory": {
            "supported": True,
            "group": {"id": "lab", "name": "lab"},
            "allowed_vids": list(range(1, 4095)),
            "vlans": [],
        },
    }


class OperationalSwitchportMappingTests(unittest.TestCase):
    def test_actual_dynamic_access_selects_known_access_vlan_without_guessing(self):
        values, _ = operational_values()
        discovered = cisco.collect(FixtureClient(values))
        mapped = bundle(discovered)
        self.assertEqual(
            (mapped["mode"], mapped["untagged_vid"], mapped["tagged_vids"]), ("access", 1, [])
        )
        self.assertEqual(mapped["observations"]["configured_mode"], "dynamic-auto")
        self.assertEqual(mapped["observations"]["operational_mode"], "access")
        self.assertNotIn("ntc_inference", mapped["source"])
        self.assertEqual(mapped["source"]["operational_mode"]["revision"], "2024-03-01")
        self.assertEqual(settings(discovered)["configured_mode"], "dynamic-auto")
        self.assertEqual(
            settings(discovered)["field_sources"]["operational_mode"],
            "device-reported-after-negotiation",
        )
        first = planner.plan_vlans(discovered, inventory(discovered))
        self.assertFalse(first["errors"])
        self.assertEqual(first["summary"]["switching_dynamic_resolved"], 1)
        self.assertEqual(first["summary"]["switching_operational"], 1)
        self.assertEqual(first["summary"]["switching_inferred"], 0)
        repeat = planner.plan_vlans(discovered, apply_to_snapshot(first, inventory(discovered)))
        self.assertFalse(repeat["errors"])
        self.assertFalse(repeat["assignments"])
        self.assertFalse(any(row["create"] or row["changes"] for row in repeat["catalog"]))

    def test_actual_dynamic_trunk_retains_configured_allowed_policy(self):
        for finite in (False, True):
            with self.subTest(finite=finite):
                values, row = operational_values("oper-trunk")
                config = {
                    "mode": {"dynamic": "auto"},
                    "trunk": {"native": {"vlan": {"vlan-id": 2}}},
                }
                if finite:
                    config["trunk"]["allowed"] = {"vlan-v2": {"vlan-choices": {"vlans": "2,10-11"}}}
                native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
                    "switchport": config
                }
                # These distinct operational ranges must not replace configured policy.
                row["port-details"].update(
                    {
                        "trunk-vlan": [{"start-id": 20, "end-id": 30}],
                        "pruning-vlan": [{"start-id": 10, "end-id": 11}],
                    }
                )
                found = cisco.collect(FixtureClient(values))
                mapped = bundle(found)
                self.assertEqual(mapped["mode"], "tagged" if finite else "tagged-all")
                self.assertEqual(mapped["untagged_vid"], 2)
                self.assertEqual(mapped["tagged_vids"], [10, 11] if finite else [])
                self.assertEqual(settings(found)["observations"]["switchport_oper"], row)

    def test_reported_admin_mode_can_establish_omitted_dynamic_mode_without_profile(self):
        values, _ = operational_values()
        # Use an unreviewed release and an explicit access VID, so no omitted-leaf
        # default can establish either the administrative mode or VLAN identity.
        for row in values[cisco.INSTALL_PATH][
            "Cisco-IOS-XE-install-oper:install-location-information"
        ]:
            for version in row.get("install-version-info", []):
                version["version"] = "17.18.1"
        native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
            "switchport": {"access": {"vlan": {"vlan": 2}}}
        }
        found = cisco.collect(FixtureClient(values))
        self.assertEqual(bundle(found)["mode"], "access")
        self.assertEqual(bundle(found)["untagged_vid"], 2)
        self.assertNotIn("defaults", bundle(found)["source"])
        self.assertEqual(
            settings(found)["field_sources"]["configured_mode"], "device-reported-admin-mode"
        )

    def test_reviewed_1715_actual_access_and_trunk_use_documented_scoped_defaults(self):
        for mode in ("oper-dyn-acc", "oper-trunk"):
            with self.subTest(mode=mode):
                values, _ = operational_values(mode)
                for row in values[cisco.INSTALL_PATH][
                    "Cisco-IOS-XE-install-oper:install-location-information"
                ]:
                    for version in row.get("install-version-info", []):
                        version["version"] = "17.15.1"
                found = cisco.collect(FixtureClient(values))
                mapped = bundle(found)
                self.assertEqual(
                    mapped["mode"], "access" if mode == "oper-dyn-acc" else "tagged-all"
                )
                self.assertEqual(mapped["untagged_vid"], 1)
                self.assertEqual(mapped["source"]["defaults"]["software_family"], "17.15")
                self.assertIn(
                    "17-15/", mapped["source"]["defaults"]["documents"]["global_native_tagging"]
                )
                self.assertNotIn("inferred", mapped)
                # Switchport review does not widen the separate duplex profile.
                copper = next(row for row in found["interfaces"] if row["name"] == PORT)
                self.assertIsNone(copper["duplex"])

    def test_reviewed_1715_finite_trunk_uses_successful_204_global_configuration_scope(self):
        values, _ = operational_values("oper-trunk")
        for row in values[cisco.INSTALL_PATH][
            "Cisco-IOS-XE-install-oper:install-location-information"
        ]:
            for version in row.get("install-version-info", []):
                version["version"] = "17.15.1"
        native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
            "switchport": {
                "mode": {"dynamic": "auto"},
                "trunk": {
                    "native": {"vlan": {"vlan-id": 2}},
                    "allowed": {"vlan-v2": {"vlan-choices": {"vlans": "2,10-11"}}},
                },
            }
        }
        values[cisco.cisco_layer2.GLOBAL_PATH] = {}

        class ScopedEmptyClient(FixtureClient):
            def get(self, path, **kwargs):
                payload = super().get(path, **kwargs)
                if path == cisco.cisco_layer2.GLOBAL_PATH:
                    self.trace[-1]["status"] = 204
                return payload

        found = cisco.collect(ScopedEmptyClient(values))
        mapped = bundle(found)
        self.assertEqual(
            (mapped["mode"], mapped["untagged_vid"], mapped["tagged_vids"]), ("tagged", 2, [10, 11])
        )
        self.assertEqual(mapped["source"]["global_tagging"]["http_status"], 204)
        self.assertFalse(mapped["source"]["global_tagging"]["enabled"])

    def test_explicit_configured_access_retains_precedence_over_operational_mode(self):
        values, row = operational_values("oper-trunk", "admin-stat-acc")
        native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
            "switchport": {"mode": {"access": {}}, "access": {"vlan": {"vlan": 2}}}
        }
        found = cisco.collect(FixtureClient(values))
        self.assertEqual(bundle(found)["mode"], "access")
        self.assertEqual(settings(found)["operational_mode"], "trunk")
        self.assertNotIn("operational_assignment_supported", settings(found))

    def test_actual_down_is_blank_in_strict_mode_and_uses_existing_opt_in_only(self):
        values, _ = operational_values("oper-down", ready=False)
        self.assertIsNone(bundle(cisco.collect(FixtureClient(values))))
        mapped = bundle(cisco.collect(FixtureClient(values), use_ntc_defaults=True))
        self.assertEqual(mapped["mode"], "tagged-all")
        self.assertTrue(mapped["inferred"])
        values, _ = operational_values("oper-down", ready=True)
        self.assertIsNone(bundle(cisco.collect(FixtureClient(values), use_ntc_defaults=True)))

    def test_actual_positive_unknown_or_special_modes_never_become_down_guesses(self):
        for mode in (
            "oper-dyn-acc",
            "oper-trunk",
            "oper-unknown",
            "oper-tunnel",
            "oper-pvlan-host",
        ):
            with self.subTest(mode=mode):
                values, _ = operational_values(mode, ready=False)
                found = cisco.collect(FixtureClient(values), use_ntc_defaults=True)
                self.assertIsNone(bundle(found))
                self.assertNotIn("inference", settings(found))

    def test_conflicting_voice_private_vlan_routed_and_aggregate_evidence_blocks_mapping(self):
        for change in ("voice", "pvlan", "routed", "suspended", "wrong-lag", "admin-mismatch"):
            with self.subTest(change=change):
                values, row = operational_values()
                details = row["port-details"]
                if change == "voice":
                    details["voice-state"] = "voice-active"
                elif change == "pvlan":
                    details["access-state"] = "acc-pvlan-community"
                elif change == "routed":
                    row.pop("enabled")
                elif change == "suspended":
                    details.update({"agport-if-name": "Port-channel1", "is-agport-suspend": True})
                elif change == "wrong-lag":
                    details["agport-if-name"] = "Po99"
                else:
                    row["admin-mode"] = "admin-trunk"
                found = cisco.collect(FixtureClient(values), use_ntc_defaults=True)
                self.assertIsNone(bundle(found))
                self.assertNotIn("inference", settings(found))

    def test_absent_hardware_prevents_actual_resolution_and_down_guessing(self):
        for ready in (False, True):
            with self.subTest(ready=ready):
                values, row = operational_values("oper-down", ready=ready)
                row.pop("hardware-present")
                found = cisco.collect(FixtureClient(values), use_ntc_defaults=True)
                self.assertIsNone(bundle(found))
                self.assertNotIn("inference", settings(found))

    def test_matching_short_aggregate_name_uses_only_the_members_own_mode(self):
        values, row = operational_values("oper-trunk")
        native_row(values, "TwoGigabitEthernet", "1/0/35")[
            "Cisco-IOS-XE-ethernet:channel-group"
        ] = {"number": 1, "mode": "active"}
        row["port-details"].update({"agport-if-name": "Po1", "is-agport-suspend": False})
        found = cisco.collect(FixtureClient(values))
        self.assertEqual(bundle(found)["mode"], "tagged-all")
        # Only one operational row exists. The LAG receives no inferred actual
        # mode from this member; its explicit configuration remains independent.
        self.assertNotIn("operational_mode", settings(found, "Port-channel1"))

    def test_known_static_configuration_remains_usable_when_actual_mode_is_down_or_unknown(self):
        for mode in ("oper-down", "oper-unknown"):
            with self.subTest(mode=mode):
                values, row = operational_values(mode, "admin-stat-acc", ready=False)
                native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
                    "switchport": {"mode": {"access": {}}, "access": {"vlan": {"vlan": 2}}}
                }
                found = cisco.collect(FixtureClient(values))
                self.assertEqual(bundle(found)["mode"], "access")
                self.assertEqual(bundle(found)["untagged_vid"], 2)
                self.assertNotIn("inference", settings(found))

    def test_namespaced_enums_retain_their_documented_meaning(self):
        values, row = operational_values()
        row["admin-mode"] = oper.MODULE + ":admin-dyn-auto"
        row["port-details"]["oper-mode"] = oper.MODULE + ":oper-dyn-acc"
        row["port-details"]["voice-state"] = oper.MODULE + ":voice-none"
        self.assertEqual(bundle(cisco.collect(FixtureClient(values)))["mode"], "access")

    def test_foreign_operational_enum_cannot_approve_a_static_or_dynamic_bundle(self):
        for static in (False, True):
            with self.subTest(static=static):
                values, row = operational_values("unrelated:oper-pvlan-host")
                if static:
                    row["admin-mode"] = "admin-stat-acc"
                    native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
                        "switchport": {"mode": {"access": {}}, "access": {"vlan": {"vlan": 2}}}
                    }
                self.assertIsNone(
                    bundle(cisco.collect(FixtureClient(values), use_ntc_defaults=True))
                )

    def test_populated_mode_is_preserved_when_actual_discovery_differs(self):
        values, _ = operational_values()
        discovered = cisco.collect(FixtureClient(values))
        before = inventory(discovered)
        next(row for row in before["interfaces"] if row["name"] == PORT)["mode"] = "tagged-all"
        planned = planner.plan_vlans(discovered, before)
        self.assertFalse(planned["errors"])
        self.assertNotIn(PORT, {row["name"] for row in planned["assignments"]})
        self.assertTrue(
            any(row["name"] == PORT and row["field"] == "mode" for row in planned["conflicts"])
        )

    def test_actual_mode_survives_an_unavailable_interface_configuration_row(self):
        values, _ = operational_values()
        native = values[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"]
        native["TwoGigabitEthernet"] = [
            row for row in native["TwoGigabitEthernet"] if row["name"] != "1/0/35"
        ]
        found = cisco.collect(FixtureClient(values))
        observed = next(
            row for row in found["layer2"]["operational_interfaces"] if row["name"] == PORT
        )
        self.assertEqual(observed["operational_mode"], "access")
        self.assertIsNone(bundle(found))
        self.assertNotIn(PORT, {row["name"] for row in found["layer2"]["settings"]})
        planned = planner.plan_vlans(found, inventory(found))
        self.assertFalse(planned["errors"])
        self.assertEqual(planned["summary"]["switching_operational"], 1)
        self.assertEqual(planned["summary"]["switching_dynamic_resolved"], 0)

    def test_malformed_library_triggers_a_valid_probe_without_a_claimed_revision(self):
        for entry in (
            {},
            {"name": [oper.MODULE]},
            {"name": oper.MODULE, "unrelated:revision": "2024-03-01"},
            {"name": oper.MODULE, "ietf-yang-library:name": oper.MODULE},
        ):
            with self.subTest(entry=entry):
                values, _ = operational_values()
                values[cisco.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]["module"] = [
                    {"name": "Cisco-IOS-XE-native", "revision": "2023-08-20"},
                    {"name": oper.MODULE, "revision": "2024-03-01"},
                    entry,
                ]
                client = FixtureClient(values)
                found = cisco.collect(client)
                source = found["layer2"]["operational_source"]
                self.assertEqual(source["status"], "available")
                self.assertEqual(source["capability_status"], "unknown")
                self.assertTrue(source["probed_without_advertisement"])
                self.assertIsNone(source["revision"])
                self.assertTrue(any(path.startswith(oper.PATH) for path in client.requests))
                self.assertEqual(bundle(found)["mode"], "access")
                self.assertIsNone(bundle(found)["source"]["operational_mode"]["revision"])
                self.assertEqual(found["evidence"]["modules"], {})

    def test_unavailable_library_probes_valid_json_with_bounded_read_on_supported_releases(self):
        class UnknownLibraryClient(FixtureClient):
            def __init__(self, values):
                super().__init__(values)
                self.probe_options = []

            def get(self, path, **kwargs):
                if path.startswith(cisco.YANG_LIBRARY_PATH):
                    raise cisco.RestconfError("secret-response-body", status_code=503)
                if path.startswith(oper.PATH):
                    self.probe_options.append(kwargs)
                return super().get(path, **kwargs)

        for release in ("17.12.8", "17.15.1", "17.18.1"):
            with self.subTest(release=release):
                values, _ = operational_values()
                for row in values[cisco.INSTALL_PATH][
                    "Cisco-IOS-XE-install-oper:install-location-information"
                ]:
                    for version in row.get("install-version-info", []):
                        version["version"] = release
                # Explicit configuration makes this test independent of release defaults.
                native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
                    "switchport": {"mode": {"dynamic": "auto"}, "access": {"vlan": {"vlan": 2}}}
                }
                client = UnknownLibraryClient(values)
                found = cisco.collect(client)
                source = found["layer2"]["operational_source"]
                self.assertEqual(source["status"], "available")
                self.assertEqual(source["capability_status"], "unknown")
                self.assertTrue(source["probed_without_advertisement"])
                self.assertIsNone(source["revision"])
                self.assertEqual(client.probe_options, [{"timeout": 15}])
                self.assertEqual(bundle(found)["mode"], "access")
                self.assertEqual(bundle(found)["untagged_vid"], 2)
                self.assertEqual(len(found["interfaces"]), 58)
                self.assertEqual(found["evidence"]["modules"], {})
                self.assertNotIn("secret-response-body", str(found["warnings"]))

    def test_known_unadvertised_module_skips_probe_and_keeps_native_configuration(self):
        values, _ = operational_values()
        library = values[cisco.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]
        library["module"] = [row for row in library["module"] if row["name"] != oper.MODULE]
        client = FixtureClient(values)
        found = cisco.collect(client)
        self.assertEqual(found["layer2"]["operational_source"]["status"], "not-advertised")
        self.assertFalse(any(path.startswith(oper.PATH) for path in client.requests))
        self.assertEqual(len(found["layer2"]["interfaces"]), 19)
        self.assertIsNone(bundle(found))

    def test_failed_optional_probe_preserves_core_and_explicit_native_config(self):
        for status in (None, 200, 201, 299, 401, 403, 404, 501, 503):
            with self.subTest(status=status):
                values, _ = operational_values()
                values[cisco.YANG_LIBRARY_PATH] = {}

                class FailedProbeClient(FixtureClient):
                    def __init__(self, payloads, failure_status):
                        super().__init__(payloads)
                        self.failure_status = failure_status

                    def get(self, path, **kwargs):
                        if path.startswith(oper.PATH):
                            raise cisco.RestconfError(
                                "secret-response-body", status_code=self.failure_status
                            )
                        return super().get(path, **kwargs)

                found = cisco.collect(FailedProbeClient(values, status))
                source = found["layer2"]["operational_source"]
                self.assertEqual(
                    source["status"],
                    "invalid"
                    if status is not None and 200 <= status < 300
                    else "unsupported"
                    if status in (404, 501)
                    else "unavailable",
                )
                self.assertEqual(source["capability_status"], "unknown")
                self.assertEqual(found["layer2"]["operational_interfaces"], [])
                self.assertEqual(len(found["interfaces"]), 58)
                self.assertEqual(len(found["layer2"]["interfaces"]), 19)
                self.assertIsNone(bundle(found))
                self.assertNotIn("secret-response-body", str(found["warnings"]))

    def test_malformed_successful_http_body_blocks_ntc_even_after_a_filter_retry(self):
        class MalformedBodyClient(FixtureClient):
            def __init__(self, values, retry, body_kind):
                super().__init__(values)
                self.retry = retry
                self.body_kind = body_kind
                self.probe_requests = []

            def get(self, path, **kwargs):
                if path.startswith(oper.PATH):
                    self.probe_requests.append(path)
                    status = 400 if self.retry and len(self.probe_requests) == 1 else 200
                    self.requests.append(path)
                    self.trace.append({"path": path, "status": status})
                    raise cisco.RestconfError(
                        "secret-response-body: " + self.body_kind, status_code=status
                    )
                return super().get(path, **kwargs)

        for retry in (False, True):
            for body_kind in ("non-JSON response", "JSON array instead of object"):
                with self.subTest(retry=retry, body_kind=body_kind):
                    values, _ = operational_values("oper-down", ready=False)
                    values[cisco.YANG_LIBRARY_PATH] = {}
                    client = MalformedBodyClient(values, retry, body_kind)
                    found = cisco.collect(client, use_ntc_defaults=True)
                    source = found["layer2"]["operational_source"]
                    self.assertEqual(source["status"], "invalid")
                    self.assertEqual(source["http_status"], 200)
                    self.assertTrue(source["reason"])
                    self.assertEqual(found["layer2"]["operational_interfaces"], [])
                    self.assertIsNone(bundle(found))
                    self.assertFalse(any("inference" in row for row in found["layer2"]["settings"]))
                    self.assertFalse(
                        any(row.get("inferred") for row in found["layer2"]["interfaces"])
                    )
                    self.assertEqual(len(found["layer2"]["interfaces"]), 19)
                    self.assertEqual(len(found["interfaces"]), 58)
                    self.assertEqual(
                        client.probe_requests,
                        [oper.PATH + "?fields=" + oper.FIELDS] + ([oper.PATH] if retry else []),
                    )
                    self.assertNotIn("secret-response-body", str(source) + str(found["warnings"]))
                    planned = planner.plan_vlans(found, inventory(found))
                    self.assertFalse(planned["errors"])
                    self.assertEqual(planned["summary"]["switching_inferred"], 0)
                    self.assertEqual(planned["summary"]["interface_vlan_assignments_inferred"], 0)
                    self.assertEqual(len(planned["assignments"]), 19)
                    self.assertNotIn(PORT, {row["name"] for row in planned["assignments"]})

    def test_required_core_decode_failures_still_propagate(self):
        class BadCoreClient(FixtureClient):
            def __init__(self, values, failed_path):
                super().__init__(values)
                self.failed_path = failed_path

            def get(self, path, **kwargs):
                if path.split("?", 1)[0] == self.failed_path:
                    raise cisco.RestconfError("Malformed successful core response", status_code=200)
                return super().get(path, **kwargs)

        for path in (
            cisco.HOSTNAME_PATH,
            cisco.HARDWARE_PATH,
            cisco.INSTALL_PATH,
            cisco.INTERFACES_PATH,
        ):
            with self.subTest(path=path):
                values, _ = operational_values()
                with self.assertRaises(cisco.RestconfError):
                    cisco.collect(BadCoreClient(values, path), use_ntc_defaults=True)

    def test_invalid_late_optional_row_discards_all_facts_and_blocks_ntc_guessing(self):
        for advertised in (False, True):
            with self.subTest(advertised=advertised):
                values, row = operational_values("oper-down", ready=False)
                if not advertised:
                    values[cisco.YANG_LIBRARY_PATH] = {}
                rows = values[oper.PATH][oper.MODULE + ":switchport-oper-data"]["switchport-info"]
                rows.append({**row, "if-name": "secret-response-body"})
                found = cisco.collect(FixtureClient(values), use_ntc_defaults=True)
                self.assertEqual(found["layer2"]["operational_source"]["status"], "invalid")
                self.assertEqual(found["layer2"]["operational_interfaces"], [])
                self.assertIsNone(bundle(found))
                self.assertFalse(any(row.get("inferred") for row in found["layer2"]["interfaces"]))
                self.assertFalse(any("inference" in row for row in found["layer2"]["settings"]))
                self.assertEqual(len(found["layer2"]["interfaces"]), 19)
                self.assertEqual(len(found["interfaces"]), 58)
                self.assertNotIn("secret-response-body", str(found["layer2"]["operational_source"]))
                self.assertNotIn("secret-response-body", str(found["warnings"]))
                planned = planner.plan_vlans(found, inventory(found))
                self.assertFalse(planned["errors"])
                self.assertEqual(planned["summary"]["switching_operational"], 0)
                self.assertEqual(planned["summary"]["switching_inferred"], 0)
                self.assertNotIn(PORT, {row["name"] for row in planned["assignments"]})

    def test_invalid_optional_source_preserves_populated_inventory(self):
        values, _ = operational_values(ready=False)
        # A successful 200 wrong envelope is invalid rather than evidence of defaults.
        values[oper.PATH] = {}
        discovered = cisco.collect(FixtureClient(values), use_ntc_defaults=True)
        before = inventory(discovered)
        existing = next(row for row in before["interfaces"] if row["name"] == PORT)
        existing.update({"mode": "tagged-all", "untagged_vlan_id": "operator-vlan"})
        planned = planner.plan_vlans(discovered, before)
        self.assertFalse(planned["errors"])
        self.assertNotIn(PORT, {row["name"] for row in planned["assignments"]})
        after = apply_to_snapshot(planned, before)
        self.assertEqual(next(row for row in after["interfaces"] if row["name"] == PORT), existing)

    def test_required_core_sources_still_block_before_optional_fallback(self):
        for path in (cisco.HOSTNAME_PATH, cisco.INSTALL_PATH, cisco.INTERFACES_PATH):
            with self.subTest(path=path):
                values, _ = operational_values()
                values[path] = {}
                values[cisco.YANG_LIBRARY_PATH] = {}
                values[oper.PATH] = {}
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(values), use_ntc_defaults=True)

    def test_optional_probe_cancellation_and_programming_errors_still_propagate(self):
        for error in (RuntimeError("worker time limit"), TypeError("programming error")):
            with self.subTest(error=type(error).__name__):
                values, _ = operational_values()
                values[cisco.YANG_LIBRARY_PATH] = {}

                class BrokenProbeClient(FixtureClient):
                    def __init__(self, payloads, failure):
                        super().__init__(payloads)
                        self.failure = failure

                    def get(self, path, **kwargs):
                        if path.startswith(oper.PATH):
                            raise self.failure
                        return super().get(path, **kwargs)

                with self.assertRaises(type(error)):
                    cisco.collect(BrokenProbeClient(values, error))

    def test_qualified_library_leaves_still_establish_actual_capability(self):
        values, _ = operational_values()
        library = values[cisco.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]
        library["ietf-yang-library:module"] = [
            {"ietf-yang-library:name": row["name"], "ietf-yang-library:revision": row["revision"]}
            for row in library.pop("module")
        ]
        found = cisco.collect(FixtureClient(values))
        self.assertEqual(found["layer2"]["operational_source"]["status"], "available")
        self.assertEqual(bundle(found)["mode"], "access")

    def test_known_actual_mode_with_unknown_vlan_policy_is_retained_without_assignment(self):
        values, _ = operational_values("oper-trunk")
        native_row(values, "TwoGigabitEthernet", "1/0/35")["switchport-config"] = {
            "switchport": {
                "mode": {"dynamic": "auto"},
                "trunk": {"native": {"vlan": {"vlan-id": 2, "tag": False}}},
            }
        }
        found = cisco.collect(FixtureClient(values), use_ntc_defaults=True)
        self.assertEqual(settings(found)["operational_mode"], "trunk")
        self.assertIsNone(bundle(found))
        self.assertNotIn("inference", settings(found))
