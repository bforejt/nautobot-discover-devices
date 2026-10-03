"""Explicit structured joins for StackWise membership and physical capability."""

import unittest
from copy import deepcopy

from tests._loader import fixture, load
from tests.test_cisco_iosxe import FixtureClient, fixture_payloads

stack = load("adapters.cisco_stack")
cisco = load("adapters.cisco_iosxe")


def stack_payloads():
    payloads = fixture_payloads()
    hardware = payloads[cisco.HARDWARE_PATH][
        "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
    ]["device-hardware"]
    hardware["device-inventory"].append(
        {
            **hardware["device-inventory"][0],
            "hw-dev-index": 8,
            "serial-number": "LAB93000002",
            "dev-name": "Switch 2",
        }
    )
    hardware["device-inventory"].reverse()
    payloads[stack.STACK_PATH] = fixture("iosxe_stack_oper.json")
    installs = payloads[cisco.INSTALL_PATH][
        "Cisco-IOS-XE-install-oper:install-location-information"
    ]
    installs.append({**deepcopy(installs[0]), "chassis": 2})
    rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"]
    port = next(
        row
        for row in rows
        if cisco.canonical_interface_name(row["name"]) == "TwoGigabitEthernet1/0/1"
    )
    rows.append({**deepcopy(port), "name": "TwoGigabitEthernet2/0/1"})
    return payloads


def inventory(payloads):
    return payloads[cisco.HARDWARE_PATH]["Cisco-IOS-XE-device-hardware-oper:device-hardware-data"][
        "device-hardware"
    ]["device-inventory"]


def nodes(payloads):
    return payloads[stack.STACK_PATH]["Cisco-IOS-XE-stack-oper:stack-oper-data"]["stack-node"]


class StackCollectionTests(unittest.TestCase):
    def test_active_second_member_and_reverse_inventory_use_serial_not_index_or_order(self):
        payloads = stack_payloads()
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(result["identity"]["serial"], "LAB93000002")
        self.assertEqual(result["stack"]["active_position"], 2)
        self.assertTrue(result["stack"]["is_stack"])
        self.assertEqual(
            [(row["position"], row["serial"]) for row in result["stack"]["members"]],
            [(1, "LAB93000001"), (2, "LAB93000002")],
        )
        self.assertEqual(
            result["stack"]["active_identity"]["sources"]["identity"]["inventory_index"], 8
        )
        expected = stack.collect(
            FixtureClient(payloads), inventory(payloads), hostname="switch", warnings=[]
        )["members"]
        for order in (list(reversed(inventory(payloads))), inventory(payloads)):
            self.assertEqual(
                stack.collect(FixtureClient(payloads), order, hostname="switch", warnings=[])[
                    "members"
                ],
                expected,
            )

    def test_provisioned_removed_unprovisioned_slots_do_not_become_members(self):
        for state in stack.ABSENT_STATES:
            with self.subTest(state=state):
                payloads = stack_payloads()
                nodes(payloads).append(
                    {
                        "chassis-number": 3,
                        "role": "role-unknown",
                        "node-state": state,
                        "stack-mode": "mode-stackwise-rear",
                        "priority": 1,
                    }
                )
                result = cisco.collect(FixtureClient(payloads))["stack"]
                self.assertEqual(len(result["members"]), 2)
                self.assertEqual(result["absent_members"][0]["position"], 3)

    def test_one_physical_chassis_with_provisioned_slots_remains_standalone(self):
        payloads = fixture_payloads()
        payloads[stack.STACK_PATH] = fixture("iosxe_stack_oper.json")
        nodes(payloads)[0].update(
            {"node-state": "state-provisioned", "serial-number": "", "role": "role-unknown"}
        )
        nodes(payloads)[1]["role"] = "role-active"
        result = cisco.collect(FixtureClient(payloads))
        self.assertFalse(result["stack"]["is_stack"])
        self.assertEqual(len(result["stack"]["members"]), 1)
        self.assertTrue(result["components"]["items"])
        self.assertEqual(len(result["console_ports"]["items"]), 2)

    def test_stack_physical_components_console_and_management_writes_are_deferred(self):
        client = FixtureClient(stack_payloads())
        result = cisco.collect(client)
        self.assertEqual(result["components"]["items"], [])
        self.assertTrue(result["components"]["unresolved"])
        self.assertEqual(result["console_ports"]["items"], [])
        self.assertEqual(result["management"]["interfaces"], [])
        self.assertTrue(result["evidence"]["inventory"])
        self.assertNotIn(
            cisco.cisco_components.PLATFORM_PATH,
            [request.split("?", 1)[0] for request in client.requests],
        )
        self.assertFalse(any(row.get("mgmt_only") for row in result["interfaces"]))

    def test_member_specific_model_controls_each_physical_type(self):
        payloads = stack_payloads()
        chassis = next(row for row in inventory(payloads) if row.get("dev-name") == "Switch 2")
        chassis["part-number"] = "C9300-24T"
        ports = {row["name"]: row for row in cisco.collect(FixtureClient(payloads))["interfaces"]}
        self.assertEqual(ports["TwoGigabitEthernet1/0/1"]["type"], "2.5gbase-t")
        self.assertIsNone(ports["TwoGigabitEthernet2/0/1"]["type"])
        self.assertEqual(ports["TwoGigabitEthernet2/0/1"]["stack_member"], 2)
        self.assertIsNone(ports["GigabitEthernet0/0"]["type"])

    def test_uplink_profile_inventory_is_scoped_to_its_real_member(self):
        payloads = stack_payloads()
        rows = payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ]
        rows.append(
            {
                "name": "GigabitEthernet2/1/1",
                "oper-status": "if-oper-state-lower-layer-down",
                "admin-status": "if-state-up",
            }
        )
        ports = {row["name"]: row for row in cisco.collect(FixtureClient(payloads))["interfaces"]}
        self.assertEqual(ports["GigabitEthernet1/1/1"]["type"], "1000base-x-sfp")
        self.assertIsNone(ports["GigabitEthernet2/1/1"]["type"])

    def test_unknown_present_physical_member_aborts(self):
        payloads = stack_payloads()
        payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ].append({"name": "GigabitEthernet3/0/1"})
        with self.assertRaisesRegex(cisco.DiscoveryError, "physical stack owner"):
            cisco.collect(FixtureClient(payloads))

    def test_not_present_interface_on_absent_member_is_excluded(self):
        payloads = stack_payloads()
        payloads[cisco.INTERFACES_PATH]["Cisco-IOS-XE-interfaces-oper:interfaces"][
            "interface"
        ].append({"name": "GigabitEthernet3/0/1", "oper-status": "if-oper-state-not-present"})
        result = cisco.collect(FixtureClient(payloads))
        self.assertIn(
            "GigabitEthernet3/0/1", [row["name"] for row in result["excluded_interfaces"]]
        )

    def test_duplicate_chassis_serial_aborts(self):
        payloads = stack_payloads()
        chassis = [row for row in inventory(payloads) if row["hw-type"] == "hw-type-chassis"]
        chassis[1]["serial-number"] = chassis[0]["serial-number"]
        with self.assertRaisesRegex(cisco.DiscoveryError, "repeats a chassis serial"):
            cisco.collect(FixtureClient(payloads))

    def test_duplicate_node_serial_or_position_aborts(self):
        for field in ("serial-number", "chassis-number"):
            with self.subTest(field=field):
                payloads = stack_payloads()
                nodes(payloads)[1][field] = nodes(payloads)[0][field]
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_named_member_disagrees_with_serial_join_aborts(self):
        payloads = stack_payloads()
        next(row for row in inventory(payloads) if row.get("dev-name") == "Switch 2")[
            "dev-name"
        ] = "Switch 3"
        with self.assertRaisesRegex(cisco.DiscoveryError, "hardware Switch name"):
            cisco.collect(FixtureClient(payloads))

    def test_ready_node_without_physical_chassis_and_missing_physical_node_abort(self):
        for change in ("missing-hardware", "missing-node"):
            with self.subTest(change=change):
                payloads = stack_payloads()
                if change == "missing-hardware":
                    nodes(payloads)[0]["serial-number"] = "UNCONFIRMED"
                else:
                    nodes(payloads).pop()
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_unsupported_mode_nonready_or_unknown_role_blocks_multichassis(self):
        for field, value in (
            ("stack-mode", "mode-stackwise-virtual"),
            ("node-state", "state-initializing"),
            ("role", "role-unknown"),
        ):
            with self.subTest(field=field):
                payloads = stack_payloads()
                nodes(payloads)[0][field] = value
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_zero_or_multiple_active_members_abort(self):
        for role in ("role-member", "role-active"):
            payloads = stack_payloads()
            if role == "role-member":
                nodes(payloads)[0]["role"] = role
            else:
                nodes(payloads)[1]["role"] = role
            with self.assertRaisesRegex(cisco.DiscoveryError, "exactly one active"):
                cisco.collect(FixtureClient(payloads))

    def test_absent_node_cannot_claim_present_hardware(self):
        payloads = stack_payloads()
        nodes(payloads)[0]["node-state"] = "state-provisioned"
        with self.assertRaisesRegex(cisco.DiscoveryError, "contradicts physical"):
            cisco.collect(FixtureClient(payloads))

    def test_running_release_must_be_known_and_equal_for_every_member(self):
        for change in ("conflict", "present-only", "missing"):
            with self.subTest(change=change):
                payloads = stack_payloads()
                rows = payloads[cisco.INSTALL_PATH][
                    "Cisco-IOS-XE-install-oper:install-location-information"
                ]
                if change == "conflict":
                    rows[1]["install-version-info"][0]["version"] = "17.15.06.0.123"
                elif change == "present-only":
                    rows[1]["install-version-info"][0]["current"] = "install-version-state-present"
                else:
                    rows.pop()
                with self.assertRaises(cisco.DiscoveryError):
                    cisco.collect(FixtureClient(payloads))

    def test_install_present_image_is_not_used_and_evidence_retains_member_keys(self):
        result = cisco.collect(FixtureClient(stack_payloads()))
        self.assertEqual(result["identity"]["software_version"], "17.12.08")
        self.assertEqual({row["chassis"] for row in result["evidence"]["install"]}, {1, 2})

    def test_stack_does_not_apply_a_singular_chassis_duplex_default_to_members(self):
        result = cisco.collect(FixtureClient(stack_payloads()))
        self.assertFalse(
            any(
                row["source"]["basis"] == "documented-default"
                for row in result["evidence"]["sources"]["configured_duplex"]["interfaces"]
            )
        )

    def test_explicit_member_duplex_is_loaded_without_a_chassis_default(self):
        payloads = stack_payloads()
        container = payloads[cisco.NATIVE_INTERFACES_PATH]["Cisco-IOS-XE-native:interface"]
        container["TwoGigabitEthernet"].append(
            {"name": "2/0/1", "Cisco-IOS-XE-ethernet:duplex": "full"}
        )
        result = cisco.collect(FixtureClient(payloads))
        port = next(row for row in result["interfaces"] if row["name"] == "TwoGigabitEthernet2/0/1")
        self.assertEqual(port["duplex"], "full")
        self.assertEqual(port["duplex_source"]["basis"], "explicit")

    def test_optional_single_chassis_stack_transport_failure_does_not_block_discovery(self):
        transport = load("transport_restconf")

        class MissingStack(FixtureClient):
            def get(self, path, **kwargs):
                if path.split("?", 1)[0] == stack.STACK_PATH:
                    raise transport.RestconfError("sanitized", status_code=404)
                return super().get(path, **kwargs)

        result = cisco.collect(MissingStack())
        self.assertFalse(result["stack"]["is_stack"])
        self.assertTrue(result["stack"]["unresolved"])
        with self.assertRaises(cisco.DiscoveryError):
            cisco.collect(MissingStack(stack_payloads()))

    def test_uint8_fields_reject_bool_strings_and_out_of_range_values(self):
        for field in ("chassis-number", "priority"):
            for value in (True, "2", -1, 256):
                with self.subTest(field=field, value=value):
                    payloads = stack_payloads()
                    nodes(payloads)[0][field] = value
                    with self.assertRaises(cisco.DiscoveryError):
                        cisco.collect(FixtureClient(payloads))

    def test_optional_priority_stays_blank_instead_of_inventing_default(self):
        payloads = stack_payloads()
        nodes(payloads)[0].pop("priority")
        result = cisco.collect(FixtureClient(payloads))
        self.assertIsNone(result["stack"]["members"][1]["priority"])

    def test_stack_source_revisions_are_recorded_after_shared_yang_query(self):
        payloads = stack_payloads()
        payloads[cisco.YANG_LIBRARY_PATH]["ietf-yang-library:modules-state"]["module"].append(
            {"name": "Cisco-IOS-XE-stack-oper", "revision": "2022-11-01"}
        )
        result = cisco.collect(FixtureClient(payloads))["stack"]
        self.assertEqual(result["source"]["revision"], "2022-11-01")
        self.assertEqual(result["members"][1]["sources"]["membership"]["revision"], "2022-11-01")
        self.assertEqual(
            result["active_identity"]["sources"]["membership"]["revision"], "2022-11-01"
        )

    def test_qualified_stack_children_and_leaves_preserve_member_identity(self):
        payloads = stack_payloads()
        container = payloads[stack.STACK_PATH]["Cisco-IOS-XE-stack-oper:stack-oper-data"]
        for row in container["stack-node"]:
            qualified = {"Cisco-IOS-XE-stack-oper:" + key: value for key, value in row.items()}
            row.clear()
            row.update(qualified)
        payloads[stack.STACK_PATH]["Cisco-IOS-XE-stack-oper:stack-oper-data"] = {
            "Cisco-IOS-XE-stack-oper:" + key: value for key, value in container.items()
        }
        result = cisco.collect(FixtureClient(payloads))
        self.assertTrue(result["stack"]["is_stack"])
        self.assertEqual(result["stack"]["active_position"], 2)

    def test_duplicate_namespace_children_and_leaves_or_foreign_namespace_abort(self):
        for scope in ("container", "leaf", "foreign"):
            with self.subTest(scope=scope):
                payloads = stack_payloads()
                container = payloads[stack.STACK_PATH]["Cisco-IOS-XE-stack-oper:stack-oper-data"]
                if scope == "container":
                    container["Cisco-IOS-XE-stack-oper:stack-node"] = deepcopy(
                        container["stack-node"]
                    )
                elif scope == "leaf":
                    nodes(payloads)[0]["Cisco-IOS-XE-stack-oper:chassis-number"] = 2
                else:
                    nodes(payloads)[0]["foreign:priority"] = nodes(payloads)[0].pop("priority")
                with self.assertRaisesRegex(cisco.DiscoveryError, "YANG namespaces"):
                    cisco.collect(FixtureClient(payloads))

    def test_serial_case_disagreement_is_not_silently_folded(self):
        payloads = stack_payloads()
        nodes(payloads)[0]["serial-number"] = nodes(payloads)[0]["serial-number"].lower()
        with self.assertRaisesRegex(cisco.DiscoveryError, "does not uniquely match"):
            cisco.collect(FixtureClient(payloads))

    def test_serial_padding_is_trimmed_without_changing_identity_case(self):
        payloads = stack_payloads()
        nodes(payloads)[0]["serial-number"] = "  LAB93000002  "
        next(row for row in inventory(payloads) if row.get("dev-name") == "Switch 2")[
            "serial-number"
        ] = " LAB93000002 "
        result = cisco.collect(FixtureClient(payloads))
        self.assertEqual(result["identity"]["serial"], "LAB93000002")


if __name__ == "__main__":
    unittest.main()
