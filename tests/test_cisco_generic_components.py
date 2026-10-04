"""Matrix-independent identities and explicit component containment regressions."""

import unittest
from copy import deepcopy

from tests._loader import load

generic = load("adapters.cisco_generic_components")
cisco = load("adapters.cisco_iosxe")


def observed_interface(name, **values):
    """Explicit schema classification, independent of a Nautobot hardware type."""
    name = cisco.canonical_interface_name(name)
    return {
        "name": name,
        "type": "other",
        "physical_ethernet": True,
        "physical_ethernet_source": {
            "module": "Cisco-IOS-XE-interfaces-oper",
            "path": "interfaces/interface/interface-type",
            "value": "iana-iftype-ethernet-csmacd",
            "name": name,
        },
        **values,
    }


def hardware(name="reported-bay-X", *, hw_type="hw-type-pim", model="NEW-PID", serial="NEW001"):
    return {
        "name": name,
        "hw_type": hw_type,
        "hardware_class": "hw-class-physical",
        "inventory_index": 712,
        "model": model,
        "serial": serial,
        "hardware_revision": "HW1",
        "field_replaceable": True,
    }


def component(
    name="reported-bay-X",
    *,
    model="NEW-PID",
    serial="NEW001",
    platform_type="comp-module",
    parent="opaque chassis",
):
    return {
        "name": name,
        "model": model,
        "serial": serial,
        "manufacturer": "Actual Manufacturer",
        "hardware_revision": "FW2",
        "platform_type": platform_type,
        "platform_id": "independent-ID",
        "parent": parent,
        "location": "undocumented/encoding/999",
        "empty": False,
        "removable": True,
        "oper_status": "status-active",
        "status_description": "status-desc-ok",
        "platform_properties": [{"name": "uninterpreted", "value": {"string": "unknown"}}],
    }


def root_and_owners():
    root = component(
        "opaque chassis",
        model="C9350-ILLUSTRATIVE",
        serial="CHASSIS001",
        platform_type="comp-chassis",
        parent=None,
    )
    root["removable"] = False
    owner = {
        "model": root["model"],
        "serial": root["serial"],
        "position": 3,
        "root": root,
        "identity_source": {"hw_type": "hw-type-chassis", "inventory_index": 1},
        "membership_source": {"membership": "explicit structured member 3"},
    }
    return root, {3: owner}


def discover(flat=None, parts=None, *, interfaces=(), existing_items=(), existing_unresolved=()):
    root, owners = root_and_owners()
    return generic.collect(
        [hardware()] if flat is None else flat,
        [root, component()] if parts is None else [root, *parts],
        owners,
        interfaces=list(interfaces),
        existing_items=list(existing_items),
        existing_unresolved=list(existing_unresolved),
    )


class GenericComponentTests(unittest.TestCase):
    def test_unlisted_chassis_and_module_use_explicit_fields_without_profiles(self):
        result = discover()
        self.assertEqual(len(result["identities"]), 1)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["unresolved"], [])
        item = result["items"][0]
        self.assertEqual(item["manufacturer"], "Actual Manufacturer")
        self.assertEqual(item["chassis_model"], "C9350-ILLUSTRATIVE")
        self.assertEqual(item["member"], 3)
        self.assertEqual(item["device_serial"], "CHASSIS001")
        self.assertEqual(item["hardware_revision"], "HW1")
        self.assertEqual(item["parent_key"], None)
        self.assertEqual(item["interfaces"], [])
        self.assertNotIn("power_ports", item)
        self.assertEqual(
            item["bay"],
            {"name": "reported-bay-X", "position": "reported-bay-X", "label": ""},
        )
        self.assertEqual(item["source"]["manufacturer"]["field"], "state/mfg-name")
        self.assertEqual(item["source"]["manufacturer"]["component"], "reported-bay-X")
        self.assertEqual(item["source"]["manufacturer"]["value"], "Actual Manufacturer")
        self.assertEqual(item["observations"], component())
        self.assertEqual(item["hardware_observations"], hardware())
        self.assertEqual(result["handled_hardware"], {("reported-bay-X", "NEW-PID", "NEW001")})
        self.assertEqual(result["handled_platform_names"], {"reported-bay-X"})

    def test_attachment_identity_does_not_change_when_occupant_pid_or_serial_changes(self):
        first = discover()["items"][0]
        second = discover(
            [hardware(model="REPLACEMENT", serial="REPLACED001")],
            [component(model="REPLACEMENT", serial="REPLACED001")],
        )["items"][0]
        self.assertEqual(first["key"], second["key"])
        self.assertEqual(first["bay"], second["bay"])
        self.assertNotEqual(first["serial"], second["serial"])

    def test_supported_schema_classes_are_independent_of_part_numbers(self):
        for hw_type, platform_type, kind in (
            ("hw-type-pim", "comp-linecard", "network-module"),
            ("hw-type-pem", "comp-power-supply", "power-supply"),
            ("hw-type-fantray", "comp-fan", "fan-tray"),
            ("hw-type-ssd", "comp-sed", "storage"),
        ):
            with self.subTest(hw_type=hw_type):
                result = discover(
                    [hardware(hw_type=hw_type)], [component(platform_type=platform_type)]
                )
                self.assertEqual(result["items"][0]["kind"], kind)
                self.assertNotIn("power_ports", result["items"][0])

    def test_direct_and_nested_transceivers_need_exact_observed_interface_evidence(self):
        module = component("new uplink")
        optic = component(
            "TwentyFiveGigE3/7/9",
            model="NEW-BIDI-PID",
            serial="BIDI001",
            platform_type="comp-transceiver",
            parent="new uplink",
        )
        flat = [
            hardware("new uplink"),
            hardware(
                "Twe3/7/9", hw_type="hw-type-transceiver", model="NEW-BIDI-PID", serial="BIDI001"
            ),
        ]
        result = discover(
            list(reversed(flat)),
            [optic, module],
            interfaces=[observed_interface("TwentyFiveGigE3/7/9", speed=1000000)],
        )
        self.assertEqual(len(result["items"]), 2)
        optic_item = next(item for item in result["items"] if item["kind"] == "transceiver")
        module_item = next(item for item in result["items"] if item["kind"] == "network-module")
        self.assertEqual(optic_item["parent_key"], module_item["key"])
        self.assertEqual(optic_item["interfaces"], [])
        self.assertNotIn("physical_type", optic_item["source"]["ownership"])
        self.assertEqual(
            optic_item["source"]["interface_classification"],
            observed_interface("TwentyFiveGigE3/7/9")["physical_ethernet_source"],
        )
        # A reported root parent supports device containment without asserting the
        # unknown uplink parent, cage type or maximum speed.
        optic["parent"] = "opaque chassis"
        direct = discover(
            [flat[1]], [optic], interfaces=[observed_interface("TwentyFiveGigE3/7/9")]
        )["items"][0]
        self.assertIsNone(direct["parent_key"])

    def test_nesting_under_existing_reviewed_module_retains_its_key(self):
        module = component("Reviewed Uplink")
        existing = {
            "key": "uplink:3/1",
            "kind": "network-module",
            "model": module["model"],
            "serial": module["serial"],
            "member": 3,
            "device_serial": "CHASSIS001",
            "observations": module,
        }
        optic = component(
            "GigabitEthernet3/1/2",
            model="NEW-BIDI",
            serial="OPTIC002",
            platform_type="comp-transceiver",
            parent=module["name"],
        )
        result = discover(
            [
                hardware("Reviewed Uplink"),
                hardware(
                    optic["name"],
                    hw_type="hw-type-transceiver",
                    model=optic["model"],
                    serial=optic["serial"],
                ),
            ],
            [module, optic],
            interfaces=[observed_interface(optic["name"])],
            existing_items=[existing],
        )
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(len(result["identities"]), 1)
        self.assertEqual(result["items"][0]["parent_key"], existing["key"])

    def test_unknown_containment_preserves_identity_catalog(self):
        for field, value in (
            ("parent", None),
            ("parent", "missing component"),
            ("platform_type", "comp-power-supply"),
            ("platform_type", None),
            ("empty", True),
            ("empty", None),
            ("removable", False),
            ("removable", None),
        ):
            with self.subTest(field=field, value=value):
                part = component()
                part[field] = value
                result = discover(parts=[part])
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)
                self.assertEqual(len(result["unresolved"]), 1)
                self.assertEqual(result["identities"][0]["kind"], "network-module")

    def test_replaceability_is_required_for_placement_only(self):
        for value in (None, False, "true", 1):
            with self.subTest(value=value):
                fact = hardware()
                fact["field_replaceable"] = value
                result = discover([fact])
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)

    def test_missing_or_virtual_identity_never_catalogs(self):
        for target, field, value in (
            ("hardware", "model", None),
            ("hardware", "serial", None),
            ("hardware", "hardware_class", None),
            ("hardware", "hardware_class", "hw-class-virtual"),
            ("platform", "manufacturer", None),
            ("platform", "manufacturer", ""),
        ):
            with self.subTest(target=target, field=field):
                fact, part = hardware(), component()
                (fact if target == "hardware" else part)[field] = value
                result = discover([fact], [part])
                self.assertEqual(result["items"], [])
                self.assertEqual(result["identities"], [])
                self.assertEqual(len(result["unresolved"]), 1)

    def test_duplicate_inventory_or_platform_identity_never_catalogs(self):
        for duplicate_hardware in (True, False):
            with self.subTest(duplicate_hardware=duplicate_hardware):
                fact, part = hardware(), component()
                facts = [fact, deepcopy(fact)] if duplicate_hardware else [fact]
                parts = [part] if duplicate_hardware else [part, {**part, "name": "alias"}]
                result = discover(facts, parts)
                self.assertEqual(result["items"], [])
                self.assertEqual(result["identities"], [])
                self.assertTrue(result["unresolved"])

    def test_platform_name_duplicate_never_claims_a_bay(self):
        result = discover(parts=[component(), component(model="OTHER", serial="OTHER001")])
        self.assertEqual(result["items"], [])
        self.assertEqual(result["identities"], [])
        self.assertIn("ambiguous", result["unresolved"][0]["reason"])

    def test_mismatched_platform_identity_is_unresolved(self):
        result = discover(parts=[component(serial="DIFFERENT")])
        self.assertEqual(result["items"], [])
        self.assertEqual(result["identities"], [])
        self.assertIn("identity", result["unresolved"][0]["reason"])

    def test_ambiguous_or_nonphysical_root_keeps_catalog_without_installation(self):
        root, owners = root_and_owners()
        for invalid in ("classification", "presence", "identity", "owners"):
            with self.subTest(invalid=invalid):
                new_root, new_owners = deepcopy(root), deepcopy(owners)
                if invalid == "classification":
                    new_root["platform_type"] = "comp-container"
                elif invalid == "presence":
                    new_root["empty"] = None
                elif invalid == "identity":
                    new_root["serial"] = "WRONG"
                else:
                    new_owners[4] = deepcopy(new_owners[3])
                new_owners[3]["root"] = new_root
                result = generic.collect(
                    [hardware()],
                    [new_root, component()],
                    new_owners,
                    interfaces=[],
                    existing_items=[],
                    existing_unresolved=[],
                )
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)

    def test_root_names_and_same_chassis_aliases_need_no_switch_name_convention(self):
        root, owners = root_and_owners()
        owners[3]["root"] = None
        result = generic.collect(
            [hardware()],
            [root, component()],
            owners,
            interfaces=[],
            existing_items=[],
            existing_unresolved=[],
        )
        self.assertEqual(len(result["items"]), 1)
        # A structured aggregate alias repeats the physical identity. An exact
        # unique state/parent reference still selects the reported root safely.
        switch_root = {**root, "name": "Switch1"}
        aggregate = {**root, "name": "c93xx Stack"}
        part = {**component(), "parent": "Switch1"}
        result = generic.collect(
            [hardware()],
            [switch_root, aggregate, part],
            owners,
            interfaces=[],
            existing_items=[],
            existing_unresolved=[],
        )
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["member"], 3)

    def test_parent_cycle_and_unresolved_parent_never_create_partial_children(self):
        for cycle in (True, False):
            with self.subTest(cycle=cycle):
                a = component("A", parent="B")
                b = component("B", model="OTHER", serial="B001", parent="A")
                if not cycle:
                    b["parent"] = "opaque chassis"
                    b["removable"] = None
                result = discover(
                    [hardware("A"), hardware("B", model="OTHER", serial="B001")], [a, b]
                )
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 2)
                self.assertEqual(len(result["unresolved"]), 2)

    def test_transceiver_missing_or_ambiguous_port_corroboration_keeps_identity(self):
        fact = hardware("Gi3/8/1", hw_type="hw-type-transceiver")
        part = component("GigabitEthernet3/8/1", platform_type="comp-transceiver")
        for interfaces, cname in (
            ([], part["name"]),
            ([observed_interface(part["name"]), observed_interface("Gi3/8/1")], part["name"]),
            ([observed_interface(part["name"])], "GigabitEthernet3/8/2"),
        ):
            with self.subTest(interfaces=interfaces, cname=cname):
                result = discover([fact], [{**part, "name": cname}], interfaces=interfaces)
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)

    def test_transceiver_logical_absent_and_different_owner_interfaces_stay_unplaced(self):
        name = "GigabitEthernet3/8/1"
        fact = hardware(name, hw_type="hw-type-transceiver")
        part = component(name, platform_type="comp-transceiver")
        for interface in (
            observed_interface(name, type="virtual"),
            observed_interface(name, type="lag"),
            observed_interface(name, present=False),
            observed_interface(name, stack_member=2),
        ):
            with self.subTest(interface=interface):
                result = discover([fact], [part], interfaces=[interface])
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)

    def test_transceiver_names_cannot_prove_physical_ports_by_themselves(self):
        name = "GigabitEthernet3/8/1"
        fact = hardware(name, hw_type="hw-type-transceiver")
        part = component(name, platform_type="comp-transceiver")
        source_fields = {
            "module": "Different-Module",
            "path": "unrelated/path",
            "value": "iana-iftype-l2vlan",
            "name": "GigabitEthernet3/8/2",
        }
        invalid = [
            {"name": name, "type": "other"},
            observed_interface(name, physical_ethernet=None),
            observed_interface(name, physical_ethernet=1),
            observed_interface(name, physical_ethernet_source=None),
            observed_interface(name, physical_ethernet_source=[]),
        ]
        for field, value in source_fields.items():
            interface = observed_interface(name)
            interface["physical_ethernet_source"][field] = value
            invalid.append(interface)
        for interface in invalid:
            with self.subTest(interface=interface):
                result = discover([fact], [part], interfaces=[interface])
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)
                self.assertIn("IANA", result["unresolved"][0]["reason"])

    def test_transceiver_unsupported_names_breakouts_and_subinterfaces_stay_unplaced(self):
        for name in (
            "GigabitEthernet3/8/1.42",
            "HundredGigE3/8/1/2",
            "Loopback0",
            "Port-channel3",
            "AppGigabitEthernet3/0/1",
            "UnknownPhysicalEthernet3/8/1",
            "GigabitEthernet3",
        ):
            with self.subTest(name=name):
                fact = hardware(name, hw_type="hw-type-transceiver")
                part = component(name, platform_type="comp-transceiver")
                result = discover([fact], [part], interfaces=[observed_interface(name)])
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)
                self.assertIn("supported physical", result["unresolved"][0]["reason"])

    def test_three_coordinate_interface_owner_is_checked_without_stack_member_fact(self):
        name = "TwentyFiveGigE2/7/9"
        fact = hardware(name, hw_type="hw-type-transceiver")
        part = component(name, platform_type="comp-transceiver")
        interface = observed_interface(name)
        self.assertNotIn("stack_member", interface)
        result = discover([fact], [part], interfaces=[interface])
        self.assertEqual(result["items"], [])
        self.assertEqual(len(result["identities"]), 1)
        self.assertIn("member", result["unresolved"][0]["reason"])

    def test_two_coordinate_interface_uses_verified_parent_without_member_guess(self):
        name = "TenGigabitEthernet7/9"
        fact = hardware(name, hw_type="hw-type-transceiver")
        part = component(name, platform_type="comp-transceiver")
        interface = observed_interface(name, type=None)
        result = discover([fact], [part], interfaces=[interface])
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["member"], 3)
        self.assertEqual(result["items"][0]["device_serial"], "CHASSIS001")

    def test_reviewed_deferred_profiles_and_copper_capabilities_cannot_be_bypassed(self):
        for reason, source in (
            ("Reviewed placement disagrees", {"placement": {"profile": "existing-rule"}}),
            ("Documented uplink port is copper and cannot establish an optical cage", {}),
        ):
            with self.subTest(reason=reason):
                unresolved = {**hardware(), "source": source, "reason": reason}
                result = discover(existing_unresolved=[unresolved])
                self.assertEqual(result["items"], [])
                self.assertEqual(len(result["identities"]), 1)
                self.assertIn("reviewed", result["unresolved"][0]["reason"])
                missing_manufacturer = {**component(), "manufacturer": None}
                result = discover(parts=[missing_manufacturer], existing_unresolved=[unresolved])
                self.assertEqual(result["identities"], [])
                self.assertIn(reason, result["unresolved"][0]["reason"])
        ordinary = {
            **hardware(),
            "source": {"identity": {}},
            "reason": "Serialized part or chassis has no reviewed component profile",
        }
        self.assertEqual(len(discover(existing_unresolved=[ordinary])["items"]), 1)

    def test_reviewed_component_assets_are_never_duplicated(self):
        existing = {"key": "old-key", "model": "NEW-PID", "serial": "NEW001"}
        result = discover(existing_items=[existing])
        self.assertEqual(result["items"], [])
        self.assertEqual(result["identities"], [])
        self.assertEqual(result["unresolved"], [])

    def test_hardware_revision_is_never_inferred_from_platform_version(self):
        fact = hardware()
        fact["hardware_revision"] = None
        result = discover([fact])
        self.assertIsNone(result["items"][0]["hardware_revision"])
        self.assertEqual(result["items"][0]["observations"]["hardware_revision"], "FW2")

    def test_collection_is_order_independent_and_does_not_mutate_inputs(self):
        root, owners = root_and_owners()
        fact, part = hardware(), component()
        flat, parts = [fact], [root, part]
        before = deepcopy((flat, parts, owners))
        normal = generic.collect(
            flat, parts, owners, interfaces=[], existing_items=[], existing_unresolved=[]
        )
        reversed_result = generic.collect(
            flat[::-1],
            parts[::-1],
            owners,
            interfaces=[],
            existing_items=[],
            existing_unresolved=[],
        )
        self.assertEqual(normal, reversed_result)
        self.assertEqual((flat, parts, owners), before)


if __name__ == "__main__":
    unittest.main()
