"""Real 802.1Q regressions, called only inside an outer transaction rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    """Expose VLAN catalog counts for the harness's before/after rollback check."""
    from nautobot.ipam.models import VLAN, VLANGroup

    return {model.__name__: model.objects.count() for model in (VLAN, VLANGroup)}


def run(device, interface_status, checks):
    """Verify scope, unsaved relations, conflict preservation and complete rollback."""
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import (
        Device,
        Interface,
        Location,
        LocationType,
        Module,
        ModuleBay,
        ModuleType,
        SoftwareVersion,
    )
    from nautobot.extras.models import Status
    from nautobot.ipam.models import VLAN, VLANGroup

    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "VLAN tests require outer rollback"
    device.refresh_from_db()
    token = uuid.uuid4().hex[:12]
    port_prefix = str(uuid.uuid4().int)[:12]
    description = "VLAN ORM verification " + token

    def active(model):
        return Status.objects.get_for_model(model).get(name="Active")

    def name(number, short=False):
        return ("Gi" if short else "GigabitEthernet") + port_prefix + "/1/" + str(number)

    def vlan_name(vid):
        return "CODEX-VLAN-" + token + "-" + str(vid)

    def fact(interface_name, type_="1000base-t", *, speed=None, duplex=None):
        return {
            "name": interface_name,
            "type": type_,
            "enabled": True,
            "description": description,
            "mtu": 1500,
            "mac_address": None,
            "speed": speed,
            "duplex": duplex,
            "type_source": "synthetic reviewed integration capability",
            "observations": {
                "normalized_speed_unit": "Kbps",
                "duplex_source": "Synthetic explicit configured setting",
            },
        }

    def switching(interface_name, mode, native=None, tagged=()):
        return {
            "name": interface_name,
            "mode": mode,
            "untagged_vid": native,
            "tagged_vids": list(tagged),
            "source": {"method": "synthetic structured configuration"},
            "observations": {},
        }

    def unused_version():
        for patch_number in range(1, 100):
            version = "17.97.%02d" % patch_number
            if not SoftwareVersion.objects.filter(
                platform=device.platform, version=version
            ).exists():
                return version
        raise AssertionError("No unused synthetic VLAN-test software version")

    identity = {
        "hostname": device.name or "vlan-integration",
        "serial": device.serial or "CODEX-VLAN-INTEGRATION",
        "model": device.device_type.model,
        "software_version": (
            device.software_version.version if device.software_version_id else unused_version()
        ),
    }

    def observed(facts, switching_rows, vids=(), *, vlan_rows=None):
        return {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": copy.deepcopy(identity),
            "interfaces": facts,
            "lag_memberships": [],
            "warnings": [],
            "excluded_interfaces": [],
            "layer2": {
                "schema_version": 1,
                "interfaces": switching_rows,
                "vlans": (
                    [{"vid": vid, "name": vlan_name(vid)} for vid in vids]
                    if vlan_rows is None
                    else vlan_rows
                ),
                "unresolved": [],
            },
        }

    def assert_no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    def snapshot():
        return snapshot_inventory(Device.objects.get(pk=device.pk), vlan_group=group)

    def inventory_counts():
        return {
            **catalog_counts(),
            **{
                model.__name__: model.objects.count()
                for model in (Interface, SoftwareVersion, ModuleType, ModuleBay, Module)
            },
        }

    def apply(discovery, *, selected_group=None):
        return apply_discovery(
            discovery,
            device,
            interface_status=interface_status,
            vlan_group=group if selected_group is None else selected_group,
        )

    def seed_interface(interface_name, type_="1000base-t", **kwargs):
        interface = Interface(
            device=device,
            name=interface_name,
            type=type_,
            status=interface_status,
            enabled=True,
            mtu=1500,
            description=kwargs.pop("description", description),
            **kwargs,
        )
        interface.validated_save()
        return interface

    group = VLANGroup(name="CODEX-VLAN-SCOPE-" + token, range="100-200")
    group.validated_save()

    assert group.location_id is None, "The regression group must be global"
    other_group = VLANGroup(name="CODEX-VLAN-OTHER-" + token)
    other_group.validated_save()
    elsewhere = VLAN(
        vlan_group=other_group,
        vid=101,
        name="Operator VLAN outside selected scope " + token,
        status=active(VLAN),
    )
    elsewhere.validated_save()

    # Start with an existing module-owned short alias and populated LAG.
    # Discovery must enrich this exact UUID, including when its type is copper.
    module_type = ModuleType(
        manufacturer=device.device_type.manufacturer,
        model="CODEX-VLAN-MODULE-" + token,
        part_number="CODEX-VLAN-MODULE-" + token,
    )
    module_type.validated_save()
    bay = ModuleBay(parent_device=device, name="VLAN test module " + token, position="1")
    bay.validated_save()
    module = Module(
        module_type=module_type,
        parent_module_bay=bay,
        serial="CODEX-VLAN-SERIAL-" + token,
        status=active(Module),
    )
    with SkipAutoComponentCreation():
        module.validated_save()
    existing_lag = seed_interface("Port-channel" + port_prefix, type_="lag")
    member = seed_interface(name(1, short=True), module=module, lag=existing_lag)
    member_id = member.pk
    main_facts = [
        fact(name(1), speed=1_000_000, duplex="full"),
        fact(name(2), type_="1000base-x-sfp", speed=1_000_000),
        fact(name(3)),
    ]
    discovery = observed(
        main_facts,
        [
            switching(name(1), "access", 101),
            switching(name(2), "tagged", 102, [103, 104]),
            switching(name(3), "tagged-all", 105),
        ],
        [101, 102, 103, 104, 105],
    )

    before_preview, before_counts = snapshot(), inventory_counts()
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(discovery, snapshot_inventory(device, vlan_group=group))
        validate_plan(preview, device, interface_status=interface_status)
    assert_no_dml(captured, "VLAN preview wrote proposed FK parents or M2M assignments")
    assert snapshot() == before_preview and inventory_counts() == before_counts
    assert preview["summary"]["vlans_created"] == 5
    assert preview["summary"]["interface_vlan_assignments_updated"] == 3
    checks.append(
        "VLAN preview validates new untagged FK parents and tagged membership with zero DML"
    )

    applied = apply(discovery)
    device.refresh_from_db()
    member.refresh_from_db()
    finite = Interface.objects.get(device=device, name=name(2))
    unrestricted = Interface.objects.get(device=device, name=name(3))
    selected = {vlan.vid: vlan for vlan in VLAN.objects.filter(vlan_group=group)}
    assert set(selected) == {101, 102, 103, 104, 105}, "Tagged-all expanded the VLAN catalog"
    assert applied["summary"]["vlans_created"] == 5
    assert member.pk == member_id and member.name == name(1, short=True)
    assert member.module_id == module.pk and member.lag_id == existing_lag.pk
    assert member.device_id == device.pk
    assert not Interface.objects.filter(device=device, name=name(1)).exists()
    assert member.mode == "access" and member.untagged_vlan_id == selected[101].pk
    assert not member.tagged_vlans.exists()
    assert member.untagged_vlan_id != elsewhere.pk, "Selected an equal VID from another group"
    assert finite.mode == "tagged" and finite.untagged_vlan_id == selected[102].pk
    assert set(finite.tagged_vlans.values_list("vid", flat=True)) == {103, 104}
    assert unrestricted.mode == "tagged-all" and unrestricted.untagged_vlan_id == selected[105].pk
    assert not unrestricted.tagged_vlans.exists()
    assert member.speed == finite.speed == 1_000_000, "Operational speed is not stored in Kbps"
    assert member.duplex == "full" and finite.duplex == ""
    member.full_clean()
    finite.full_clean()
    checks.append(
        "access, finite tagged, and tagged-all store correct scoped VLANs and preserve "
        "module, LAG, UUID and existing interface alias"
    )
    checks.append(
        "operational speed is Kbps and explicit configured copper duplex passes model validation"
    )

    before_repeat, before_counts = snapshot(), inventory_counts()
    with CaptureQueriesContext(connection) as captured:
        repeated = apply(discovery)
    assert_no_dml(captured, "Repeated VLAN apply issued inventory DML")
    for key in (
        "vlans_created",
        "vlans_updated",
        "interface_vlan_assignments_updated",
        "interfaces_created",
        "interfaces_updated",
        "device_fields_updated",
    ):
        assert repeated["summary"][key] == 0, "Repeated VLAN apply changed " + key
    assert snapshot() == before_repeat and inventory_counts() == before_counts
    elsewhere.refresh_from_db()
    assert elsewhere.name == "Operator VLAN outside selected scope " + token
    checks.append(
        "repeated scoped VLAN discovery issues zero DML and ignores other groups' equal VIDs"
    )

    # Each incompatible switching bundle must preserve all of its populated
    # fields and membership, without merging tags or creating unused VLANs.
    conflicts = [
        (
            "mode",
            observed([main_facts[0]], [switching(name(1), "tagged", 106, [107])], [106, 107]),
        ),
        (
            "untagged_vlan",
            observed([main_facts[0]], [switching(name(1), "access", 106)], [106]),
        ),
        (
            "tagged_vlans",
            observed(
                [main_facts[1]],
                [switching(name(2), "tagged", 102, [103, 106])],
                [102, 103, 106],
            ),
        ),
    ]
    for field, conflicting in conflicts:
        before_conflict, before_counts = snapshot(), inventory_counts()
        with CaptureQueriesContext(connection) as captured:
            preserved = apply(conflicting)
        assert_no_dml(captured, "Switching conflict issued DML for " + field)
        assert any(row["field"] == field for row in preserved["conflicts"])
        assert snapshot() == before_conflict and inventory_counts() == before_counts
        assert not VLAN.objects.filter(vlan_group=group, vid__in=[106, 107]).exists()
    checks.append("populated mode, untagged VLAN and tagged-set conflicts preserve whole bundles")

    # A location-incompatible existing VLAN is not a usable match even in the
    # explicitly selected group. The location and type are rolled back by the harness.
    location_type = LocationType(name="CODEX-VLAN-LOCATION-TYPE-" + token)
    location_type.validated_save()
    location_type.content_types.add(ContentType.objects.get_for_model(VLAN))
    other_location = Location(
        name="CODEX-VLAN-LOCATION-" + token,
        location_type=location_type,
        status=active(Location),
    )
    other_location.validated_save()
    unavailable = VLAN(vlan_group=group, vid=151, name=vlan_name(151), status=active(VLAN))
    unavailable.validated_save()
    unavailable.locations.add(other_location)
    unresolved_port = seed_interface(name(6))
    unresolved_cases = [
        observed([fact(name(6))], [switching(name(6), "access", 150)], vlan_rows=[]),
        observed([fact(name(6))], [switching(name(6), "access", 201)], [201]),
        observed([fact(name(6))], [switching(name(6), "access", 151)], [151]),
    ]
    for unresolved_discovery in unresolved_cases:
        before_unresolved, before_counts = snapshot(), inventory_counts()
        with CaptureQueriesContext(connection) as captured:
            unresolved_plan = apply(unresolved_discovery)
        assert_no_dml(captured, "Unresolved VLAN identity or location issued DML")
        assert unresolved_plan["layer2"]["unresolved"]
        assert unresolved_plan["summary"]["vlans_created"] == 0
        assert unresolved_plan["summary"]["interface_vlan_assignments_updated"] == 0
        assert snapshot() == before_unresolved and inventory_counts() == before_counts
    unresolved_port.refresh_from_db()
    assert unresolved_port.mode == "" and unresolved_port.untagged_vlan_id is None
    assert not VLAN.objects.filter(vlan_group=group, vid__in=[150, 201]).exists()
    no_scope = observed([fact(name(6))], [switching(name(6), "access", 152)], [152])
    before_unresolved, before_counts = snapshot(), inventory_counts()
    with CaptureQueriesContext(connection) as captured:
        no_scope_plan = apply_discovery(no_scope, device, interface_status=interface_status)
    assert_no_dml(captured, "Discovery without a VLAN Group wrote inventory")
    assert no_scope_plan["layer2"]["unresolved"]
    assert snapshot() == before_unresolved and inventory_counts() == before_counts
    checks.append(
        "unknown VLAN names, out-of-range VIDs, incompatible locations and absent scope "
        "remain unresolved without catalog writes"
    )

    # All relation parents are unsaved simultaneously: module catalog/type,
    # bay/module, Port-channel, physical member, native VLAN and tagged VLAN.
    combined_lag_name = "Port-channel" + port_prefix + "7"
    combined = observed(
        [fact(name(7), speed=1_000_000, duplex="full"), fact(combined_lag_name, type_="lag")],
        [switching(name(7), "tagged", 110, [111])],
        [110, 111],
    )
    combined["lag_memberships"] = [{"member": name(7), "lag": combined_lag_name, "source": {}}]
    combined_module = {
        "key": "integration:" + token,
        "kind": "network-module",
        "manufacturer": device.device_type.manufacturer.name,
        "model": "CODEX-COMBINED-VLAN-" + token,
        "part_number": "CODEX-COMBINED-VLAN-" + token,
        "serial": "CODEX-COMBINED-SERIAL-" + token,
        "parent_key": None,
        "bay": {"name": "Combined VLAN module " + token, "position": "2", "label": "2"},
        "interfaces": [name(7)],
        "source": {},
        "observations": {},
    }
    combined["components"] = {
        "schema_version": 1,
        "items": [combined_module],
        "unresolved": [],
        "excluded": [],
    }
    before_combined, before_counts = snapshot(), inventory_counts()
    with CaptureQueriesContext(connection) as captured:
        combined_plan = build_plan(combined, snapshot_inventory(device, vlan_group=group))
        validate_plan(combined_plan, device, interface_status=interface_status)
    assert_no_dml(captured, "Combined unsaved module/LAG/VLAN preview issued DML")
    assert snapshot() == before_combined and inventory_counts() == before_counts
    assert combined_plan["summary"]["modules_created"] == 1
    assert combined_plan["summary"]["lag_memberships_updated"] == 1
    assert combined_plan["summary"]["vlans_created"] == 2
    apply(combined)
    combined_member = Interface.objects.get(device=device, name=name(7))
    combined_lag = Interface.objects.get(device=device, name=combined_lag_name)
    assert combined_member.module.serial == combined_module["serial"]
    assert combined_member.module.device.pk == device.pk
    assert combined_member.lag_id == combined_lag.pk
    assert combined_member.mode == "tagged" and combined_member.untagged_vlan.vid == 110
    assert set(combined_member.tagged_vlans.values_list("vid", flat=True)) == {111}
    combined_member.full_clean()
    with CaptureQueriesContext(connection) as captured:
        apply(combined)
    assert_no_dml(captured, "Repeated combined module/LAG/VLAN discovery issued DML")
    checks.append(
        "new Module, LAG and VLAN graph previews without DML and applies cached relations"
    )

    with CaptureQueriesContext(connection) as captured:
        for type_, speed, duplex in (
            ("lag", 1_000_000, ""),
            ("lag", None, "full"),
            ("1000base-x-sfp", None, "full"),
        ):
            invalid = Interface(
                device=device,
                name="Invalid operational test " + token,
                type=type_,
                status=interface_status,
                speed=speed,
                duplex=duplex,
            )
            try:
                invalid.full_clean()
            except ValidationError as exc:
                assert "speed" in exc.message_dict or "duplex" in exc.message_dict
            else:
                raise AssertionError("Invalid LAG/optical speed/duplex passed model validation")
        copper_auto = Interface(
            device=device,
            name="Valid copper auto " + token,
            type="1000base-t",
            status=interface_status,
            speed=1_000_000,
            duplex="auto",
        )
        copper_auto.full_clean()
    assert_no_dml(captured, "Operational field validation wrote inventory")
    checks.append("native full_clean rejects LAG speed/duplex and optical duplex without DML")

    # Capture known VLAN identities without inventing a DTP access/trunk mode.
    from nautobot.extras.models import CustomField

    dynamic = seed_interface(name(17), duplex="")
    dynamic_before = snapshot()
    dynamic_cf_before = copy.deepcopy(dynamic._custom_field_data)
    fields_before = CustomField.objects.count()
    catalog_only = observed([fact(name(17))], [], [191])
    catalog_only["layer2"].update(
        catalog_complete=True,
        settings=[
            {
                "name": name(17),
                "configured_mode": "dynamic-auto",
                "access_vid": 191,
                "native_vid": 191,
                "untagged_vid": 191,
                "field_sources": {"configured_mode": "explicit"},
            }
        ],
        unresolved=[
            {
                "name": name(17),
                "category": "dynamic-mode",
                "reason": "Configured DTP mode does not establish a static tagging mode",
            }
        ],
    )
    catalog_plan = build_plan(catalog_only, snapshot())
    assert catalog_plan["summary"]["vlans_created"] == 1
    assert not catalog_plan["layer2"]["assignments"]
    with CaptureQueriesContext(connection) as captured:
        validate_plan(catalog_plan, device, interface_status=interface_status)
    assert_no_dml(captured, "Catalog-only preview issued database writes")
    assert snapshot() == dynamic_before
    checks.append("complete unused VLAN catalog preview validates with zero database writes")
    applied_catalog = apply(catalog_only)
    dynamic.refresh_from_db()
    assert dynamic.mode == "" and dynamic.untagged_vlan_id is None
    assert not dynamic.tagged_vlans.exists()
    assert dynamic._custom_field_data == dynamic_cf_before
    assert VLAN.objects.filter(vlan_group=group, vid=191, name=vlan_name(191)).exists()
    assert CustomField.objects.count() == fields_before
    assert applied_catalog["layer2"]["settings"][0]["native_vid"] == 191
    checks.append("unused named VLANs load independently while DTP native fields stay blank")
    with CaptureQueriesContext(connection) as captured:
        repeat_catalog = apply(catalog_only)
    assert_no_dml(captured, "Catalog-only repeat issued database writes")
    assert repeat_catalog["summary"]["vlans_created"] == 0
    assert repeat_catalog["summary"]["interface_vlan_assignments_updated"] == 0
    checks.append("catalog-only repeat is idempotent and creates no custom fields")

    # Fail the final tagged membership after catalog, software, Device,
    # interface fields, and an earlier tagged membership have actually saved.
    final_member = seed_interface(name(9), description="")
    Device.objects.filter(pk=device.pk).update(serial="", software_version=None)
    device.refresh_from_db()
    failure = observed(
        [fact(name(8)), fact(name(9))],
        [switching(name(8), "tagged", 112, [115]), switching(name(9), "tagged", 113, [114])],
        [112, 113, 114, 115],
    )
    failure["identity"]["software_version"] = unused_version()
    before_failure, before_counts = snapshot(), inventory_counts()
    manager_class = type(finite.tagged_vlans)
    original_add = manager_class.add
    writes_seen = []

    def fail_final_add(manager, *objects, **kwargs):
        if manager.instance.pk == final_member.pk:
            assert {vlan.vid for vlan in objects} == {114}
            assert VLAN.objects.filter(vlan_group=group, vid__in=[112, 113, 114, 115]).count() == 4
            prior = Interface.objects.get(device=device, name=name(8))
            assert prior.mode == "tagged" and prior.untagged_vlan.vid == 112
            assert set(prior.tagged_vlans.values_list("vid", flat=True)) == {115}
            saved_final = Interface.objects.get(pk=final_member.pk)
            assert saved_final.mode == "tagged" and saved_final.untagged_vlan.vid == 113
            assert saved_final.description == description and not saved_final.tagged_vlans.exists()
            saved_device = Device.objects.get(pk=device.pk)
            assert saved_device.serial == failure["identity"]["serial"]
            assert saved_device.software_version.version == failure["identity"]["software_version"]
            writes_seen.append("VLAN catalog, software, Device, interfaces and earlier M2M saved")
            raise ValidationError({"tagged_vlans": "Intentional final membership-add failure"})
        return original_add(manager, *objects, **kwargs)

    with patch.object(manager_class, "add", fail_final_add):
        try:
            apply(failure)
        except ValidationError:
            pass
        else:
            raise AssertionError("The injected final VLAN membership-add failure did not occur")
    assert writes_seen, "Rollback scenario did not save all preceding inventory changes"
    assert snapshot() == before_failure and inventory_counts() == before_counts
    assert not VLAN.objects.filter(vlan_group=group, vid__in=[112, 113, 114, 115]).exists()
    assert not Interface.objects.filter(device=device, name=name(8)).exists()
    assert not SoftwareVersion.objects.filter(
        platform=device.platform, version=failure["identity"]["software_version"]
    ).exists()
    final_member.refresh_from_db()
    assert final_member.mode == "" and final_member.untagged_vlan_id is None
    assert final_member.description == "" and not final_member.tagged_vlans.exists()
    checks.append(
        "final VLAN membership failure rolls back catalog, software, Device, "
        "interface fields and preceding M2M additions"
    )
