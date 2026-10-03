"""Native StackWise regressions inside the harness's outer rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.dcim.models import Device, DeviceType, VirtualChassis

    return {model.__name__: model.objects.count() for model in (Device, DeviceType, VirtualChassis)}


def run(device, interface_status, checks):
    """Verify identity, missing catalogs, previews, idempotence and rollback."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import (
        Cable,
        Device,
        DeviceType,
        Interface,
        InterfaceTemplate,
        SoftwareVersion,
        VirtualChassis,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import Status
    from nautobot.ipam.models import IPAddressToInterface

    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Stack checks require outer rollback"
    device.refresh_from_db()
    suffix = uuid.uuid4().hex[:12]
    serial1, serial2 = "STACK-1-" + suffix, "STACK-2-" + suffix
    model2 = "C9300-STACK-CHECK-" + suffix
    version = (
        device.software_version or SoftwareVersion.objects.filter(platform=device.platform).first()
    )
    assert version is not None
    with SkipAutoComponentCreation():
        target = Device(
            name="discovery-stack-" + suffix,
            serial=serial1,
            device_type=device.device_type,
            location=device.location,
            role=device.role,
            status=device.status,
            platform=device.platform,
            tenant=device.tenant,
            software_version=version,
            secrets_group=device.secrets_group,
        )
        target.validated_save()
    seed = Interface(
        device=target, name="Loopback77", type="virtual", enabled=False, status=interface_status
    )
    seed.validated_save()
    primary_id = device.primary_ip4_id
    assert primary_id is not None, "The lab fixture must have its existing primary IPv4 address"
    assignment = IPAddressToInterface(ip_address_id=primary_id, interface=seed)
    assignment.validated_save()
    target.primary_ip4_id = primary_id
    target.validated_save()
    physical = []
    for port_number in (1, 2):
        port = Interface(
            device=target,
            name="GigabitEthernet1/0/" + str(port_number),
            type="1000base-t",
            status=interface_status,
        )
        port.validated_save()
        physical.append(port)
    cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
    cable.validated_save()
    for cable_end, port in zip(("A", "B"), physical):
        termination = CableToCableTermination(
            cable=cable,
            cable_end=cable_end,
            connector=1,
            interface=port,
        )
        termination.full_clean()
        termination.save()
    cable_joins = list(cable.terminations.order_by("pk").values())
    preserved = {
        "id": target.pk,
        "name": target.name,
        "primary_ip4_id": primary_id,
        "primary_ip6_id": target.primary_ip6_id,
        "secrets_group_id": target.secrets_group_id,
        "interface_id": seed.pk,
        "assignment_id": assignment.pk,
        "custom_fields": copy.deepcopy(target._custom_field_data),
    }

    def member(position, serial, model, role, priority):
        return {
            "position": position,
            "serial": serial,
            "model": model,
            "role": role,
            "priority": priority,
            "state": "state-ready",
            "stack_mode": "mode-stackwise-rear",
            "sources": {"identity": "synthetic structured stack fixture"},
        }

    def fact(name):
        return {
            "name": name,
            "type": "virtual",
            "enabled": False,
            "type_source": "synthetic stack fixture",
        }

    observed = {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": target.name,
            "serial": serial2,
            "model": model2,
            "software_version": version.version,
        },
        "stack": {
            "schema_version": 1,
            "name": target.name,
            "is_stack": True,
            "active_position": 2,
            "members": [
                member(2, serial2, model2, "role-active", 15),
                member(1, serial1, target.device_type.model, "role-standby", 10),
            ],
            "absent_members": [{"position": 3, "state": "state-provisioned"}],
            "unresolved": [],
            "observations": {},
        },
        "interfaces": [fact(seed.name)],
        "warnings": [],
        "excluded_interfaces": [],
    }

    def inventory():
        return snapshot_inventory(Device.objects.get(pk=target.pk), discovery=observed)

    baseline = inventory()
    initial_counts = catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        plan = build_plan(observed, inventory())
        validate_plan(plan, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert inventory() == baseline and catalog_counts() == initial_counts
    assert not plan["errors"]
    assert plan["summary"]["virtual_chassis_created"] == 1
    assert plan["summary"]["stack_members_created"] == 1
    assert plan["summary"]["device_types_created"] == 1
    checks.append("stack preview validates active member 2 and missing DeviceType with zero DML")

    reversed_order = copy.deepcopy(observed)
    reversed_order["stack"]["members"].reverse()
    assert build_plan(reversed_order, inventory())["stack"] == plan["stack"]
    checks.append("stack member identity and plan are independent of payload ordering")

    member_failure_seen = []
    original_device_save = Device.validated_save

    def fail_new_member(member_device, *args, **kwargs):
        if member_device.serial == serial2:
            assert VirtualChassis.objects.filter(name=target.name).exists()
            assert DeviceType.objects.filter(model=model2).exists()
            assert Device.objects.get(pk=target.pk).virtual_chassis_id is not None
            member_failure_seen.append(True)
            raise ValidationError({"name": "Intentional new-member failure"})
        return original_device_save(member_device, *args, **kwargs)

    with patch.object(Device, "validated_save", fail_new_member):
        try:
            apply_discovery(observed, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Intentional stack member failure did not occur")
    assert member_failure_seen and inventory() == baseline and catalog_counts() == initial_counts
    checks.append("late member failure rolls back new VC, DeviceType and selected membership")

    master_failure_seen = []
    original_chassis_save = VirtualChassis.validated_save

    def fail_master(chassis, *args, **kwargs):
        if chassis.master_id is not None:
            assert VirtualChassis.objects.filter(pk=chassis.pk).exists()
            assert Device.objects.filter(serial=serial2, virtual_chassis=chassis).exists()
            master_failure_seen.append(True)
            raise ValidationError({"master": "Intentional final VC-master failure"})
        return original_chassis_save(chassis, *args, **kwargs)

    with patch.object(VirtualChassis, "validated_save", fail_master):
        try:
            apply_discovery(observed, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Intentional stack master failure did not occur")
    assert master_failure_seen and inventory() == baseline and catalog_counts() == initial_counts
    checks.append("late master failure rolls back the complete previously saved stack graph")

    failing = copy.deepcopy(observed)
    first_name, failure_name = "Loopback78", "Loopback79"
    failing["interfaces"] += [fact(first_name), fact(failure_name)]
    writes_seen = []
    original_save = Interface.validated_save

    def fail_last(interface, *args, **kwargs):
        if interface.name == failure_name:
            assert VirtualChassis.objects.filter(name=target.name).exists()
            assert Device.objects.filter(serial=serial2, vc_position=2).exists()
            assert DeviceType.objects.filter(model=model2).exists()
            assert Interface.objects.filter(device=target, name=first_name).exists()
            writes_seen.append(True)
            raise ValidationError({"name": "Intentional final stack-interface failure"})
        return original_save(interface, *args, **kwargs)

    with patch.object(Interface, "validated_save", fail_last):
        try:
            apply_discovery(failing, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Intentional stack rollback failure did not occur")
    assert writes_seen and inventory() == baseline and catalog_counts() == initial_counts
    checks.append(
        "late interface failure rolls back VC, member Device, DeviceType and prior interfaces"
    )

    applied = apply_discovery(observed, target, interface_status=interface_status)
    target.refresh_from_db()
    child = Device.objects.get(serial=serial2)
    chassis = VirtualChassis.objects.get(pk=target.virtual_chassis_id)
    assert applied["summary"]["stack_members_created"] == 1
    assert target.vc_position == 1 and target.vc_priority == 10
    assert child.vc_position == 2 and child.vc_priority == 15 and chassis.master_id == child.pk
    assert child.name == target.name + ":2"
    assert child.device_type.model == model2
    assert child.primary_ip4_id is None and child.primary_ip6_id is None
    assert child.secrets_group_id is None and child.software_version_id is None
    assert child.rack_id is None and child.position is None
    assert child.location_id == target.location_id and child.role_id == target.role_id
    assert child.status_id == target.status_id and child.platform_id == target.platform_id
    assert child.tenant_id == target.tenant_id
    assert not child.interfaces.exists() and not child.console_ports.exists()
    assert set(chassis.members.values_list("vc_position", flat=True)) == {1, 2}
    assert seed.device_id == target.pk
    checks.append(
        "apply creates only present members with NtC naming and keeps network ownership "
        "on selected Device"
    )

    def assert_preserved():
        target.refresh_from_db()
        seed.refresh_from_db()
        assignment.refresh_from_db()
        assert target.pk == preserved["id"] and target.name == preserved["name"]
        assert target.primary_ip4_id == preserved["primary_ip4_id"]
        assert target.primary_ip6_id == preserved["primary_ip6_id"]
        assert target.secrets_group_id == preserved["secrets_group_id"]
        assert target._custom_field_data == preserved["custom_fields"]
        assert seed.pk == preserved["interface_id"] and seed.device_id == target.pk
        assert assignment.pk == preserved["assignment_id"] and assignment.interface_id == seed.pk
        assert list(cable.terminations.order_by("pk").values()) == cable_joins
        for port in physical:
            port.refresh_from_db()
            assert port.device_id == target.pk and port.cable_id == cable.pk

    assert_preserved()
    before_repeat = inventory()
    with CaptureQueriesContext(connection) as captured:
        repeat = apply_discovery(observed, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert inventory() == before_repeat
    assert all(
        repeat["summary"][key] == 0
        for key in (
            "virtual_chassis_created",
            "virtual_chassis_updated",
            "stack_members_created",
            "stack_members_updated",
            "device_types_created",
        )
    )
    checks.append("repeated stack apply preserves identities and issues zero inventory DML")

    master_flip = copy.deepcopy(observed)
    master_flip["identity"].update(serial=serial1, model=target.device_type.model)
    master_flip["stack"]["active_position"] = 1
    for row in master_flip["stack"]["members"]:
        row["role"] = "role-active" if row["position"] == 1 else "role-standby"
        if row["position"] == 2:
            row["priority"] = 9
    changed = apply_discovery(master_flip, target, interface_status=interface_status)
    chassis.refresh_from_db()
    child.refresh_from_db()
    assert chassis.master_id == target.pk and child.vc_priority == 9
    assert changed["summary"]["virtual_chassis_updated"] == 1
    assert child.pk == Device.objects.get(serial=serial2).pk
    assert_preserved()
    checks.append(
        "master and priority updates preserve Device, primary-IP, credentials "
        "and interface identities"
    )

    template = InterfaceTemplate(
        device_type=child.device_type,
        name="Unobserved template " + suffix,
        type="1000base-t",
    )
    template.validated_save()
    templated_observed = copy.deepcopy(master_flip)
    templated_serial = "TEMPLATED-" + suffix
    templated_observed["stack"]["members"].append(
        member(4, templated_serial, model2, "role-member", 1)
    )
    with CaptureQueriesContext(connection) as captured:
        templated_plan = build_plan(
            templated_observed,
            snapshot_inventory(target, discovery=templated_observed),
        )
        validate_plan(templated_plan, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    apply_discovery(templated_observed, target, interface_status=interface_status)
    unobserved = Device.objects.get(serial=templated_serial)
    assert not unobserved.interfaces.exists()
    checks.append("new stack-member DeviceType templates are suppressed without guessed ports")

    chassis.master = unobserved
    chassis.validated_save()
    takeover = apply_discovery(master_flip, target, interface_status=interface_status)
    chassis.refresh_from_db()
    unobserved.refresh_from_db()
    assert chassis.master_id == target.pk
    assert unobserved.virtual_chassis_id == chassis.pk and unobserved.vc_position == 4
    assert takeover["summary"]["virtual_chassis_updated"] == 1
    assert takeover["summary"]["stack_members_created"] == 0
    checks.append(
        "confirmed active takeover preserves the unobserved previous VC master as a member"
    )

    child.serial = "\t " + serial2 + " \n"
    child.validated_save()
    padded_baseline = inventory()
    with CaptureQueriesContext(connection) as captured:
        padded = apply_discovery(master_flip, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert inventory() == padded_baseline and padded["summary"]["stack_members_created"] == 0
    checks.append("trimmed global serial matching adopts padded existing assets without duplicates")

    def reject(discovery):
        before = inventory()
        before_counts = catalog_counts()
        with CaptureQueriesContext(connection) as captured:
            try:
                apply_discovery(discovery, target, interface_status=interface_status)
            except (InventoryError, ValidationError):
                pass
            else:
                raise AssertionError("Stack collision unexpectedly applied")
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
        assert inventory() == before and catalog_counts() == before_counts

    # A collision must be present in the ORM snapshot, not only a fabricated
    # planner input. Seed it solely inside this test's outer rollback.
    extra_serial = "STACK-3-" + suffix
    with SkipAutoComponentCreation():
        occupied = Device(
            name=target.name + ":3",
            serial="OTHER-" + suffix,
            device_type=target.device_type,
            location=target.location,
            role=target.role,
            status=target.status,
            platform=target.platform,
            tenant=target.tenant,
        )
        occupied.validated_save()
    collision = copy.deepcopy(master_flip)
    collision["stack"]["members"].append(
        member(3, extra_serial, target.device_type.model, "role-member", 1)
    )
    reject(collision)
    checks.append("real occupied member names block stack apply before inventory writes")

    conflicting = copy.deepcopy(master_flip)
    conflicting["stack"]["members"][0]["position"] = 3
    reject(conflicting)
    checks.append("established stack-position conflicts block renumbering without writes")

    other_vc = VirtualChassis(name="foreign-stack-" + suffix)
    other_vc.validated_save()
    foreign = Device.objects.get(pk=occupied.pk)
    foreign.virtual_chassis = other_vc
    foreign.vc_position = 3
    foreign.validated_save()
    foreign_observed = copy.deepcopy(master_flip)
    foreign_observed["stack"]["members"].append(
        member(3, foreign.serial, foreign.device_type.model, "role-member", 1)
    )
    reject(foreign_observed)
    checks.append("a serial-matched member in another VirtualChassis blocks implicit reparenting")

    named_collision = copy.deepcopy(master_flip)
    named_collision["identity"]["hostname"] = other_vc.name
    named_collision["stack"]["name"] = other_vc.name
    reject(named_collision)
    checks.append(
        "an existing named VirtualChassis collision blocks replacement of selected membership"
    )

    with SkipAutoComponentCreation():
        duplicate = Device(
            name="global-duplicate-" + suffix,
            serial=serial2,
            device_type=child.device_type,
            location=target.location,
            role=target.role,
            status=target.status,
            platform=target.platform,
            tenant=target.tenant,
        )
        duplicate.validated_save()
    reject(master_flip)
    checks.append("global duplicate serial identities block stack discovery before writes")

    with SkipAutoComponentCreation():
        empty = Device(
            name=None,
            serial="",
            device_type=device.device_type,
            location=device.location,
            role=device.role,
            status=device.status,
            platform=device.platform,
            tenant=device.tenant,
        )
        empty.validated_save()
    empty_observed = copy.deepcopy(observed)
    empty_name = "blank-stack-" + suffix
    empty_observed["identity"].update(
        hostname=empty_name,
        serial="BLANK-ACTIVE-" + suffix,
        model=device.device_type.model,
    )
    for patch_number in range(1, 100):
        release = "17.96.%02d" % patch_number
        if not SoftwareVersion.objects.filter(platform=device.platform, version=release).exists():
            empty_observed["identity"]["software_version"] = release
            break
    else:
        raise AssertionError("No unused stack-test release token")
    empty_observed["interfaces"] = [fact("Loopback88")]
    empty_observed["stack"].update(
        name=empty_name,
        members=[
            member(1, "BLANK-MEMBER-" + suffix, device.device_type.model, "role-standby", 5),
            member(
                2, empty_observed["identity"]["serial"], device.device_type.model, "role-active", 10
            ),
        ],
    )
    empty_before = snapshot_inventory(empty, discovery=empty_observed)
    with CaptureQueriesContext(connection) as captured:
        empty_plan = build_plan(empty_observed, empty_before)
        validate_plan(empty_plan, empty, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert (
        snapshot_inventory(Device.objects.get(pk=empty.pk), discovery=empty_observed)
        == empty_before
    )
    assert empty_plan["summary"]["device_fields_updated"] == 3
    assert empty_plan["software_version"]["create"]
    apply_discovery(empty_observed, empty, interface_status=interface_status)
    empty.refresh_from_db()
    assert empty.name == empty_name and empty.serial == empty_observed["identity"]["serial"]
    assert empty.vc_position == 2 and empty.virtual_chassis.master_id == empty.pk
    assert empty.software_version.version == empty_observed["identity"]["software_version"]
    checks.append(
        "blank selected identity and new software validate with unsaved VC and fill atomically"
    )

    unnamed_serial = "UNNAMED-MEMBER-" + suffix
    with SkipAutoComponentCreation():
        unnamed = Device(
            name=None,
            serial=unnamed_serial,
            device_type=device.device_type,
            location=device.location,
            role=device.role,
            status=device.status,
            platform=device.platform,
            tenant=device.tenant,
        )
        unnamed.validated_save()
        name_guard = Device(
            name=empty_name + ":3",
            serial="NAME-GUARD-" + suffix,
            device_type=device.device_type,
            location=device.location,
            role=device.role,
            status=device.status,
            platform=device.platform,
            tenant=device.tenant,
        )
        name_guard.validated_save()
    unnamed_observed = copy.deepcopy(empty_observed)
    unnamed_observed["stack"]["members"].append(
        member(3, unnamed_serial, device.device_type.model, "role-member", 1)
    )
    unnamed_before = snapshot_inventory(empty, discovery=unnamed_observed)
    with CaptureQueriesContext(connection) as captured:
        occupied_plan = build_plan(unnamed_observed, unnamed_before)
        assert occupied_plan["errors"]
        try:
            validate_plan(occupied_plan, empty, interface_status=interface_status)
        except InventoryError:
            pass
        else:
            raise AssertionError("Occupied derived member name passed preview validation")
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert (
        snapshot_inventory(Device.objects.get(pk=empty.pk), discovery=unnamed_observed)
        == unnamed_before
    )
    checks.append(
        "a blank serial-matched member name with occupied NtC name blocks zero-DML preview"
    )

    name_guard.delete()
    with CaptureQueriesContext(connection) as captured:
        unnamed_plan = build_plan(
            unnamed_observed,
            snapshot_inventory(empty, discovery=unnamed_observed),
        )
        validate_plan(unnamed_plan, empty, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert unnamed_plan["summary"]["stack_members_created"] == 0
    apply_discovery(unnamed_observed, empty, interface_status=interface_status)
    unnamed.refresh_from_db()
    assert unnamed.name == empty_name + ":3" and unnamed.vc_position == 3
    assert unnamed.virtual_chassis_id == empty.virtual_chassis_id
    checks.append(
        "existing unnamed serial-matched members receive the derived NtC name without replacement"
    )
