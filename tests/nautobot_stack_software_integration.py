"""Platform-scoped member software checks, enclosed by the harness's rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.dcim.models import Device, DeviceType, Platform, SoftwareVersion, VirtualChassis

    return {
        model.__name__: model.objects.count()
        for model in (Device, DeviceType, Platform, SoftwareVersion, VirtualChassis)
    }


def run(device, interface_status, checks):
    """Validate shared cached catalogs, member Platform preservation and rollback."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import Device, Platform, SoftwareVersion, VirtualChassis

    from jobs.adapters.cisco_iosxe import INSTALL_PATH, canonical_software_version
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Software checks require outer rollback"
    suffix = uuid.uuid4().hex[:12]
    platforms = []
    for label in ("selected", "operator"):
        platform = Platform(
            name="stack-software-%s-%s" % (label, suffix),
            manufacturer=device.device_type.manufacturer,
            network_driver=device.platform.network_driver,
        )
        platform.validated_save()
        platforms.append(platform)
    selected_platform, operator_platform = platforms
    serials = {position: "SOFTWARE-%s-%s" % (position, suffix) for position in (1, 2, 3)}

    def device_for(position, platform):
        obj = Device(
            name="software-%s:%s" % (suffix, position),
            serial=serials[position],
            device_type=device.device_type,
            location=device.location,
            role=device.role,
            status=device.status,
            platform=platform,
            tenant=device.tenant,
        )
        with SkipAutoComponentCreation():
            obj.validated_save()
        return obj

    target = device_for(1, selected_platform)
    operator_member = device_for(2, operator_platform)
    release = canonical_software_version("17.18.4")

    def member(position):
        return {
            "position": position,
            "serial": serials[position],
            "model": device.device_type.model,
            "priority": 15 if position == 3 else 10,
            "role": "role-active" if position == 3 else "role-member",
            "state": "state-ready",
            "stack_mode": "mode-stackwise-rear",
            "software_version": release,
            "sources": {
                "identity": {"module": "Cisco-IOS-XE-stack-oper", "field": "serial-number"},
                "software_version": {
                    "module": "Cisco-IOS-XE-install-oper",
                    "path": INSTALL_PATH,
                    "chassis": position,
                    "install_rows": [
                        {
                            "chassis": position,
                            "fru": "fru-rp",
                            "current": "install-version-state-provisioned-committed",
                            "version": "17.18.04.0.1234",
                            "release": release,
                        }
                    ],
                },
            },
        }

    observed = {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": target.name,
            "serial": serials[3],
            "model": device.device_type.model,
            "software_version": release,
        },
        "stack": {
            "schema_version": 1,
            "name": target.name,
            "is_stack": True,
            "active_position": 3,
            "members": [member(3), member(1), member(2)],
            "absent_members": [],
            "unresolved": [],
            "observations": {},
        },
        "interfaces": [],
        "warnings": [],
        "excluded_interfaces": [],
    }

    def inventory():
        return snapshot_inventory(Device.objects.get(pk=target.pk), discovery=observed)

    def no_dml(captured):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)

    baseline, initial_counts = inventory(), catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        plan = build_plan(observed, inventory())
        validate_plan(plan, target, interface_status=interface_status)
    no_dml(captured)
    assert not plan["errors"] and inventory() == baseline and catalog_counts() == initial_counts
    assert len(plan["stack"]["software_versions"]) == 2
    assert {row["platform_id"] for row in plan["stack"]["software_versions"]} == {
        str(selected_platform.pk),
        str(operator_platform.pk),
    }
    assert plan["software_version"]["key"] in {
        row["key"] for row in plan["stack"]["software_versions"]
    }
    checks.append(
        "member software preview validates distinct Platforms and unsaved versions with zero DML"
    )

    original_save = Device.validated_save
    failure_seen = []

    def fail_member(obj, *args, **kwargs):
        if obj.serial == serials[3]:
            assert (
                SoftwareVersion.objects.filter(platform=selected_platform, version=release).count()
                == 1
            )
            assert (
                SoftwareVersion.objects.filter(platform=operator_platform, version=release).count()
                == 1
            )
            assert Device.objects.get(pk=operator_member.pk).software_version_id is not None
            failure_seen.append(True)
            raise ValidationError({"name": "Intentional member software rollback"})
        return original_save(obj, *args, **kwargs)

    with patch.object(Device, "validated_save", fail_member):
        try:
            apply_discovery(observed, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Expected member failure did not occur")
    assert failure_seen and inventory() == baseline and catalog_counts() == initial_counts
    checks.append(
        "late member failure rolls back both Platform software catalogs and member assignments"
    )

    applied = apply_discovery(observed, target, interface_status=interface_status)
    target.refresh_from_db()
    operator_member.refresh_from_db()
    new_member = Device.objects.get(serial=serials[3])
    assert target.software_version_id == new_member.software_version_id
    assert target.software_version.platform_id == selected_platform.pk
    assert operator_member.software_version.platform_id == operator_platform.pk
    assert operator_member.platform_id == operator_platform.pk
    assert new_member.platform_id == selected_platform.pk
    assert SoftwareVersion.objects.filter(platform=selected_platform, version=release).count() == 1
    assert SoftwareVersion.objects.filter(platform=operator_platform, version=release).count() == 1
    assert applied["summary"]["stack_member_software_assigned"] == 2
    checks.append(
        "apply assigns each member's own Platform release and shares the selected/new-member row"
    )

    after_apply = inventory()
    with CaptureQueriesContext(connection) as captured:
        repeat = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured)
    assert inventory() == after_apply and repeat["summary"]["stack_member_software_assigned"] == 0
    checks.append("repeated member software apply issues zero inventory DML")

    older = SoftwareVersion(
        platform=operator_platform, version="17.12.08", status=target.software_version.status
    )
    older.validated_save()
    operator_member.software_version = older
    operator_member.validated_save()
    with CaptureQueriesContext(connection) as captured:
        conflicting = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured)
    operator_member.refresh_from_db()
    assert operator_member.software_version_id == older.pk
    assert operator_member.platform_id == operator_platform.pk
    assert any(row["field"] == "software_version" for row in conflicting["conflicts"])
    checks.append("populated member software disagreements preserve its assignment and Platform")

    operator_member.software_version = None
    operator_member.platform = None
    operator_member.validated_save()
    with CaptureQueriesContext(connection) as captured:
        missing_platform = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured)
    operator_member.refresh_from_db()
    assert operator_member.platform_id is None and operator_member.software_version_id is None
    assert any("assign its Platform" in warning for warning in missing_platform["warnings"])
    checks.append(
        "missing existing member Platform defers software without copying selected Platform"
    )

    operator_member.platform = operator_platform
    operator_member.validated_save()
    previous_driver = operator_platform.network_driver
    operator_platform.network_driver = "arista_eos"
    operator_platform.validated_save()
    with CaptureQueriesContext(connection) as captured:
        incompatible_platform = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured)
    operator_member.refresh_from_db()
    assert operator_member.software_version_id is None
    assert operator_member.platform_id == operator_platform.pk
    assert any(row["field"] == "platform" for row in incompatible_platform["conflicts"])
    checks.append(
        "incompatible existing Platform driver defers member software without changing Platform"
    )
    operator_platform.network_driver = previous_driver
    operator_platform.validated_save()

    no_evidence = copy.deepcopy(observed)
    no_evidence["stack"]["members"][2]["sources"].pop("software_version")
    with CaptureQueriesContext(connection) as captured:
        missing_evidence = apply_discovery(no_evidence, target, interface_status=interface_status)
    no_dml(captured)
    operator_member.refresh_from_db()
    assert operator_member.software_version_id is None
    assert any("installation evidence" in warning for warning in missing_evidence["warnings"])
    checks.append("missing per-member install evidence cannot fill software from the active member")

    vc = VirtualChassis.objects.get(pk=target.virtual_chassis_id)
    assert vc.master_id == new_member.pk
    assert {row["position"] for row in applied["stack"]["members"]} == {1, 2, 3}
