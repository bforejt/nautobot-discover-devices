"""Full StackWise and PSU reconciliation inside the harness's outer rollback."""

import re
import uuid
from decimal import Decimal
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Module,
        ModuleBay,
        ModuleType,
        PowerPort,
        VirtualChassis,
    )

    return {
        model.__name__: model.objects.count()
        for model in (Device, DeviceType, VirtualChassis, ModuleType, ModuleBay, Module, PowerPort)
    }


def run(device, interface_status, checks):
    """Exercise joint preview, cached stack parents, repeats and late rollback."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Module,
        ModuleBay,
        PowerPort,
        SoftwareVersion,
    )

    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Joint stack checks require outer rollback"
    device.refresh_from_db()
    version = (
        device.software_version or SoftwareVersion.objects.filter(platform=device.platform).first()
    )
    assert version is not None, "The lab fixture needs a SoftwareVersion"

    def no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    def fixture():
        suffix = uuid.uuid4().hex[:12]
        serial1, serial2 = "STACK-POWER-1-" + suffix, "STACK-POWER-2-" + suffix
        model2 = "C9300-STACK-POWER-CHECK-" + suffix
        psu_model = "STACK-PSU-CHECK-" + suffix
        with SkipAutoComponentCreation():
            target = Device(
                name="discovery-stack-power-" + suffix,
                serial=serial1,
                device_type=device.device_type,
                location=device.location,
                role=device.role,
                status=device.status,
                platform=device.platform,
                tenant=device.tenant,
                software_version=version,
            )
            target.validated_save()

        def member(position, serial, model, role, priority):
            return {
                "position": position,
                "serial": serial,
                "model": model,
                "role": role,
                "priority": priority,
                "state": "state-ready",
                "stack_mode": "mode-stackwise-rear",
                "sources": {"identity": "Synthetic structured stack and PSU fixture"},
            }

        members = [
            member(2, serial2, model2, "role-active", 15),
            member(1, serial1, target.device_type.model, "role-standby", 10),
        ]
        physical_bays, items = [], []
        for owner in members:
            position = owner["position"]
            for slot in ("A", "B"):
                bay = {
                    "name": "Power Supply " + slot,
                    "position": "PSU-" + slot,
                    "label": "Power Supply " + slot,
                }
                physical_bays.append(
                    {
                        "key": "psu:%d/%s" % (position, slot),
                        "device_serial": owner["serial"],
                        "member": position,
                        "chassis_model": owner["model"],
                        "bay": bay,
                        "source": {"documentation": "Synthetic reviewed physical bay fixture"},
                        "observations": {
                            "reported_presence": "reported-nonempty" if slot == "B" else "unknown"
                        },
                    }
                )
                if slot == "A":
                    continue
                items.append(
                    {
                        "key": "psu:%d/B" % position,
                        "kind": "power-supply",
                        "manufacturer": target.device_type.manufacturer.name,
                        "model": psu_model,
                        "part_number": psu_model,
                        "serial": "STACK-PSU-%s-%d" % (suffix, position),
                        "device_serial": owner["serial"],
                        "member": position,
                        "parent_key": None,
                        "bay": bay,
                        "interfaces": [],
                        "power_ports": [
                            {
                                "name": "Power Input",
                                "type": "iec-60320-c14",
                                "maximum_draw": 1200,
                                "allocated_draw": None,
                                "power_factor": 1.0,
                                "source": {"fixture": "Synthetic known input specification"},
                            }
                        ],
                        "source": {"identity": "Synthetic structured serialized PSU fixture"},
                        "observations": {},
                    }
                )
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
                "members": members,
                "absent_members": [],
                "unresolved": [],
                "observations": {},
            },
            "components": {
                "schema_version": 1,
                "physical_bays": physical_bays,
                "items": items,
                "unresolved": [],
                "excluded": [],
            },
            "interfaces": [],
            "warnings": [],
            "excluded_interfaces": [],
        }
        return target, observed

    target, observed = fixture()
    initial_counts = catalog_counts()
    baseline = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(observed, snapshot_inventory(target, discovery=observed))
        assert not preview["errors"], preview["errors"]
        validate_plan(preview, target, interface_status=interface_status)
    no_dml(captured, "Joint stack/PSU preview issued inventory writes")
    assert catalog_counts() == initial_counts
    assert snapshot_inventory(target, discovery=observed) == baseline
    assert preview["summary"]["device_types_created"] == 1
    assert preview["summary"]["stack_members_created"] == 1
    assert preview["summary"]["module_bays_created"] == 4
    assert preview["summary"]["modules_created"] == 2
    assert preview["summary"]["module_types_created"] == 1
    assert preview["summary"]["power_ports_created"] == 2
    checks.append("joint stack and PSU preview validates unsaved member/type parents with zero DML")

    applied = apply_discovery(observed, target, interface_status=interface_status)
    target.refresh_from_db()
    assert target.serial == baseline["device"]["serial"]
    assert target.vc_position == 1
    assert target.virtual_chassis.master.vc_position == 2
    owners = {row.vc_position: row for row in target.virtual_chassis.members.all()}
    assert set(owners) == {1, 2}
    assert owners[1].pk == target.pk
    assert owners[2].device_type.model == observed["identity"]["model"]
    for item in observed["components"]["items"]:
        owner = owners[item["member"]]
        assert owner.serial == item["device_serial"]
        bay = ModuleBay.objects.get(parent_device=owner, name="Power Supply B")
        asset = Module.objects.get(parent_module_bay=bay, serial=item["serial"])
        inlet = PowerPort.objects.get(device=owner, module=asset)
        assert asset.device.pk == owner.pk
        assert inlet.name == "Power Input" and inlet.type == "iec-60320-c14"
        assert inlet.maximum_draw == 1200 and inlet.allocated_draw is None
        assert inlet.power_factor == Decimal("1.00")
        empty_bay = ModuleBay.objects.get(parent_device=owner, name="Power Supply A")
        assert not Module.objects.filter(parent_module_bay=empty_bay).exists()
    assert applied["summary"]["power_ports_created"] == 2
    checks.append("full stack apply places both PSU Modules/inlets on their serial-matched members")

    stable = snapshot_inventory(target, discovery=observed)
    stable_counts = catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured, "Repeated joint stack/PSU discovery issued inventory writes")
    assert catalog_counts() == stable_counts
    assert snapshot_inventory(target, discovery=observed) == stable
    assert all(value == 0 for value in repeated["summary"].values()), repeated["summary"]
    checks.append("repeated full stack/PSU apply preserves the graph and issues zero DML")

    failing_target, failing = fixture()
    before_failure = catalog_counts()
    failure_snapshot = snapshot_inventory(failing_target, discovery=failing)
    failed_item = next(item for item in failing["components"]["items"] if item["member"] == 2)
    original_save = PowerPort.validated_save
    preceding_writes = []

    def fail_last_inlet(port, *args, **kwargs):
        if port.module.serial == failed_item["serial"]:
            assert Device.objects.filter(serial=failed_item["device_serial"]).exists()
            assert DeviceType.objects.filter(model=failing["identity"]["model"]).exists()
            current_target = Device.objects.get(pk=failing_target.pk)
            assert current_target.virtual_chassis is not None
            assert current_target.virtual_chassis.master.serial == failed_item["device_serial"]
            assert Module.objects.filter(serial=port.module.serial).exists()
            assert PowerPort.objects.filter(
                device_id=failing_target.pk,
                module__serial=failing["components"]["items"][1]["serial"],
            ).exists()
            preceding_writes.append(True)
            raise ValidationError({"name": "Intentional late joint stack/PSU inlet failure"})
        return original_save(port, *args, **kwargs)

    try:
        with patch.object(PowerPort, "validated_save", fail_last_inlet):
            apply_discovery(failing, failing_target, interface_status=interface_status)
    except ValidationError:
        pass
    else:
        raise AssertionError("Intentional late joint stack/PSU failure did not occur")
    assert preceding_writes, "Late failure did not exercise the previously saved stack graph"
    assert catalog_counts() == before_failure
    failing_target.refresh_from_db()
    assert failing_target.virtual_chassis_id is None
    assert snapshot_inventory(failing_target, discovery=failing) == failure_snapshot
    assert not Device.objects.filter(serial=failed_item["device_serial"]).exists()
    assert not DeviceType.objects.filter(model=failing["identity"]["model"]).exists()
    assert not Module.objects.filter(serial=failed_item["serial"]).exists()
    checks.append("late inlet failure rolls back the full new VC/member/type/PSU/inlet graph")
