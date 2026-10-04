"""Native physical stack console placement within an outer rollback."""

import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def run(device, interface_status, checks):
    from django.core.exceptions import ValidationError
    from django.db import connection
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import Cable, ConsolePort, ConsoleServerPort, Device, VirtualChassis
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import CustomField, Status

    from jobs.adapters.cisco_access_ports import collect_stack_consoles
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert connection.in_atomic_block, "Stack console checks require outer rollback"
    device.refresh_from_db()
    assert device.device_type.model == "C9300-48UXM", (
        "These console checks need the reviewed chassis"
    )
    assert device.software_version is not None

    def counts():
        return {
            model.__name__: model.objects.count()
            for model in (
                Device,
                VirtualChassis,
                ConsolePort,
                ConsoleServerPort,
                Cable,
                CableToCableTermination,
                CustomField,
            )
        }

    def fixture():
        suffix = uuid.uuid4().hex[:12]
        serials = {position: "STACK-CONSOLE-%s-%d" % (suffix, position) for position in (1, 2)}
        target = Device(
            name="stack-console-check-" + suffix,
            serial=serials[1],
            device_type=device.device_type,
            platform=device.platform,
            location=device.location,
            role=device.role,
            status=device.status,
            tenant=device.tenant,
            software_version=device.software_version,
        )
        with SkipAutoComponentCreation():
            target.validated_save()
        members = [
            {
                "position": position,
                "serial": serials[position],
                "model": device.device_type.model,
                "role": "role-active" if position == 2 else "role-standby",
                "priority": position + 10,
                "state": "state-ready",
                "stack_mode": "mode-stackwise-rear",
                "sources": {
                    "identity": {"module": "Cisco-IOS-XE-device-hardware-oper", "synthetic": True},
                    "membership": {"module": "Cisco-IOS-XE-stack-oper", "chassis_number": position},
                },
            }
            for position in (1, 2)
        ]
        stack = {
            "schema_version": 1,
            "name": target.name,
            "is_stack": True,
            "active_position": 2,
            "members": members,
            "absent_members": [],
            "unresolved": [],
            "observations": {},
        }
        facts = {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": {
                "hostname": target.name,
                "serial": serials[2],
                "model": device.device_type.model,
                "software_version": device.software_version.version,
            },
            "stack": stack,
            "console_ports": collect_stack_consoles(stack),
            "interfaces": [],
            "warnings": [],
            "excluded_interfaces": [],
        }
        return target, facts

    target, observed = fixture()
    existing = ConsolePort(device=target, name="Console RJ45", type="", label="Operator label")
    existing.validated_save()
    server = ConsoleServerPort(device=target, name="Synthetic server", type="rj-45")
    server.validated_save()
    cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
    cable.validated_save()
    for attrs in (
        {"cable_end": "A", "console_port": existing},
        {"cable_end": "B", "console_server_port": server},
    ):
        termination = CableToCableTermination(cable=cable, connector=1, **attrs)
        termination.full_clean()
        termination.save()
    joins = list(cable.terminations.order_by("pk").values())
    initial = counts()
    baseline = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(observed, snapshot_inventory(target, discovery=observed))
        assert not preview["errors"], preview["errors"]
        validate_plan(preview, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert counts() == initial
    assert snapshot_inventory(target, discovery=observed) == baseline
    assert preview["summary"]["console_ports_created"] == 3
    assert preview["summary"]["console_ports_updated"] == 1
    checks.append("physical stack ConsolePort preview validates an unsaved member with zero DML")

    apply_discovery(observed, target, interface_status=interface_status)
    target.refresh_from_db()
    for owner in target.virtual_chassis.members.all():
        assert ConsolePort.objects.filter(device=owner, module__isnull=True).count() == 2
        assert set(owner.console_ports.values_list("type", flat=True)) == {"rj-45", "usb-mini-b"}
    existing.refresh_from_db()
    assert existing.type == "rj-45" and existing.label == "Operator label"
    assert existing.cable_id == cable.pk
    assert list(cable.terminations.order_by("pk").values()) == joins
    assert CustomField.objects.count() == initial["CustomField"]
    checks.append(
        "stack consoles save on their physical members while preserving an existing cable"
    )

    existing.name = "Operator serial connector"
    existing.validated_save()
    stable = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(observed, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert repeated["summary"]["console_ports_created"] == 0
    assert repeated["summary"]["console_ports_updated"] == 0
    assert snapshot_inventory(target, discovery=observed) == stable
    checks.append("same connector names on two members remain distinct and repeat without writes")

    other = target.virtual_chassis.members.get(vc_position=2)
    reported_serial = other.serial
    other.serial = "  " + reported_serial + "  "
    other.validated_save()
    other.console_ports.get(type="usb-mini-b").delete()
    other_rj45 = other.console_ports.get(type="rj-45")
    other_rj45.type = ""
    other_rj45.validated_save()
    with CaptureQueriesContext(connection) as captured:
        padded_preview = build_plan(observed, snapshot_inventory(target, discovery=observed))
        validate_plan(padded_preview, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert padded_preview["summary"]["console_ports_created"] == 1
    assert padded_preview["summary"]["console_ports_updated"] == 1
    apply_discovery(observed, target, interface_status=interface_status)
    other.refresh_from_db()
    assert other.serial == "  " + reported_serial + "  "
    assert set(other.console_ports.values_list("type", flat=True)) == {"rj-45", "usb-mini-b"}
    stable = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        apply_discovery(observed, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert snapshot_inventory(target, discovery=observed) == stable
    checks.append("existing padded member serial is preserved while console ownership resolves")

    failing_target, failing = fixture()
    initial = counts()
    baseline = snapshot_inventory(failing_target, discovery=failing)
    member_serial = failing["stack"]["members"][1]["serial"]
    original_save = ConsolePort.validated_save
    writes = []

    def fail_last(port, *args, **kwargs):
        if port.device.serial == member_serial and port.type == "usb-mini-b":
            assert Device.objects.filter(serial=member_serial).exists()
            assert ConsolePort.objects.filter(device=port.device, type="rj-45").exists()
            writes.append(True)
            raise ValidationError({"name": "Intentional late physical stack console failure"})
        return original_save(port, *args, **kwargs)

    try:
        with patch.object(ConsolePort, "validated_save", fail_last):
            apply_discovery(failing, failing_target, interface_status=interface_status)
    except ValidationError:
        pass
    else:
        raise AssertionError("Expected late physical stack console failure")
    assert writes
    assert counts() == initial
    failing_target.refresh_from_db()
    assert failing_target.virtual_chassis_id is None
    assert not Device.objects.filter(serial=member_serial).exists()
    assert snapshot_inventory(failing_target, discovery=failing) == baseline
    checks.append("late console failure rolls back the new physical stack and preceding consoles")
