"""Verify access-port inventory through real models inside the outer rollback."""

import copy
import json
import re
import uuid
from pathlib import Path
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.dcim.models import (
        Cable,
        ConsolePort,
        ConsolePortTemplate,
        ConsoleServerPort,
        Device,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import CustomField
    from nautobot.ipam.models import VRF, IPAddress, IPAddressToInterface, Namespace, Prefix

    return {
        model.__name__: model.objects.count()
        for model in (
            Device,
            ConsolePort,
            ConsolePortTemplate,
            ConsoleServerPort,
            Cable,
            CableToCableTermination,
            CustomField,
            Namespace,
            Prefix,
            VRF,
            IPAddress,
            IPAddressToInterface,
        )
    }


def run(device, interface_status, checks):
    """Exercise purpose correction, console creation, validation and idempotence."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Cable,
        ConsolePort,
        ConsoleServerPort,
        Device,
        Interface,
        SoftwareVersion,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import Status

    from jobs.adapters import cisco_access_ports as access
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Access checks require outer rollback"
    device.refresh_from_db()
    suffix = str(uuid.uuid4().int)[:12]
    target = Device(
        name="discovery-access-" + suffix,
        serial="ACCESS-" + suffix,
        device_type=device.device_type,
        location=device.location,
        role=device.role,
        status=device.status,
        platform=device.platform,
        software_version=device.software_version
        or SoftwareVersion.objects.filter(platform=device.platform).first(),
    )
    target.validated_save()
    assert not target.console_ports.exists(), "This lab DeviceType has no console templates"
    port = Interface(
        device=target,
        name=access.MANAGEMENT_INTERFACE,
        type="1000base-t",
        enabled=False,
        mgmt_only=False,
        mtu=1500,
        port_type="8p8c",
        duplex="auto",
        status=interface_status,
    )
    port.validated_save()
    interfaces = [
        {
            "name": port.name,
            "type": port.type,
            "enabled": port.enabled,
            "mtu": port.mtu,
            "port_type": port.port_type,
            "duplex": port.duplex,
            "type_source": "C9300-48UXM dedicated 1G copper management port",
        }
    ]
    raw = json.loads((Path(__file__).parent / "fixtures/iosxe_access_ports.json").read_text())
    payloads = {
        access.CONSOLE_PATH: raw["console_config"],
        access.MANAGEMENT_PATH: raw["management_config"],
        access.MANAGEMENT_OPER_PATH: raw["management_oper"],
        access.VRF_PATH: raw["vrf_config"],
    }

    class FixtureClient:
        def get(self, path):
            return copy.deepcopy(payloads[path.split("?", 1)[0]])

    console, management = access.collect(
        FixtureClient(), interfaces, model=target.device_type.model, member=1
    )
    observed = {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": target.name,
            "serial": target.serial,
            "model": target.device_type.model,
            "software_version": target.software_version.version,
        },
        "interfaces": interfaces,
        "console_ports": console,
        "management": management,
        "warnings": [],
        "excluded_interfaces": [],
    }
    baseline = snapshot_inventory(target)
    before_domains = catalog_counts()

    with CaptureQueriesContext(connection) as captured:
        plan = build_plan(observed, snapshot_inventory(target))
        validate_plan(plan, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert snapshot_inventory(target) == baseline
    assert plan["summary"]["console_ports_created"] == 2
    assert plan["summary"]["management_interfaces_updated"] == 1
    assert management["interfaces"][0]["vrf"] == "Mgmt-vrf"
    assert management["interfaces"][0]["ipv4"] == []
    assert console["observations"]["console_line"]["baudrate"] is None
    checks.append("console creation and management-purpose preview validate with zero DML")

    invalid = copy.deepcopy(observed)
    invalid["console_ports"]["items"][1]["name"] = "x" * 300
    try:
        apply_discovery(invalid, target, interface_status=interface_status)
    except ValidationError:
        pass
    else:
        raise AssertionError("Overlong console name passed native validation")
    assert snapshot_inventory(target) == baseline
    checks.append("native console validation rejects the full plan before inventory is saved")

    saved_before_failure = []
    original_save = ConsolePort.validated_save

    def fail_second_console(console_port, *args, **kwargs):
        if console_port.name == "Console USB":
            assert ConsolePort.objects.filter(device=target, name="Console RJ45").exists()
            assert Interface.objects.get(pk=port.pk).mgmt_only is True
            saved_before_failure.append(True)
            raise ValidationError({"name": "Intentional last-console failure"})
        return original_save(console_port, *args, **kwargs)

    with patch.object(ConsolePort, "validated_save", fail_second_console):
        try:
            apply_discovery(observed, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Intentional console save failure did not occur")
    assert saved_before_failure
    assert snapshot_inventory(target) == baseline
    checks.append("late console failure rolls back the earlier console and management correction")

    applied = apply_discovery(observed, target, interface_status=interface_status)
    port.refresh_from_db()
    target.refresh_from_db()
    assert port.mgmt_only is True
    assert port.enabled is False and port.vrf_id is None and not port.ip_addresses.exists()
    assert target.primary_ip4_id is None and target.primary_ip6_id is None
    assert sorted(target.console_ports.values_list("type", flat=True)) == ["rj-45", "usb-mini-b"]
    assert applied["summary"]["console_ports_created"] == 2
    assert applied["summary"]["management_interfaces_updated"] == 1
    after_domains = catalog_counts()
    assert {key: value for key, value in after_domains.items() if key != "ConsolePort"} == {
        key: value for key, value in before_domains.items() if key != "ConsolePort"
    }
    checks.append("apply creates two native console ports without VRF, IP or custom-field changes")

    before_repeat = snapshot_inventory(target)
    with CaptureQueriesContext(connection) as captured:
        repeat = apply_discovery(observed, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert repeat["summary"]["console_ports_created"] == 0
    assert repeat["summary"]["console_ports_updated"] == 0
    assert repeat["summary"]["management_interfaces_updated"] == 0
    assert snapshot_inventory(target) == before_repeat
    checks.append("repeated console and management discovery preserves IDs with zero DML")

    rj45 = target.console_ports.get(type="rj-45")
    rj45.name = "Operator Console " + suffix
    rj45.label = "Operator label"
    rj45.description = "Operator description"
    rj45.validated_save()
    operator_snapshot = snapshot_inventory(target)
    with CaptureQueriesContext(connection) as captured:
        preserved = apply_discovery(observed, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)
    assert snapshot_inventory(target) == operator_snapshot
    assert preserved["summary"]["console_ports_created"] == 0
    assert preserved["summary"]["console_ports_updated"] == 0
    checks.append(
        "unique connector adoption preserves operator console name, label and description"
    )

    # Persist a real native cable relationship, then fill a blank connector.
    # Discovery must not recreate or modify either termination join.
    rj45.name = "Console RJ45"
    rj45.type = ""
    rj45.validated_save()
    counterpart = ConsoleServerPort(device=target, name="Synthetic server", type="rj-45")
    counterpart.validated_save()
    cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
    cable.validated_save()
    for attributes in (
        {"cable_end": "A", "console_port": rj45},
        {"cable_end": "B", "console_server_port": counterpart},
    ):
        termination = CableToCableTermination(cable=cable, connector=1, **attributes)
        termination.full_clean()
        termination.save()
    joins_before = list(cable.terminations.order_by("pk").values())
    rj45.refresh_from_db()
    cable_id = rj45.cable_id
    assert cable_id == cable.pk
    cabled = apply_discovery(observed, target, interface_status=interface_status)
    rj45.refresh_from_db()
    assert rj45.type == "rj-45" and rj45.cable_id == cable_id
    assert rj45.label == "Operator label" and rj45.description == "Operator description"
    assert list(cable.terminations.order_by("pk").values()) == joins_before
    assert cabled["summary"]["console_ports_updated"] == 1
    checks.append("filling a cabled console connector preserves cable and termination identities")
