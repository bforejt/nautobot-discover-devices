"""Native checks for evidence-led discovery without chassis or component PID maps."""

import re
import uuid
from copy import deepcopy

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def run(device, interface_status, checks):
    """Use native Other interfaces and placement-free catalog facts under rollback."""
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Interface,
        Manufacturer,
        Module,
        ModuleBay,
        ModuleType,
        PowerPort,
    )
    from nautobot.extras.models import CustomField

    from jobs.adapters.cisco_generic_components import collect as collect_components
    from jobs.adapters.cisco_iosxe import _interfaces
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Generic checks require outer rollback"
    assert ("other", "Other") in Interface._meta.get_field("type").flatchoices
    initial_custom_fields = CustomField.objects.count()
    token = uuid.uuid4().hex[:10]
    pid = "SYNTHETIC-UNLISTED-CHASSIS-" + token
    device_type = DeviceType(manufacturer=device.device_type.manufacturer, model=pid)
    device_type.validated_save()
    target = Device(
        name="CODEX-GENERIC-" + token,
        serial="SYNTHETIC-GENERIC-" + token,
        device_type=device_type,
        role=device.role,
        location=device.location,
        status=device.status,
        platform=device.platform,
        software_version=device.software_version,
    )
    target.validated_save()
    raw = {
        "Cisco-IOS-XE-interfaces-oper:interfaces": {
            "interface": [
                {
                    "name": "TenGigabitEthernet1/0/1",
                    "interface-type": "iana-iftype-ethernet-csmacd",
                    "admin-status": "if-state-up",
                    "oper-status": "if-oper-state-ready",
                    "description": "No chassis capability matrix required",
                    "phys-address": "02:00:00:00:00:01",
                    "mtu": 9216,
                    "speed": 1_000_000_000,
                },
                {
                    "name": "GigabitEthernet1/0/2",
                    "interface-type": "iana-iftype-ethernet-csmacd",
                    "admin-status": "if-state-down",
                    "oper-status": "if-oper-state-down",
                    "speed": 1_000_000_000,
                    "ether-state": {"media-type": "ether-media-type-rj45"},
                },
            ]
        }
    }
    interfaces, excluded = _interfaces(raw, pid, 1, [], [])
    assert all(row["type"] is None and "hardware_profile" not in row for row in interfaces)
    source = {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": target.name,
            "serial": target.serial,
            "model": pid,
            "software_version": device.software_version.version,
        },
        "interfaces": interfaces,
        "excluded_interfaces": excluded,
        "warnings": [],
        "lag_memberships": [],
    }
    before = snapshot_inventory(target, discovery=source)
    plan = build_plan(source, before)
    assert not plan["errors"] and not plan["summary"]["blocked"]
    assert plan["summary"]["unknown_interface_capabilities"] == 2
    assert all(row["type"] == "other" for row in plan["interface_creates"])
    with CaptureQueriesContext(connection) as captured:
        validate_plan(plan, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert snapshot_inventory(target, discovery=source) == before
    checks.append(
        "unknown chassis native Other interface preview validates without database writes"
    )

    saved = apply_discovery(source, target, interface_status=interface_status)
    assert saved["summary"]["interfaces_created"] == 2
    ready = target.interfaces.get(name="TenGigabitEthernet1/0/1")
    down = target.interfaces.get(name="GigabitEthernet1/0/2")
    assert ready.type == down.type == "other"
    assert ready.is_connectable and not ready.is_virtual and not ready.is_lag
    assert ready.enabled is True and ready.speed == 1_000_000
    assert str(ready.mac_address) == "02:00:00:00:00:01" and ready.mtu == 9216
    assert ready.port_type == "" and ready.duplex == ""
    assert down.enabled is False and down.speed is None and down.port_type == "8p8c"
    assert down.duplex == "" and down.mgmt_only is False
    after = snapshot_inventory(target, discovery=source)
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(source, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert repeated["summary"]["interfaces_created"] == 0
    assert repeated["summary"]["interfaces_updated"] == 0
    assert not any(row["field"] == "type" for row in repeated["conflicts"])
    assert snapshot_inventory(target, discovery=source) == after
    checks.append("unknown chassis known interface facts apply natively and repeat without writes")

    ready.type = "10gbase-x-sfpp"
    ready.validated_save()
    before = snapshot_inventory(target, discovery=source)
    with CaptureQueriesContext(connection) as captured:
        preserved = apply_discovery(source, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert not any(row["field"] == "type" for row in preserved["conflicts"])
    assert snapshot_inventory(target, discovery=source) == before
    checks.append("unknown capability preserves an existing native type without an Other conflict")

    missing = deepcopy(source)
    raw_missing = {
        "Cisco-IOS-XE-interfaces-oper:interfaces": {
            "interface": [
                {
                    "name": "TenGigabitEthernet1/0/99",
                    "admin-status": "if-state-up",
                    "oper-status": "if-oper-state-ready",
                    "speed": 1_000_000_000,
                }
            ]
        }
    }
    missing["interfaces"], _ = _interfaces(raw_missing, pid, 1, [], [])
    missing_plan = build_plan(missing, snapshot_inventory(target, discovery=missing))
    assert not missing_plan["interface_creates"]
    assert not missing_plan["unknown_interface_capabilities"]
    checks.append(
        "unknown chassis lacks no-guessing Ethernet fallback without structured classification"
    )

    manufacturer = "New optics OEM " + token
    part_number = "FUTURE-BIDI-" + token
    identity = {
        "key": "identity:future-optic",
        "kind": "transceiver",
        "manufacturer": manufacturer,
        "model": part_number,
        "part_number": part_number,
        "serial": "SERIAL-" + token,
        "source": {
            "manufacturer": {
                "module": "Cisco-IOS-XE-platform-oper",
                "path": "/data/Cisco-IOS-XE-platform-oper:components",
                "field": "state/mfg-name",
                "component": "Reported Transceiver",
                "value": manufacturer,
            }
        },
        "observations": {"parent": "Unknown chassis", "location": None},
    }
    generic = deepcopy(source)
    generic["components"] = {
        "schema_version": 1,
        "items": [],
        "identities": [identity],
        "unresolved": [],
        "excluded": [],
    }
    physical_counts = (Module.objects.count(), ModuleBay.objects.count(), PowerPort.objects.count())
    before = snapshot_inventory(target, discovery=generic)
    plan = build_plan(generic, before)
    assert not plan["errors"] and not plan["summary"]["blocked"]
    assert plan["summary"]["manufacturers_created"] == 1
    assert plan["summary"]["module_types_created"] == 1
    assert not plan["components"]["modules"] and not plan["components"]["bays"]
    assert not plan["components"]["interface_assignments"]
    with CaptureQueriesContext(connection) as captured:
        validate_plan(plan, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert snapshot_inventory(target, discovery=generic) == before
    checks.append(
        "unfamiliar component identity previews its native catalog without guessing placement"
    )

    saved = apply_discovery(generic, target, interface_status=interface_status)
    assert saved["summary"]["module_types_created"] == 1
    catalog_type = ModuleType.objects.get(manufacturer__name=manufacturer, part_number=part_number)
    assert catalog_type.model == part_number
    assert Manufacturer.objects.filter(name=manufacturer).exists()
    assert not catalog_type.interface_templates.exists()
    assert not catalog_type.power_port_templates.exists()
    assert (Module.objects.count(), ModuleBay.objects.count(), PowerPort.objects.count()) == (
        physical_counts
    )
    after = snapshot_inventory(target, discovery=generic)
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(generic, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert repeated["summary"]["module_types_created"] == 0
    assert repeated["summary"]["manufacturers_created"] == 0
    assert repeated["summary"]["modules_created"] == 0
    assert snapshot_inventory(target, discovery=generic) == after
    checks.append(
        "unfamiliar component creates only native manufacturer/type and repeats without writes"
    )

    # Native catalog aliases can match an explicitly reported PID without renaming.
    catalog_type.model = "Operator optics name " + token
    catalog_type.validated_save()
    alias_before = snapshot_inventory(target, discovery=generic)
    with CaptureQueriesContext(connection) as captured:
        alias_result = apply_discovery(generic, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert alias_result["summary"]["module_types_created"] == 0
    assert snapshot_inventory(target, discovery=generic) == alias_before
    checks.append(
        "placement-free identity respects native ModuleType aliases matched by reported PID"
    )
    # Matrix-free placement uses actual reported parent references and opaque
    # names, even for a new chassis, module, PSU, fan and optic PID.
    root_name = "Reported chassis " + token
    root = {
        "name": root_name,
        "model": pid,
        "serial": target.serial,
        "manufacturer": device.device_type.manufacturer.name,
        "platform_type": "comp-chassis",
        "parent": None,
        "empty": False,
        "removable": False,
    }
    owner = {
        "model": pid,
        "serial": target.serial,
        "position": 1,
        "identity_source": {"hw_type": "hw-type-chassis", "inventory_index": 1},
    }
    reported_module_name = "Reported attachment alpha " + token
    reported_parts = (
        (reported_module_name, "hw-type-pim", "comp-module", "UPLINK", root_name),
        ("Reported power beta " + token, "hw-type-pem", "comp-power-supply", "PSU", root_name),
        ("Reported fan gamma " + token, "hw-type-fantray", "comp-fan", "FAN", root_name),
        (
            "TenGigabitEthernet1/0/1",
            "hw-type-transceiver",
            "comp-transceiver",
            "BIDI",
            reported_module_name,
        ),
    )
    flat, platform = [], [root]
    reported_manufacturer = "Reported components OEM " + token
    for index, (name, hw_type, platform_type, suffix, parent) in enumerate(reported_parts, 2):
        component_pid = "UNLISTED-" + suffix + "-" + token
        serial = "SERIAL-" + suffix + "-" + token
        flat.append(
            {
                "name": name,
                "hw_type": hw_type,
                "hardware_class": "hw-class-physical",
                "field_replaceable": True,
                "inventory_index": index,
                "model": component_pid,
                "serial": serial,
                "hardware_revision": "HW-EXPLICIT",
            }
        )
        platform.append(
            {
                "name": name,
                "model": component_pid,
                "serial": serial,
                "manufacturer": reported_manufacturer,
                "platform_type": platform_type,
                "parent": parent,
                "location": "Unknown location encoding remains an observation",
                "empty": False,
                "removable": True,
            }
        )
    collected = collect_components(
        flat,
        platform,
        {1: owner},
        interfaces=source["interfaces"],
        existing_items=[],
        existing_unresolved=[],
    )
    assert not collected["unresolved"] and len(collected["items"]) == 4
    assert all(not item["interfaces"] and "power_ports" not in item for item in collected["items"])
    placed = deepcopy(source)
    placed["components"] = {
        "schema_version": 1,
        "items": collected["items"],
        "identities": collected["identities"],
        "unresolved": collected["unresolved"],
        "excluded": [],
    }
    interface_snapshot = list(target.interfaces.values("id", "name", "type", "module_id"))
    before = snapshot_inventory(target, discovery=placed)
    placed_plan = build_plan(placed, before)
    assert not placed_plan["errors"] and not placed_plan["summary"]["blocked"]
    assert placed_plan["summary"]["modules_created"] == 4
    assert placed_plan["summary"]["module_bays_created"] == 4
    assert placed_plan["summary"]["module_types_created"] == 4
    assert placed_plan["summary"]["power_ports_created"] == 0
    assert not placed_plan["components"]["interface_assignments"]
    with CaptureQueriesContext(connection) as captured:
        validate_plan(placed_plan, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert snapshot_inventory(target, discovery=placed) == before
    checks.append(
        "unlisted module, PSU, fan and nested optic preview uses only reported containment"
    )

    saved = apply_discovery(placed, target, interface_status=interface_status)
    assert saved["summary"]["modules_created"] == 4
    module = Module.objects.get(serial="SERIAL-UPLINK-" + token)
    optic = Module.objects.get(serial="SERIAL-BIDI-" + token)
    psu = Module.objects.get(serial="SERIAL-PSU-" + token)
    fan = Module.objects.get(serial="SERIAL-FAN-" + token)
    assert module.parent_module_bay.parent_device_id == target.pk
    assert psu.parent_module_bay.parent_device_id == target.pk
    assert fan.parent_module_bay.parent_device_id == target.pk
    assert optic.parent_module_bay.parent_module_id == module.pk
    for asset, name in (
        (module, reported_module_name),
        (psu, reported_parts[1][0]),
        (fan, reported_parts[2][0]),
        (optic, "TenGigabitEthernet1/0/1"),
    ):
        assert asset.parent_module_bay.name == name
        assert asset.parent_module_bay.position == name
        assert asset.parent_module_bay.label == ""
        assert asset.module_type.manufacturer.name == reported_manufacturer
        assert not asset.module_type.interface_templates.exists()
        assert not asset.module_type.power_port_templates.exists()
    assert list(target.interfaces.values("id", "name", "type", "module_id")) == interface_snapshot
    assert PowerPort.objects.count() == physical_counts[2]
    after = snapshot_inventory(target, discovery=placed)
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(placed, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert repeated["summary"]["modules_created"] == 0
    assert repeated["summary"]["module_bays_created"] == 0
    assert repeated["summary"]["module_types_created"] == 0
    assert repeated["summary"]["interfaces_updated"] == 0
    assert snapshot_inventory(target, discovery=placed) == after
    checks.append(
        "unlisted serialized assets apply to native bays and repeat without inferred inlets"
    )
    assert CustomField.objects.count() == initial_custom_fields
