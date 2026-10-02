"""Verify serialized optics through real models inside the outer rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def run(device, interface_status, checks):
    """Create a nested optic without replacing its physical interface or owner."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Cable,
        Device,
        Interface,
        Manufacturer,
        Module,
        ModuleBay,
        ModuleType,
        SoftwareVersion,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import Status

    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan
    from tests.nautobot_access_integration import catalog_counts as access_catalog_counts
    from tests.nautobot_components_integration import catalog_counts as component_catalog_counts

    assert transaction.get_connection().in_atomic_block, "Optic checks require outer rollback"
    device.refresh_from_db()
    suffix = str(uuid.uuid4().int)[:12]
    target = Device(
        name="discovery-transceiver-" + suffix,
        serial="TRANSCEIVER-" + suffix,
        device_type=device.device_type,
        location=device.location,
        role=device.role,
        status=device.status,
        platform=device.platform,
        software_version=device.software_version
        or SoftwareVersion.objects.filter(platform=device.platform).first(),
    )
    target.validated_save()
    canonical_port = "GigabitEthernet1/1/1"
    port_fact = {
        "name": canonical_port,
        "type": "1000base-x-sfp",
        "enabled": True,
        "description": "Operator-configured SFP port",
        "mtu": 1500,
        "mac_address": None,
        "type_source": "synthetic transceiver integration fixture",
        "observations": {},
    }
    parent = {
        "key": "uplink:1/1",
        "kind": "network-module",
        "manufacturer": target.device_type.manufacturer.name,
        "model": "CODEX-NM-" + suffix,
        "part_number": "CODEX-NM-" + suffix,
        "serial": "CODEX-NM-SERIAL-" + suffix,
        "parent_key": None,
        "bay": {"name": "Uplink 1/1", "position": "1", "label": "Uplink 1/1"},
        "interfaces": [canonical_port],
        "source": {},
        "observations": {},
    }

    def observed(items):
        return {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": {
                "hostname": target.name,
                "serial": target.serial,
                "model": target.device_type.model,
                "software_version": target.software_version.version,
            },
            "interfaces": [copy.deepcopy(port_fact)],
            "lag_memberships": [],
            "warnings": [],
            "excluded_interfaces": [],
            "components": {
                "schema_version": 1,
                "items": copy.deepcopy(items),
                "unresolved": [],
                "excluded": [],
            },
        }

    apply_discovery(observed([parent]), target, interface_status=interface_status)
    target.refresh_from_db()
    uplink = Module.objects.get(serial=parent["serial"])
    port = Interface.objects.get(device=target, name=canonical_port)
    port.name = "Gi1/1/1"
    lag = Interface(
        device=target,
        name="Port-channel1",
        type="lag",
        enabled=True,
        status=interface_status,
    )
    lag.validated_save()
    port.lag = lag
    port.validated_save()
    counterpart = Interface(
        device=target,
        name="Gi1/1/99",
        type="1000base-x-sfp",
        enabled=True,
        status=interface_status,
    )
    counterpart.validated_save()
    cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
    cable.validated_save()
    for cable_end, interface in (("A", port), ("B", counterpart)):
        join = CableToCableTermination(
            cable=cable, cable_end=cable_end, connector=1, interface=interface
        )
        join.full_clean()
        join.save()
    port.refresh_from_db()
    assert port.module_id == uplink.pk and port.cable_id == cable.pk
    port_values = {
        "id": port.pk,
        "name": port.name,
        "module_id": port.module_id,
        "lag_id": port.lag_id,
        "cable_id": port.cable_id,
        "description": port.description,
        "type": port.type,
        "custom_fields": copy.deepcopy(port._custom_field_data),
    }
    cable_joins = list(cable.terminations.order_by("pk").values())
    reported_manufacturer = "CISCO-EQUIV-" + suffix
    assert not Manufacturer.objects.filter(name=reported_manufacturer).exists()
    optic = {
        "key": "transceiver:" + canonical_port,
        "kind": "transceiver",
        "manufacturer": reported_manufacturer,
        "model": "GLC-SX-MM",
        "part_number": "GLC-SX-MM",
        "serial": "CODEX-SFP-SERIAL-" + suffix,
        "parent_key": parent["key"],
        "bay": {
            "name": "SFP " + canonical_port,
            "position": "1",
            "label": canonical_port,
        },
        "interfaces": [],
        "source": {
            "path": "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware",
            "field": "device-inventory",
            "manufacturer": {
                "module": "Cisco-IOS-XE-platform-oper",
                "path": "/data/Cisco-IOS-XE-platform-oper:components",
                "field": "state/mfg-name",
                "component": "synthetic-transceiver-component-" + suffix,
                "value": reported_manufacturer,
            },
        },
        "observations": {"version": "V03"},
    }
    discovery = observed([optic, parent])

    def counts():
        return {
            **component_catalog_counts(),
            **access_catalog_counts(),
            "Interface": Interface.objects.count(),
        }

    def assert_no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    def assert_port_preserved():
        port.refresh_from_db()
        assert {
            "id": port.pk,
            "name": port.name,
            "module_id": port.module_id,
            "lag_id": port.lag_id,
            "cable_id": port.cable_id,
            "description": port.description,
            "type": port.type,
            "custom_fields": port._custom_field_data,
        } == port_values
        assert list(cable.terminations.order_by("pk").values()) == cable_joins
        assert not Interface.objects.filter(device=target, name=canonical_port).exists()

    baseline = snapshot_inventory(target)
    before_counts = counts()
    before_custom_fields = copy.deepcopy(target._custom_field_data)
    with CaptureQueriesContext(connection) as captured:
        plan = build_plan(discovery, snapshot_inventory(target, discovery=discovery))
        validate_plan(plan, target, interface_status=interface_status)
    assert_no_dml(captured, "Transceiver preview saved an unsaved Manufacturer or nested parent")
    assert not plan["errors"] and not plan["conflicts"]
    for field in (
        "manufacturers_created",
        "module_types_created",
        "module_bays_created",
        "modules_created",
    ):
        assert plan["summary"][field] == 1, field
    assert plan["summary"]["interface_modules_updated"] == 0
    assert snapshot_inventory(target) == baseline and counts() == before_counts
    assert_port_preserved()
    checks.append(
        "nested transceiver preview validates a new Manufacturer and catalogs with zero DML"
    )

    invalid = copy.deepcopy(discovery)
    invalid["components"]["items"][0]["manufacturer"] = "x" * (
        Manufacturer._meta.get_field("name").max_length + 1
    )
    invalid["components"]["items"][0]["source"]["manufacturer"]["value"] = invalid["components"][
        "items"
    ][0]["manufacturer"]
    with CaptureQueriesContext(connection) as captured:
        try:
            apply_discovery(invalid, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                "Overlong reported transceiver Manufacturer passed native validation"
            )
    assert_no_dml(captured, "Invalid transceiver Manufacturer was saved before rejection")
    assert snapshot_inventory(target) == baseline and counts() == before_counts
    checks.append(
        "native Manufacturer validation rejects the entire transceiver plan before writes"
    )

    original_save = Module.validated_save
    preceding_writes = []

    def fail_transceiver(module, *args, **kwargs):
        if module.serial == optic["serial"]:
            manufacturer = Manufacturer.objects.get(name=reported_manufacturer)
            assert ModuleType.objects.filter(
                manufacturer=manufacturer, model=optic["model"], part_number=optic["part_number"]
            ).exists()
            assert ModuleBay.objects.filter(
                parent_device=target, parent_module=uplink, name=optic["bay"]["name"]
            ).exists()
            preceding_writes.append(True)
            raise ValidationError({"serial": "Intentional last-transceiver save failure"})
        return original_save(module, *args, **kwargs)

    with patch.object(Module, "validated_save", fail_transceiver):
        try:
            apply_discovery(discovery, target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Intentional nested transceiver save failure did not occur")
    assert preceding_writes, "Transceiver rollback test did not save preceding catalog and bay rows"
    assert snapshot_inventory(target) == baseline and counts() == before_counts
    assert not Manufacturer.objects.filter(name=reported_manufacturer).exists()
    assert_port_preserved()
    checks.append(
        "late transceiver save failure rolls back its Manufacturer, ModuleType and nested bay"
    )

    applied = apply_discovery(discovery, target, interface_status=interface_status)
    transceiver = Module.objects.get(serial=optic["serial"])
    manufacturer = Manufacturer.objects.get(name=reported_manufacturer)
    assert transceiver.module_type.manufacturer_id == manufacturer.pk
    assert transceiver.module_type.model == optic["model"]
    assert transceiver.module_type.part_number == optic["part_number"]
    assert transceiver.parent_module_bay.parent_module_id == uplink.pk
    assert transceiver.parent_module_bay.parent_device_id == target.pk
    assert transceiver.parent_module_bay.name == optic["bay"]["name"]
    assert transceiver.parent_module_bay.position == "1"
    assert transceiver.parent_module_bay.label == canonical_port
    assert transceiver.device.pk == target.pk and not transceiver.interfaces.exists()
    assert transceiver._custom_field_data == {} and transceiver.module_type._custom_field_data == {}
    assert applied["summary"]["manufacturers_created"] == 1
    assert applied["summary"]["modules_created"] == 1
    assert applied["summary"]["interface_modules_updated"] == 0
    after_counts = counts()
    for field, count in before_counts.items():
        expected_delta = 1 if field in {"Manufacturer", "ModuleType", "ModuleBay", "Module"} else 0
        assert after_counts[field] == count + expected_delta, field
    target.refresh_from_db()
    assert target._custom_field_data == before_custom_fields
    assert target.primary_ip4_id is None and target.primary_ip6_id is None
    assert_port_preserved()
    checks.append(
        "apply stores a native serialized optic under its uplink while preserving the port alias, "
        "UUID, module, LAG, cable, IPAM and custom fields"
    )

    before_repeat = snapshot_inventory(target)
    with CaptureQueriesContext(connection) as captured:
        repeat = apply_discovery(discovery, target, interface_status=interface_status)
    assert_no_dml(captured, "Repeated transceiver discovery issued inventory DML")
    for field in (
        "manufacturers_created",
        "module_types_created",
        "module_types_updated",
        "module_bays_created",
        "module_bays_updated",
        "modules_created",
        "modules_updated",
        "interfaces_created",
        "interfaces_updated",
        "interface_modules_updated",
    ):
        assert repeat["summary"][field] == 0, field
    assert snapshot_inventory(target) == before_repeat and counts() == after_counts
    assert_port_preserved()
    checks.append(
        "repeated nested transceiver discovery reuses every native row and issues zero DML"
    )

    replacement = copy.deepcopy(optic)
    replacement["serial"] = "CODEX-REPLACEMENT-" + suffix
    other_vendor = copy.deepcopy(replacement)
    other_vendor["manufacturer"] = "Other reported optic vendor " + suffix
    other_vendor["source"]["manufacturer"]["value"] = other_vendor["manufacturer"]
    relocated = copy.deepcopy(optic)
    relocated["bay"]["name"] = "SFP GigabitEthernet1/1/2"
    relocated["bay"]["position"] = "2"
    relocated["bay"]["label"] = "GigabitEthernet1/1/2"
    relocated["key"] = "transceiver:GigabitEthernet1/1/2"
    for conflicting in (replacement, other_vendor, relocated):
        with CaptureQueriesContext(connection) as captured:
            conflict = apply_discovery(
                observed([conflicting, parent]), target, interface_status=interface_status
            )
        assert_no_dml(
            captured, "A transceiver replacement or relocation changed populated inventory"
        )
        assert conflict["conflicts"]
        assert snapshot_inventory(target) == before_repeat and counts() == after_counts
        assert_port_preserved()
    assert not Manufacturer.objects.filter(name=other_vendor["manufacturer"]).exists()
    checks.append(
        "occupied SFP bays and same-serial relocation preserve inventory without orphan vendor rows"
    )

    with CaptureQueriesContext(connection) as captured:
        missing = apply_discovery(observed([parent]), target, interface_status=interface_status)
    assert_no_dml(captured, "An unobserved transceiver was removed or changed")
    assert Module.objects.filter(pk=transceiver.pk, serial=optic["serial"]).exists()
    assert any(row["id"] == str(transceiver.pk) for row in missing["components"]["missing_modules"])
    assert snapshot_inventory(target) == before_repeat and counts() == after_counts
    assert_port_preserved()
    checks.append(
        "an unobserved transceiver is reported as missing while its native inventory is preserved"
    )
