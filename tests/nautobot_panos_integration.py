"""Prove PAN-OS native inventory behavior inside an unconditional outer rollback.

Run in a configured Nautobot Django process via ``nbshell`` and ``runpy``. Select
an existing Device explicitly with ``NAUTOBOT_DISCOVERY_DEVICE_ID``; it supplies
only the temporary synthetic target's Location, Role and Status. These checks
are synthetic ORM proof, not evidence for a particular firewall's capabilities.
No credentials or live device connections are used, and all records roll back.
"""

import copy
import json
import os
import re
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _fact(name, **values):
    from jobs.transport_ssh import INTERFACES, RUNNING_INTERFACES

    fact = {
        "name": name,
        "type": None,
        "enabled": True,
        "description": "Synthetic PAN-OS native ORM verification",
        "mtu": 1500,
        "mac_address": None,
        "type_source": "Synthetic capability unknown; exact DeviceType template required",
        **values,
    }
    fact["source"] = {
        "contract": "panos-interface-v1",
        "operational_command": INTERFACES,
        "hardware_path": "result/hw/entry",
        "name": name,
        "id": "synthetic-" + name,
        "applied_command": RUNNING_INTERFACES,
        "applied_path": "result/interface/ethernet/entry",
        "link_state": {True: "up", False: "down"}.get(fact["enabled"]),
        "comment": fact["description"],
        "mtu": str(fact["mtu"]) if fact["mtu"] is not None else None,
    }
    return fact


def run(device_id=None):
    """Verify strict previews, native apply, preservation, repeats and rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Cable,
        Device,
        DeviceType,
        Interface,
        InterfaceTemplate,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import CustomField, Status

    from jobs.discovery_job import _adapter
    from jobs.nautobot_inventory import (
        InventoryError,
        apply_discovery,
        snapshot_inventory,
        validate_plan,
    )
    from jobs.reconcile import build_plan

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not device_id:
        raise ValueError("Select an existing anchor with NAUTOBOT_DISCOVERY_DEVICE_ID")
    anchor = Device.objects.select_related("location", "role", "status").get(pk=device_id)
    baseline = snapshot_inventory(anchor)
    tracked = (
        Manufacturer,
        Platform,
        DeviceType,
        Device,
        InterfaceTemplate,
        Interface,
        SoftwareVersion,
        Cable,
        CableToCableTermination,
        CustomField,
    )
    before_counts = {model.__name__: model.objects.count() for model in tracked}
    interface_status = Status.objects.get_for_model(Interface).get(name="Active")
    checks = []
    token = uuid.uuid4().hex[:12]
    with transaction.atomic():
        try:
            manufacturer = Manufacturer(name="Palo Alto Networks")
            existing_manufacturer = Manufacturer.objects.filter(name=manufacturer.name).first()
            if existing_manufacturer:
                manufacturer = existing_manufacturer
            else:
                manufacturer.validated_save()
            platform = Platform(
                name="PAN-OS synthetic " + token,
                network_driver="paloalto_panos",
                manufacturer=manufacturer,
            )
            platform.validated_save()
            device_type = DeviceType(manufacturer=manufacturer, model="SYNTHETIC-PANOS-" + token)
            device_type.validated_save()
            target = Device(
                name="panos-native-" + token,
                serial="",
                device_type=device_type,
                platform=platform,
                role=anchor.role,
                location=anchor.location,
                status=anchor.status,
            )
            target.validated_save()
            assert _adapter(target).__name__.endswith(".panos")
            checks.append("PAN-OS Platform dispatch selects the PAN-OS adapter")
            # Create templates after the Device: test planner use of the exact
            # template rather than automatic component creation at Device save.
            for number in range(1, 8):
                InterfaceTemplate(
                    device_type=device_type, name="ethernet1/%d" % number, type="1000base-t"
                ).validated_save()
            port = Interface(
                device=target,
                name="ethernet1/1",
                type="other",
                enabled=False,
                description="Operator description",
                mtu=9000,
                mac_address="02:00:00:00:00:01",
                status=interface_status,
            )
            port.validated_save()
            peer = Interface(
                device=target,
                name="ethernet1/99",
                type="1000base-t",
                enabled=False,
                status=interface_status,
            )
            peer.validated_save()
            cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
            cable.validated_save()
            for cable_end, interface in (("A", port), ("B", peer)):
                CableToCableTermination(
                    cable=cable, cable_end=cable_end, connector=1, interface=interface
                ).validated_save()
            port.refresh_from_db()
            preserved_port_id = port.pk
            cable_joins = list(cable.terminations.order_by("pk").values())
            identity = {
                "hostname": target.name,
                "serial": "SYNTHETIC-PANOS-" + token,
                "model": device_type.model,
                "software_version": "99.99.1-h1",
            }
            discovery = {
                "schema_version": 1,
                "adapter": "panos",
                "identity": identity,
                "interfaces": [
                    _fact("ethernet1/1"),
                    _fact("ethernet1/2", enabled=False),
                    _fact("ethernet1/3", enabled=None),
                ],
                "warnings": [],
                "excluded_interfaces": [],
            }
            before = snapshot_inventory(target, discovery=discovery)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(discovery, snapshot_inventory(target, discovery=discovery))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "PAN-OS preview issued inventory DML")
            assert not plan["errors"] and not plan["summary"]["blocked"]
            assert plan["summary"]["interfaces_created"] == 1
            assert plan["interface_creates"][0]["name"] == "ethernet1/2"
            assert plan["interface_creates"][0]["enabled"] is False
            assert snapshot_inventory(target, discovery=discovery) == before
            checks.append(
                "PAN-OS preview validates new software and exact-template interfaces without DML"
            )
            checks.append(
                "missing administrative state defers creation despite an exact type template"
            )

            applied = apply_discovery(discovery, target, interface_status=interface_status)
            target.refresh_from_db()
            port.refresh_from_db()
            created = target.interfaces.get(name="ethernet1/2")
            assert applied["summary"]["interfaces_created"] == 1
            assert created.type == "1000base-t" and created.enabled is False
            assert not target.interfaces.filter(name="ethernet1/3").exists()
            assert target.serial == identity["serial"]
            assert target.software_version.version == "99.99.1-h1"
            assert target.platform_id == platform.pk and target.device_type_id == device_type.pk
            checks.append(
                "apply creates disabled interfaces and fills exact PAN-OS software "
                "release and serial"
            )
            assert port.pk == preserved_port_id and port.type == "other" and port.enabled is False
            assert port.description == "Operator description" and port.mtu == 9000
            assert str(port.mac_address) == "02:00:00:00:00:01" and port.cable_id == cable.pk
            assert list(cable.terminations.order_by("pk").values()) == cable_joins
            checks.append(
                "apply preserves populated Other, False, description, MTU, MAC, UUID "
                "and cable joins"
            )

            after = snapshot_inventory(target, discovery=discovery)
            with CaptureQueriesContext(connection) as captured:
                repeated = apply_discovery(discovery, target, interface_status=interface_status)
            _no_dml(captured, "Repeated PAN-OS apply issued inventory DML")
            assert repeated["summary"]["interfaces_created"] == 0
            assert repeated["summary"]["interfaces_updated"] == 0
            assert repeated["summary"]["device_fields_updated"] == 0
            assert snapshot_inventory(target, discovery=discovery) == after
            checks.append("repeat PAN-OS discovery produces zero inventory DML")

            unknown = copy.deepcopy(discovery)
            unknown["interfaces"] = [_fact("ethernet1/98")]
            with CaptureQueriesContext(connection) as captured:
                unknown_plan = build_plan(unknown, snapshot_inventory(target, discovery=unknown))
                validate_plan(unknown_plan, target, interface_status=interface_status)
            _no_dml(captured, "Unknown PAN-OS type preview issued inventory DML")
            assert unknown_plan["interface_creates"] == []
            checks.append(
                "unclassified interface without an exact template is unresolved rather than guessed"
            )

            incomplete = copy.deepcopy(discovery)
            incomplete["identity"]["serial"] = None
            incomplete["interfaces"] = [_fact("ethernet1/4")]
            before_incomplete = snapshot_inventory(target, discovery=incomplete)
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(incomplete, target, interface_status=interface_status)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("PAN-OS apply accepted missing discovered serial identity")
            _no_dml(captured, "PAN-OS missing-serial apply issued inventory DML")
            assert snapshot_inventory(target, discovery=incomplete) == before_incomplete
            checks.append(
                "missing discovered serial blocks all PAN-OS apply writes even with "
                "existing identity"
            )

            invalid = copy.deepcopy(discovery)
            too_long = "X" * (Interface._meta.get_field("description").max_length + 1)
            invalid["interfaces"] = [
                _fact("ethernet1/4"),
                _fact("ethernet1/5", description=too_long),
            ]
            before_failure = snapshot_inventory(target, discovery=invalid)
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(invalid, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError(
                        "PAN-OS oversized description unexpectedly passed real model validation"
                    )
            _no_dml(
                captured,
                "PAN-OS whole-plan validation issued DML before rejecting an oversized description",
            )
            assert snapshot_inventory(target, discovery=invalid) == before_failure
            checks.append("native whole-plan validation rejects invalid PAN-OS rows before any DML")

            Device.objects.filter(pk=target.pk).update(serial="", software_version=None)
            target.refresh_from_db()
            failing = copy.deepcopy(discovery)
            failing["identity"]["software_version"] = "99.99.2-h1"
            failing["interfaces"] = [_fact("ethernet1/6"), _fact("ethernet1/7")]
            before_failure = snapshot_inventory(target, discovery=failing)
            version_count = SoftwareVersion.objects.count()
            interface_count = Interface.objects.count()
            original_save = Interface.validated_save
            writes_seen = []

            def fail_late(interface, *args, **kwargs):
                if interface.name == "ethernet1/7":
                    assert target.interfaces.filter(name="ethernet1/6").exists()
                    assert SoftwareVersion.objects.filter(
                        platform=platform, version="99.99.2-h1"
                    ).exists()
                    saved = Device.objects.get(pk=target.pk)
                    assert saved.serial == identity["serial"]
                    assert saved.software_version_id is not None
                    writes_seen.append(True)
                    raise ValidationError(
                        {"name": "Intentional PAN-OS final interface save failure"}
                    )
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", fail_late):
                try:
                    apply_discovery(failing, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("PAN-OS late interface failure did not occur")
            assert writes_seen, "PAN-OS rollback scenario did not first save related inventory"
            assert (
                snapshot_inventory(Device.objects.get(pk=target.pk), discovery=failing)
                == before_failure
            )
            assert SoftwareVersion.objects.count() == version_count
            assert Interface.objects.count() == interface_count
            assert list(cable.terminations.order_by("pk").values()) == cable_joins
            checks.append(
                "late PAN-OS save failure rolls back preceding device, software and "
                "interface writes"
            )
        finally:
            transaction.set_rollback(True)

    assert snapshot_inventory(Device.objects.get(pk=anchor.pk)) == baseline
    assert {model.__name__: model.objects.count() for model in tracked} == before_counts
    checks.append("outer rollback restores anchor inventory and every tracked native catalog count")
    return {
        "anchor_device_id": str(anchor.pk),
        "passed": True,
        "checks": checks,
        "persistent_changes": 0,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
