"""Native PSU bay and inlet checks, enclosed by the harness's outer rollback."""

import copy
import re
import uuid
from decimal import Decimal
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.dcim.models import Device, Module, ModuleBay, ModuleType, PowerPort

    return {
        model.__name__: model.objects.count()
        for model in (Device, ModuleType, ModuleBay, Module, PowerPort)
    }


def run(device, interface_status, checks):
    """Exercise staged parents, strict defaults, cable preservation and rollback."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import (
        Cable,
        Device,
        Module,
        ModuleBay,
        PowerOutlet,
        PowerPort,
        PowerPortTemplate,
        VirtualChassis,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import Status

    from jobs.exceptions import InventoryError
    from jobs.nautobot_components import (
        component_objects,
        save_components,
        snapshot_components,
        validate_components,
    )
    from jobs.nautobot_inventory import _status
    from jobs.reconcile_components import plan_components

    assert transaction.get_connection().in_atomic_block, "Power tests require outer rollback"
    suffix = uuid.uuid4().hex[:12]
    chassis = VirtualChassis(name="power-check-" + suffix)
    chassis.validated_save()

    def member(position, *, saved=True):
        obj = Device(
            name="power-check-%s:%d" % (suffix, position),
            serial="POWER-MEMBER-%s-%d" % (suffix, position),
            device_type=device.device_type,
            location=device.location,
            role=device.role,
            status=device.status,
            platform=device.platform,
            tenant=device.tenant,
            virtual_chassis=chassis,
            vc_position=position,
        )
        if saved:
            with SkipAutoComponentCreation():
                obj.validated_save()
        return obj

    target, new_member = member(1), member(2, saved=False)
    owners = {target.serial: target, new_member.serial: new_member}
    members_by_position = {1: target, 2: new_member}

    def no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    def plan_for(position, slot="B", *, asset=True, inlet=True):
        owner = members_by_position[position]
        key = "psu:%d/%s" % (position, slot)
        plan = {
            "schema_version": 1,
            "manufacturers": [],
            "module_types": [],
            "bays": [
                {
                    "key": key,
                    "id": None,
                    "parent_key": None,
                    "device_id": str(owner.pk) if not owner._state.adding else None,
                    "device_serial": owner.serial,
                    "member_position": position,
                    "name": "Power Supply " + slot,
                    "position": "PSU-" + slot,
                    "label": "Power Supply " + slot,
                    "create": True,
                    "changes": [],
                }
            ],
            "modules": [],
            "power_ports": [],
            "interface_assignments": [],
        }
        if asset:
            type_key = "power-type-%s-%d-%s" % (suffix, position, slot)
            plan["module_types"] = [
                {
                    "key": type_key,
                    "id": None,
                    "manufacturer_id": str(device.device_type.manufacturer_id),
                    "manufacturer_key": None,
                    "model": type_key,
                    "part_number": type_key,
                    "create": True,
                    "changes": [],
                }
            ]
            plan["modules"] = [
                {
                    "key": key,
                    "id": None,
                    "bay_key": key,
                    "module_type_key": type_key,
                    "serial": "POWER-ASSET-%s-%d-%s" % (suffix, position, slot),
                    "device_id": plan["bays"][0]["device_id"],
                    "device_serial": owner.serial,
                    "member_position": position,
                    "create": True,
                    "changes": [],
                }
            ]
        if inlet and asset:
            plan["power_ports"] = [
                {
                    "key": key + ":input",
                    "module_key": key,
                    "module_id": None,
                    "device_id": plan["bays"][0]["device_id"],
                    "device_serial": owner.serial,
                    "member_position": position,
                    "id": None,
                    "name": "Power Input",
                    "type": "iec-60320-c14",
                    "maximum_draw": 1200,
                    "allocated_draw": None,
                    "power_factor": 1.0,
                    "create": True,
                    "changes": [],
                }
            ]
        return plan

    def staged(plan):
        return component_objects(
            plan,
            target,
            module_status=None,
            status_resolver=_status,
            devices_by_serial=owners,
        )

    empty_a = plan_for(1, "A", asset=False, inlet=False)
    before = catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        a_objects = staged(empty_a)
        validate_components(a_objects)
    no_dml(captured, "Unknown-identity physical bay preview issued DML")
    assert catalog_counts() == before
    save_components(a_objects)
    assert ModuleBay.objects.filter(parent_device=target, name="Power Supply A").count() == 1
    assert not Module.objects.filter(parent_module_bay__parent_device=target).exists()
    assert not PowerPort.objects.filter(device=target).exists()
    checks.append("physical PSU bay applies without manufacturing an unknown Module or inlet")

    primary = plan_for(1)
    additional = plan_for(2)
    together = copy.deepcopy(primary)
    for field in ("module_types", "bays", "modules", "power_ports"):
        together[field].extend(copy.deepcopy(additional[field]))
    before = catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        objects = staged(together)
        validate_components(objects)
    no_dml(captured, "Stack PSU preview persisted an unsaved Device or module parent")
    assert catalog_counts() == before
    assert objects["bays"]["psu:2/B"].parent_device is new_member
    assert objects["power_ports"]["psu:2/B:input"].device is new_member
    with SkipAutoComponentCreation():
        new_member.validated_save()
    save_components(objects)
    for position, owner in ((1, target), (2, new_member)):
        key = "psu:%d/B" % position
        bay, module, port = (
            objects["bays"][key],
            objects["modules"][key],
            objects["power_ports"][key + ":input"],
        )
        bay.refresh_from_db()
        module.refresh_from_db()
        port.refresh_from_db()
        assert bay.parent_device_id == owner.pk and module.device.pk == owner.pk
        assert port.module_id == module.pk and port.device_id == owner.pk
        assert port.maximum_draw == 1200 and port.allocated_draw is None
        assert port.power_factor == Decimal("1.00")
    checks.append("two member PSUs and Module-owned inlets save on their serial-matched Devices")

    def repeat_plan(plan, objects):
        repeated = copy.deepcopy(plan)
        for specs, cache in (
            ("module_types", "types"),
            ("bays", "bays"),
            ("modules", "modules"),
            ("power_ports", "power_ports"),
        ):
            for spec in repeated[specs]:
                spec["id"] = str(objects[cache][spec["key"]].pk)
                spec["create"] = False
                spec["changes"] = []
        return repeated

    repeated = repeat_plan(together, objects)
    with CaptureQueriesContext(connection) as captured:
        repeated_objects = staged(repeated)
        validate_components(repeated_objects)
        save_components(repeated_objects)
    no_dml(captured, "Repeated native PSU/inlet apply issued DML")
    checks.append("repeated PSU bay, Module and PowerPort apply writes zero inventory rows")

    unknown = plan_for(1, "UNKNOWN")
    unknown["power_ports"][0]["power_factor"] = None
    with CaptureQueriesContext(connection) as captured:
        try:
            staged(unknown)
        except InventoryError as exc:
            assert "power factor" in str(exc)
        else:
            raise AssertionError("Unknown PF silently received the native 0.95 default")
    no_dml(captured, "Unknown-power-factor rejection issued DML")
    checks.append("unknown power factor cannot silently instantiate Nautobot's native default")

    second_psu = plan_for(1, "A")
    second_psu["bays"][0]["create"] = False
    second_psu["bays"][0]["id"] = str(a_objects["bays"]["psu:1/A"].pk)
    second_objects = staged(second_psu)
    validate_components(second_objects)
    save_components(second_objects)
    assert PowerPort.objects.filter(device=target, name="Power Input").count() == 2
    assert set(
        PowerPort.objects.filter(device=target, name="Power Input").values_list(
            "module_id", flat=True
        )
    ) == {second_objects["modules"]["psu:1/A"].pk, objects["modules"]["psu:1/B"].pk}
    checks.append("PSU A and B can each own a Power Input on the same physical Device")

    inlet = objects["power_ports"]["psu:1/B:input"]
    inlet.name = "Operator inlet name"
    inlet.type = "iec-60320-c16"
    inlet.maximum_draw = 1400
    inlet.allocated_draw = 300
    inlet.power_factor = Decimal("0.97")
    inlet.validated_save()
    outlet = PowerOutlet(device=target, name="Power test outlet " + suffix)
    outlet.validated_save()
    cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
    cable.validated_save()
    for cable_end, field, port in (("A", "power_port", inlet), ("B", "power_outlet", outlet)):
        join = CableToCableTermination(
            cable=cable, cable_end=cable_end, connector=1, **{field: port}
        )
        join.full_clean()
        join.save()
    cable_rows = list(cable.terminations.order_by("pk").values())
    preserved = (
        inlet.pk,
        inlet.name,
        inlet.type,
        inlet.maximum_draw,
        inlet.allocated_draw,
        inlet.power_factor,
    )
    with CaptureQueriesContext(connection) as captured:
        snapshot = snapshot_components(target, lock=True, discovery={"components": {"items": []}})
        repeated_objects = staged(repeated)
        validate_components(repeated_objects)
        save_components(repeated_objects)
    no_dml(captured, "An existing cabled inlet was modified by unchanged inventory discovery")
    inlet.refresh_from_db()
    assert preserved == (
        inlet.pk,
        inlet.name,
        inlet.type,
        inlet.maximum_draw,
        inlet.allocated_draw,
        inlet.power_factor,
    )
    assert list(cable.terminations.order_by("pk").values()) == cable_rows
    assert next(row for row in snapshot["power_ports"] if row["id"] == str(inlet.pk))[
        "cable_id"
    ] == str(cable.pk)
    assert any(row["parent_device_id"] == str(new_member.pk) for row in snapshot["module_bays"])
    checks.append(
        "stack snapshot and repeat preserve populated inlet names, draws, factor and cables"
    )

    # A populated ModuleType must not auto-instantiate a duplicate inlet when
    # the staged Module is saved. The explicitly planned port owns the create.
    template_type = objects["types"][primary["module_types"][0]["key"]]
    template = PowerPortTemplate(
        module_type=template_type, name="Power Input", type="iec-60320-c14"
    )
    template.validated_save()
    template_plan = plan_for(1, "TEMPLATE")
    template_plan["module_types"] = [copy.deepcopy(repeated["module_types"][0])]
    template_plan["modules"][0]["module_type_key"] = template_plan["module_types"][0]["key"]
    before_ports = PowerPort.objects.count()
    template_objects = staged(template_plan)
    validate_components(template_objects)
    save_components(template_objects)
    assert PowerPort.objects.count() == before_ports + 1
    template_snapshot = snapshot_components(target, discovery={"components": {"items": []}})
    catalog = next(
        row for row in template_snapshot["module_types"] if row["id"] == str(template_type.pk)
    )
    assert catalog["power_port_templates"][0]["name"] == "Power Input"
    checks.append(
        "ModuleType power templates are suppressed and exposed for explicit inlet reconciliation"
    )

    # Exercise the pure plan against real cabled rows rather than constructing
    # an unchanged plan: disagreements preserve metadata, blanks can be filled,
    # and an occupied slot cannot silently exchange serialized assets.
    observed_item = {
        "key": "psu:1/B",
        "kind": "power-supply",
        "manufacturer": device.device_type.manufacturer.name,
        "model": primary["module_types"][0]["model"],
        "part_number": primary["module_types"][0]["part_number"],
        "serial": primary["modules"][0]["serial"],
        "device_serial": target.serial,
        "member": 1,
        "parent_key": None,
        "bay": {field: primary["bays"][0][field] for field in ("name", "position", "label")},
        "interfaces": [],
        "power_ports": [
            {
                field: primary["power_ports"][0][field]
                for field in ("name", "type", "maximum_draw", "allocated_draw", "power_factor")
            }
        ],
        "source": {},
        "observations": {},
    }
    stack_scope = {
        "errors": [],
        "members": [
            {
                "serial": owner.serial,
                "position": position,
                "model": owner.device_type.model,
                "existing_id": str(owner.pk),
                "create": False,
            }
            for position, owner in ((1, target), (2, new_member))
        ],
    }

    def reconcile(item):
        discovery = {
            "identity": {"serial": target.serial, "model": target.device_type.model},
            "components": {"schema_version": 1, "items": [item], "unresolved": [], "excluded": []},
        }
        existing = {
            "device": {
                "id": str(target.pk),
                "serial": target.serial,
                "model": target.device_type.model,
            },
            "components": snapshot_components(target, lock=True, discovery=discovery),
            "interfaces": [],
        }
        plan = plan_components(discovery, existing, stack_plan=stack_scope)
        assert not plan["errors"], plan["errors"]
        return plan

    with CaptureQueriesContext(connection) as captured:
        populated = reconcile(observed_item)
        assert populated["conflicts"]
        populated_objects = staged(populated)
        validate_components(populated_objects)
        save_components(populated_objects)
    no_dml(captured, "Populated cabled inlet disagreements caused inventory writes")
    inlet.refresh_from_db()
    assert preserved == (
        inlet.pk,
        inlet.name,
        inlet.type,
        inlet.maximum_draw,
        inlet.allocated_draw,
        inlet.power_factor,
    )
    assert list(cable.terminations.order_by("pk").values()) == cable_rows

    inlet.type, inlet.maximum_draw = "", None
    inlet.validated_save()
    adoption = reconcile(observed_item)
    assert adoption["summary"]["power_ports_created"] == 0
    assert adoption["summary"]["power_ports_updated"] == 1
    adopted_objects = staged(adoption)
    validate_components(adopted_objects)
    save_components(adopted_objects)
    inlet.refresh_from_db()
    assert inlet.pk == preserved[0] and inlet.name == preserved[1]
    assert inlet.type == "iec-60320-c14" and inlet.maximum_draw == 1200
    assert inlet.allocated_draw == 300 and inlet.power_factor == Decimal("0.97")
    assert list(cable.terminations.order_by("pk").values()) == cable_rows
    with CaptureQueriesContext(connection) as captured:
        repeated_adoption = staged(reconcile(observed_item))
        validate_components(repeated_adoption)
        save_components(repeated_adoption)
    no_dml(captured, "Repeated adoption of a cabled inlet issued DML")

    replacement = copy.deepcopy(observed_item)
    replacement["serial"] = "POWER-REPLACEMENT-" + suffix
    with CaptureQueriesContext(connection) as captured:
        occupied = reconcile(replacement)
        assert occupied["conflicts"]
        occupied_objects = staged(occupied)
        validate_components(occupied_objects)
        save_components(occupied_objects)
    no_dml(captured, "Replacement observation changed the occupied PSU bay")
    assert inlet.module.serial == observed_item["serial"]
    assert list(cable.terminations.order_by("pk").values()) == cable_rows
    checks.append(
        "real planner fills blank cabled inlet fields while preserving occupied assets and metadata"
    )

    # Fail the last inlet save after preceding catalogs, bays and Modules have
    # been inserted; all records must disappear with the caller's transaction.
    rollback_member = member(3, saved=False)
    owners[rollback_member.serial] = rollback_member
    members_by_position[3] = rollback_member
    failing = plan_for(3, "ROLLBACK")
    before = catalog_counts()
    original_save = PowerPort.validated_save
    preceding_writes = []

    def fail_inlet(port, *args, **kwargs):
        if port.module.serial == failing["modules"][0]["serial"]:
            assert Module.objects.filter(serial=port.module.serial).exists()
            preceding_writes.append(True)
            raise ValidationError({"name": "Intentional power-inlet save failure"})
        return original_save(port, *args, **kwargs)

    try:
        with transaction.atomic(), patch.object(PowerPort, "validated_save", fail_inlet):
            failing_objects = staged(failing)
            validate_components(failing_objects)
            with SkipAutoComponentCreation():
                rollback_member.validated_save()
            save_components(failing_objects)
    except ValidationError:
        pass
    else:
        raise AssertionError("Injected final power-inlet failure did not occur")
    assert preceding_writes and catalog_counts() == before
    assert not Device.objects.filter(pk=rollback_member.pk).exists()
    assert not ModuleBay.objects.filter(
        parent_device=rollback_member, name="Power Supply ROLLBACK"
    ).exists()
    checks.append(
        "final inlet failure rolls back a new member Device and its PSU catalogs, bays and Modules"
    )
