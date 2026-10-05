"""Serialized hardware snapshots and staged Module objects for Nautobot."""

from django.db.models import Q
from nautobot.dcim.models import Manufacturer

from .exceptions import InventoryError


def _models():
    from nautobot.dcim.models import Module, ModuleBay, ModuleType

    return ModuleType, ModuleBay, Module


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def _scope_device_ids(device, discovery):
    """Include observed physical members and every existing member of their VC."""
    from nautobot.dcim.models import Device

    serials = set()
    source = (discovery or {}).get("components", {})
    source = source if isinstance(source, dict) else {}
    for rows in (
        source.get("items", []),
        source.get("identities", []),
        source.get("physical_bays", []),
    ):
        if isinstance(rows, list):
            serials.update(
                row["device_serial"].strip()
                for row in rows
                if isinstance(row, dict)
                and isinstance(row.get("device_serial"), str)
                and row["device_serial"].strip()
            )
    stack = (discovery or {}).get("stack", {})
    members = stack.get("members", []) if isinstance(stack, dict) else []
    if isinstance(members, list):
        serials.update(
            row["serial"].strip()
            for row in members
            if isinstance(row, dict)
            and isinstance(row.get("serial"), str)
            and row["serial"].strip()
        )
    query = Q(pk=device.pk)
    if device.virtual_chassis_id:
        query |= Q(virtual_chassis_id=device.virtual_chassis_id)
    # Trim in Python, as elsewhere in discovery, so padded identity collisions
    # cannot disappear from the snapshot used for strict planner matching.
    if serials:
        ids = [
            pk
            for pk, serial in Device.objects.exclude(serial="").values_list("pk", "serial")
            if isinstance(serial, str) and serial.strip() in serials
        ]
        query |= Q(pk__in=ids)
    return set(Device.objects.filter(query).values_list("pk", flat=True))


def _power_row(row):
    return {
        "id": str(row.pk),
        "module_id": str(row.module_id) if row.module_id else None,
        "device_id": str(row.device_id) if row.device_id else None,
        "name": row.name,
        "type": row.type,
        "maximum_draw": row.maximum_draw,
        "allocated_draw": row.allocated_draw,
        "power_factor": float(row.power_factor) if row.power_factor is not None else None,
        "cable_id": str(row.cable_id) if row.cable_id else None,
    }


def snapshot_components(device, *, lock=False, discovery=None):
    """Include installed parts and candidate asset matches elsewhere in inventory."""
    try:
        ModuleType, ModuleBay, Module = _models()
    except ImportError:
        return {"supported": False}
    source = (discovery or {}).get("components")
    raw_items = source.get("items", []) if isinstance(source, dict) else []
    placed_items = (
        [row for row in raw_items if isinstance(row, dict)] if isinstance(raw_items, list) else []
    )
    raw_identities = source.get("identities", []) if isinstance(source, dict) else []
    identities = (
        [row for row in raw_identities if isinstance(row, dict)]
        if isinstance(raw_identities, list)
        else []
    )
    # A placement-free identity must see the same complete manufacturer catalog
    # on every run, including operator model aliases and conflicting PIDs.
    items = placed_items + identities
    manufacturers = list(_locked(Manufacturer.objects.all().order_by("pk"), lock))
    module_query = Module.objects.all()
    scoped_ids = _scope_device_ids(device, discovery)
    scoped_bay_ids = set()
    if discovery is not None:
        serials = {
            item["serial"].strip()
            for item in items
            if isinstance(item.get("serial"), str) and item["serial"].strip()
        }
        candidate_module_ids = [
            pk
            for pk, serial in Module.objects.exclude(serial=None).values_list("pk", "serial")
            if isinstance(serial, str) and serial.strip() in serials
        ]
        scoped_bay_ids = set(
            ModuleBay.objects.filter(parent_device_id__in=scoped_ids).values_list("pk", flat=True)
        )
        # Include nested bays even when a legacy native record stores only its
        # immediate Module parent rather than a root parent_device relation.
        while True:
            parent_ids = Module.objects.filter(parent_module_bay_id__in=scoped_bay_ids).values_list(
                "pk", flat=True
            )
            nested_ids = set(
                ModuleBay.objects.filter(parent_module_id__in=parent_ids).values_list(
                    "pk", flat=True
                )
            )
            if nested_ids.issubset(scoped_bay_ids):
                break
            scoped_bay_ids.update(nested_ids)
        module_query = module_query.filter(
            Q(parent_module_bay_id__in=scoped_bay_ids) | Q(pk__in=candidate_module_ids)
        )
    modules = list(
        _locked(module_query, lock)
        .select_related("parent_module_bay__parent_device")
        .order_by("pk")
    )
    bay_query = ModuleBay.objects.all()
    type_query = ModuleType.objects.all()
    if discovery is not None:
        bay_query = bay_query.filter(
            Q(pk__in=scoped_bay_ids)
            | Q(pk__in=[row.parent_module_bay_id for row in modules if row.parent_module_bay_id])
        )
        manufacturer_names = {
            item["manufacturer"].strip().casefold()
            for item in items
            if isinstance(item.get("manufacturer"), str) and item["manufacturer"].strip()
        }
        candidate_manufacturer_ids = [
            row.pk for row in manufacturers if row.name.strip().casefold() in manufacturer_names
        ]
        # The planner compares trimmed PIDs and accepts a unique catalog model
        # alias. Exact model/PID filtering would hide padded catalog values or
        # ambiguous aliases, so include each candidate manufacturer's catalog.
        type_query = type_query.filter(
            Q(pk__in=[row.module_type_id for row in modules])
            | Q(manufacturer_id__in=candidate_manufacturer_ids)
        )
    from nautobot.dcim.models import Cable, PowerPort

    ports_query = PowerPort.objects.all()
    if discovery is not None:
        ports_query = ports_query.filter(
            Q(device_id__in=scoped_ids) | Q(module_id__in=[row.pk for row in modules])
        )
    ports = list(_locked(ports_query, lock).select_related("module").order_by("pk"))
    power_rows = [_power_row(row) for row in ports]
    if lock:
        cable_ids = {row["cable_id"] for row in power_rows if row["cable_id"]}
        list(_locked(Cable.objects.filter(pk__in=cable_ids), True).order_by("pk"))
    return {
        "supported": True,
        "manufacturers": [{"id": str(row.pk), "name": row.name} for row in manufacturers],
        "module_types": [
            {
                "id": str(row.pk),
                "manufacturer_id": str(row.manufacturer_id),
                "model": row.model,
                "part_number": row.part_number,
                "module_family_id": str(row.module_family_id) if row.module_family_id else None,
                "power_port_templates": [
                    {
                        "name": template.name,
                        "type": template.type,
                        "maximum_draw": template.maximum_draw,
                        "allocated_draw": template.allocated_draw,
                        "power_factor": float(template.power_factor),
                    }
                    for template in row.power_port_templates.all().order_by("pk")
                ],
            }
            for row in _locked(type_query, lock).order_by("pk")
        ],
        "module_bays": [
            {
                "id": str(row.pk),
                "parent_device_id": str(row.parent_device_id) if row.parent_device_id else None,
                "parent_module_id": str(row.parent_module_id) if row.parent_module_id else None,
                "name": row.name,
                "position": row.position,
                "label": row.label,
                "module_family_id": str(row.module_family_id) if row.module_family_id else None,
            }
            for row in _locked(bay_query, lock).order_by("pk")
        ],
        "modules": [
            {
                "id": str(row.pk),
                "module_type_id": str(row.module_type_id),
                "serial": row.serial,
                "parent_module_bay_id": str(row.parent_module_bay_id)
                if row.parent_module_bay_id
                else None,
                "location_id": str(row.location_id) if row.location_id else None,
                "device_id": str(row.device.pk) if row.device else None,
            }
            for row in modules
        ],
        "power_ports": power_rows,
    }


def _changes(instance, spec):
    for change in spec["changes"]:
        setattr(instance, change["field"], change["after"])
    return instance


def component_objects(plan, device, *, module_status, status_resolver, devices_by_serial=None):
    """Construct a cached hierarchy, including unsaved parents, without INSERTs."""
    from decimal import Decimal

    from nautobot.dcim.models import PowerPort

    ModuleType, ModuleBay, Module = _models()
    device_map = dict(devices_by_serial or {})
    if device.serial and device.serial.strip():
        device_map.setdefault(device.serial.strip(), device)

    def owner(spec):
        serial = spec.get("device_serial")
        serial = serial.strip() if isinstance(serial, str) and serial.strip() else None
        obj = device_map.get(serial) if serial else device
        if obj is None:
            raise InventoryError("Component owner is not a validated stack member: %s" % serial)
        if serial and (not obj.serial or obj.serial.strip() != serial):
            raise InventoryError("Component owner serial changed after planning")
        if spec.get("device_id") is not None and str(obj.pk) != str(spec["device_id"]):
            raise InventoryError("Component owner Device changed after planning")
        position = spec.get("member_position")
        if position is not None and obj.vc_position is not None and obj.vc_position != position:
            raise InventoryError("Component owner stack position changed after planning")
        return obj

    manufacturers = {
        spec["key"]: Manufacturer(name=spec["name"]) for spec in plan.get("manufacturers", [])
    }
    types, bays, modules, power_ports = {}, {}, {}, {}
    for spec in plan["module_types"]:
        if spec["create"]:
            manufacturer = (
                manufacturers[spec["manufacturer_key"]]
                if spec["manufacturer_id"] is None
                else Manufacturer.objects.get(pk=spec["manufacturer_id"])
            )
            obj = ModuleType(
                manufacturer=manufacturer,
                model=spec["model"],
                part_number=spec["part_number"],
            )
        else:
            obj = ModuleType.objects.select_related("manufacturer", "module_family").get(
                pk=spec["id"]
            )
        types[spec["key"]] = _changes(obj, spec)
    status = (
        status_resolver(Module, module_status)
        if any(row["create"] for row in plan["modules"])
        else None
    )
    remaining_bays = list(plan["bays"])
    remaining_modules = list(plan["modules"])
    while remaining_bays or remaining_modules:
        progress = False
        for bay_spec in remaining_bays[:]:
            parent_key = bay_spec.get("parent_key")
            if parent_key is not None and parent_key not in modules:
                continue
            parent_device = owner(bay_spec)
            if parent_key is not None:
                parent = modules[parent_key]
                if parent.parent_module_bay.parent_device_id != parent_device.pk:
                    raise InventoryError("Nested component bay changed its physical owner")
            if bay_spec["create"]:
                bay = ModuleBay(
                    parent_device=parent_device,
                    parent_module=modules[parent_key] if parent_key is not None else None,
                    name=bay_spec["name"],
                    position=bay_spec["position"],
                    label=bay_spec["label"],
                )
            else:
                bay = ModuleBay.objects.select_related(
                    "parent_device", "parent_module", "module_family"
                ).get(pk=bay_spec["id"])
                if bay.parent_device_id != parent_device.pk:
                    raise InventoryError("Component bay Device changed after planning")
                expected_parent_id = modules[parent_key].pk if parent_key is not None else None
                if bay.parent_module_id != expected_parent_id:
                    raise InventoryError("Component bay Module parent changed after planning")
                bay.parent_device = parent_device
                if parent_key is not None:
                    bay.parent_module = modules[parent_key]
            bays[bay_spec["key"]] = _changes(bay, bay_spec)
            remaining_bays.remove(bay_spec)
            progress = True
        for spec in remaining_modules[:]:
            if spec["bay_key"] not in bays:
                continue
            bay = bays[spec["bay_key"]]
            if owner(spec).pk != bay.parent_device_id:
                raise InventoryError("Module and bay physical owners disagree")
            if spec["create"]:
                obj = Module(
                    module_type=types[spec["module_type_key"]],
                    parent_module_bay=bay,
                    serial=spec["serial"],
                    status=status,
                )
            else:
                obj = Module.objects.select_related(
                    "module_type__manufacturer",
                    "module_type__module_family",
                    "parent_module_bay__parent_device",
                    "parent_module_bay__module_family",
                ).get(pk=spec["id"])
                if obj.parent_module_bay_id != bay.pk:
                    raise InventoryError(
                        "Module placement changed while resolving %s" % spec["key"]
                    )
                obj.parent_module_bay = bay
            modules[spec["key"]] = _changes(obj, spec)
            remaining_modules.remove(spec)
            progress = True
        if not progress:
            raise InventoryError("Component hierarchy has an unresolved parent or cycle")
    allowed_power_fields = {"type", "maximum_draw", "allocated_draw", "power_factor"}
    for spec in plan.get("power_ports", []):
        if spec["module_key"] not in modules:
            raise InventoryError("Power inlet requires a resolved PSU Module")
        module = modules[spec["module_key"]]
        parent_device = owner(spec)
        if module.parent_module_bay.parent_device_id != parent_device.pk:
            raise InventoryError("Power inlet and PSU physical owners disagree")
        if spec["create"]:
            if spec.get("power_factor") is None:
                raise InventoryError(
                    "Native PowerPort requires an explicit power factor; "
                    "unknown values cannot default"
                )
            obj = PowerPort(
                device=parent_device,
                module=module,
                name=spec["name"],
                type=spec.get("type") or "",
                maximum_draw=spec.get("maximum_draw"),
                allocated_draw=spec.get("allocated_draw"),
                power_factor=Decimal(str(spec["power_factor"])),
            )
        else:
            obj = PowerPort.objects.select_related("device", "module").get(pk=spec["id"])
            if obj.module_id != module.pk or obj.device_id not in (None, parent_device.pk):
                raise InventoryError("Power inlet ownership changed after planning")
            obj.device = parent_device
            obj.module = module
            for change in spec["changes"]:
                if change["field"] not in allowed_power_fields:
                    raise InventoryError("Discovery cannot change PowerPort %s" % change["field"])
                if change["field"] == "power_factor":
                    if change["after"] is None:
                        raise InventoryError("Native PowerPort power factor cannot be blank")
                    setattr(obj, change["field"], Decimal(str(change["after"])))
                else:
                    setattr(obj, change["field"], change["after"])
        power_ports[spec["key"]] = obj
    return {
        "plan": plan,
        "manufacturers": manufacturers,
        "types": types,
        "bays": bays,
        "modules": modules,
        "power_ports": power_ports,
    }


def _template_relations(module_type):
    return (
        module_type.console_port_templates,
        module_type.console_server_port_templates,
        module_type.power_port_templates,
        module_type.power_outlet_templates,
        module_type.interface_templates,
        module_type.front_port_templates,
        module_type.rear_port_templates,
        module_type.module_bay_templates,
    )


def _suppression_context(module_type):
    try:
        from nautobot.apps.dcim import SkipAutoComponentCreation
    except ImportError:
        from contextlib import nullcontext

        if any(relation.exists() for relation in _template_relations(module_type)):
            raise InventoryError(
                "This Nautobot release cannot suppress automatic Module components; "
                "use a release with SkipAutoComponentCreation for populated ModuleType templates"
            ) from None
        return nullcontext()
    return SkipAutoComponentCreation()


def validate_components(objects):
    """Skip only nonexistent FK checks; preserve cached-object model validation."""
    for obj in objects.get("manufacturers", {}).values():
        obj.full_clean()
    for obj in objects["types"].values():
        excluded = ["manufacturer"] if obj.manufacturer._state.adding else []
        obj.full_clean(exclude=excluded)
    for obj in objects["bays"].values():
        excluded = []
        if obj.parent_device and obj.parent_device._state.adding:
            excluded.append("parent_device")
        if obj.parent_module and obj.parent_module._state.adding:
            excluded.append("parent_module")
        obj.full_clean(exclude=excluded)
    for obj in objects["modules"].values():
        excluded = []
        if obj.module_type._state.adding:
            excluded.append("module_type")
        if obj.parent_module_bay._state.adding:
            excluded.append("parent_module_bay")
        obj.full_clean(exclude=excluded)
        if obj._state.adding:
            _suppression_context(obj.module_type)
    for obj in objects.get("power_ports", {}).values():
        excluded = []
        if obj.device and obj.device._state.adding:
            excluded.append("device")
        if obj.module and obj.module._state.adding:
            excluded.append("module")
        obj.full_clean(exclude=excluded)


def save_components(objects):
    """Save catalogs then parent-first assets; callers own the atomic transaction."""
    for obj in objects.get("manufacturers", {}).values():
        obj.validated_save()
    for spec in objects["plan"]["module_types"]:
        if spec["create"] or spec["changes"]:
            objects["types"][spec["key"]].validated_save()
    bay_specs = {row["key"]: row for row in objects["plan"]["bays"]}
    module_specs = {row["key"]: row for row in objects["plan"]["modules"]}
    saved, saved_bays = set(), set()

    def save_bay(key):
        if key in saved_bays:
            return
        spec = bay_specs[key]
        if spec.get("parent_key") is not None:
            save_module(spec["parent_key"])
        if spec["create"] or spec["changes"]:
            objects["bays"][key].validated_save()
        saved_bays.add(key)

    def save_module(key):
        if key in saved:
            return
        spec = module_specs[key]
        save_bay(spec["bay_key"])
        obj = objects["modules"][key]
        if spec["create"]:
            with _suppression_context(obj.module_type):
                obj.validated_save()
        elif spec["changes"]:
            obj.validated_save()
        saved.add(key)

    for key in module_specs:
        save_module(key)
    for key in bay_specs:
        save_bay(key)
    for spec in objects["plan"].get("power_ports", []):
        if spec["create"] or spec["changes"]:
            objects["power_ports"][spec["key"]].validated_save()
