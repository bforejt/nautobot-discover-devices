"""Serialized hardware snapshots and staged Module objects for Nautobot."""

from django.db.models import Q
from nautobot.dcim.models import Manufacturer

from .exceptions import InventoryError


def _models():
    from nautobot.dcim.models import Module, ModuleBay, ModuleType

    return ModuleType, ModuleBay, Module


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def snapshot_components(device, *, lock=False, discovery=None):
    """Include installed parts and candidate asset matches elsewhere in inventory."""
    try:
        ModuleType, ModuleBay, Module = _models()
    except ImportError:
        return {"supported": False}
    source = (discovery or {}).get("components")
    raw_items = source.get("items", []) if isinstance(source, dict) else []
    items = (
        [row for row in raw_items if isinstance(row, dict)] if isinstance(raw_items, list) else []
    )
    manufacturers = list(_locked(Manufacturer.objects.all().order_by("pk"), lock))
    module_query = Module.objects.all()
    if discovery is not None:
        serials = {item.get("serial") for item in items if item.get("serial")}
        module_query = module_query.filter(
            Q(parent_module_bay__parent_device=device) | Q(serial__in=serials)
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
            Q(parent_device=device)
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
    return {
        "supported": True,
        "manufacturers": [{"id": str(row.pk), "name": row.name} for row in manufacturers],
        "module_types": [
            {
                "id": str(row.pk),
                "manufacturer_id": str(row.manufacturer_id),
                "model": row.model,
                "part_number": row.part_number,
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
    }


def _changes(instance, spec):
    for change in spec["changes"]:
        setattr(instance, change["field"], change["after"])
    return instance


def component_objects(plan, device, *, module_status, status_resolver):
    """Construct a cached hierarchy, including unsaved parents, without INSERTs."""
    ModuleType, ModuleBay, Module = _models()
    manufacturers = {
        spec["key"]: Manufacturer(name=spec["name"]) for spec in plan.get("manufacturers", [])
    }
    types, bays, modules = {}, {}, {}
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
    bay_specs = {row["key"]: row for row in plan["bays"]}
    remaining = list(plan["modules"])
    while remaining:
        progress = False
        for spec in remaining[:]:
            bay_spec = bay_specs[spec["bay_key"]]
            parent_key = bay_spec["parent_key"]
            if parent_key is not None and parent_key not in modules:
                continue
            if bay_spec["create"]:
                bay = ModuleBay(
                    parent_device=device,
                    parent_module=modules[parent_key] if parent_key is not None else None,
                    name=bay_spec["name"],
                    position=bay_spec["position"],
                    label=bay_spec["label"],
                )
            else:
                bay = ModuleBay.objects.select_related(
                    "parent_device", "parent_module", "module_family"
                ).get(pk=bay_spec["id"])
            bays[bay_spec["key"]] = _changes(bay, bay_spec)
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
            remaining.remove(spec)
            progress = True
        if not progress:
            raise InventoryError("Component hierarchy has an unresolved parent or cycle")
    return {
        "plan": plan,
        "manufacturers": manufacturers,
        "types": types,
        "bays": bays,
        "modules": modules,
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
        excluded = (
            ["parent_module"] if obj.parent_module and obj.parent_module._state.adding else []
        )
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


def save_components(objects):
    """Save catalogs then parent-first assets; callers own the atomic transaction."""
    for obj in objects.get("manufacturers", {}).values():
        obj.validated_save()
    for spec in objects["plan"]["module_types"]:
        if spec["create"] or spec["changes"]:
            objects["types"][spec["key"]].validated_save()
    bay_specs = {row["key"]: row for row in objects["plan"]["bays"]}
    module_specs = {row["key"]: row for row in objects["plan"]["modules"]}
    saved = set()

    def save_module(key):
        if key in saved:
            return
        spec = module_specs[key]
        bay_spec = bay_specs[spec["bay_key"]]
        if bay_spec["parent_key"] is not None:
            save_module(bay_spec["parent_key"])
        if bay_spec["create"] or bay_spec["changes"]:
            objects["bays"][spec["bay_key"]].validated_save()
        obj = objects["modules"][key]
        if spec["create"]:
            with _suppression_context(obj.module_type):
                obj.validated_save()
        elif spec["changes"]:
            obj.validated_save()
        saved.add(key)

    for key in module_specs:
        save_module(key)
