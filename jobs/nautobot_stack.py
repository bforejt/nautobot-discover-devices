"""Native VirtualChassis snapshots and atomic, staged stack-member saves."""

from contextlib import nullcontext

from django.db.models import Q

from .adapters.cisco_iosxe import canonical_software_version
from .exceptions import InventoryError


def _models():
    from nautobot.dcim.models import Device, DeviceType, Manufacturer, VirtualChassis

    return Device, DeviceType, Manufacturer, VirtualChassis


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def _device_row(device):
    return {
        "id": str(device.pk),
        "name": device.name,
        "serial": device.serial,
        "model": device.device_type.model,
        "manufacturer_id": str(device.device_type.manufacturer_id),
        "manufacturer_name": device.device_type.manufacturer.name,
        "device_type_id": str(device.device_type_id),
        "location_id": str(device.location_id),
        "tenant_id": str(device.tenant_id) if device.tenant_id else None,
        "role_id": str(device.role_id),
        "status_id": str(device.status_id),
        "platform_id": str(device.platform_id) if device.platform_id else None,
        "platform_network_driver": device.platform.network_driver if device.platform_id else None,
        "software_version_id": str(device.software_version_id)
        if device.software_version_id
        else None,
        "software_version": device.software_version.version if device.software_version_id else None,
        "virtual_chassis_id": str(device.virtual_chassis_id) if device.virtual_chassis_id else None,
        "vc_position": device.vc_position,
        "vc_priority": device.vc_priority,
    }


def snapshot_stack(device, *, discovery=None, lock=False):
    """Include global identity collisions and every occupant of candidate chassis."""
    try:
        Device, DeviceType, Manufacturer, VirtualChassis = _models()
    except ImportError:
        return {"supported": False}
    source = (discovery or {}).get("stack", {})
    source = source if isinstance(source, dict) else {}
    members = source.get("members", [])
    members = members if isinstance(members, list) else []
    serials = {
        row["serial"].strip()
        for row in members
        if isinstance(row, dict) and isinstance(row.get("serial"), str) and row["serial"].strip()
    }
    if device.serial:
        serials.add(device.serial.strip())
    name = source.get("name")
    name = name.strip() if isinstance(name, str) else ""
    # NtC names stack members after the hostname and position. Include operator
    # naming variants so potential identity collisions remain visible.
    matched_ids = [
        pk
        for pk, serial in Device.objects.exclude(serial="").values_list("pk", "serial")
        if isinstance(serial, str) and serial.strip() in serials
    ]
    candidates = Q(pk=device.pk) | Q(pk__in=matched_ids)
    if name:
        candidates |= (
            Q(name=name)
            | Q(name__startswith=name + "-")
            | Q(name__startswith=name + "_")
            | Q(name__startswith=name + ":")
        )
    if device.virtual_chassis_id:
        candidates |= Q(virtual_chassis_id=device.virtual_chassis_id)
    candidate_devices = Device.objects.filter(candidates)
    chassis_ids = set(
        candidate_devices.exclude(virtual_chassis=None).values_list("virtual_chassis_id", flat=True)
    )
    chassis_query = VirtualChassis.objects.filter(Q(pk__in=chassis_ids) | Q(name=name))
    chassis = list(_locked(chassis_query, lock).order_by("pk"))
    chassis_ids.update(row.pk for row in chassis)
    candidates |= Q(virtual_chassis_id__in=chassis_ids)
    devices = list(
        _locked(Device.objects.filter(candidates), lock)
        .select_related("device_type__manufacturer", "software_version", "platform")
        .order_by("pk")
    )
    manufacturer_ids = {device.device_type.manufacturer_id}
    manufacturer_ids.update(row.device_type.manufacturer_id for row in devices)
    if lock:
        list(
            Manufacturer.objects.filter(pk__in=manufacturer_ids).select_for_update().order_by("pk")
        )
    types = _locked(DeviceType.objects.filter(manufacturer_id__in=manufacturer_ids), lock)
    from nautobot.dcim.models import Platform, SoftwareVersion

    platform_ids = {row.platform_id for row in devices if row.platform_id}
    if device.platform_id:
        platform_ids.add(device.platform_id)
    if lock:
        list(Platform.objects.filter(pk__in=platform_ids).order_by("pk").select_for_update())
    versions = _locked(SoftwareVersion.objects.filter(platform_id__in=platform_ids), lock)
    return {
        "supported": True,
        "selected": _device_row(device),
        "devices": [_device_row(row) for row in devices],
        "virtual_chassis": [
            {
                "id": str(row.pk),
                "name": row.name,
                "master_id": str(row.master_id) if row.master_id else None,
            }
            for row in chassis
        ],
        "device_types": [
            {"id": str(row.pk), "model": row.model, "manufacturer_id": str(row.manufacturer_id)}
            for row in types.order_by("pk")
        ],
        "software_versions": [
            {"id": str(row.pk), "version": row.version, "platform_id": str(row.platform_id)}
            for row in versions.order_by("pk")
        ],
    }


def _suppression_context(device_type):
    """Older releases remain usable when the exact DeviceType has no templates."""
    try:
        from nautobot.apps.dcim import SkipAutoComponentCreation
    except ImportError:
        relations = (
            "console_port_templates",
            "console_server_port_templates",
            "power_port_templates",
            "power_outlet_templates",
            "interface_templates",
            "rear_port_templates",
            "front_port_templates",
            "device_bay_templates",
            "module_bay_templates",
        )
        if any(
            getattr(device_type, name, None) is not None and getattr(device_type, name).exists()
            for name in relations
        ):
            raise InventoryError(
                "This Nautobot release cannot suppress automatic Device components; "
                "use a release with SkipAutoComponentCreation for populated DeviceType templates"
            ) from None
        return nullcontext()
    return SkipAutoComponentCreation()


def stack_objects(plan, device, *, software_version_status=None, status_resolver=None):
    """Construct a complete cached native graph without writing inventory."""
    if not plan or plan.get("virtual_chassis") is None:
        return None
    if plan.get("errors"):
        raise InventoryError("; ".join(plan["errors"]))
    Device, DeviceType, _Manufacturer, VirtualChassis = _models()
    chassis_spec = plan["virtual_chassis"]
    chassis = (
        VirtualChassis(name=chassis_spec["name"])
        if chassis_spec["create"]
        else VirtualChassis.objects.get(pk=chassis_spec["existing_id"])
    )
    if chassis.name != chassis_spec["name"]:
        raise InventoryError("VirtualChassis identity changed after planning")
    types = {}
    for spec in plan["device_types"]:
        obj = (
            DeviceType(manufacturer_id=spec["manufacturer_id"], model=spec["model"])
            if spec["create"]
            else DeviceType.objects.get(pk=spec["existing_id"])
        )
        if obj.model != spec["model"] or str(obj.manufacturer_id) != spec["manufacturer_id"]:
            raise InventoryError("Stack member DeviceType identity changed after planning")
        types[spec["model"]] = obj
    from nautobot.dcim.models import SoftwareVersion

    versions = {}
    for spec in plan.get("software_versions", []):
        if spec["create"]:
            if status_resolver is None:
                from nautobot.extras.models import Status

                status = Status.objects.get_for_model(SoftwareVersion).filter(name="Active").first()
                if software_version_status is not None:
                    status = (
                        Status.objects.get_for_model(SoftwareVersion)
                        .filter(pk=software_version_status.pk)
                        .first()
                    )
                if status is None:
                    raise InventoryError(
                        "Select an applicable status for new SoftwareVersion records"
                    )
            else:
                status = status_resolver(SoftwareVersion, software_version_status)
            obj = SoftwareVersion(
                platform_id=spec["platform_id"], version=spec["version"], status=status
            )
        else:
            obj = SoftwareVersion.objects.get(pk=spec["existing_id"])
        if (
            str(obj.platform_id) != str(spec["platform_id"])
            or canonical_software_version(obj.version) != spec["version"]
        ):
            raise InventoryError("Stack member SoftwareVersion Platform changed after planning")
        versions[spec["key"]] = obj
    members = {}
    for spec in plan["members"]:
        if spec["selected"]:
            obj = device
            if spec["create"] or str(obj.pk) != spec["existing_id"]:
                raise InventoryError("The selected Device cannot be replaced by stack discovery")
        elif spec["create"]:
            obj = Device(
                name=spec["name"],
                serial=spec["serial"],
                device_type=types[spec["model"]],
                location=device.location,
                role=device.role,
                status=device.status,
                platform=device.platform,
                tenant=device.tenant,
                virtual_chassis=chassis,
                vc_position=spec["position"],
                vc_priority=spec["priority"],
            )
        else:
            obj = Device.objects.select_related("device_type__manufacturer").get(
                pk=spec["existing_id"]
            )
        if obj.serial and obj.serial.strip() != spec["serial"]:
            raise InventoryError("Stack member serial changed after planning")
        if obj.device_type.model != spec["model"]:
            raise InventoryError("Stack member model changed after planning")
        if (str(obj.platform_id) if obj.platform_id else None) != spec.get("platform_id"):
            raise InventoryError("Stack member Platform changed after planning")
        software_key = spec.get("software_version_key")
        if software_key:
            if obj.software_version_id:
                raise InventoryError("Stack discovery cannot overwrite populated member software")
            version = versions[software_key]
            if str(obj.platform_id) != str(version.platform_id):
                raise InventoryError("Stack member software must match its own Platform")
            obj.software_version = version
        for change in spec["changes"]:
            field = change["field"]
            if field == "virtual_chassis":
                obj.virtual_chassis = chassis
            elif field == "software_version":
                if (
                    not software_key
                    or canonical_software_version(versions[software_key].version) != change["after"]
                ):
                    raise InventoryError("Stack member software assignment lacks its catalog row")
            elif field in {"serial", "name", "vc_position", "vc_priority"}:
                if field == "name" and obj.name and obj.name.strip():
                    raise InventoryError("Stack discovery cannot rename a populated member name")
                setattr(obj, field, change["after"])
            else:
                raise InventoryError("Stack discovery cannot modify member field %s" % field)
        # Bind cached parents even for unchanged existing members so graph
        # validation sees the same planned VirtualChassis throughout.
        if obj.virtual_chassis_id != chassis.pk:
            raise InventoryError("Stack member was not assigned to the planned VirtualChassis")
        obj.virtual_chassis = chassis
        if spec["position"] in members:
            raise InventoryError("Several stack members occupy the same position")
        members[spec["position"]] = obj
    if chassis_spec["master_position"] not in members:
        raise InventoryError("The stack master must be an observed physical member")
    return {
        "plan": plan,
        "chassis": chassis,
        "types": types,
        "members": members,
        "software_versions": versions,
    }


def validate_stack(objects):
    """Validate models plus unsaved-parent relationships with zero DML."""
    if objects is None:
        return
    chassis = objects["chassis"]
    chassis.full_clean()
    for obj in objects["types"].values():
        obj.full_clean()
    for version in objects["software_versions"].values():
        version.full_clean()
    positions = set()
    for obj in objects["members"].values():
        if obj.virtual_chassis_id != chassis.pk or obj.vc_position is None:
            raise InventoryError(
                "Every stack member must have a position in the planned VirtualChassis"
            )
        if obj.vc_position in positions:
            raise InventoryError("Several stack members occupy the same position")
        positions.add(obj.vc_position)
        excluded = []
        if obj.device_type._state.adding:
            excluded.append("device_type")
        if chassis._state.adding:
            excluded.append("virtual_chassis")
        if obj.software_version_id:
            if str(obj.platform_id) != str(obj.software_version.platform_id):
                raise InventoryError("Stack member software must match its own Platform")
            if obj.software_version._state.adding:
                excluded.append("software_version")
        obj.full_clean(exclude=excluded)
        if obj._state.adding:
            _suppression_context(obj.device_type)


def save_stack(objects):
    """Save parents before members and master; the caller owns the transaction."""
    if objects is None:
        return
    chassis = objects["chassis"]
    if objects["plan"]["virtual_chassis"]["create"]:
        chassis.validated_save()
    for obj in objects["types"].values():
        if obj._state.adding:
            obj.validated_save()
    for version in objects["software_versions"].values():
        if version._state.adding:
            version.validated_save()
    for spec in objects["plan"]["members"]:
        obj = objects["members"][spec["position"]]
        if spec["create"]:
            with _suppression_context(obj.device_type):
                obj.validated_save()
        elif spec["changes"]:
            obj.validated_save()
    master = objects["members"][objects["plan"]["virtual_chassis"]["master_position"]]
    if chassis.master_id != master.pk:
        chassis.master = master
        chassis.validated_save()
