"""Nautobot console connector snapshots, validation and staged saves."""

from .exceptions import InventoryError


def _models():
    from nautobot.dcim.models import ConsolePort, ConsolePortTemplate

    return ConsolePort, ConsolePortTemplate


def snapshot_console_ports(device, *, lock=False, discovery=None):
    """Include root and Module ports so duplicate or ownership conflicts stay visible."""
    try:
        ConsolePort, ConsolePortTemplate = _models()
    except ImportError:
        return {"supported": False}
    stack = (discovery or {}).get("stack", {})
    if isinstance(stack, dict) and stack.get("is_stack") is True:
        from nautobot.dcim.models import Device, DeviceType

        from .nautobot_components import _scope_device_ids

        ids = _scope_device_ids(device, discovery)
        ports = ConsolePort.objects.filter(device_id__in=ids)
        models = {row.get("model") for row in stack.get("members", []) if isinstance(row, dict)}
        type_ids = set(Device.objects.filter(pk__in=ids).values_list("device_type_id", flat=True))
        type_ids.update(
            DeviceType.objects.filter(
                manufacturer_id=device.device_type.manufacturer_id, model__in=models
            ).values_list("pk", flat=True)
        )
    else:
        ports = (
            device.all_console_ports
            if hasattr(device, "all_console_ports")
            else device.console_ports
        )
        type_ids = {device.device_type_id}
    templates = ConsolePortTemplate.objects.filter(device_type_id__in=type_ids)
    if lock:
        ports = ports.select_for_update(of=("self",))
        templates = templates.select_for_update(of=("self",))
    template_rows = list(
        templates.order_by("pk").values("device_type_id", "name", "type", "label", "description")
    )
    return {
        "supported": True,
        "ports": [
            {
                "id": str(port.pk),
                "name": port.name,
                "type": port.type,
                "label": port.label,
                "description": port.description,
                "device_id": str(port.device_id) if port.device_id else None,
                "module_id": str(port.module_id) if port.module_id else None,
                "cable_id": str(port.cable_id) if getattr(port, "cable_id", None) else None,
            }
            for port in ports.order_by("pk")
        ],
        "templates": [
            {key: value for key, value in row.items() if key != "device_type_id"}
            for row in template_rows
            if row["device_type_id"] == device.device_type_id
        ],
        "templates_by_device_type": {
            str(pk): [
                {key: value for key, value in row.items() if key != "device_type_id"}
                for row in template_rows
                if row["device_type_id"] == pk
            ]
            for pk in sorted(type_ids, key=str)
        },
    }


def console_objects(plan, device, *, devices_by_serial=None):
    """Stage only native field changes; never rename or move an existing termination."""
    ConsolePort, _ConsolePortTemplate = _models()
    creates, updates = [], []
    owners = dict(devices_by_serial or {})
    if device.serial and device.serial.strip():
        owners.setdefault(device.serial.strip(), device)

    def owner(row):
        serial = row.get("device_serial")
        obj = owners.get(serial) if serial is not None else device
        if obj is None or serial is not None and obj.serial.strip() != serial:
            raise InventoryError("Console owner is not a validated physical stack member")
        if row.get("device_id") is not None and str(obj.pk) != str(row["device_id"]):
            raise InventoryError("Console owner Device changed after planning")
        if row.get("member_position") is not None and obj.vc_position != row["member_position"]:
            raise InventoryError("Console owner member position changed after planning")
        return obj

    for row in plan["creates"]:
        parent = owner(row)
        port = ConsolePort(
            device=parent,
            **{
                field: row[field]
                for field in ("name", "type", "label", "description")
                if row.get(field) is not None
            },
        )
        port._discovery_console_owner = parent
        creates.append(port)
    for row in plan["updates"]:
        parent = owner(row)
        try:
            port = ConsolePort.objects.get(pk=row["id"], device=parent, module__isnull=True)
        except ConsolePort.DoesNotExist as exc:
            raise InventoryError(
                "Console port must belong directly to its validated physical Device"
            ) from exc
        if port.name != row["name"]:
            raise InventoryError("Console port identity changed after planning")
        for change in row["changes"]:
            if change["field"] not in {"type", "label", "description"}:
                raise InventoryError("Console discovery cannot rename or reattach existing ports")
            setattr(port, change["field"], change["after"])
        port.device = parent
        port._discovery_console_owner = parent
        updates.append(port)
    return creates + updates


def validate_console_ports(objects, device):
    """Validate all console objects before the transaction saves any inventory."""
    for port in objects:
        parent = getattr(port, "_discovery_console_owner", device)
        if port.device_id != parent.pk or port.module_id is not None:
            raise InventoryError(
                "Console port must belong directly to its validated physical Device"
            )
        port.full_clean(exclude=["device"] if parent._state.adding else [])


def save_console_ports(objects):
    for port in objects:
        port.validated_save()
