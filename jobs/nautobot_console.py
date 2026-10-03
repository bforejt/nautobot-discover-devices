"""Nautobot console connector snapshots, validation and staged saves."""

from .exceptions import InventoryError


def _models():
    from nautobot.dcim.models import ConsolePort, ConsolePortTemplate

    return ConsolePort, ConsolePortTemplate


def snapshot_console_ports(device, *, lock=False):
    """Include root and Module ports so duplicate or ownership conflicts stay visible."""
    try:
        ConsolePort, ConsolePortTemplate = _models()
    except ImportError:
        return {"supported": False}
    ports = (
        device.all_console_ports if hasattr(device, "all_console_ports") else device.console_ports
    )
    templates = ConsolePortTemplate.objects.filter(device_type_id=device.device_type_id)
    if lock:
        ports = ports.select_for_update(of=("self",))
        templates = templates.select_for_update(of=("self",))
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
        "templates": list(templates.order_by("pk").values("name", "type", "label", "description")),
    }


def console_objects(plan, device):
    """Stage only native field changes; never rename or move an existing termination."""
    ConsolePort, _ConsolePortTemplate = _models()
    creates, updates = [], []
    for row in plan["creates"]:
        creates.append(
            ConsolePort(
                device=device,
                **{
                    field: row[field]
                    for field in ("name", "type", "label", "description")
                    if row.get(field) is not None
                },
            )
        )
    for row in plan["updates"]:
        try:
            port = ConsolePort.objects.get(pk=row["id"], device=device, module__isnull=True)
        except ConsolePort.DoesNotExist as exc:
            raise InventoryError(
                "Console port must belong directly to the selected Device"
            ) from exc
        if port.name != row["name"]:
            raise InventoryError("Console port identity changed after planning")
        for change in row["changes"]:
            if change["field"] not in {"type", "label", "description"}:
                raise InventoryError("Console discovery cannot rename or reattach existing ports")
            setattr(port, change["field"], change["after"])
        updates.append(port)
    return creates + updates


def validate_console_ports(objects, device):
    """Validate all console objects before the transaction saves any inventory."""
    for port in objects:
        if port.device_id != device.pk or port.module_id is not None:
            raise InventoryError("Console port must belong directly to the selected Device")
        port.full_clean()


def save_console_ports(objects):
    for port in objects:
        port.validated_save()
