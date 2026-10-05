"""Native capability snapshots and validated PAN interface relationships.

Creation and scalar updates use the shared Interface writer. This boundary owns
only direct parent and LAG assignments and relies on its caller's transaction.
Preparing and validating relationship objects issues no DML.
"""

from nautobot.dcim.models import Interface

from .adapters.panos import DiscoveryError
from .adapters.panos_logical import CONTRACT, canonical_row
from .exceptions import InventoryError


def _choices(field):
    values = []
    for value, label in field.choices:
        if isinstance(label, (list, tuple)):
            values.extend(item[0] for item in label)
        else:
            values.append(value)
    return sorted(set(values))


def snapshot_panos_interfaces(device, *, lock=False, discovery=None):
    if discovery is not None and discovery.get("adapter") != "panos":
        return {"supported": False, "capabilities": {}, "interfaces": []}
    fields = {field.name for field in Interface._meta.fields}
    supported = {"device", "type", "enabled", "name"} <= fields
    capabilities = {
        "types": _choices(Interface._meta.get_field("type")) if "type" in fields else [],
        "parent_interface": "parent_interface" in fields,
        "lag": "lag" in fields,
    }
    query = device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
    if lock:
        query = query.select_for_update(of=("self",))
    query = query.select_related(
        *[field for field in ("parent_interface", "lag") if field in fields]
    )
    rows = []
    for interface in query.order_by("pk"):
        row = {"id": str(interface.pk), "name": interface.name}
        for field in ("parent_interface", "lag"):
            value = getattr(interface, field, None) if field in fields else None
            row[field + "_id"] = str(value.pk) if value is not None else None
            row[field + "_name"] = value.name if value is not None else None
        rows.append(row)
    return {"supported": supported, "capabilities": capabilities, "interfaces": rows}


def _owned(interface, device):
    return interface.device_id == device.pk and getattr(interface, "module_id", None) is None


def _provenance(row, field):
    source = row.get("source")
    if not isinstance(source, dict) or source.get("contract") != CONTRACT:
        raise InventoryError("PAN interface relationship provenance is invalid")
    if field == "parent_interface":
        try:
            fact = canonical_row(source.get("evidence"))
        except (DiscoveryError, ValueError, TypeError, AttributeError):
            raise InventoryError("PAN parent relationship provenance is invalid") from None
        if (
            fact["source"] != source
            or fact["name"] != row["name"]
            or fact["parent_name"] != row["parent_name"]
        ):
            raise InventoryError(
                "PAN parent relationship disagrees with its direct configuration parent"
            )
    else:
        from .transport_ssh import RUNNING_VPN

        if source != {
            "contract": CONTRACT,
            "command": RUNNING_VPN,
            "path": "result/network/interface/ethernet/entry/aggregate-group",
            "configured_name": row["name"],
            "value": row["lag_name"],
        }:
            raise InventoryError("PAN aggregation relationship provenance is invalid")


def panos_interface_objects(plan, interfaces, device):
    """Bind relation candidates to the shared existing/new Interface object map."""
    if plan.get("errors"):
        raise InventoryError("; ".join(plan["errors"]))
    if plan.get("contract") != CONTRACT:
        raise InventoryError("PAN interface relationship contract is invalid")
    objects, assigned = [], set()
    for collection, field, target_key in (
        ("parents", "parent_interface", "parent_name"),
        ("lag_assignments", "lag", "lag_name"),
    ):
        if plan.get(collection) and field not in {item.name for item in Interface._meta.fields}:
            raise InventoryError("Native PAN interface relationship field is unavailable")
        for row in plan.get(collection, []):
            _provenance(row, field)
            interface, target = interfaces.get(row["name"]), interfaces.get(row[target_key])
            if interface is None or target is None or interface.pk == target.pk:
                raise InventoryError("PAN interface relationship endpoint is missing or ambiguous")
            if not _owned(interface, device) or not _owned(target, device):
                raise InventoryError(
                    "PAN interface relationships must remain on the selected Device"
                )
            if (interface.pk, field) in assigned:
                raise InventoryError("PAN interface relationship is duplicated")
            assigned.add((interface.pk, field))
            if row.get("before_id") is not None or getattr(interface, field + "_id") is not None:
                raise InventoryError(
                    "PAN interface relationship would overwrite a populated assignment"
                )
            if field == "parent_interface" and interface.type != "virtual":
                raise InventoryError("Native subinterface children must retain virtual type")
            if field == "lag" and (target.type != "lag" or interface.is_virtual):
                raise InventoryError(
                    "Native LAG assignment requires a physical member and a LAG target"
                )
            objects.append({"interface": interface, "target": target, "field": field})
    # Exact PAN parent paths are one level deep; additionally reject native graph
    # cycles rather than depending on the order in which relationships are saved.
    parents = {
        item["interface"].pk: item["target"]
        for item in objects
        if item["field"] == "parent_interface"
    }
    for item in objects:
        if item["field"] != "parent_interface":
            continue
        visited, current = {item["interface"].pk}, item["target"]
        while current is not None:
            if current.pk in visited:
                raise InventoryError("PAN direct-parent relationship would create a cycle")
            visited.add(current.pk)
            current = parents.get(current.pk) or getattr(current, "parent_interface", None)
    return objects


def validate_panos_interfaces(objects, device):
    """Run native clean with cached prospective parents, restoring preview state."""
    for item in objects:
        interface, target, field = item["interface"], item["target"], item["field"]
        if not _owned(interface, device) or not _owned(target, device):
            raise InventoryError("PAN interface relationship ownership changed")
        original = getattr(interface, field)
        try:
            if interface.mode != "tagged" and interface.tagged_vlans.exists():
                raise InventoryError(
                    "Saving this interface would clear populated tagged VLAN membership"
                )
            setattr(interface, field, target)
            excluded = [field] if target._state.adding else []
            interface.full_clean(exclude=excluded)
        finally:
            setattr(interface, field, original)


def save_panos_interfaces(objects, device):
    """Save relations after ordinary Interface creates, inside the outer atomic apply."""
    for item in objects:
        interface, target, field = item["interface"], item["target"], item["field"]
        if interface._state.adding or target._state.adding:
            raise InventoryError("Save PAN interface endpoints before their relationships")
        if (
            not _owned(interface, device)
            or not _owned(target, device)
            or getattr(interface, field + "_id") is not None
        ):
            raise InventoryError("PAN interface relationship changed before apply")
        if interface.mode != "tagged" and interface.tagged_vlans.exists():
            raise InventoryError(
                "Saving this interface would clear populated tagged VLAN membership"
            )
        setattr(interface, field, target)
        interface.full_clean()
        interface.save(update_fields=[field])
