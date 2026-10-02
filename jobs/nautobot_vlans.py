"""Scoped VLAN snapshots and staged 802.1Q assignments without preview writes."""

from nautobot.ipam.models import VLAN, VLANGroup

from .adapters.cisco_iosxe import canonical_interface_name
from .exceptions import InventoryError


def _location_ids(device):
    return set(device.location.ancestors(include_self=True).values_list("pk", flat=True))


def snapshot_vlans(device, group, *, lock=False):
    """A VID is resolved only in an explicitly selected Layer-2 domain."""
    if group is None:
        return {"supported": True, "group": None, "allowed_vids": [], "vlans": []}
    groups = VLANGroup.objects.all()
    if lock:
        groups = groups.select_for_update()
    group = groups.get(pk=group.pk)
    locations = _location_ids(device)
    if group.location_id is not None and group.location_id not in locations:
        raise InventoryError("The selected VLAN Group is outside the Device's location hierarchy")
    rows = VLAN.objects.filter(vlan_group=group).prefetch_related("locations").order_by("pk")
    if lock:
        rows = rows.select_for_update(of=("self",))
    return {
        "supported": True,
        "group": {"id": str(group.pk), "name": group.name},
        "allowed_vids": list(group.expanded_range),
        "vlans": [
            {
                "id": str(row.pk),
                "vid": row.vid,
                "name": row.name,
                "applicable": not row.locations.all()
                or any(location.pk in locations for location in row.locations.all()),
            }
            for row in rows
        ],
    }


def vlan_objects(plan, interfaces, *, vlan_status, status_resolver):
    """Construct unsaved VLANs and references to the shared interface objects."""
    catalog = {}
    status = (
        status_resolver(VLAN, vlan_status) if any(s["create"] for s in plan["catalog"]) else None
    )
    for spec in plan["catalog"]:
        if spec["create"]:
            vlan = VLAN(
                vlan_group=VLANGroup.objects.get(pk=spec["group_id"]),
                vid=spec["vid"],
                name=spec["name"],
                status=status,
            )
        else:
            vlan = VLAN.objects.get(pk=spec["id"])
        for change in spec["changes"]:
            setattr(vlan, change["field"], change["after"])
        catalog[spec["key"]] = vlan
    assignments = []
    for spec in plan["assignments"]:
        interface = interfaces[canonical_interface_name(spec["name"])]
        assignments.append((interface, spec))
    return {"plan": plan, "catalog": catalog, "assignments": assignments}


def validate_vlan_objects(objects, device):
    """Validate cached parents and proposed M2M membership without saving."""
    locations = _location_ids(device)
    for vlan in objects["catalog"].values():
        vlan.full_clean()
    for interface, spec in objects["assignments"]:
        if interface.device_id != device.pk:
            raise InventoryError("802.1Q assignments must belong to the selected Device")
        if interface.type in ("virtual", "bridge", "tunnel"):
            raise InventoryError("802.1Q discovery requires a physical or LAG interface")
        before_tags = set(interface.tagged_vlans.values_list("pk", flat=True))
        for change in spec["changes"]:
            if change["field"] == "mode":
                if interface.mode and interface.mode != change["after"]:
                    raise InventoryError("Interface 802.1Q mode changed during validation")
                if before_tags and change["after"] != "tagged":
                    raise InventoryError("Changing mode would clear existing tagged VLANs")
                interface.mode = change["after"]
            elif change["field"] == "untagged_vlan":
                vlan = objects["catalog"][change["after"]]
                if interface.untagged_vlan_id not in (None, vlan.pk):
                    raise InventoryError("Interface untagged VLAN changed during validation")
                interface.untagged_vlan = vlan
            else:
                raise InventoryError("Unsupported planned 802.1Q field")
        if interface.mode != spec["mode"]:
            raise InventoryError("802.1Q assignment and interface mode disagree")
        tag_keys = spec["tagged_vlan_keys"]
        if tag_keys is not None:
            intended = {objects["catalog"][key].pk for key in tag_keys}
            if interface.mode != "tagged":
                raise InventoryError("Explicit tagged VLANs require Tagged mode")
            if before_tags and before_tags != intended:
                raise InventoryError("Existing tagged VLAN membership must be preserved")
            if interface.untagged_vlan_id in intended:
                raise InventoryError("A discovered VLAN cannot be both tagged and untagged")
        referenced = [objects["catalog"][key] for key in tag_keys or []]
        if interface.untagged_vlan is not None:
            referenced.append(interface.untagged_vlan)
        for vlan in referenced:
            # New VLANs are intentionally global within the selected group.
            if vlan._state.adding:
                continue
            vlan_locations = set(vlan.locations.values_list("pk", flat=True))
            if vlan_locations and not vlan_locations.intersection(locations):
                raise InventoryError("A discovered VLAN is outside the Device's location hierarchy")


def save_vlan_catalog(objects):
    """Save only new/enriched VLANs inside the caller's inventory transaction."""
    for spec in objects["plan"]["catalog"]:
        if spec["create"] or spec["changes"]:
            objects["catalog"][spec["key"]].validated_save()


def save_vlan_assignments(objects, device):
    """Save the interface fields before adding its explicitly resolved tagged set."""
    validate_vlan_objects(objects, device)
    for interface, spec in objects["assignments"]:
        if spec["changes"]:
            interface.validated_save()
        keys = spec["tagged_vlan_keys"]
        if keys is not None and keys:
            interface.tagged_vlans.add(*(objects["catalog"][key] for key in keys))
