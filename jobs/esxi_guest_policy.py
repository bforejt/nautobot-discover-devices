"""Explicit NFV guest Device identities for the existing Hosted On relationship."""

import json
from uuid import UUID

CONTRACT = "esxi-guest-policy-v1"
RELATIONSHIP_KEY = "hosted_on"


def canonical_uuid(value):
    """Accept an explicit non-sentinel UUID, never a name or registration ID."""
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    if parsed.int in (0, (1 << 128) - 1):
        return None
    return str(parsed) if value.lower() == str(parsed) else None


def normalize_esxi_guest_policy(value, resolve_target, *, selected_device_id):
    """Resolve existing objects; create neither Devices nor relationship schema."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        raise ValueError("ESXi guest mappings must be a JSON list")
    try:
        rows = json.loads(value)
    except (ValueError, TypeError):
        raise ValueError("ESXi guest mappings must be a valid JSON list") from None
    if not isinstance(rows, list) or len(rows) > 4096:
        raise ValueError("ESXi guest mappings must contain at most 4096 mappings")
    if not rows:
        return None
    host_id = canonical_uuid(str(selected_device_id))
    if host_id is None:
        raise ValueError("Select an existing ESXi host Device UUID")
    parsed = []
    vm_ids, device_ids = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"vm_uuid", "device"}:
            raise ValueError("Each ESXi guest mapping requires only vm_uuid and device")
        vm_id, device_id = canonical_uuid(row["vm_uuid"]), canonical_uuid(row["device"])
        if vm_id is None or device_id is None:
            raise ValueError("ESXi guest mappings require non-sentinel VM and Device UUIDs")
        if vm_id in vm_ids or device_id in device_ids:
            raise ValueError("ESXi guest mappings contain an ambiguous VM or Device identity")
        if device_id == host_id:
            raise ValueError("An ESXi host cannot be its own hosted guest")
        vm_ids.add(vm_id)
        device_ids.add(device_id)
        parsed.append((vm_id, device_id))
    relationship = resolve_target("relationship", RELATIONSHIP_KEY)
    if not isinstance(relationship, dict) or (
        canonical_uuid(relationship.get("id")) is None
        or relationship.get("key") != RELATIONSHIP_KEY
        or relationship.get("type") != "one-to-many"
        or relationship.get("source_type") != "dcim.device"
        or relationship.get("destination_type") != "dcim.device"
    ):
        raise ValueError("Hosted On must be the existing one-to-many Device to Device relationship")
    mappings = []
    for vm_id, device_id in parsed:
        device = resolve_target("device", device_id)
        if not isinstance(device, dict) or canonical_uuid(device.get("id")) != device_id:
            raise ValueError("An explicitly mapped ESXi guest Device does not exist")
        mappings.append({"vm_uuid": vm_id, "device": device})
    return {
        "contract": CONTRACT,
        "host_device_id": host_id,
        "relationship": relationship,
        "mappings": mappings,
    }
