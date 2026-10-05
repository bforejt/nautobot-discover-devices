"""Explicit existing-device intent for PAN-OS active/passive HA discovery."""

import json
from uuid import UUID

from .adapters.panos import canonical_vm_uuid

CONTRACT = "panos-ha-policy-v1"


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("PAN-OS HA selection contains duplicate JSON fields")
        result[key] = value
    return result


def _identifier(value):
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("PAN-OS HA selection requires exact existing-object UUIDs")
    try:
        identifier = UUID(value)
    except (ValueError, AttributeError):
        raise ValueError("PAN-OS HA selection requires exact existing-object UUIDs") from None
    if str(identifier) != value.lower() or identifier.int in (0, (1 << 128) - 1):
        raise ValueError("PAN-OS HA selection requires exact existing-object UUIDs")
    return str(identifier)


def _label(value):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("PAN-OS HA selected objects require exact nonblank labels")
    return value


def normalize_panos_ha_policy(text, resolve, *, selected_device_id):
    """Resolve only explicit existing UUIDs; no HA address selects an inventory object.

    ``resolve(kind, identifier)`` returns a serialized existing ``device`` or
    ``redundancy_group``. The selected Device is supplied by the enclosing Job.
    A blank selection retains the earlier HA report-only behavior.
    """
    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        raise ValueError("PAN-OS HA selection must be bounded JSON text")
    if not text.strip():
        return None
    selected_id = _identifier(str(selected_device_id))
    try:
        row = json.loads(text, object_pairs_hook=_object)
    except json.JSONDecodeError:
        raise ValueError("PAN-OS HA selection must be a JSON object") from None
    if not isinstance(row, dict) or set(row) != {"peer_device", "peer_vm_uuid", "redundancy_group"}:
        raise ValueError(
            "PAN-OS HA selection requires peer_device, peer_vm_uuid and redundancy_group"
        )
    peer_id = _identifier(row["peer_device"])
    group_id = _identifier(row["redundancy_group"])
    peer_uuid = canonical_vm_uuid(row["peer_vm_uuid"])
    if peer_id == selected_id:
        raise ValueError("PAN-OS HA peer must be a different existing Device")
    if peer_uuid is None or row["peer_vm_uuid"] != row["peer_vm_uuid"].strip():
        raise ValueError("PAN-OS HA peer requires an explicit valid VM UUID")
    peer = resolve("device", peer_id)
    if not isinstance(peer, dict) or str(peer.get("id")) != peer_id or peer.get("model") != "PA-VM":
        raise ValueError("PAN-OS HA peer requires the selected existing PA-VM Device")
    group = resolve("redundancy_group", group_id)
    if not isinstance(group, dict) or str(group.get("id")) != group_id:
        raise ValueError("PAN-OS HA requires the selected existing DeviceRedundancyGroup")
    strategy = group.get("failover_strategy")
    if strategy not in ("", "active-passive"):
        raise ValueError("PAN-OS HA group must have blank or active-passive failover strategy")
    return {
        "contract": CONTRACT,
        "selected_device_id": selected_id,
        "peer_device": {"id": peer_id, "name": _label(peer.get("name")), "model": "PA-VM"},
        "peer_vm_uuid": peer_uuid,
        "redundancy_group": {
            "id": group_id,
            "name": _label(group.get("name")),
            "failover_strategy": strategy,
        },
    }
