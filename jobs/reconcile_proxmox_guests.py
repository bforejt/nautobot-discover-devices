"""Fill-only Hosted On links from explicit Device selections and Proxmox BIOS UUIDs."""

from collections import defaultdict
from copy import deepcopy

from .adapters import proxmox
from .proxmox_guest_policy import CONTRACT as POLICY_CONTRACT
from .proxmox_guest_policy import RELATIONSHIP_KEY, canonical_uuid

CONTRACT = "proxmox-hosted-on-v1"
RELATIONSHIP_FIELDS = ("id", "key", "type", "source_type", "destination_type")


def canonical_guest_uuid(value):
    """Read the UUID in native QEMU smbios1 properties without guessing VM identity."""
    if not isinstance(value, str) or not value or len(value) > 65536:
        return None
    properties = {}
    for entry in value.split(","):
        key, separator, content = entry.partition("=")
        if (
            not separator
            or not key
            or not key.isascii()
            or not all(
                character.islower() or character.isdigit() or character == "_" for character in key
            )
            or key in properties
            or not content
            or content.strip() != content
        ):
            return None
        properties[key] = content
    return canonical_uuid(properties.get("uuid"))


def _non_template(value):
    # QEMU API and config schema define an omitted template flag as false (0).
    return value is False or (type(value) is int and value == 0)


def _pending_identity_change(rows, vm_uuid):
    """Current UUIDs cannot establish ownership during an identity/lifecycle transition."""
    if not isinstance(rows, list):
        return True
    keys = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("key"), str) or row["key"] in keys:
            return True
        keys.add(row["key"])
        # Opaque custom QEMU arguments can override SMBIOS identity. Their
        # values are redacted, so presence cannot prove an effective BIOS UUID.
        if row["key"] == "args":
            return True
        if row["key"] not in {"smbios1", "template", "lock"}:
            continue
        if "pending" in row or row.get("delete") not in (None, False, 0):
            return True
        # /pending also exposes the current value from a separate API read.
        # It must corroborate the identity captured in the two config views.
        if "value" not in row:
            return True
        if row["key"] == "smbios1" and canonical_guest_uuid(row["value"]) != vm_uuid:
            return True
        if row["key"] == "template" and not _non_template(row["value"]):
            return True
        if row["key"] == "lock" and row["value"] is not None:
            return True
    return False


def validated_policy(policy, host_id):
    """Validate the resolved operator policy independently of Job input parsing."""
    if not isinstance(policy, dict) or set(policy) != {
        "contract",
        "host_device_id",
        "relationship",
        "mappings",
    }:
        return False
    if (
        policy.get("contract") != POLICY_CONTRACT
        or canonical_uuid(host_id) is None
        or policy.get("host_device_id") != host_id
    ):
        return False
    relationship = policy.get("relationship")
    if not isinstance(relationship, dict) or (
        canonical_uuid(relationship.get("id")) is None
        or relationship.get("key") != RELATIONSHIP_KEY
        or relationship.get("type") != "one-to-many"
        or relationship.get("source_type") != "dcim.device"
        or relationship.get("destination_type") != "dcim.device"
    ):
        return False
    mappings = policy.get("mappings")
    if not isinstance(mappings, list) or not 1 <= len(mappings) <= 4096:
        return False
    vm_ids, device_ids = set(), set()
    for row in mappings:
        if not isinstance(row, dict) or set(row) != {"vm_uuid", "device"}:
            return False
        device = row["device"]
        vm_id = canonical_uuid(row["vm_uuid"])
        device_id = canonical_uuid(device.get("id")) if isinstance(device, dict) else None
        if (
            vm_id is None
            or vm_id != row["vm_uuid"]
            or device_id is None
            or device_id != device["id"]
            or device_id == host_id
            or vm_id in vm_ids
            or device_id in device_ids
        ):
            return False
        vm_ids.add(vm_id)
        device_ids.add(device_id)
    return True


def relationship_matches(relationship, policy):
    """Require the same existing relationship identity, direction and cardinality."""
    expected = policy["relationship"]
    return isinstance(relationship, dict) and all(
        relationship.get(field) == expected.get(field) for field in RELATIONSHIP_FIELDS
    )


def plan_proxmox_guests(discovery, existing, *, identity_verified=False):
    """Plan additions from QEMU BIOS UUIDs; names, VMIDs and LXC never choose Devices."""
    plan = {
        "contract": CONTRACT,
        "policy": None,
        "node": None,
        "relationship": None,
        "creates": [],
        "preserved": [],
        "errors": [],
        "conflicts": [],
        "warnings": [],
        "summary": {"hosted_on_created": 0, "hosted_on_preserved": 0},
    }
    policy = discovery.get("guest_policy")
    if discovery.get("adapter") != "proxmox" or policy is None:
        return plan
    host_id = str(existing.get("device", {}).get("id") or "")
    if not validated_policy(policy, host_id):
        plan["errors"].append(
            "Proxmox Hosted On policy does not match the selected existing Devices"
        )
        return plan
    plan["policy"] = deepcopy(policy)
    if identity_verified is not True:
        plan["errors"].append(
            "Verified selected Proxmox host identity is required for Hosted On links"
        )
        return plan
    native = existing.get("proxmox_guest_inventory")
    if not isinstance(native, dict) or native.get("supported") is not True:
        plan["errors"].append("Native Hosted On capability is unavailable")
        return plan
    relationship = native.get("relationship")
    if not relationship_matches(relationship, policy):
        plan["errors"].append("The selected Hosted On relationship changed identity or scope")
        return plan
    plan["relationship"] = deepcopy(relationship)
    try:
        reconstructed = proxmox.reconstruct(discovery)
    except (proxmox.DiscoveryError, ValueError, TypeError, KeyError):
        plan["errors"].append("Proxmox Hosted On source provenance is invalid")
        return plan
    inventory = reconstructed["source"]["inventory"]
    node = inventory.get("node")
    if (
        not isinstance(node, str)
        or not node
        or inventory.get("completeness", {}).get("guests") is not True
    ):
        plan["errors"].append("Complete selected-node Proxmox guest evidence is required")
        return plan
    plan["node"] = node
    by_uuid, by_registration = defaultdict(list), defaultdict(list)
    registrations = defaultdict(list)
    for row in inventory["api"].get("qemu", []):
        if isinstance(row, dict):
            registrations[row.get("vmid")].append(row)
    for row in inventory["guests"]:
        if not isinstance(row, dict):
            continue
        by_registration[(row.get("kind"), row.get("vmid"), row.get("node"))].append(row)
        if row.get("kind") != "qemu":
            continue
        vm_id = canonical_guest_uuid(row.get("current_config", {}).get("smbios1"))
        if vm_id is not None:
            by_uuid[vm_id].append(row)
    devices = defaultdict(list)
    for row in native.get("devices", []):
        if isinstance(row, dict):
            devices[row.get("id")].append(row)
    associations = defaultdict(list)
    for row in native.get("associations", []):
        if isinstance(row, dict):
            associations[row.get("destination_id")].append(row)
    for mapping in sorted(policy["mappings"], key=lambda row: row["device"]["id"]):
        vm_id, device_id = mapping["vm_uuid"], mapping["device"]["id"]
        if len(devices[device_id]) != 1:
            plan["errors"].append(
                "An explicitly mapped Proxmox guest Device is missing or ambiguous"
            )
            continue
        rows = by_uuid[vm_id]
        if len(rows) != 1:
            plan["errors"].append("A mapped Proxmox guest BIOS UUID is unobserved or ambiguous")
            continue
        guest = rows[0]
        vmid = guest.get("vmid")
        summary, config, status = (
            guest.get("summary"),
            guest.get("current_config"),
            guest.get("status"),
        )
        if (
            type(vmid) is not int
            or not 100 <= vmid <= 999999999
            or guest.get("kind") != "qemu"
            or guest.get("node") != node
            or len(by_registration[("qemu", vmid, node)]) != 1
            or len(registrations[vmid]) != 1
            or summary != registrations[vmid][0]
            or summary.get("node", node) != node
        ):
            plan["errors"].append("A mapped Proxmox QEMU guest is not uniquely registered locally")
            continue
        if (
            not isinstance(config, dict)
            or not isinstance(summary, dict)
            or (
                not _non_template(config.get("template", 0))
                or not _non_template(summary.get("template", 0))
                or not _non_template(guest.get("config", {}).get("template", 0))
            )
        ):
            plan["errors"].append(
                "A mapped Proxmox guest is a template or has invalid guest status"
            )
            continue
        if (
            not isinstance(status, dict)
            or status.get("status") not in {"running", "stopped"}
            or status.get("status") != summary.get("status")
            or ("vmid" in status and (type(status["vmid"]) is not int or status["vmid"] != vmid))
            or status.get("node", node) != node
            or not _non_template(status.get("template", 0))
            or status.get("lock") is not None
            or summary.get("lock") is not None
            or config.get("lock") is not None
            or guest.get("config", {}).get("lock") is not None
        ):
            plan["errors"].append("A mapped Proxmox guest lacks a stable current local status")
            continue
        if (
            "args" in config
            or "args" in guest.get("config", {})
            or _pending_identity_change(guest.get("pending"), vm_id)
            or canonical_guest_uuid(guest.get("config", {}).get("smbios1")) != vm_id
        ):
            plan["errors"].append(
                "A mapped Proxmox guest has pending or ambiguous identity changes"
            )
            continue
        observed = {
            "relationship_id": relationship["id"],
            "source_type": "dcim.device",
            "source_id": host_id,
            "destination_type": "dcim.device",
            "destination_id": device_id,
        }
        found = associations[device_id]
        if found:
            if len(found) == 1 and all(
                found[0].get(key) == value for key, value in observed.items()
            ):
                if canonical_uuid(found[0].get("id")) is None:
                    plan["errors"].append("An existing Hosted On association lacks native identity")
                else:
                    plan["preserved"].append(deepcopy(found[0]))
                continue
            plan["conflicts"].append(
                {
                    "scope": "proxmox_guest",
                    "name": mapping["device"].get("name"),
                    "field": "hosted_on",
                    "before": deepcopy(found),
                    "observed": observed,
                }
            )
            plan["errors"].append("A mapped guest already has conflicting Hosted On ownership")
            continue
        plan["creates"].append(
            {**observed, "vm_uuid": vm_id, "kind": "qemu", "vmid": vmid, "node": node}
        )
    if plan["errors"]:
        plan["creates"] = []
    plan["summary"] = {
        "hosted_on_created": len(plan["creates"]),
        "hosted_on_preserved": len(plan["preserved"]),
    }
    return plan
