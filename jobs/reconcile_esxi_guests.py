"""Fill-only Hosted On links from explicit Device selections and ESXi BIOS UUIDs."""

from collections import defaultdict
from copy import deepcopy

from .adapters import esxi
from .esxi_guest_policy import CONTRACT as POLICY_CONTRACT
from .esxi_guest_policy import RELATIONSHIP_KEY, canonical_uuid

CONTRACT = "esxi-hosted-on-v1"
RELATIONSHIP_FIELDS = ("id", "key", "type", "source_type", "destination_type")


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


def plan_esxi_guests(discovery, existing, *, identity_verified=False):
    """Plan only additions; guest names, MORs and instance UUIDs never select Devices."""
    plan = {
        "contract": CONTRACT,
        "policy": None,
        "relationship": None,
        "creates": [],
        "preserved": [],
        "errors": [],
        "conflicts": [],
        "warnings": [],
        "summary": {"hosted_on_created": 0, "hosted_on_preserved": 0},
    }
    policy = discovery.get("guest_policy")
    if discovery.get("adapter") != "esxi" or policy is None:
        return plan
    host_id = str(existing.get("device", {}).get("id") or "")
    if not validated_policy(policy, host_id):
        plan["errors"].append("ESXi Hosted On policy does not match the selected existing Devices")
        return plan
    plan["policy"] = deepcopy(policy)
    if identity_verified is not True:
        plan["errors"].append(
            "Verified selected ESXi host identity is required for Hosted On links"
        )
        return plan
    native = existing.get("esxi_guest_inventory")
    if not isinstance(native, dict) or native.get("supported") is not True:
        plan["errors"].append("Native Hosted On capability is unavailable")
        return plan
    relationship = native.get("relationship")
    if not relationship_matches(relationship, policy):
        plan["errors"].append("The selected Hosted On relationship changed identity or scope")
        return plan
    plan["relationship"] = deepcopy(relationship)
    try:
        reconstructed = esxi.reconstruct(discovery)
    except (esxi.DiscoveryError, ValueError, TypeError, KeyError):
        plan["errors"].append("ESXi Hosted On source provenance is invalid")
        return plan
    inventory = reconstructed["source"]["inventory"]
    host = inventory["host"]
    host_refs = defaultdict(int)
    for row in host["properties"].get("vm", []):
        if isinstance(row, dict) and row.get("type") == "VirtualMachine":
            host_refs[row.get("ref")] += 1
    by_uuid, by_ref = defaultdict(list), defaultdict(list)
    for row in inventory["guests"]:
        by_ref[row["ref"]].append(row)
        vm_id = esxi.canonical_host_uuid(row["properties"].get("config.uuid"))
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
            plan["errors"].append("An explicitly mapped ESXi guest Device is missing or ambiguous")
            continue
        rows = by_uuid[vm_id]
        if len(rows) != 1:
            plan["errors"].append("A mapped ESXi guest BIOS UUID is unobserved or ambiguous")
            continue
        guest = rows[0]
        properties = guest["properties"]
        if (
            len(by_ref[guest["ref"]]) != 1
            or host_refs[guest["ref"]] != 1
            or properties.get("runtime.host") != {"type": "HostSystem", "ref": host["ref"]}
        ):
            plan["errors"].append("A mapped ESXi guest is not uniquely registered on this host")
            continue
        if properties.get("config.template") is not False:
            plan["errors"].append(
                "A mapped ESXi guest is a template or lacks explicit guest status"
            )
            continue
        if properties.get("runtime.connectionState") != "connected":
            plan["errors"].append("A mapped ESXi guest does not have a connected inventory state")
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
                    "scope": "esxi_guest",
                    "name": mapping["device"].get("name"),
                    "field": "hosted_on",
                    "before": deepcopy(found),
                    "observed": observed,
                }
            )
            plan["errors"].append("A mapped guest already has conflicting Hosted On ownership")
            continue
        plan["creates"].append({**observed, "vm_uuid": vm_id})
    if plan["errors"]:
        plan["creates"] = []
    plan["summary"] = {
        "hosted_on_created": len(plan["creates"]),
        "hosted_on_preserved": len(plan["preserved"]),
    }
    return plan
