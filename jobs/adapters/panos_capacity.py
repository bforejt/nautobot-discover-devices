"""Palo-only structured capacity observations; unsupported quantities stay unknown."""

import re

from ..transport_ssh import SYSTEM_INFO

CONTRACT = "panos-capacity-v1"
FIELDS = ("vcpus", "memory_mb", "disk_gb")


def _positive(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,10}", value) is None:
        return None
    number = int(value)
    return number if 0 < number <= 2**31 - 1 else None


def parse_capacity(discovery):
    """Use exact system-info scalars; never infer allocation from a VM profile."""
    identity = discovery.get("identity", {})
    observations = discovery.get("observations", {})
    system = observations.get("system", {})
    sources = discovery.get("sources", {})
    if (
        discovery.get("adapter") != "panos"
        or discovery.get("schema_version") != 1
        or sources.get("identity") != {"command": SYSTEM_INFO, "path": "result/system"}
    ):
        raise ValueError("PAN-OS capacity requires reviewed system-info provenance")
    fields, unresolved = {}, []
    vm_series = identity.get("model") == "PA-VM" and system.get("family") == "vm"
    cores = _positive(system.get("vm-cores")) if vm_series else None
    if cores is not None:
        fields["vcpus"] = {
            "value": cores,
            "source": {
                "command": SYSTEM_INFO,
                "path": "result/system/vm-cores",
                "raw_value": system["vm-cores"],
                "unit": "count",
            },
        }
    else:
        unresolved.append(
            {
                "field": "vcpus",
                "reason": "Palo system-info does not establish an explicit positive "
                "VM-Series core count",
            }
        )
    unresolved.extend(
        [
            {
                "field": "memory_mb",
                "reason": "Palo vm-mem has no verified unit or whole-MiB capacity mapping",
                "source": {"command": SYSTEM_INFO, "path": "result/system/vm-mem"},
                "raw_value": system.get("vm-mem"),
            },
            {
                "field": "disk_gb",
                "reason": "No reviewed Palo structured response establishes primary-disk capacity",
            },
        ]
    )
    return {
        "contract": CONTRACT,
        "scope": "vm-series" if vm_series else "unsupported",
        "fields": fields,
        "unresolved": unresolved,
    }


def validate_capacity(discovery, capacity):
    """Recompute facts from independent Palo source evidence before planning any write."""
    try:
        return (
            isinstance(capacity, dict)
            and capacity == parse_capacity(discovery)
            and all(type(row["value"]) is int for row in capacity["fields"].values())
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
