"""Reviewed physical capabilities; negotiated speed never identifies port type."""

import re
from copy import deepcopy

from .cisco_hardware_profiles import chassis_profile, port_capability


def interface_capability(name, model, member, inventory):
    """Classify an observed port using its chassis and a unique installed module."""
    capability = port_capability(name, model, member)
    if capability is not None:
        return capability
    if chassis_profile(model) is None:
        return None
    # The hardware source lacks an independent slot leaf. A unique PIM within
    # this physical owner's inventory is required; ordering bundles and port
    # prefixes alone do not prove which network module is installed.
    modules = [
        row
        for row in inventory
        if isinstance(row, dict) and str(row.get("hw-type", "")).split(":")[-1] == "hw-type-pim"
    ]
    if len(modules) != 1:
        return None
    part = modules[0].get("part-number")
    if not isinstance(part, str):
        return None
    capability = port_capability(name, model, member, part.strip())
    if capability is None:
        return None
    return {
        **capability,
        "installed_module": {
            "part_number": part.strip(),
            "serial": deepcopy(modules[0].get("serial-number")),
            "name": deepcopy(modules[0].get("dev-name")),
            "identity_module": "Cisco-IOS-XE-device-hardware-oper",
            "identity_field": "device-hardware/device-inventory",
            "rule": "Unique network-module identity in the physical owner's inventory",
        },
    }


def interface_type(name, model, member, inventory):
    """Return (Nautobot type, evidence description) or (None, review reason)."""
    if re.fullmatch(r"(?:Vlan|Loopback|Tunnel)\d+(?:\.\d+)?", name):
        return "virtual", "IOS XE logical interface family"
    if re.fullmatch(r"Port-channel\d+", name):
        return "lag", "IOS XE Port-channel family"
    capability = interface_capability(name, model, member, inventory)
    if capability is not None:
        return capability["type"], capability["description"]
    profile = chassis_profile(model)
    if profile is None:
        return None, "No reviewed hardware mapping for this chassis"
    reason = (
        profile.get("deferred_reason") or "No reviewed physical capability mapping for this port"
    )
    return None, reason
