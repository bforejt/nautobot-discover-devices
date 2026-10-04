"""Exact Cisco chassis/module capabilities backed by published hardware profiles.

Profiles classify observed interfaces. They never synthesize ports, infer an
installed module from an ordering bundle, or use link speed to identify a cage.
"""

import re
from copy import deepcopy

from . import cisco_c9300_profiles, cisco_c9500_profiles

CHASSIS_PROFILES = {
    **cisco_c9300_profiles.CHASSIS_PROFILES,
    **cisco_c9500_profiles.CHASSIS_PROFILES,
}
NETWORK_MODULE_PROFILES = {
    **cisco_c9300_profiles.NETWORK_MODULE_PROFILES,
    **cisco_c9500_profiles.NETWORK_MODULE_PROFILES,
}


def chassis_profile(model):
    """Return only an exact documented PID, with independent consumer state."""
    if not isinstance(model, str) or model not in CHASSIS_PROFILES:
        return None
    return {**deepcopy(CHASSIS_PROFILES[model]), "model": model}


def module_profile(chassis_model, module_pid):
    """Compatibility is explicit; a bundle PID never establishes module presence."""
    chassis = chassis_profile(chassis_model)
    if chassis is None or module_pid not in chassis.get("network_modules", ()):
        return None
    module = NETWORK_MODULE_PROFILES.get(module_pid)
    if module is None:
        return None
    resolved = {**deepcopy(module), "model": module_pid, "chassis_model": chassis_model}
    override = chassis.get("network_module_ports", {}).get(module_pid)
    if override is not None:
        resolved["ports"] = deepcopy(override)
    return resolved


def _matches(name, region, member):
    if "name" in region:
        return name == region["name"]
    match = re.fullmatch(r"([A-Za-z][A-Za-z-]*)(\d+)/(\d+)/(\d+)", name)
    return bool(
        match
        and match.group(1) in region["families"]
        and int(match.group(2)) == member
        and int(match.group(3)) == region["slot"]
        and region["first"] <= int(match.group(4)) <= region["last"]
    )


def port_capability(name, chassis_model, member, module_pid=None):
    """Resolve an exact physical name against one documented region.

    The optional module PID must be independently established by the caller.
    Breakout children, subinterfaces, unsupported aliases and ambiguous regions
    cannot identify a physical capability here.
    """
    if not isinstance(name, str) or type(member) is not int or not 1 <= member <= 255:
        return None
    chassis = chassis_profile(chassis_model)
    if chassis is None:
        return None
    if module_pid is None:
        profile = chassis
        regions = list(chassis.get("fixed_ports", ()))
        if chassis.get("management"):
            regions.append(chassis["management"])
    else:
        profile = module_profile(chassis_model, module_pid)
        if profile is None:
            return None
        regions = list(profile.get("ports", ()))
    matches = [region for region in regions if _matches(name, region, member)]
    if len(matches) != 1:
        return None
    return {
        # Catalog tuples remain immutable; report facts use JSON-native arrays.
        **{
            key: list(value) if isinstance(value, tuple) else deepcopy(value)
            for key, value in matches[0].items()
        },
        "profile": profile["profile"],
        "model": chassis_model,
        "module_pid": module_pid,
        "documents": list(
            dict.fromkeys((*profile.get("documents", ()), *matches[0].get("documents", ())))
        ),
    }
