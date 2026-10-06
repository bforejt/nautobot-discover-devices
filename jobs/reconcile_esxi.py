"""Reconstruct ESXi host facts and preserve operator inventory intent."""

from .adapters import esxi
from .esxi_guest_policy import canonical_uuid

UNSUPPORTED_DOMAINS = (
    "stack",
    "components",
    "console_ports",
    "layer2",
    "lag_memberships",
    "ipam",
    "logical_interfaces",
    "management",
    "ha_pair",
    "vpn_policy",
    "capacity",
    "ha",
    "vpn",
    "route_targets",
)


def prepare_esxi(discovery):
    """Never allow supplied normalized fields to outrun their reviewed source."""
    errors = [
        "ESXi schema v1 does not support %s inventory" % key
        for key in UNSUPPORTED_DOMAINS
        if discovery.get(key) is not None
    ]
    try:
        rebuilt = esxi.reconstruct(discovery)
    except (ValueError, RuntimeError, TypeError, KeyError):
        rebuilt = {
            "adapter": "esxi",
            "schema_version": 1,
            "identity": {
                key: None
                for key in (
                    "hostname",
                    "model",
                    "serial",
                    "software_version",
                    "vendor",
                    "host_uuid",
                )
            },
            "interfaces": [],
            "warnings": [],
            "excluded_interfaces": [],
            "identity_binding": None,
            "interface_policy": None,
        }
        errors.append("ESXi source contract failed validation")
    # Guest mappings are explicit operator policy, validated independently by
    # their planner and by the native relationship boundary.
    if discovery.get("guest_policy") is not None:
        rebuilt["guest_policy"] = discovery["guest_policy"]
    return rebuilt, errors


def validate_esxi_identity(discovery, device, plan):
    """A host BIOS UUID binding permits an unavailable serial to remain blank."""
    driver = str(device.get("platform_network_driver") or "").lower()
    name = str(device.get("platform_name") or "").lower()
    name = name.replace("-", "").replace("_", "").replace(" ", "")
    if driver not in ("esxi", "vmware_esxi") and not (
        not driver and name in ("esxi", "vmwareesxi")
    ):
        plan["errors"].append("The selected Device must have an ESXi platform")
    identity = discovery["identity"]
    observed_vendor = identity.get("vendor")
    selected_vendor = device.get("manufacturer_name")
    if (
        observed_vendor
        and selected_vendor
        and observed_vendor.strip().casefold() != (str(selected_vendor).strip().casefold())
    ):
        plan["errors"].append("Selected Device manufacturer differs from the ESXi host hardware")
    binding = discovery.get("identity_binding")
    if binding is None:
        return False
    valid = (
        isinstance(binding, dict)
        and binding.get("contract") == "esxi-host-identity-v1"
        and binding.get("property") == "hardware.systemInfo.uuid"
        and canonical_uuid(binding.get("expected_uuid")) is not None
        and binding.get("expected_uuid")
        == binding.get("observed_uuid")
        == identity.get("host_uuid")
        and binding.get("host_ref") == discovery["source"]["inventory"]["host"]["ref"]
    )
    if not valid:
        plan["errors"].append("ESXi host UUID binding failed validation")
        return False
    plan["identity_binding"] = dict(binding)
    return True


def esxi_new_interface_policy(discovery, values, name, plan):
    """Apply explicit intent only to a newly created native interface."""
    policy = discovery.get("interface_policy")
    if policy is None:
        return None
    if (
        not isinstance(policy, dict)
        or set(policy) != {"contract", "new_enabled"}
        or (
            policy.get("contract") != "esxi-interface-policy-v1"
            or type(policy.get("new_enabled")) is not bool
            or values.get("enabled") is not None
        )
    ):
        plan["errors"].append("ESXi new-interface inventory policy failed validation")
        return None
    values["enabled"] = policy["new_enabled"]
    source = {"contract": policy["contract"], "new_enabled": policy["new_enabled"]}
    plan["warnings"].append(
        "%s: new enabled state comes from explicit inventory policy; ESXi admin state is unknown"
        % name
    )
    return source
