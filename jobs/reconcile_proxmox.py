"""Reconstruct Proxmox source facts before planning native host writes."""

from .adapters import proxmox
from .reconcile_esxi import UNSUPPORTED_DOMAINS


def prepare_proxmox(discovery):
    """Allow only the reviewed host and explicit Hosted On write contracts."""
    errors = [
        "Proxmox schema v1 does not support %s inventory" % key
        for key in UNSUPPORTED_DOMAINS
        if discovery.get(key) is not None
    ]
    try:
        rebuilt = proxmox.reconstruct(discovery)
    except (ValueError, RuntimeError, TypeError, KeyError):
        rebuilt = {
            "adapter": "proxmox",
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
        }
        errors.append("Proxmox source contract failed validation")
    if discovery.get("guest_policy") is not None:
        rebuilt["guest_policy"] = discovery["guest_policy"]
    return rebuilt, errors


def validate_proxmox_identity(discovery, device, plan):
    """Verify the selected hardware and the optional explicit BIOS UUID binding."""
    driver = str(device.get("platform_network_driver") or "").lower()
    name = str(device.get("platform_name") or "").lower()
    name = name.replace("-", "").replace("_", "").replace(" ", "")
    if driver not in ("proxmox", "proxmox_ve") and not (
        not driver and name in ("proxmox", "proxmoxve")
    ):
        plan["errors"].append("The selected Device must have a Proxmox platform")
    identity = discovery["identity"]
    observed_vendor = identity.get("vendor")
    selected_vendor = device.get("manufacturer_name")
    if (
        observed_vendor
        and selected_vendor
        and observed_vendor.strip().casefold() != str(selected_vendor).strip().casefold()
    ):
        plan["errors"].append("Selected Device manufacturer differs from the Proxmox host hardware")
    binding = discovery.get("identity_binding")
    if binding is None:
        return False
    valid = (
        isinstance(binding, dict)
        and binding.get("contract") == "proxmox-host-identity-v1"
        and proxmox.canonical_host_uuid(binding.get("expected_uuid")) is not None
        and binding.get("expected_uuid")
        == binding.get("observed_uuid")
        == identity.get("host_uuid")
        and binding.get("node") == identity.get("hostname")
    )
    if not valid:
        plan["errors"].append("Proxmox host UUID binding failed validation")
        return False
    plan["identity_binding"] = dict(binding)
    return True
