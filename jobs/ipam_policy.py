"""Explicit operator policy for IPv4 Namespace selection and VRF identity."""

import ipaddress
import re


def _lines(value, label):
    if not isinstance(value, str):
        raise ValueError("%s must be text" % label)
    return [item for item in re.split(r"[\s,]+", value.strip()) if item]


def normalize_ipam_policy(
    default_namespace,
    override_namespace=None,
    *,
    override_rfc1918=True,
    override_networks="",
    create_missing_prefixes=True,
    group_user_vrfs=False,
    local_vrf_names="Mgmt-vrf",
    location=None,
    location_reason=None,
):
    """Normalize form inputs without fetching or writing inventory.

    Selecting a default Namespace enables IPAM. Address classification is
    explicit organizational policy, independent of NTC switchport guessing.
    """
    for value, label in (
        (override_rfc1918, "Use override for RFC1918"),
        (create_missing_prefixes, "Create missing networks"),
        (group_user_vrfs, "Group matching user VRF names across devices"),
    ):
        if type(value) is not bool:
            raise ValueError("%s must be true or false" % label)
    networks = []
    for item in _lines(override_networks, "Additional override networks"):
        if "/" not in item:
            raise ValueError("Additional override networks require an explicit CIDR mask")
        try:
            network = ipaddress.IPv4Network(item, strict=True)
        except ValueError:
            raise ValueError(
                "Additional override networks require valid IPv4 network CIDRs"
            ) from None
        if str(network) not in networks:
            networks.append(str(network))
    local_names = sorted(set(_lines(local_vrf_names, "Device-local VRF names")))
    if default_namespace is None:
        if override_namespace is not None or networks or group_user_vrfs:
            raise ValueError("Select a default Namespace before configuring IPAM overrides")
        return None
    if networks and override_namespace is None:
        raise ValueError("Select an override Namespace for additional override networks")

    def namespace(value):
        if value is None:
            return None
        if getattr(value, "pk", None) is None or not isinstance(getattr(value, "name", None), str):
            raise ValueError("IPAM Namespace selections must be existing named objects")
        return {"id": str(value.pk), "name": value.name}

    return {
        "default_namespace": namespace(default_namespace),
        "override_namespace": namespace(override_namespace),
        "override_rfc1918": override_rfc1918,
        "override_networks": sorted(networks),
        "create_missing_prefixes": create_missing_prefixes,
        "group_user_vrfs": group_user_vrfs,
        "local_vrf_names": local_names,
        "location": location,
        "location_reason": location_reason,
    }
