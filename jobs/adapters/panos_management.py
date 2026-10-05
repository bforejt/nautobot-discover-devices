"""Dedicated management facts from Palo operational and applied XML only."""

import re
import xml.etree.ElementTree as ET
from ipaddress import ip_interface

from ..transport_ssh import MANAGEMENT_INTERFACE, RUNNING_HA
from .panos import DiscoveryError, _one, _result, _text
from .panos_vpn_config import _branch, _semantic_errors

CONTRACT = "panos-management-v1"


def _scalar(element, path):
    if element is None:
        return None
    if "/" in path:
        parent, path = path.rsplit("/", 1)
        element = _branch(element, parent)
        if element is None:
            return None
    node = _one(element, path)
    if node is not None:
        _semantic_errors(node, recursive=True)
    if node is not None and node.attrib:
        raise DiscoveryError("Management scalar has unsupported attributes")
    return _text(element, path)


def _address(host, mask, version):
    if host in (None, "", "unknown", "N/A", "0.0.0.0", "::"):
        return None
    try:
        value = ip_interface(host if "/" in host else "%s/%s" % (host, mask))
        if value.version != version or value.ip.is_multicast or value.ip.is_unspecified:
            raise ValueError
        if version == 6 and value.ip.is_link_local:
            return None
    except (TypeError, ValueError):
        raise DiscoveryError("Management address or mask is invalid") from None
    return str(value)


def parse_management(output, deviceconfig_output, system):
    """Allowlist scalars; applied deviceconfig may also contain secrets."""
    result = _result(output, MANAGEMENT_INTERFACE)
    info = _one(result, "info", required=True)
    _semantic_errors(info, recursive=True)
    config = _one(_result(deviceconfig_output, RUNNING_HA), "deviceconfig", required=True)
    applied = _branch(config, "system")
    if applied is not None:
        _semantic_errors(applied)
    fields = (
        "name",
        "state_c",
        "state",
        "hwaddr",
        "ip",
        "ip-type",
        "netmask",
        "gw",
        "ipv6",
        "ip6-type",
        "ipv6ll",
        "ipv6gw",
        "speed",
        "duplex",
    )
    observed = {key: _scalar(info, key) for key in fields}
    if any(_one(info, key) is not None and _one(info, key).attrib for key in fields):
        raise DiscoveryError("Management scalar has unsupported attributes")
    name = observed["name"]
    if not name or name != name.strip() or any(ord(c) < 32 for c in name):
        raise DiscoveryError("Management interface has no unambiguous name")
    mac = observed["hwaddr"]
    if mac is not None:
        mac = mac.lower()
        if (
            not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
            or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
            or int(mac[:2], 16) & 1
        ):
            mac = None
    # An up runtime link positively establishes that this interface is enabled.
    # A down runtime link alone cannot distinguish a disabled port from no carrier.
    enabled = (
        False
        if observed["state_c"] == "down"
        else (
            True
            if observed["state_c"] == "up"
            or (observed["state_c"] == "auto" and observed["state"] == "up")
            else None
        )
    )
    applied_fields = {
        key: _scalar(applied, key) for key in ("mtu", "ip-address", "netmask", "ipv6-address")
    }
    dhcp = _branch(applied, "type/dhcp-client") if applied is not None else None
    if dhcp is not None:
        _semantic_errors(dhcp, recursive=True)
        if dhcp.attrib:
            raise DiscoveryError("Management addressing mode has unsupported attributes")
    applied_fields["dhcp_client_present"] = dhcp is not None
    mtu_raw = applied_fields["mtu"]
    mtu = (
        int(mtu_raw)
        if mtu_raw and len(mtu_raw) <= 4 and mtu_raw.isdecimal() and 576 <= int(mtu_raw) <= 1500
        else None
    )
    addresses, unresolved = [], []
    for version, host_key, mode_key, mask_key, config_key in (
        (4, "ip", "ip-type", "netmask", "ip-address"),
        (6, "ipv6", "ip6-type", None, "ipv6-address"),
    ):
        literal = _address(observed[host_key], observed.get(mask_key), version)
        mode = observed[mode_key]
        if literal is None:
            continue
        configured = applied_fields[config_key]
        config_mask = applied_fields["netmask"] if version == 4 else None
        reviewed = (
            mode == "static"
            and (version != 4 or dhcp is None)
            and configured is not None
            and (_address(configured, config_mask, version) == literal)
        )
        if mode == "dhcp-client" and version == 4:
            reviewed = dhcp is not None
        if not reviewed:
            unresolved.append(
                {
                    "scope": "management_address",
                    "name": literal,
                    "reason": "Operational address lacks matching applied addressing mode",
                }
            )
            continue
        addresses.append(
            {
                "address": literal,
                "version": version,
                "method": mode,
                "source": {
                    "command": MANAGEMENT_INTERFACE,
                    "path": "result/info/" + host_key,
                    "applied_command": RUNNING_HA,
                    "applied_path": "result/deviceconfig/system/"
                    + ("type/dhcp-client" if mode == "dhcp-client" else config_key),
                    "host": observed[host_key],
                    "mask": observed.get(mask_key),
                    "configured_host": configured,
                    "configured_mask": config_mask,
                    "applied_dhcp_client_present": dhcp is not None,
                },
            }
        )
    return {
        "contract": CONTRACT,
        "interface": {
            "name": name,
            "enabled": enabled,
            "mac_address": mac,
            "mtu": mtu,
            "type": "virtual" if system.get("model") == "PA-VM" else None,
            "source": {
                "command": MANAGEMENT_INTERFACE,
                "path": "result/info",
                "fields": observed,
                "applied_command": RUNNING_HA,
                "mtu": mtu_raw,
                "model": system.get("model"),
                "applied_fields": applied_fields,
                "applied_system_present": applied is not None,
            },
        },
        "addresses": addresses,
        "observations": observed,
        "unresolved": unresolved,
    }


def canonical_management(facts, model):
    """Rebuild only allowlisted evidence; no source payload or secret is retained."""
    source = facts["interface"]["source"]
    operational = ET.Element("response", status="success")
    info = ET.SubElement(ET.SubElement(operational, "result"), "info")
    for key, value in source["fields"].items():
        if value is not None:
            ET.SubElement(info, key).text = value
    configured = ET.Element("response", status="success")
    config = ET.SubElement(ET.SubElement(configured, "result"), "deviceconfig")
    evidence = source["applied_fields"]
    if source["applied_system_present"] is True:
        applied = ET.SubElement(config, "system")
        for key in ("mtu", "ip-address", "netmask", "ipv6-address"):
            if evidence[key] is not None:
                ET.SubElement(applied, key).text = evidence[key]
        if evidence["dhcp_client_present"] is True:
            ET.SubElement(ET.SubElement(applied, "type"), "dhcp-client")
    result = parse_management(
        ET.tostring(operational, encoding="unicode"),
        ET.tostring(configured, encoding="unicode"),
        {"model": model},
    )
    if result != facts:
        raise ValueError("Management facts differ from their allowlisted source evidence")
    return result


def normalize_management_policy(
    text, resolve, *, create_missing_prefixes=True, location=None, location_reason=None
):
    """An explicit Namespace and optional DHCP/primary intent; never choose from addresses."""
    import json

    from ..panos_ipam_policy import _object

    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        raise ValueError("PAN-OS management policy must be bounded JSON text")
    if type(create_missing_prefixes) is not bool:
        raise ValueError("Create missing networks must be a boolean")
    if not text.strip():
        return None
    try:
        raw = json.loads(text, object_pairs_hook=_object)
    except (TypeError, ValueError):
        raise ValueError("PAN-OS management policy must be a JSON object") from None
    if not isinstance(raw, dict) or raw.keys() - {"namespace", "include_dhcp", "fill_primary"}:
        raise ValueError("PAN-OS management policy has unsupported fields")
    if (
        not isinstance(raw.get("namespace"), str)
        or not raw["namespace"].strip()
        or raw["namespace"] != raw["namespace"].strip()
    ):
        raise ValueError("PAN-OS management policy requires an existing Namespace")
    for flag in ("include_dhcp", "fill_primary"):
        if type(raw.get(flag, False)) is not bool:
            raise ValueError("Management policy flags must be booleans")
    return {
        "contract": "panos-management-policy-v1",
        "namespace": resolve("namespace", raw["namespace"], None),
        "include_dhcp": raw.get("include_dhcp", False),
        "fill_primary": raw.get("fill_primary", False),
        "create_missing_prefixes": create_missing_prefixes,
        "location": location,
        "location_reason": location_reason,
    }
