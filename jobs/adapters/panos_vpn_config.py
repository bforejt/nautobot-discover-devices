"""Allowlisted applied VPN configuration observations, independent of VPN runtime.

The successful network ancestor distinguishes absent VPN configuration from a
failed scoped read. Authentication and unrelated network branches are never
copied, serialized, or included in diagnostics. No device defaults are inferred.
"""

import re
from ipaddress import ip_interface, ip_network

from ..transport_ssh import RUNNING_VPN
from .panos import DiscoveryError, _container, _one, _result, _text

_SOURCES = {
    "ike_gateways": "ike/gateway",
    "ipsec_tunnels": "tunnel/ipsec",
    "ike_crypto_profiles": "ike/crypto-profiles/ike-crypto-profiles",
    "ipsec_crypto_profiles": "ike/crypto-profiles/ipsec-crypto-profiles",
}
_ERROR_TAGS = {"error", "errors", "errmsg", "error-message", "msg"}


def _semantic_errors(element, *, recursive=False):
    """Reject semantic errors without reading or reporting their contents.

    Ancestors check their own status and direct error markers; discarded sibling
    branches are outside VPN evidence. Approved collections check every child,
    including unsupported fields that would otherwise be omitted from facts.
    """
    nodes = element.iter() if recursive else (element, *element)
    for node in nodes:
        tag = node.tag.rsplit("}", 1)[-1].casefold()
        failed_status = (recursive or node is element) and any(
            key.rsplit("}", 1)[-1].casefold() == "status" and value.casefold() == "error"
            for key, value in node.attrib.items()
        )
        if tag in _ERROR_TAGS or failed_status:
            raise DiscoveryError("PAN-OS VPN configuration contains an embedded error")


def _branch(element, path):
    """Check each parent so a duplicated intermediate container cannot be hidden."""
    for part in path.split("/"):
        element = _one(element, part)
        if element is None:
            return None
        _semantic_errors(element)
        _container(element)
    return element


def _string(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise DiscoveryError("PAN-OS VPN configuration contains an invalid identifier")
    return value.strip()


def _scalar(element, path):
    if "/" in path:
        parent, path = path.rsplit("/", 1)
        element = _branch(element, parent)
        if element is None:
            return None
    if _one(element, path) is None:
        return None
    return _string(_text(element, path))


def _boolean(element, path):
    value = _scalar(element, path)
    if value is None:
        return None
    if value not in {"yes", "no"}:
        raise DiscoveryError("PAN-OS VPN configuration contains an invalid boolean")
    return value == "yes"


def _number(element, path, *, maximum=(1 << 64) - 1):
    value = _scalar(element, path)
    if value is None:
        return None
    if len(value) > 20 or re.fullmatch(r"[0-9]+", value) is None:
        raise DiscoveryError("PAN-OS VPN configuration contains an invalid integer")
    number = int(value)
    if number > maximum:
        raise DiscoveryError("PAN-OS VPN configuration contains an invalid integer")
    return number


def _address(element, path, *, version=None, network=False):
    value = _scalar(element, path)
    if value is None:
        return None
    try:
        parsed = ip_network(value, strict=False) if network else ip_interface(value)
    except ValueError:
        raise DiscoveryError("PAN-OS VPN configuration contains an invalid IP address") from None
    if version is not None and parsed.version != version:
        raise DiscoveryError("PAN-OS VPN selector has an unexpected address family")
    # Keep the literal configuration, including its prefix and spelling.
    return value


def _entries(container):
    if container is None:
        return []
    _semantic_errors(container, recursive=True)
    _container(container)
    if any(child.tag != "entry" for child in container):
        raise DiscoveryError("PAN-OS VPN collection contains an unexpected structure")
    rows = []
    names = set()
    for entry in container:
        _container(entry)
        name = _string(entry.get("name"))
        if name in names:
            raise DiscoveryError("PAN-OS VPN collection contains duplicate names")
        names.add(name)
        rows.append((name, entry))
    return rows


def _members(element, path):
    container = _branch(element, path)
    if container is None:
        return None
    if any(child.tag != "member" or len(child) for child in container):
        raise DiscoveryError("PAN-OS VPN algorithm list contains an unexpected structure")
    return [_string(child.text) for child in container]


def _units(element, path, units):
    container = _branch(element, path)
    if container is None:
        return None
    values = {unit: _number(container, unit) for unit in units}
    if sum(value is not None for value in values.values()) > 1:
        raise DiscoveryError("PAN-OS VPN lifetime contains conflicting units")
    return values


def _local_address(element):
    local = _branch(element, "local-address")
    if local is None:
        return {"interface": None, "ip": None, "floating_ip": None}
    result = {
        "interface": _scalar(local, "interface"),
        "ip": _address(local, "ip"),
        "floating_ip": _address(local, "floating-ip"),
    }
    if result["ip"] is not None and result["floating_ip"] is not None:
        raise DiscoveryError("PAN-OS VPN local address contains conflicting choices")
    return result


def _peer_address(element):
    peer = _branch(element, "peer-address")
    result = {"kind": None, "ip": None, "fqdn": None, "dynamic": None}
    if peer is None:
        return result
    choices = [name for name in ("ip", "fqdn", "dynamic") if _one(peer, name) is not None]
    if len(choices) > 1:
        raise DiscoveryError("PAN-OS VPN peer address contains conflicting choices")
    if not choices:
        result["kind"] = "unknown" if len(peer) else None
    elif choices[0] == "dynamic":
        dynamic = _one(peer, "dynamic")
        _container(dynamic)
        if len(dynamic):
            raise DiscoveryError("PAN-OS VPN dynamic peer contains unexpected structure")
        result.update(kind="dynamic", dynamic=True)
    elif choices[0] == "ip":
        result.update(kind="ip", ip=_address(peer, "ip"))
    else:
        # Configuration only: never resolve or infer an operational peer address.
        result.update(kind="fqdn", fqdn=_scalar(peer, "fqdn"))
    return result


def _selector_protocol(element):
    protocol = _branch(element, "protocol")
    result = {"kind": None, "number": None, "local_port": None, "remote_port": None}
    if protocol is None:
        return result
    choices = [name for name in ("any", "number", "tcp", "udp") if _one(protocol, name) is not None]
    if len(choices) > 1:
        raise DiscoveryError("PAN-OS VPN selector protocol contains conflicting choices")
    if not choices:
        result["kind"] = "unknown" if len(protocol) else None
        return result
    result["kind"] = choices[0]
    if choices[0] == "number":
        result["number"] = _number(protocol, "number", maximum=255)
    else:
        node = _branch(protocol, choices[0])
        if choices[0] == "any":
            if len(node):
                raise DiscoveryError("PAN-OS VPN any protocol contains unexpected structure")
        else:
            result["local_port"] = _number(node, "local-port", maximum=65535)
            result["remote_port"] = _number(node, "remote-port", maximum=65535)
    return result


def _selectors(element, path, version):
    container = _branch(element, path)
    if container is None:
        return None
    return [
        {
            "name": name,
            "local": _address(entry, "local", version=version, network=True),
            "remote": _address(entry, "remote", version=version, network=True),
            "protocol": _selector_protocol(entry),
        }
        for name, entry in _entries(container)
    ]


def _gateways(container):
    return [
        {
            "name": name,
            "disabled": _boolean(entry, "disabled"),
            "local_address": _local_address(entry),
            "peer_address": _peer_address(entry),
            "protocol": {
                "version": _scalar(entry, "protocol/version"),
                "ikev1_profile": _scalar(entry, "protocol/ikev1/ike-crypto-profile"),
                "ikev2_profile": _scalar(entry, "protocol/ikev2/ike-crypto-profile"),
            },
        }
        for name, entry in _entries(container)
    ]


def _manual_key(element):
    protocol = [name for name in ("esp", "ah") if _branch(element, name) is not None]
    if len(protocol) > 1:
        raise DiscoveryError("PAN-OS manual VPN contains conflicting protocol choices")
    result = {
        "local_address": _local_address(element),
        "peer_address": _peer_address(element),
        "local_spi": _scalar(element, "local-spi"),
        "remote_spi": _scalar(element, "remote-spi"),
        "protocol": protocol[0] if protocol else None,
    }
    for key in ("local_spi", "remote_spi"):
        value = result[key]
        if value is not None and re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,8}", value) is None:
            raise DiscoveryError("PAN-OS manual VPN contains an invalid SPI")
    return result


def _tunnels(container):
    rows = []
    for name, entry in _entries(container):
        auto = _branch(entry, "auto-key")
        manual = _branch(entry, "manual-key")
        satellite = _branch(entry, "global-protect-satellite")
        if sum(node is not None for node in (auto, manual, satellite)) > 1:
            raise DiscoveryError("PAN-OS IPsec tunnel contains conflicting key modes")
        mode = "auto-key" if auto is not None else "manual-key" if manual is not None else "unknown"
        auto_fact = None
        if auto is not None:
            gateways = _branch(auto, "ike-gateway")
            auto_fact = {
                "ike_gateways": (
                    [gateway for gateway, _ in _entries(gateways)] if gateways is not None else None
                ),
                "crypto_profile": _scalar(auto, "ipsec-crypto-profile"),
                "selectors_ipv4": _selectors(auto, "proxy-id", 4),
                "selectors_ipv6": _selectors(auto, "proxy-id-v6", 6),
            }
        rows.append(
            {
                "name": name,
                "mode": mode,
                "mode_observed": mode
                if mode != "unknown"
                else ("global-protect-satellite" if satellite is not None else None),
                "tunnel_interface": _scalar(entry, "tunnel-interface"),
                "disabled": _boolean(entry, "disabled"),
                "auto_key": auto_fact,
                "manual_key": _manual_key(manual) if manual is not None else None,
                "monitor": {
                    "enabled": _boolean(entry, "tunnel-monitor/enable"),
                    "destination_ip": _address(entry, "tunnel-monitor/destination-ip"),
                    "profile": _scalar(entry, "tunnel-monitor/tunnel-monitor-profile"),
                    "proxy_id": _scalar(entry, "tunnel-monitor/proxy-id"),
                },
            }
        )
    return rows


def _ike_profiles(container):
    return [
        {
            "name": name,
            "encryption": _members(entry, "encryption"),
            "hash": _members(entry, "hash"),
            "dh_groups": _members(entry, "dh-group"),
            "lifetime": _units(entry, "lifetime", ("seconds", "minutes", "hours", "days")),
        }
        for name, entry in _entries(container)
    ]


def _ipsec_profiles(container):
    return [
        {
            "name": name,
            "esp": {
                "encryption": _members(entry, "esp/encryption"),
                "authentication": _members(entry, "esp/authentication"),
            },
            "ah": {"authentication": _members(entry, "ah/authentication")},
            "dh_group": _scalar(entry, "dh-group"),
            "lifetime": _units(entry, "lifetime", ("seconds", "minutes", "hours", "days")),
            "lifesize": _units(entry, "lifesize", ("kb", "mb", "gb", "tb")),
        }
        for name, entry in _entries(container)
    ]


def parse_vpn_configuration(output, command=RUNNING_VPN):
    """Parse a complete applied network ancestor into safe configured facts only."""
    if command != RUNNING_VPN:
        raise DiscoveryError("PAN-OS VPN configuration requires the reviewed network read")
    result = _result(output, command)
    _semantic_errors(result)
    network = _one(result, "network", required=True)
    if len(result) != 1:
        raise DiscoveryError("PAN-OS VPN configuration has an unexpected result structure")
    _semantic_errors(network)
    _container(network)
    containers = {name: _branch(network, path) for name, path in _SOURCES.items()}
    return {
        "contract": "panos-vpn-config-v1",
        "sources": {
            name: {
                "command": command,
                "path": "result/network/" + path,
                "present": containers[name] is not None,
            }
            for name, path in _SOURCES.items()
        },
        "ike_gateways": _gateways(containers["ike_gateways"]),
        "ipsec_tunnels": _tunnels(containers["ipsec_tunnels"]),
        "ike_crypto_profiles": _ike_profiles(containers["ike_crypto_profiles"]),
        "ipsec_crypto_profiles": _ipsec_profiles(containers["ipsec_crypto_profiles"]),
    }
