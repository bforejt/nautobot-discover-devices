"""Applied PAN-OS addressing and routing scope, without native model assumptions.

Only literal host/prefix entries become address candidates. Dynamic, generated,
symbolic and incomplete addressing remains observation-only. Virtual-router and
vsys associations come from separate complete configured memberships; names do
not select a Nautobot Namespace/VRF. No configuration subtree is retained.
"""

import re
from ipaddress import ip_interface

from ..transport_ssh import RUNNING_VPN, RUNNING_VSYS
from .panos import DiscoveryError, _container, _one, _result
from .panos_vpn_config import _boolean, _branch, _scalar, _semantic_errors, _string

CONTRACT = "panos-ipam-v1"
VR_MEMBERSHIP_PATH = "result/network/virtual-router/entry/interface/member"
VSYS_INTERFACE_PATH = "result/vsys/entry/import/network/interface/member"
VSYS_ROUTER_PATH = "result/vsys/entry/import/network/virtual-router/member"
INTERFACE_PATHS = {
    "ethernet": "result/network/interface/ethernet/entry/layer3",
    "ethernet-subinterface": "result/network/interface/ethernet/entry/layer3/units/entry",
    "aggregate-ethernet": "result/network/interface/aggregate-ethernet/entry/layer3",
    "aggregate-subinterface": (
        "result/network/interface/aggregate-ethernet/entry/layer3/units/entry"
    ),
    "loopback": "result/network/interface/loopback/units/entry",
    "tunnel": "result/network/interface/tunnel/units/entry",
}
_ETHERNET = r"ethernet[0-9]+/[0-9]+(?:/[0-9]+)?"
_INTERFACE_IDENTITIES = {
    "ethernet": re.compile(_ETHERNET),
    "ethernet-subinterface": re.compile("(?P<parent>" + _ETHERNET + r")\.[0-9]+"),
    "aggregate-ethernet": re.compile(r"ae[0-9]+"),
    "aggregate-subinterface": re.compile(r"(?P<parent>ae[0-9]+)\.[0-9]+"),
    "loopback": re.compile(r"loopback\.[0-9]+"),
    "tunnel": re.compile(r"tunnel\.[0-9]+"),
}
_MODES = ("layer3", "layer2", "virtual-wire", "ha", "aggregate-group")
_DYNAMIC = {
    "ipv4_dhcp": "dhcp-client",
    "ipv4_pppoe": "pppoe",
    "ipv6_dhcp": "ipv6/dhcp-client",
    "ipv6_pppoe": "ipv6/pppoe",
    "ipv6_inherited": "ipv6/inherited",
}


def reviewed_interface_identity(row):
    """Recognize exact configured families and direct subinterface parent evidence.

    This validates an existing name; it does not rewrite aliases, establish
    physical capability, or impose unproven platform-specific numeric limits.
    Routing labels are separate opaque identifiers and never use this grammar.
    """
    if not isinstance(row, dict) or row.get("mode") != "layer3":
        return False
    kind = row.get("kind")
    if not isinstance(kind, str):
        return False
    pattern = _INTERFACE_IDENTITIES.get(kind)
    name, source = row.get("name"), row.get("source")
    if pattern is None or not isinstance(name, str) or not isinstance(source, dict):
        return False
    matched = pattern.fullmatch(name)
    if matched is None:
        return False
    parent = matched.groupdict().get("parent")
    return source.get("parent_name") == parent


def _source(command, path, configured_name=None, **fields):
    return {
        "contract": CONTRACT,
        "command": command,
        "path": path,
        "configured_name": configured_name,
        **fields,
    }


def _entries(container):
    """Validate identities without inspecting discarded sibling configuration."""
    if container is None:
        return []
    _semantic_errors(container)
    _container(container)
    if any(child.tag != "entry" for child in container):
        raise DiscoveryError("PAN-OS IPAM collection contains an unexpected structure")
    seen, rows = set(), []
    for entry in container:
        _semantic_errors(entry)
        _container(entry)
        if set(entry.attrib) != {"name"}:
            raise DiscoveryError("PAN-OS IPAM entry contains unsupported scope attributes")
        name = entry.get("name")
        _string(name)
        if name in seen:
            raise DiscoveryError("PAN-OS IPAM collection contains duplicate names")
        seen.add(name)
        rows.append((name, entry))
    return rows


def _members(element, path):
    container = _branch(element, path)
    if container is None:
        return [], False
    _semantic_errors(container, recursive=True)
    if container.attrib:
        raise DiscoveryError("PAN-OS IPAM membership contains unsupported scope attributes")
    if any(child.tag != "member" or child.attrib or len(child) for child in container):
        raise DiscoveryError("PAN-OS IPAM membership contains an unexpected structure")
    values = [_string(child.text) for child in container]
    if len(values) != len(set(values)):
        raise DiscoveryError("PAN-OS IPAM membership contains duplicate identifiers")
    return values, True


def _flag(element, path, source_path):
    node = _one(element, path)
    if node is not None and node.attrib:
        raise DiscoveryError("PAN-OS IPAM boolean contains unsupported scope attributes")
    return _boolean(element, path), {
        "path": source_path + "/" + path,
        "presence": "absent" if node is None else "value",
    }


def _marker(element, path, source_path):
    node = _one(element, path)
    if node is None:
        return None, {"path": source_path + "/" + path, "presence": "absent"}
    _semantic_errors(node, recursive=True)
    _container(node)
    if node.attrib or len(node):
        raise DiscoveryError("PAN-OS IPAM existence marker contains unsupported structure")
    return True, {"path": source_path + "/" + path, "presence": "marker"}


def _unresolved(rows, name, reason, source, **values):
    rows.append({"scope": "interface", "name": name, "reason": reason, "source": source, **values})


def _literal(value, version):
    # ip_interface supplies /32 or /128 when absent; that is not configured evidence.
    if "/" not in value or "%" in value:
        return None
    try:
        address = ip_interface(value)
    except ValueError:
        return None
    if address.version != version:
        raise DiscoveryError("PAN-OS IPAM literal address has the wrong address family")
    return {
        "address": value,
        "host": str(address.ip),
        "prefix_length": address.network.prefixlen,
        "network": str(address.network),
    }


def _addresses(body, name, path, version, unresolved):
    address_path = "ip" if version == 4 else "ipv6/address"
    collection = _branch(body, address_path)
    rows, hosts = [], set()
    for configured_name, entry in _entries(collection):
        _semantic_errors(entry, recursive=True)
        source_path = path + "/" + address_path + "/entry"
        source = _source(RUNNING_VPN, source_path, configured_name, interface=name, fields={})
        flags = {}
        if version == 6:
            for fact, field in (
                ("enable_on_interface", "enable-on-interface"),
                ("prefix", "prefix"),
                ("anycast", "anycast"),
            ):
                parser = _marker if fact in {"prefix", "anycast"} else _flag
                flags[fact], source["fields"][fact] = parser(entry, field, source_path)
            advertise = _branch(entry, "advertise")
            for fact, field in (("advertise_enabled", "enable"), ("onlink_flag", "onlink-flag")):
                if advertise is None:
                    flags[fact] = None
                    source["fields"][fact] = {
                        "path": source_path + "/advertise/" + field,
                        "presence": "absent",
                    }
                else:
                    flags[fact], source["fields"][fact] = _flag(
                        advertise, field, source_path + "/advertise"
                    )
        address = _literal(configured_name, version)
        if address is None:
            _unresolved(
                unresolved,
                name,
                "Address is not a literal host with an explicit prefix",
                source,
                configured_name=configured_name,
                family=version,
                **({"ipv6_flags": flags} if version == 6 else {}),
            )
            continue
        if address["host"] in hosts:
            raise DiscoveryError("PAN-OS IPAM interface contains overlapping address identities")
        hosts.add(address["host"])
        address.update(flags)
        address["source"] = source
        rows.append(address)
    return rows


def _addressing(body, name, path, unresolved):
    observations = {}
    for fact, branch_path in _DYNAMIC.items():
        node = _branch(body, branch_path)
        enabled = _boolean(node, "enable") if node is not None else None
        source = _source(RUNNING_VPN, path + "/" + branch_path, name)
        observations[fact] = {"present": node is not None, "enabled": enabled, "source": source}
        if node is not None and enabled is not False:
            _unresolved(
                unresolved,
                name,
                "Dynamic or generated addressing is observation-only",
                source,
                method=fact,
                enabled=enabled,
            )
        if node is not None and fact == "ipv4_pppoe":
            static_ip = _scalar(node, "static-address/ip")
            if static_ip is not None:
                _unresolved(
                    unresolved,
                    name,
                    "PPPoE address has no reviewed configured prefix",
                    _source(RUNNING_VPN, source["path"] + "/static-address/ip", name),
                    configured_name=static_ip,
                    family=4,
                )
    return observations


def _interface(name, body, kind, parent_name, unresolved):
    _semantic_errors(body, recursive=True)
    _container(body)
    path = INTERFACE_PATHS[kind]
    source = {
        "contract": CONTRACT,
        "network_command": RUNNING_VPN,
        "path": path,
        "configured_name": name,
        "parent_name": parent_name,
        "fields": {},
        "vr_membership": None,
        "vsys_import": None,
    }
    ipv6 = _branch(body, "ipv6")
    if ipv6 is None:
        enabled, presence = None, {"path": path + "/ipv6/enabled", "presence": "absent"}
    else:
        enabled, presence = _flag(ipv6, "enabled", path + "/ipv6")
    source["fields"]["ipv6_enabled"] = presence
    return {
        "name": name,
        "kind": kind,
        "mode": "layer3",
        "ipv4": _addresses(body, name, path, 4, unresolved),
        "ipv6": _addresses(body, name, path, 6, unresolved),
        "ipv6_enabled": enabled,
        "addressing": _addressing(body, name, path, unresolved),
        "virtual_router": None,
        "vsys": None,
        "source": source,
    }


def _interfaces(network, unresolved, excluded):
    container = _branch(network, "interface")
    rows, seen = [], set()

    def register(name, entry, kind, parent_name=None, mode=None):
        if name in seen:
            raise DiscoveryError("PAN-OS IPAM interface identity is duplicated across collections")
        seen.add(name)
        if mode == "layer3":
            row = _interface(name, entry, kind, parent_name, unresolved)
            if reviewed_interface_identity(row):
                rows.append(row)
            else:
                reason = "Configured interface name or parent has no reviewed family contract"
                excluded.append(
                    {
                        "name": name,
                        "kind": kind,
                        "mode": mode,
                        "reason": reason,
                        "source": row["source"],
                    }
                )
                _unresolved(unresolved, name, reason, row["source"], interface=row)
        else:
            excluded.append(
                {
                    "name": name,
                    "kind": kind,
                    "mode": mode,
                    "reason": "Interface has no reviewed Layer 3 address contract",
                }
            )

    for family in ("ethernet", "aggregate-ethernet"):
        family_container = _branch(container, family) if container is not None else None
        for name, entry in _entries(family_container):
            modes = [(mode, _one(entry, mode)) for mode in _MODES]
            modes = [(mode, node) for mode, node in modes if node is not None]
            if len(modes) > 1:
                raise DiscoveryError("PAN-OS IPAM interface has conflicting configured modes")
            mode, body = modes[0] if modes else (None, entry)
            if mode == "layer3":
                register(name, body, family, mode=mode)
            else:
                register(name, entry, family, mode=mode)
            if mode in {"layer3", "layer2", "virtual-wire"}:
                units = _branch(body, "units")
                unit_kind = (
                    "ethernet-subinterface" if family == "ethernet" else "aggregate-subinterface"
                )
                for unit_name, unit in _entries(units):
                    register(unit_name, unit, unit_kind, name, mode)
    for family in ("loopback", "tunnel"):
        units = _branch(container, family + "/units") if container is not None else None
        for name, entry in _entries(units):
            register(name, entry, family, mode="layer3")
    if container is not None:
        for family in container:
            if family.tag in {"ethernet", "aggregate-ethernet", "loopback", "tunnel"}:
                continue
            _semantic_errors(family)
            for name, entry in _entries(_branch(family, "units")):
                register(name, entry, family.tag)
    return rows


def _routers(network):
    routers, memberships = [], {}
    for name, entry in _entries(_branch(network, "virtual-router")):
        interfaces, present = _members(entry, "interface")
        source = _source(
            RUNNING_VPN,
            "result/network/virtual-router/entry",
            name,
            fields={
                "interfaces": {
                    "path": VR_MEMBERSHIP_PATH,
                    "presence": "value" if present else "absent",
                }
            },
            vsys_import=None,
        )
        routers.append({"name": name, "interfaces": interfaces, "vsys": None, "source": source})
        for interface in interfaces:
            if interface in memberships:
                raise DiscoveryError("PAN-OS IPAM interface belongs to multiple virtual routers")
            memberships[interface] = {
                "command": RUNNING_VPN,
                "path": VR_MEMBERSHIP_PATH,
                "router": name,
                "interface": interface,
            }
    return routers, memberships


def _vsys(container):
    rows, interfaces, routers = [], {}, {}
    for name, entry in _entries(container):
        imported, interface_present = _members(entry, "import/network/interface")
        router_names, router_present = _members(entry, "import/network/virtual-router")
        logical_names, logical_present = _members(entry, "import/network/logical-router")
        rows.append(
            {
                "name": name,
                "imported_interfaces": imported,
                "imported_virtual_routers": router_names,
                "imported_logical_routers": logical_names,
                "source": _source(
                    RUNNING_VSYS,
                    "result/vsys/entry",
                    name,
                    fields={
                        "imported_interfaces": {
                            "path": VSYS_INTERFACE_PATH,
                            "presence": "value" if interface_present else "absent",
                        },
                        "imported_virtual_routers": {
                            "path": VSYS_ROUTER_PATH,
                            "presence": "value" if router_present else "absent",
                        },
                        "imported_logical_routers": {
                            "path": "result/vsys/entry/import/network/logical-router/member",
                            "presence": "value" if logical_present else "absent",
                        },
                    },
                ),
            }
        )
        for interface in imported:
            if interface in interfaces:
                raise DiscoveryError(
                    "PAN-OS IPAM interface is imported by multiple virtual systems"
                )
            interfaces[interface] = {
                "command": RUNNING_VSYS,
                "path": VSYS_INTERFACE_PATH,
                "vsys": name,
                "interface": interface,
            }
        for router in router_names:
            if router in routers:
                raise DiscoveryError(
                    "PAN-OS IPAM virtual router is imported by multiple virtual systems"
                )
            routers[router] = {
                "command": RUNNING_VSYS,
                "path": VSYS_ROUTER_PATH,
                "vsys": name,
                "router": router,
            }
    return rows, interfaces, routers


def _parent(output, command, tag):
    result = _result(output, command)
    _semantic_errors(result)
    parent = _one(result, tag, required=True)
    if len(result) != 1:
        raise DiscoveryError("PAN-OS IPAM configuration has an unexpected result structure")
    if result.attrib or parent.attrib:
        raise DiscoveryError("PAN-OS IPAM configuration contains unsupported scope attributes")
    _semantic_errors(parent)
    _container(parent)
    return parent


def parse_ipam_configuration(network_output, vsys_output):
    """Read complete configured sources and independently corroborate memberships."""
    network = _parent(network_output, RUNNING_VPN, "network")
    vsys_parent = _parent(vsys_output, RUNNING_VSYS, "vsys")
    unresolved, excluded = [], []
    interfaces = _interfaces(network, unresolved, excluded)
    routers, memberships = _routers(network)
    vsys, interface_imports, router_imports = _vsys(vsys_parent)
    router_names = {router["name"] for router in routers}
    if router_imports.keys() - router_names:
        raise DiscoveryError("PAN-OS IPAM virtual-router import references missing configuration")
    for router in routers:
        proof = router_imports.get(router["name"])
        if proof is not None:
            router["vsys"] = proof["vsys"]
            router["source"]["vsys_import"] = proof
    for interface in interfaces:
        name = interface["name"]
        membership, imported = memberships.get(name), interface_imports.get(name)
        if membership is not None:
            interface["virtual_router"] = membership["router"]
            interface["source"]["vr_membership"] = membership
        if imported is not None:
            interface["vsys"] = imported["vsys"]
            interface["source"]["vsys_import"] = imported
        router_import = router_imports.get(interface["virtual_router"])
        if (
            imported is not None
            and router_import is not None
            and imported["vsys"] != router_import["vsys"]
        ):
            raise DiscoveryError("PAN-OS IPAM interface and virtual-router imports disagree")
        if (interface["ipv4"] or interface["ipv6"]) and (membership is None or imported is None):
            _unresolved(
                unresolved,
                name,
                "Configured routing or virtual-system membership is missing",
                interface["source"],
            )
    logical = _branch(network, "logical-router")
    for name, _ in _entries(logical):
        unresolved.append(
            {
                "scope": "router",
                "name": name,
                "reason": "Logical-router addressing schema is not reviewed",
                "source": _source(RUNNING_VPN, "result/network/logical-router/entry", name),
            }
        )
    return {
        "schema_version": 1,
        "contract": CONTRACT,
        "interfaces": interfaces,
        "routers": routers,
        "vsys": vsys,
        "unresolved": unresolved,
        "excluded": excluded,
        "sources": [_source(RUNNING_VPN, "result/network"), _source(RUNNING_VSYS, "result/vsys")],
    }
