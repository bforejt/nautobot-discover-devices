"""Configured interface IPv4 and named VRFs from safe RESTCONF JSON reads.

Cisco's native interfaces and IP submodules define fixed primary/secondary
addresses, masks, VRF forwarding and named VRF definitions. These configuration
facts do not depend on operational link state or a chassis hardware profile.
Dynamic, unnumbered and IPv6 observations remain outside static IPv4 writes.
"""

import ipaddress
import re
from copy import deepcopy

from ..transport_restconf import RestconfError
from . import cisco_access_ports

MODULE = "Cisco-IOS-XE-native"
INTERFACES_PATH = "/data/%s:native/interface" % MODULE
VRF_PATH = "/data/%s:native/vrf" % MODULE
LEGACY_VRF_PATH = "/data/%s:native/ip/vrf" % MODULE
INTERFACE_FAMILIES = (
    "FastEthernet",
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
    "TwoHundredGigE",
    "FourHundredGigE",
    "Loopback",
    "Port-channel",
    "Vlan",
    "Tunnel",
    "AppGigabitEthernet",
)
ROW_FIELDS = (
    "name;vrf(forwarding);ip(address;unnumbered;vrf(forwarding));"
    "ip-vrf(ip(vrf(forwarding)));ipv6(address)"
)
INTERFACE_FIELDS = ";".join(family + "(" + ROW_FIELDS + ")" for family in INTERFACE_FAMILIES)
INTERFACE_FIELDS += ";Port-channel-subinterface(Port-channel(" + ROW_FIELDS + "))"
VRF_FIELDS = "definition(name;rd;rd-auto;address-family(ipv4;ipv6))"
LEGACY_VRF_FIELDS = "name;rd"
READ_TIMEOUT = 15
MODEL_URLS = [
    "https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/1791/"
    "Cisco-IOS-XE-interfaces.yang",
    "https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/"
    "Cisco-IOS-XE-interfaces.yang",
    "https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/"
    "Cisco-IOS-XE-ip.yang",
]


class IpamDiscoveryError(ValueError):
    """Caller contracts or optional structured IPAM evidence are invalid."""


def _object(value):
    if not isinstance(value, dict):
        raise IpamDiscoveryError("Expected a structured container")
    names = set()
    for key in value:
        if not isinstance(key, str) or not key:
            raise IpamDiscoveryError("Structured keys must be nonempty strings")
        if ":" in key:
            module, local = key.split(":", 1)
            if module != MODULE or not local or ":" in local:
                raise IpamDiscoveryError("Unexpected YANG field namespace")
        else:
            local = key
        if local in names:
            raise IpamDiscoveryError("Duplicate namespace-qualified fields")
        names.add(local)
    return value


def _tree(value):
    if isinstance(value, dict):
        _object(value)
        for item in value.values():
            _tree(item)
    elif isinstance(value, list):
        for item in value:
            _tree(item)


def _value(mapping, name):
    _object(mapping)
    value = mapping.get(name, mapping.get(MODULE + ":" + name))
    if value is None and (name in mapping or MODULE + ":" + name in mapping):
        raise IpamDiscoveryError("Present fields cannot be null")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise IpamDiscoveryError("Expected an unambiguous nonempty string")
    return value


def _rows(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise IpamDiscoveryError("Expected a structured list of objects")
    return value


def _source(path, fields, revisions):
    return {
        "module": MODULE,
        "revision": revisions.get(MODULE) if revisions else None,
        "path": path,
        "requested_fields": fields,
        "request": path + "?fields=" + fields,
        "complete": False,
        "status": "unavailable",
        "documents": list(MODEL_URLS),
    }


def _notice(result, source, reason, **details):
    result["unresolved"].append({"reason": reason, "source": deepcopy(source), **details})


def _read(client, source, result):
    try:
        payload = client.get(source["request"], timeout=READ_TIMEOUT)
    except RestconfError as exc:
        # Native configuration can contain authentication secrets; never retry
        # an unsupported filter with an unfiltered interface/native GET.
        status = exc.status_code
        source["status"] = (
            "invalid"
            if status and 200 <= status < 300
            else "unsupported"
            if status in (404, 501)
            else "unavailable"
        )
        source["http_status"] = status
        _notice(result, source, "Optional configured IPAM source unavailable")
        return None
    source["http_status"] = next(
        (
            row.get("status")
            for row in reversed(getattr(client, "trace", []))
            if row.get("path") == source["request"]
        ),
        None,
    )
    # RestconfClient represents an HTTP 204 with an empty JSON object.
    # A missing VRF subtree establishes no configured VRFs, while an empty
    # interface subtree cannot establish configuration for mandatory ports.
    if payload is None or source["http_status"] == 204 and payload == {}:
        if source["http_status"] == 204 and source["path"] in (VRF_PATH, LEGACY_VRF_PATH):
            source.update(status="available", complete=True)
        else:
            _notice(result, source, "Optional configured IPAM source is empty")
        return None
    return payload


def _parse_vrfs(payload, source, *, legacy=False):
    _tree(payload)
    container = _value(_object(payload), "vrf")
    if container is None:
        raise IpamDiscoveryError("VRF response lacks its requested container")
    if legacy:
        rows = _rows(container)
    else:
        definitions = _value(_object(container), "definition")
        rows = _rows(definitions) if definitions is not None else []
    facts, seen = [], set()
    for row in rows:
        name = _text(_value(row, "name"))
        if name in seen:
            raise IpamDiscoveryError("Duplicate named VRF definitions")
        seen.add(name)
        rd = _value(row, "rd")
        if rd is not None:
            rd = _text(rd)
        if _value(row, "rd-auto") is not None and _value(row, "rd-auto") != [None]:
            raise IpamDiscoveryError("Malformed automatic RD flag")
        families = _value(row, "address-family")
        configured = []
        if families is not None:
            families = _object(families)
            for family in ("ipv4", "ipv6"):
                if _value(families, family) is not None:
                    _object(_value(families, family))
                    configured.append(family)
        facts.append(
            {"name": name, "rd": rd, "address_families": configured, "source": deepcopy(source)}
        )
    return facts


def _vrf_name(row):
    candidates = []
    vrf = _value(row, "vrf")
    if vrf is not None:
        value = _value(_object(vrf), "forwarding")
        if value is not None:
            candidates.append(_text(value))
    # Cisco retains both legacy CLI spellings in its native YANG schema.
    ip_vrf = _value(row, "ip-vrf")
    if ip_vrf is not None:
        ip = _value(_object(ip_vrf), "ip")
        vrf = _value(_object(ip), "vrf") if ip is not None else None
        forwarding = _value(_object(vrf), "forwarding") if vrf is not None else None
        if forwarding is not None:
            candidates.append(_text(forwarding))
    ip = _value(row, "ip")
    vrf = _value(_object(ip), "vrf") if ip is not None else None
    forwarding = _value(_object(vrf), "forwarding") if vrf is not None else None
    if forwarding is not None:
        forwarding = _object(forwarding)
        keys = [key.split(":")[-1] for key in forwarding]
        if keys != ["word"]:
            # Special symbolic forwarding forms need documented resolution;
            # they cannot acquire an invented VRF identity from their spelling.
            raise IpamDiscoveryError("Unsupported symbolic legacy VRF forwarding")
        candidates.append(_text(_value(forwarding, "word")))
    if len(candidates) > 1:
        raise IpamDiscoveryError("Ambiguous interface VRF configuration")
    return candidates[0] if candidates else None


def _interface_name(family, row, canonical_name, *, subinterface=False):
    suffix = _value(row, "name")
    if family in ("Loopback", "Port-channel", "Vlan", "Tunnel") and not subinterface:
        ranges = {
            "Loopback": (0, 2147483647),
            "Port-channel": (1, 512),
            "Vlan": (1, 4094),
            "Tunnel": (0, 2147483647),
        }
        if type(suffix) is not int or not ranges[family][0] <= suffix <= ranges[family][1]:
            raise IpamDiscoveryError("Numeric interface key is outside its YANG type")
        suffix = str(suffix)
    else:
        suffix = _text(suffix)
        pattern = r"[1-9]\d*\.[1-9]\d*" if subinterface else r"\d+(?:/\d+)*(?:\.\d+)?"
        if re.fullmatch(pattern, suffix) is None:
            raise IpamDiscoveryError("Native interface key lacks a supported structured spelling")
    name = canonical_name(family + suffix)
    if not isinstance(name, str) or not name:
        raise IpamDiscoveryError("Canonical interface name is unavailable")
    return name


def _parse_interfaces(payload, source, canonical_name, eligible, excluded, vrfs):
    _tree(payload)
    container = _value(_object(payload), "interface")
    if container is None:
        raise IpamDiscoveryError("Native interface response lacks its requested container")
    container = _object(container)
    facts, excluded_facts, notices, seen = [], [], [], set()
    for key, values in container.items():
        family = key.split(":")[-1]
        subinterface = family == "Port-channel-subinterface"
        if subinterface:
            values = _value(_object(values), "Port-channel")
            family = "Port-channel"
            if values is None:
                continue
        elif family not in INTERFACE_FAMILIES:
            raise IpamDiscoveryError("Unexpected interface family in filtered response")
        for row in _rows(values):
            name = _interface_name(family, row, canonical_name, subinterface=subinterface)
            if name in seen:
                raise IpamDiscoveryError("Duplicate canonical native interface names")
            seen.add(name)
            if name not in eligible and name not in excluded:
                raise IpamDiscoveryError("Configured interface has no mandatory interface identity")
            vrf = _vrf_name(row)
            if vrf is not None and vrf not in vrfs:
                raise IpamDiscoveryError("Interface VRF has no validated configured definition")
            ipv4, method4 = cisco_access_ports._ipv4(row)
            ipv6, methods6 = cisco_access_ports._ipv6(row)
            if any(ipaddress.IPv4Address(item["address"]).is_multicast for item in ipv4):
                raise IpamDiscoveryError("Configured interface IPv4 address is multicast")
            ip = _value(row, "ip")
            unnumbered = _value(_object(ip), "unnumbered") if ip is not None else None
            if unnumbered is not None:
                _text(unnumbered)
                if method4 != "not-configured":
                    raise IpamDiscoveryError("Conflicting unnumbered and IPv4 assignment methods")
                method4 = "unnumbered"
            fact = {
                "name": name,
                "vrf": vrf,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "addressing": {"ipv4_method": method4, "ipv6_methods": methods6},
                "source": deepcopy(source),
            }
            if name in excluded:
                fact["reason"] = excluded[name]
                excluded_facts.append(fact)
                continue
            facts.append(fact)
            if method4 in ("dhcp", "negotiated", "unnumbered"):
                notices.append(
                    {
                        "name": name,
                        "reason": "Dynamic or unnumbered IPv4 is observation-only",
                        "method": method4,
                        "source": deepcopy(source),
                    }
                )
            if ipv6 or any(methods6.values()):
                notices.append(
                    {
                        "name": name,
                        "reason": "IPv6 writes are deferred in the static IPv4 stage",
                        "source": deepcopy(source),
                    }
                )
    return facts, excluded_facts, notices


def collect(client, interfaces, *, canonical_name, excluded_interfaces=(), revisions=None):
    """Collect optional static IPAM evidence; malformed sources cannot drive writes."""
    if not isinstance(interfaces, list) or not callable(canonical_name):
        raise IpamDiscoveryError("Eligible interfaces and canonicalizer are required")
    if not isinstance(excluded_interfaces, (list, tuple)):
        raise IpamDiscoveryError("Excluded interfaces must be a structured sequence")
    if revisions is not None and not isinstance(revisions, dict):
        raise IpamDiscoveryError("Module revisions must be a structured mapping")
    eligible, excluded = set(), {}
    for row in interfaces:
        name = row.get("name") if isinstance(row, dict) else None
        if (
            not isinstance(name, str)
            or not name
            or canonical_name(name) != name
            or name in eligible
        ):
            raise IpamDiscoveryError("Eligible interfaces require unique canonical names")
        eligible.add(name)
    for row in excluded_interfaces:
        name = row.get("name") if isinstance(row, dict) else None
        reason = row.get("reason") if isinstance(row, dict) else None
        if (
            not isinstance(name, str)
            or not name
            or canonical_name(name) != name
            or name in eligible
            or name in excluded
            or not isinstance(reason, str)
            or not reason
        ):
            raise IpamDiscoveryError("Excluded interface identities must be unique and explicit")
        excluded[name] = reason
    result = {
        "schema_version": 1,
        "interfaces": [],
        "vrfs": [],
        "excluded": [],
        "unresolved": [],
        "sources": [],
    }
    for path, fields, legacy in (
        (VRF_PATH, VRF_FIELDS, False),
        (LEGACY_VRF_PATH, LEGACY_VRF_FIELDS, True),
    ):
        source = _source(path, fields, revisions)
        result["sources"].append(source)
        payload = _read(client, source, result)
        if payload is None:
            continue
        try:
            facts = _parse_vrfs(payload, source, legacy=legacy)
        except IpamDiscoveryError:
            source["status"] = "invalid"
            _notice(result, source, "Configured VRF source is malformed or ambiguous")
            continue
        source.update(status="available", complete=True)
        for fact in facts:
            fact["source"] = deepcopy(source)
        result["vrfs"].extend(facts)
    vrfs = {row["name"] for row in result["vrfs"]}
    if len(vrfs) != len(result["vrfs"]):
        result["vrfs"] = []
        vrfs.clear()
        for source in result["sources"]:
            source.update(status="invalid", complete=False)
        _notice(
            result,
            result["sources"][0],
            "Modern and legacy VRF definitions have ambiguous identities",
        )
    source = _source(INTERFACES_PATH, INTERFACE_FIELDS, revisions)
    result["sources"].append(source)
    payload = _read(client, source, result)
    if payload is not None:
        try:
            facts, excluded_facts, notices = _parse_interfaces(
                payload, source, canonical_name, eligible, excluded, vrfs
            )
        except (
            IpamDiscoveryError,
            cisco_access_ports._ScopedDataError,
            ipaddress.AddressValueError,
            ipaddress.NetmaskValueError,
        ):
            source["status"] = "invalid"
            _notice(
                result,
                source,
                "Configured IPAM interface source is malformed, incomplete, or ambiguous",
            )
        else:
            source.update(status="available", complete=True)
            for fact in facts + excluded_facts + notices:
                fact["source"] = deepcopy(source)
            result["interfaces"], result["excluded"] = facts, excluded_facts
            result["unresolved"].extend(notices)
    for field in ("interfaces", "vrfs", "excluded"):
        result[field].sort(key=lambda row: row["name"])
    return result
