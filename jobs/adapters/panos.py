"""PAN-OS schema v1: exact identity and name-keyed interface observations.

XML/session patterns adapted from nautobot-testsuite jobs/panos_xml.py and
jobs/checks_panos.py at 7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9 (Apache-2.0).
Modified for strict complete/successful payloads, unambiguous identities,
scoped applied configuration, and conservative native inventory semantics.
"""

import re
import xml.etree.ElementTree as ET

from ..transport_ssh import INTERFACES, RUNNING_INTERFACES, SYSTEM_INFO

MAX_XML_BYTES = 16 * 1024 * 1024
_NAME = re.compile(r"ethernet\d+/\d+(?:/\d+)?")
_RELEASE = re.compile(r"\d+\.\d+\.\d+(?:-[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*)?")
_PROMPT = re.compile(r"[A-Za-z0-9_.:@()/\-]+[>#]")


class DiscoveryError(RuntimeError):
    """Structured evidence was incomplete, unsuccessful, or ambiguous."""


def canonical_interface_name(value):
    return value.strip() if isinstance(value, str) else ""


def canonical_software_version(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _RELEASE.fullmatch(value) else None


def _result(output, command):
    """Accept one complete successful response; never scrape a display table."""
    if not isinstance(output, str) or len(output.encode("utf-8")) > MAX_XML_BYTES:
        raise DiscoveryError("%s: missing or oversized XML response" % command)
    if "<!DOCTYPE" in output.upper() or "<!ENTITY" in output.upper():
        raise DiscoveryError("%s: XML declarations are not supported" % command)
    value = output.strip()
    # Netmiko normally removes echoes/prompts. Permit only an exact command echo
    # and a complete prompt line; arbitrary output cannot hide a failed read.
    lines = value.splitlines()
    if lines and lines[0].strip() == command:
        lines.pop(0)
    if lines and _PROMPT.fullmatch(lines[-1].strip()):
        lines.pop()
    value = "\n".join(lines).strip()
    try:
        root = ET.fromstring(value)
    except ET.ParseError:
        raise DiscoveryError("%s: malformed or non-XML response" % command) from None
    if root.tag != "response" or root.get("status") != "success":
        raise DiscoveryError("%s: response did not explicitly report success" % command)
    _container(root)
    results = root.findall("result")
    if len(results) != 1 or any(child.tag != "result" for child in root):
        raise DiscoveryError("%s: ambiguous or missing result structure" % command)
    _container(results[0])
    return results[0]


def _container(element):
    if element.text and element.text.strip():
        raise DiscoveryError("PAN-OS XML container contains unexpected display text")
    if any(child.tail and child.tail.strip() for child in element):
        raise DiscoveryError("PAN-OS XML container contains unexpected trailing text")


def _one(element, path, *, required=False):
    nodes = element.findall(path)
    if len(nodes) > 1 or (required and len(nodes) != 1):
        raise DiscoveryError("PAN-OS XML contains ambiguous or missing %s structure" % path)
    return nodes[0] if nodes else None


def _text(element, path):
    node = _one(element, path)
    if node is None:
        return None
    if len(node):
        raise DiscoveryError("PAN-OS XML scalar %s contains nested elements" % path)
    value = (node.text or "").strip()
    if any(ord(char) < 32 for char in value):
        raise DiscoveryError("PAN-OS XML scalar contains control characters")
    return value or None


def _integer(value, minimum, maximum):
    if not isinstance(value, str) or len(value) > 10 or not re.fullmatch(r"[0-9]+", value):
        return None
    number = int(value)
    return number if minimum <= number <= maximum else None


def _identity_text(value):
    if value is None or value.casefold() in {"unknown", "none", "n/a", "null", "0"}:
        return None
    return value


def configured_mtu(value):
    """Strict byte count within the native Nautobot Interface MTU field bounds."""
    return _integer(value, 1, 65536)


def parse_system_info(output):
    result = _result(output, SYSTEM_INFO)
    system = _one(result, "system", required=True)
    _container(system)
    identity = {
        "hostname": _identity_text(_text(system, "hostname")),
        "model": _identity_text(_text(system, "model")),
        "serial": _identity_text(_text(system, "serial")),
        "software_version": canonical_software_version(_text(system, "sw-version")),
    }
    observations = {
        field: _text(system, field)
        for field in (
            "family",
            "vm-mode",
            "vm-license",
            "multi-vsys",
            "operational-mode",
            "advanced-routing",
            "sw-version",
        )
    }
    return identity, observations


def parse_running_interfaces(output):
    result = _result(output, RUNNING_INTERFACES)
    interface = _one(result, "interface", required=True)
    _container(interface)
    ethernet = _one(interface, "ethernet", required=True)
    _container(ethernet)
    entries = {}
    for entry in ethernet:
        if entry.tag != "entry":
            raise DiscoveryError("Applied Ethernet configuration has an unexpected structure")
        name = canonical_interface_name(entry.get("name"))
        if not name or name in entries:
            raise DiscoveryError("Applied Ethernet configuration has duplicate or missing names")
        _container(entry)
        for field in ("layer3", "layer2", "tap", "virtual-wire", "ha", "aggregate-group"):
            _one(entry, field)
        entries[name] = entry
    return entries


def observed_physical_ethernet(fact, name):
    """No hw/type-number/name combination proves physical appliance capability.

    Schema v1 deliberately has no reviewed appliance model contract. VM-Series
    also exposes hw entries. Exact DeviceType templates may supply native types;
    a later reviewed physical contract can extend this without weakening Cisco.
    """
    return False


def _operational_row(element):
    # Keep repeated/nested structured operational fields without a lossy dict.
    return [
        {
            "field": child.tag,
            "text": child.text,
            "attributes": dict(child.attrib),
            "children": _operational_row(child),
        }
        for child in element
    ]


def _applied_observation(config):
    if config is None:
        return None
    # Ethernet entries can include PPPoE credentials: never retain the subtree.
    return {
        "link_state": _text(config, "link-state"),
        "comment": _text(config, "comment"),
        "mtu": _text(config, "layer3/mtu"),
        "modes": [
            child.tag
            for child in config
            if child.tag in {"layer2", "layer3", "tap", "virtual-wire", "ha", "aggregate-group"}
        ],
        "ipv4": [entry.get("name") for entry in config.findall("layer3/ip/entry")],
        "ipv6": [entry.get("name") for entry in config.findall("layer3/ipv6/address/entry")],
    }


def parse_interfaces(output, applied):
    result = _result(output, INTERFACES)
    hw = _one(result, "hw", required=True)
    ifnet = _one(result, "ifnet", required=True)
    hardware = {}
    logical = {}
    hardware_ids = {}
    for container, rows in ((hw, hardware), (ifnet, logical)):
        _container(container)
        for entry in container:
            if entry.tag != "entry":
                raise DiscoveryError("Interface inventory has an unexpected row structure")
            _container(entry)
            name = canonical_interface_name(_text(entry, "name"))
            if not name:
                raise DiscoveryError("Interface inventory contains an unnamed row")
            if container is hw:
                identity = _text(entry, "id")
                if identity is not None and identity in hardware_ids:
                    raise DiscoveryError("Interface inventory has duplicate hardware identifiers")
                if identity is not None:
                    hardware_ids[identity] = name
            rows.setdefault(name, []).append(entry)
    interfaces, excluded, warnings = [], [], []
    observations = []
    for name in sorted(set(hardware) | set(logical) | set(applied)):
        hw_rows, logical_rows = hardware.get(name, []), logical.get(name, [])
        config = applied.get(name)
        raw = {
            "name": name,
            "hardware": [_operational_row(row) for row in hw_rows],
            "logical": [_operational_row(row) for row in logical_rows],
            "applied": _applied_observation(config),
        }
        observations.append(raw)
        if not hw_rows or not _NAME.fullmatch(name):
            excluded.append({"name": name, "reason": "logical or configuration-only observation"})
            continue
        if len(hw_rows) != 1:
            raise DiscoveryError("Interface inventory has duplicate hardware identities")
        hardware_id = _text(hw_rows[0], "id")
        # Multiple logical address rows are fine only when identity agrees.
        ids = {_text(row, "id") for row in logical_rows}
        if logical_rows and (
            len(ids) != 1 or None in ids or not hardware_id or ids != {hardware_id}
        ):
            excluded.append({"name": name, "reason": "ambiguous hardware/logical identity join"})
            warnings.append("%s: hardware/logical identity disagreement; writes deferred" % name)
            continue
        state = _text(config, "link-state") if config is not None else None
        enabled = {"up": True, "down": False}.get(state)
        if enabled is None:
            warnings.append("%s: applied administrative state is unresolved" % name)
        mtu_raw = _text(config, "layer3/mtu") if config is not None else None
        mtu = configured_mtu(mtu_raw)
        if mtu_raw is not None and mtu is None:
            warnings.append("%s: invalid applied MTU; left unresolved" % name)
        interfaces.append(
            {
                "name": name,
                "type": None,
                "type_source": None,
                "enabled": enabled,
                "description": _text(config, "comment") if config is not None else None,
                "mtu": mtu,
                "mac_address": None,
                "speed": None,
                "duplex": None,
                "port_type": None,
                "mgmt_only": None,
                "physical_ethernet": False,
                "source": {
                    "contract": "panos-interface-v1",
                    "operational_command": INTERFACES,
                    "hardware_path": "result/hw/entry",
                    "name": name,
                    "id": hardware_id,
                    "applied_command": RUNNING_INTERFACES,
                    "applied_path": "result/interface/ethernet/entry",
                    "link_state": state,
                    "comment": _text(config, "comment") if config is not None else None,
                    "mtu": mtu_raw,
                },
            }
        )
        warnings.append(
            "%s: native type requires an exact DeviceType template; capability unresolved" % name
        )
    return interfaces, excluded, warnings, observations


def collect(client, *, use_ntc_defaults=False):
    """Three fixed structured reads; guessing never changes PAN-OS facts."""
    if type(use_ntc_defaults) is not bool:
        raise ValueError("Use NTC defaults when guessing must be true or false")
    identity, system = parse_system_info(client.run(SYSTEM_INFO))
    operational = client.run(INTERFACES)
    applied = parse_running_interfaces(client.run(RUNNING_INTERFACES))
    interfaces, excluded, warnings, observations = parse_interfaces(operational, applied)
    if not interfaces:
        warnings.append(
            "No eligible Ethernet ports reported; this does not establish "
            "complete hardware inventory"
        )
    if system.get("vm-license") == "none":
        warnings.append("VM-Series reports no license; dataplane interface coverage is unverified")
    return {
        "adapter": "panos",
        "schema_version": 1,
        "identity": identity,
        "interfaces": interfaces,
        "excluded_interfaces": excluded,
        "warnings": warnings,
        "observations": {"system": system, "interfaces": observations},
        "sources": {
            "identity": {"command": SYSTEM_INFO, "path": "result/system"},
            "interfaces": {"command": INTERFACES, "path": "result/hw/entry"},
            "applied_configuration": {"command": RUNNING_INTERFACES, "path": "result/interface"},
        },
    }
