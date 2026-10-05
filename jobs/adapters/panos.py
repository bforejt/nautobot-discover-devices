"""PAN-OS schema v1: exact identity and name-keyed interface observations.

XML/session patterns adapted from nautobot-testsuite jobs/panos_xml.py and
jobs/checks_panos.py at 7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9 (Apache-2.0).
Modified for strict complete/successful payloads, unambiguous identities,
scoped applied configuration, and conservative native inventory semantics.
"""

import re
import xml.etree.ElementTree as ET
from uuid import UUID

from ..transport_ssh import (
    HA_STATE,
    IKE_SAS,
    INTERFACES,
    IPSEC_SAS,
    MANAGEMENT_INTERFACE,
    RUNNING_HA,
    RUNNING_INTERFACES,
    RUNNING_VPN,
    RUNNING_VSYS,
    SYSTEM_INFO,
    VM_INTERFACES,
    VPN_FLOWS,
    vpn_flow_detail_command,
)

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


def canonical_vm_uuid(value):
    """Accept explicit UUID notation, excluding nil and all-ones sentinels."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value) is None:
        return None
    identifier = UUID(value)
    return str(identifier) if identifier.int not in (0, (1 << 128) - 1) else None


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
            "vm-uuid",
            "vm-cpuid",
            "vm-cores",
            "vm-mem",
            "serial",
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


def canonical_vm_interface_name(value):
    """Normalize only the documented diagnostic Ethernet prefix, never other names."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.startswith("Ethernet"):
        value = "ethernet" + value[len("Ethernet") :]
    return value if _NAME.fullmatch(value) else None


def vm_interface_identity(row):
    """Recheck the reviewed diagnostic identity independently of native field values."""
    if not isinstance(row, dict):
        return None
    raw_name, port, bus = (row.get(field) for field in ("raw_name", "base_os_port", "base_os_bus"))
    if (
        not isinstance(raw_name, str)
        or not raw_name
        or raw_name != raw_name.strip()
        or any(char.isspace() or ord(char) < 32 for char in raw_name)
        or not isinstance(port, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]+", port) is None
        or not isinstance(bus, str)
        or re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[01][0-9a-fA-F]\.[0-7]", bus) is None
    ):
        return None
    name = canonical_vm_interface_name(raw_name) or raw_name
    if row.get("name") != name:
        return None
    return name, raw_name, port, bus.lower()


def parse_vm_interfaces(output):
    """Accept complete guest enumeration, retaining management/unknown kinds as observations."""
    result = _result(output, VM_INTERFACES)
    rows = []
    names, ports, buses = set(), set(), set()
    for entry in result:
        if entry.tag != "entry" or entry.attrib:
            raise DiscoveryError("VM interface inventory has an unsupported row structure")
        _container(entry)
        for child in entry:
            if child.attrib or len(child):
                raise DiscoveryError("VM interface inventory requires scalar row fields")
            _text(entry, child.tag)
        raw_name = _text(entry, "Interface_name")
        row = {
            "name": canonical_vm_interface_name(raw_name) or raw_name,
            "raw_name": raw_name,
            "base_os_port": _text(entry, "Base-OS_port"),
            "base_os_bus": _text(entry, "Base-OS_BUS"),
            "base_os_mac": _text(entry, "Base-OS_MAC"),
            "fields": _operational_row(entry),
        }
        identity = vm_interface_identity(row)
        if identity is None:
            raise DiscoveryError("VM interface inventory has missing or invalid guest identity")
        name, _, port, bus = identity
        if name in names or port in ports or bus in buses:
            raise DiscoveryError("VM interface inventory has duplicate guest identities")
        names.add(name)
        ports.add(port)
        buses.add(bus)
        rows.append(row)
    return rows


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


def _merge_vm_interfaces(interfaces, excluded, warnings, observations, vm_rows, applied):
    """Supplement absent hardware rows with independently observed guest adapters."""
    hardware_names = {
        canonical_vm_interface_name(row["name"]) or row["name"]
        for row in observations
        if row["hardware"]
    }
    vm_names = {row["name"] for row in vm_rows if canonical_vm_interface_name(row["raw_name"])}
    if any(_NAME.fullmatch(name) and name not in vm_names for name in hardware_names):
        raise DiscoveryError("Operational and VM interface inventories disagree on guest names")
    observations_by_name = {row["name"]: row for row in observations}
    for row in vm_rows:
        name = row["name"]
        config = applied.get(name)
        if name in observations_by_name:
            observations_by_name[name]["vm"] = row
        else:
            observations.append(
                {
                    "name": name,
                    "hardware": [],
                    "logical": [],
                    "applied": _applied_observation(config),
                    "vm": row,
                }
            )
        if not _NAME.fullmatch(name):
            excluded.append({"name": name, "reason": "VM management or unknown interface kind"})
            continue
        if name in hardware_names:
            # A debug row must not repair an existing ambiguous hw/ifnet join.
            continue
        excluded[:] = [item for item in excluded if item["name"] != name]
        state = _text(config, "link-state") if config is not None else None
        enabled = {"up": True, "down": False}.get(state)
        if enabled is None:
            warnings.append("%s: applied administrative state is unresolved" % name)
        mtu_raw = _text(config, "layer3/mtu") if config is not None else None
        mtu = configured_mtu(mtu_raw)
        if mtu_raw is not None and mtu is None:
            warnings.append("%s: invalid applied MTU; left unresolved" % name)
        comment = _text(config, "comment") if config is not None else None
        interfaces.append(
            {
                "name": name,
                "type": None,
                "type_source": None,
                "enabled": enabled,
                "description": comment,
                "mtu": mtu,
                "mac_address": None,
                "speed": None,
                "duplex": None,
                "port_type": None,
                "mgmt_only": None,
                "physical_ethernet": False,
                "source": {
                    "contract": "panos-vm-interface-v1",
                    "enumeration_command": VM_INTERFACES,
                    "enumeration_path": "result/entry",
                    "raw_name": row["raw_name"],
                    "name": name,
                    "base_os_port": row["base_os_port"],
                    "base_os_bus": row["base_os_bus"],
                    "applied_command": RUNNING_INTERFACES,
                    "applied_path": "result/interface/ethernet/entry",
                    "link_state": state,
                    "comment": comment,
                    "mtu": mtu_raw,
                },
            }
        )
        warnings.append(
            "%s: native type requires an exact DeviceType template; capability unresolved" % name
        )
    interfaces.sort(key=lambda row: row["name"])
    observations.sort(key=lambda row: row["name"])


def _collect_ha_vpn(client, max_vpn_flow_details):
    # These facts do not import Nautobot or enter the native inventory planners.
    from .panos_ha import parse_ha_configuration, parse_ha_state
    from .panos_vpn_config import parse_vpn_configuration
    from .panos_vpn_runtime import parse_ike_sas, parse_ipsec_sas, parse_vpn_flows

    deviceconfig_output = client.run(RUNNING_HA)
    ha = {
        "contract": "panos-ha-v1",
        "configuration": parse_ha_configuration(deviceconfig_output, command=RUNNING_HA),
        "runtime": parse_ha_state(client.run(HA_STATE), command=HA_STATE),
    }
    network_output = client.run(RUNNING_VPN)
    configuration = parse_vpn_configuration(network_output, command=RUNNING_VPN)
    ike_output = client.run(IKE_SAS)
    unresolved = []
    if isinstance(ike_output, str) and not ike_output.strip():
        # Reviewed on the passive PA-VM: a successful SSH read can be blank.
        # This is missing evidence, never a structured assertion of zero SAs.
        ike_sas = None
        unresolved.append(
            {
                "collection": "ike_sas",
                "source": {"command": IKE_SAS, "path": "result/entry"},
                "reason": "Blank SSH output; no structured IKE SA evidence",
            }
        )
    else:
        ike_sas = parse_ike_sas(ike_output, command=IKE_SAS)
    ipsec_sas = parse_ipsec_sas(client.run(IPSEC_SAS), command=IPSEC_SAS)
    flows = parse_vpn_flows(client.run(VPN_FLOWS), command=VPN_FLOWS)
    if len(flows) > max_vpn_flow_details:
        raise DiscoveryError(
            "VPN flow count exceeds the selected detail-read limit; "
            "increase Maximum VPN flow details to collect the complete observation"
        )
    details = []
    for flow in sorted(flows, key=lambda row: row["tunnel_id"]):
        try:
            command = vpn_flow_detail_command(flow["tunnel_id"])
        except ValueError:
            raise DiscoveryError(
                "VPN flow tunnel ID is outside the documented SSH read range"
            ) from None
        rows = parse_vpn_flows(client.run(command), command=command, detail=True)
        if len(rows) != 1:
            raise DiscoveryError("VPN flow detail does not identify exactly one observed flow")
        row = rows[0]
        # IDs are ephemeral. A changed/deleted/reassigned flow cannot silently
        # attach another tunnel's counters to the earlier summary snapshot.
        fields = (
            "tunnel_id",
            "gateway_id",
            "name",
            "tunnel_interface",
            "outer_interface",
            "local_address",
            "peer_address",
            "dataplane",
        )
        if any(flow.get(field) != row.get(field) for field in fields):
            raise DiscoveryError("VPN flow identity changed between summary and detail reads")
        details.append(row)
    return (
        ha,
        {
            "contract": "panos-vpn-v1",
            "scope": "ipsec",
            "configuration": configuration,
            "runtime": {
                "contract": "panos-vpn-runtime-v1",
                "ike_sas": ike_sas,
                "ipsec_sas": ipsec_sas,
                "flows": flows,
                "flow_details": details,
                "complete": not unresolved,
                "unresolved": unresolved,
            },
            "native_writes": False,
        },
        network_output,
        deviceconfig_output,
    )


def collect(client, *, use_ntc_defaults=False, expected_vm_uuid=None, max_vpn_flow_details=256):
    """Read inventory and HA/VPN evidence; never probe or mutate the firewall."""
    if type(use_ntc_defaults) is not bool:
        raise ValueError("Use NTC defaults when guessing must be true or false")
    if type(max_vpn_flow_details) is not int or not 1 <= max_vpn_flow_details <= 65535:
        raise ValueError("Maximum VPN flow details must be an integer between 1 and 65535")
    if expected_vm_uuid is not None:
        canonical_expected = canonical_vm_uuid(expected_vm_uuid)
        if canonical_expected is None:
            raise ValueError("Expected PAN-OS VM UUID must be a non-sentinel canonical UUID")
        expected_vm_uuid = canonical_expected
    identity, system = parse_system_info(client.run(SYSTEM_INFO))
    operational = client.run(INTERFACES)
    applied = parse_running_interfaces(client.run(RUNNING_INTERFACES))
    interfaces, excluded, warnings, observations = parse_interfaces(operational, applied)
    vm_rows = None
    if (
        identity.get("model") == "PA-VM"
        and system.get("family") == "vm"
        and system.get("vm-mode") == "KVM"
    ):
        vm_rows = parse_vm_interfaces(client.run(VM_INTERFACES))
        _merge_vm_interfaces(interfaces, excluded, warnings, observations, vm_rows, applied)
    if not interfaces:
        warnings.append(
            "No eligible Ethernet ports reported; this does not establish "
            "complete hardware inventory"
        )
    if system.get("vm-license") == "none":
        warnings.append("VM-Series reports no license; dataplane MAC uniqueness is not established")
    binding = None
    if expected_vm_uuid is not None:
        binding = {
            "contract": "panos-vm-identity-v1",
            "system_command": SYSTEM_INFO,
            "system_path": "result/system",
            "expected_uuid": expected_vm_uuid,
            "observed_uuid": canonical_vm_uuid(system.get("vm-uuid")),
            "model": identity.get("model"),
            "family": system.get("family"),
            "vm_mode": system.get("vm-mode"),
        }
    sources = {
        "identity": {"command": SYSTEM_INFO, "path": "result/system"},
        "interfaces": {"command": INTERFACES, "path": "result/hw/entry"},
        "applied_configuration": {"command": RUNNING_INTERFACES, "path": "result/interface"},
    }
    collected_observations = {"system": system, "interfaces": observations}
    if vm_rows is not None:
        sources["vm_interfaces"] = {"command": VM_INTERFACES, "path": "result/entry"}
        collected_observations["vm_interfaces"] = vm_rows
    from .panos_ipam import parse_ipam_configuration

    ha, vpn, network_output, deviceconfig_output = _collect_ha_vpn(client, max_vpn_flow_details)
    ipam = parse_ipam_configuration(network_output, client.run(RUNNING_VSYS))
    warnings.extend(row["reason"] for row in vpn["runtime"]["unresolved"])
    collected_observations["ha"] = ha
    collected_observations["vpn"] = vpn
    sources["ha"] = {
        "configuration": {"command": RUNNING_HA, "path": "result/deviceconfig/high-availability"},
        "runtime": {"command": HA_STATE, "path": "result"},
    }
    sources["vpn"] = {
        "configuration": {"command": RUNNING_VPN, "path": "result/network"},
        "ike_sas": {"command": IKE_SAS, "path": "result/entry"},
        "ipsec_sas": {"command": IPSEC_SAS, "path": "result/entries/entry"},
        "flows": {"command": VPN_FLOWS, "path": "result/IPSec/entry"},
        "flow_details": [row["source"] for row in vpn["runtime"]["flow_details"]],
    }
    discovery = {
        "adapter": "panos",
        "schema_version": 1,
        "identity": identity,
        "identity_binding": binding,
        "interfaces": interfaces,
        "excluded_interfaces": excluded,
        "warnings": warnings,
        "ipam": ipam,
        "observations": collected_observations,
        "sources": sources,
    }
    from .panos_capacity import parse_capacity
    from .panos_logical import parse_logical_interfaces
    from .panos_management import parse_management

    discovery["capacity"] = parse_capacity(discovery)
    discovery["logical_interfaces"] = parse_logical_interfaces(network_output)
    discovery["management"] = parse_management(
        client.run(MANAGEMENT_INTERFACE),
        deviceconfig_output,
        {**system, "model": identity["model"]},
    )
    return discovery
