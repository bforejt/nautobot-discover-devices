"""Allowlisted PAN-OS HA configuration and operational evidence, report only.

The reviewed v1 XML shapes come from PAN-OS11.2.8 PA-VM/KVM captures. Missing
fields remain unknown. This module imports no Nautobot models and performs no
collection, device operations, identity binding, or inventory writes.
"""

import ipaddress
import re

from ..transport_ssh import HA_STATE, RUNNING_HA
from .panos import DiscoveryError, _container, _one, _result, _text

CONTRACT = "panos-ha-v1"
_UINT = re.compile(r"[0-9]{1,19}")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
_ENUM = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}")


def _shape(element, *, forbid_group_rows=False):
    """Validate singleton containers without serializing unknown configuration."""
    if element is None:
        return
    _container(element)
    seen = set()
    for child in element:
        if child.tag in seen:
            raise DiscoveryError("PAN-OS HA XML contains duplicate fields or containers")
        seen.add(child.tag)
        if forbid_group_rows and child.tag in {"entry", "group", "groups"}:
            raise DiscoveryError("PAN-OS HA XML contains an unsupported group structure")
    if forbid_group_rows and any(key in element.attrib for key in ("name", "id")):
        raise DiscoveryError("PAN-OS HA XML contains an unsupported group identity")


def _reject_semantic_errors(element, *, recursive=True):
    """Inspect marker names/status only, without retaining diagnostic contents."""
    if element is None:
        return
    nodes = element.iter() if recursive else (element,)
    for node in nodes:
        if node.tag in {"error", "msg"} or node.get("status", "").casefold() == "error":
            raise DiscoveryError("PAN-OS HA response contains a semantic error marker")


def _semantic_result(output, command):
    result = _result(output, command)
    _shape(result)
    _reject_semantic_errors(result, recursive=False)
    # Configuration reads include unrelated deviceconfig branches. Inspect only
    # the envelope here; each parser defines its own recursive evidence scope.
    for child in result:
        if child.tag in {"error", "msg"}:
            _reject_semantic_errors(child, recursive=False)
    return result


def _boolean(value):
    if value not in {"yes", "no"}:
        raise DiscoveryError("PAN-OS HA XML contains an invalid explicit boolean")
    return value == "yes"


def _uint(value, maximum=(1 << 63) - 1):
    if _UINT.fullmatch(value) is None or int(value) > maximum:
        raise DiscoveryError("PAN-OS HA XML contains an invalid nonnegative integer")
    return int(value)


def _priority(value):
    return _uint(value, 255)


def _enum(value):
    if _ENUM.fullmatch(value) is None:
        raise DiscoveryError("PAN-OS HA XML contains an invalid enum token")
    # Unknown scalar enum values are observations, not inferred native choices.
    return value


def _token(value):
    if _TOKEN.fullmatch(value) is None:
        raise DiscoveryError("PAN-OS HA XML contains an invalid identity or port token")
    return value


def _serial(value):
    if value.casefold() in {"unknown", "none", "n/a", "null", "0"}:
        return None
    return _token(value)


def _ip(value):
    try:
        return str(ipaddress.ip_interface(value) if "/" in value else ipaddress.ip_address(value))
    except ValueError:
        raise DiscoveryError("PAN-OS HA XML contains an invalid IP address") from None


def _ipv4(value):
    parsed = _ip(value)
    if ":" in parsed:
        raise DiscoveryError("PAN-OS HA XML contains the wrong IP address family")
    return parsed


def _ipv6(value):
    parsed = _ip(value)
    if ":" not in parsed:
        raise DiscoveryError("PAN-OS HA XML contains the wrong IP address family")
    return parsed


def _netmask(value):
    try:
        address = ipaddress.IPv4Address(value)
        network = ipaddress.IPv4Network("0.0.0.0/" + value)
        if network.netmask != address:
            raise ValueError("hostmask is not a netmask")
    except ValueError:
        raise DiscoveryError("PAN-OS HA XML contains an invalid IPv4 netmask") from None
    return value


def _mac(value):
    if _MAC.fullmatch(value) is None:
        raise DiscoveryError("PAN-OS HA XML contains an invalid MAC address")
    return value.lower()


class _Fields:
    """Read only approved paths and retain safe source/presence metadata."""

    def __init__(self, result, command, path):
        self.result = result
        self.source = {"contract": CONTRACT, "command": command, "path": path, "fields": {}}

    def get(self, fact, path, parser=None):
        node = _one(self.result, path)
        value = _text(self.result, path)
        if node is not None and node.attrib:
            raise DiscoveryError("PAN-OS HA XML scalar contains unsupported attributes")
        self.source["fields"][fact] = {
            "path": "result/" + path,
            "presence": "absent" if node is None else "blank" if value is None else "value",
        }
        return parser(value) if value is not None and parser is not None else value


def _runtime_identity(fields, side):
    path = "group/" + side + "-info/"
    return {
        "role": fields.get(side + ".role", path + "state", _enum),
        "mode": fields.get(side + ".mode", path + "mode", _enum),
        "serial": fields.get(side + ".serial", path + "serial-num", _serial),
        # This HA source does not expose a reviewed VM UUID path. The selected
        # local device's independent system UUID binding is owned by collect().
        "vm_uuid": None,
        "platform": fields.get(side + ".platform", path + "platform-model", _token),
        "software_version": fields.get(side + ".software_version", path + "build-rel", _token),
        "vm_license_reported": fields.get(
            side + ".vm_license_reported", path + "vm-license", _enum
        ),
        "management_ip": fields.get(side + ".management_ip", path + "mgmt-ip", _ipv4),
        "management_ipv6": fields.get(side + ".management_ipv6", path + "mgmt-ipv6", _ipv6),
        "priority": fields.get(side + ".priority", path + "priority", _priority),
        "preemptive": fields.get(side + ".preemptive", path + "preemptive", _boolean),
        "state_duration": fields.get(side + ".state_duration", path + "state-duration", _uint),
    }


def _runtime_link(fields, name):
    local = "group/local-info/" + name
    peer = "group/peer-info/" + name
    connection = "group/peer-info/conn-" + name + "/"
    link = {
        "local_port": fields.get(name + ".local_port", local + "-port", _token),
        "local_mac": fields.get(name + ".local_mac", local + "-macaddr", _mac),
        "peer_mac": fields.get(name + ".peer_mac", peer + "-macaddr", _mac),
        "peer_status": fields.get(name + ".peer_status", connection + "conn-status", _enum),
        "peer_primary": fields.get(name + ".peer_primary", connection + "conn-primary", _boolean),
    }
    if name == "ha1":
        link["local_ip"] = fields.get(name + ".local_ip", local + "-ipaddr", _ip)
        link["peer_ip"] = fields.get(name + ".peer_ip", peer + "-ipaddr", _ip)
    else:
        # Preserve the actual source spelling rather than silently fixing it.
        link["peer_keepalive_enabled"] = fields.get(
            name + ".peer_keepalive_enabled", connection + "conn-ka-enbled", _boolean
        )
        link["peer_keepalive_type"] = fields.get(
            name + ".peer_keepalive_type", connection + "conn-type", _enum
        )
        link["peer_keepalive_hold"] = fields.get(
            name + ".peer_keepalive_hold", connection + "conn-hold", _uint
        )
    return link


def parse_ha_state(output, command=HA_STATE):
    """Parse one observed HA group; disabled HA is a valid explicit fact."""
    result = _semantic_result(output, command)
    _reject_semantic_errors(result)
    group = _one(result, "group")
    _shape(group, forbid_group_rows=True)
    for path in (
        "group/local-info",
        "group/peer-info",
        "group/peer-info/conn-ha1",
        "group/peer-info/conn-ha2",
        "group/link-monitoring",
        "group/path-monitoring",
    ):
        _shape(_one(result, path))
    fields = _Fields(result, command, "result")
    enabled = fields.get("enabled", "enabled", _boolean)
    if group is None and enabled is not False:
        raise DiscoveryError("PAN-OS HA XML is missing the expected runtime group")
    reviewed_group_tags = {
        "mode",
        "local-info",
        "peer-info",
        "running-sync",
        "running-sync-enabled",
    }
    if (
        enabled is not False
        and group is not None
        and not any(child.tag in reviewed_group_tags for child in group)
    ):
        raise DiscoveryError("PAN-OS HA XML has no recognized runtime group structure")
    return {
        "source": fields.source,
        "enabled": enabled,
        "mode": fields.get("mode", "group/mode", _enum),
        "local": _runtime_identity(fields, "local"),
        "peer": _runtime_identity(fields, "peer"),
        "peer_connection_status": fields.get(
            "peer_connection_status", "group/peer-info/conn-status", _enum
        ),
        "peer_identity_resolved": False,
        "identity_limitations": ["HA source does not expose a reviewed local or peer VM UUID"],
        "links": {name: _runtime_link(fields, name) for name in ("ha1", "ha2")},
        "synchronization": {
            "state_status": fields.get(
                "synchronization.state_status", "group/local-info/state-sync", _enum
            ),
            "state_transport": fields.get(
                "synchronization.state_transport", "group/local-info/state-sync-type", _enum
            ),
            "running_config_enabled": fields.get(
                "synchronization.running_config_enabled", "group/running-sync-enabled", _boolean
            ),
            "running_config_status": fields.get(
                "synchronization.running_config_status", "group/running-sync", _enum
            ),
        },
    }


def _configured_mode(fields):
    node = _one(fields.result, "deviceconfig/high-availability/group/mode")
    _shape(node)
    children = list(node) if node is not None else []
    if len(children) > 1:
        raise DiscoveryError("PAN-OS HA configuration contains ambiguous modes")
    fields.source["fields"]["mode"] = {
        "path": "result/deviceconfig/high-availability/group/mode",
        "presence": "absent" if node is None else "blank" if not children else "value",
    }
    if not children:
        return None
    child = children[0]
    _shape(child)
    mode = _enum(child.tag)
    fields.source["fields"]["mode"]["path"] += "/" + child.tag
    return mode


def _configured_link(fields, name):
    path = "deviceconfig/high-availability/interface/" + name + "/"
    return {
        "port": fields.get(name + ".port", path + "port", _token),
        "ip_address": fields.get(name + ".ip_address", path + "ip-address", _ip),
        "netmask": fields.get(name + ".netmask", path + "netmask", _netmask),
        "gateway": fields.get(name + ".gateway", path + "gateway", _ip),
    }


def parse_ha_configuration(output, command=RUNNING_HA):
    """Parse HA within the exact applied deviceconfig ancestor; discard all else."""
    result = _semantic_result(output, command)
    if any(child.tag != "deviceconfig" for child in result):
        raise DiscoveryError("PAN-OS HA configuration has an unsupported result wrapper")
    deviceconfig = _one(result, "deviceconfig", required=True)
    _shape(deviceconfig)
    _reject_semantic_errors(deviceconfig, recursive=False)
    for child in deviceconfig:
        if child.tag in {"error", "msg"}:
            _reject_semantic_errors(child, recursive=False)
    ha = _one(deviceconfig, "high-availability")
    _reject_semantic_errors(ha)
    _shape(ha)
    group = _one(ha, "group") if ha is not None else None
    _shape(group, forbid_group_rows=True)
    for path in (
        "interface",
        "interface/ha1",
        "interface/ha2",
        "group/election-option",
        "group/configuration-synchronization",
        "group/state-synchronization",
        "group/state-synchronization/ha2-keep-alive",
    ):
        _shape(_one(ha, path) if ha is not None else None)
    fields = _Fields(result, command, "result/deviceconfig")
    fields.source["fields"]["present"] = {
        "path": "result/deviceconfig/high-availability",
        "presence": "absent" if ha is None else "value",
    }
    enabled = fields.get("enabled", "deviceconfig/high-availability/enabled", _boolean)
    if enabled is True and group is None:
        raise DiscoveryError("PAN-OS HA configuration is missing the enabled HA group")
    mode = _configured_mode(fields)
    prefix = "deviceconfig/high-availability/group/"
    return {
        "source": fields.source,
        "present": ha is not None,
        "enabled": enabled,
        "group_id": fields.get("group_id", prefix + "group-id", _uint),
        "description": fields.get("description", prefix + "description"),
        "mode": mode,
        "passive_link_state": fields.get(
            "passive_link_state", prefix + "mode/active-passive/passive-link-state", _enum
        ),
        "peer_ip": fields.get("peer_ip", prefix + "peer-ip", _ip),
        "election": {
            "device_priority": fields.get(
                "election.device_priority", prefix + "election-option/device-priority", _priority
            ),
            "preemptive": fields.get(
                "election.preemptive", prefix + "election-option/preemptive", _boolean
            ),
        },
        "interfaces": {name: _configured_link(fields, name) for name in ("ha1", "ha2")},
        "synchronization": {
            "running_config_enabled": fields.get(
                "synchronization.running_config_enabled",
                prefix + "configuration-synchronization/enabled",
                _boolean,
            ),
            "state_enabled": fields.get(
                "synchronization.state_enabled", prefix + "state-synchronization/enabled", _boolean
            ),
            "state_transport": fields.get(
                "synchronization.state_transport", prefix + "state-synchronization/transport", _enum
            ),
            "ha2_keepalive_enabled": fields.get(
                "synchronization.ha2_keepalive_enabled",
                prefix + "state-synchronization/ha2-keep-alive/enabled",
                _boolean,
            ),
            "ha2_keepalive_action": fields.get(
                "synchronization.ha2_keepalive_action",
                prefix + "state-synchronization/ha2-keep-alive/action",
                _enum,
            ),
        },
    }
