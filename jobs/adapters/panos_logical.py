"""Configured logical interfaces and explicit aggregation membership.

Logical presence in effective configuration represents an instantiated interface,
not an operational link, tunnel-monitor or protocol state. PAN's reviewed logical
interface schemas have no independent administrative-disable control. A newly
observed administrative control is unresolved rather than silently defaulted.
Only allowlisted scalars are retained; addressing and authentication stay outside
this contract.
"""

import re

from ..transport_ssh import RUNNING_VPN
from .panos import DiscoveryError, _one, _text
from .panos_ipam import _entries, _parent
from .panos_vpn_config import _branch, _semantic_errors

CONTRACT = "panos-logical-interfaces-v1"
ADMIN_SEMANTICS = "effective-configured-logical-instantiation"
MODES = ("layer3", "layer2", "virtual-wire", "ha", "aggregate-group")
KINDS = {
    "ethernet-subinterface": (r"(?P<parent>ethernet[0-9]+/[0-9]+(?:/[0-9]+)?)\.[0-9]+", "virtual"),
    "aggregate-subinterface": (r"(?P<parent>ae[0-9]+)\.[0-9]+", "virtual"),
    "aggregate-ethernet": (r"ae[0-9]+", "lag"),
    "loopback": (r"loopback\.[0-9]+", "virtual"),
    "tunnel": (r"tunnel\.[0-9]+", "tunnel"),
}
_CONTROLS = {
    "link-state",
    "enabled",
    "disabled",
    "enable",
    "disable",
    "admin-state",
    "admin-status",
}


def _administrative_tag(tag):
    return isinstance(tag, str) and (
        tag in _CONTROLS
        or tag.startswith(("admin-", "enable-", "disable-", "link-state-"))
        or tag == "shutdown"
    )


def _path(kind, mode):
    base = "result/network/interface/"
    if kind in {"loopback", "tunnel"}:
        return base + kind + "/units/entry"
    if kind == "aggregate-ethernet":
        return base + "aggregate-ethernet/entry"
    family = "ethernet" if kind == "ethernet-subinterface" else "aggregate-ethernet"
    return base + family + "/entry/" + mode + "/units/entry"


def _integer(raw, minimum, maximum):
    if raw is None:
        return None
    if not isinstance(raw, str) or len(raw) > 10 or re.fullmatch(r"[0-9]+", raw) is None:
        raise DiscoveryError("PAN-OS logical interface contains an invalid integer")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise DiscoveryError("PAN-OS logical interface integer is outside the reviewed range")
    return value


def canonical_row(evidence):
    """Recheck a compact allowlisted observation before native planning."""
    keys = {"name", "kind", "mode", "parent_name", "comment", "mtu", "tag", "controls"}
    if not isinstance(evidence, dict) or set(evidence) != keys:
        raise DiscoveryError("PAN-OS logical interface evidence is invalid")
    name, kind, mode = (evidence.get(key) for key in ("name", "kind", "mode"))
    if kind not in KINDS or not isinstance(name, str):
        raise DiscoveryError("PAN-OS logical interface kind is unreviewed")
    match = re.fullmatch(KINDS[kind][0], name)
    parent = match.groupdict().get("parent") if match else None
    if match is None or parent != evidence["parent_name"]:
        raise DiscoveryError("PAN-OS logical interface parent identity is invalid")
    if mode not in {"layer2", "layer3"} or kind in {"loopback", "tunnel"} and mode != "layer3":
        raise DiscoveryError("PAN-OS logical interface mode is unreviewed")
    comment = evidence["comment"]
    if comment is not None and (
        not isinstance(comment, str)
        or not comment.strip()
        or len(comment) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in comment)
    ):
        raise DiscoveryError("PAN-OS logical interface comment is invalid")
    controls = evidence["controls"]
    if not isinstance(controls, list) or any(
        not _administrative_tag(control) for control in controls
    ):
        raise DiscoveryError("PAN-OS logical interface control evidence is invalid")
    if controls != sorted(set(controls)):
        raise DiscoveryError("PAN-OS logical interface controls are duplicated")
    mtu = _integer(evidence["mtu"], 576, 9192)
    tag = _integer(evidence["tag"], 1, 4094)
    if (
        mode != "layer3"
        and mtu is not None
        or kind not in {"ethernet-subinterface", "aggregate-subinterface"}
        and tag is not None
    ):
        raise DiscoveryError("PAN-OS logical interface field has an invalid scope")
    path = _path(kind, mode)
    return {
        "name": name,
        "kind": kind,
        "mode": mode,
        "parent_name": parent,
        "type": KINDS[kind][1],
        "enabled": None if controls else True,
        "description": comment,
        "mtu": mtu,
        "tag": tag,
        "source": {
            "contract": CONTRACT,
            "command": RUNNING_VPN,
            "path": path,
            "configured_name": name,
            "parent_name": parent,
            "administrative_semantics": ADMIN_SEMANTICS,
            "evidence": evidence,
        },
    }


def _row(name, kind, mode, entry, body, parent=None):
    _semantic_errors(entry, recursive=True)
    _semantic_errors(body, recursive=True)
    if entry is not body and body.attrib:
        raise DiscoveryError("PAN-OS logical mode contains unsupported scope attributes")
    evidence = {
        "name": name,
        "kind": kind,
        "mode": mode,
        "parent_name": parent,
        "comment": _observed_scalar(entry, "comment", allow_empty=True),
        "mtu": _observed_scalar(body, "mtu") if mode == "layer3" else None,
        "tag": _observed_scalar(entry, "tag") if parent is not None else None,
        "controls": sorted(
            {node.tag for scope in (entry, body) for node in scope if _administrative_tag(node.tag)}
        ),
    }
    return canonical_row(evidence)


def _observed_scalar(element, path, *, allow_empty=False):
    node = _one(element, path)
    if node is None:
        return None
    _semantic_errors(node, recursive=True)
    if node.attrib or len(node):
        raise DiscoveryError("PAN-OS logical scalar contains unsupported structure")
    value = _text(element, path)
    if value is None and not allow_empty:
        raise DiscoveryError("PAN-OS logical scalar is missing a configured value")
    return value


def parse_logical_interfaces(network_output):
    network = _parent(network_output, RUNNING_VPN, "network")
    interface = _branch(network, "interface")
    rows, memberships, unresolved = [], [], []
    if interface is not None:
        for family in ("ethernet", "aggregate-ethernet"):
            for name, entry in _entries(_branch(interface, family)):
                modes = [mode for mode in MODES if _one(entry, mode) is not None]
                if len(modes) > 1:
                    raise DiscoveryError("PAN-OS logical interface has conflicting modes")
                mode = modes[0] if modes else None
                if mode == "aggregate-group":
                    target = _observed_scalar(entry, "aggregate-group")
                    if (
                        re.fullmatch(r"ethernet[0-9]+/[0-9]+(?:/[0-9]+)?", name) is None
                        or re.fullmatch(r"ae[0-9]+", target or "") is None
                    ):
                        raise DiscoveryError("PAN-OS aggregation membership identity is invalid")
                    memberships.append(
                        {
                            "name": name,
                            "lag_name": target,
                            "source": {
                                "contract": CONTRACT,
                                "command": RUNNING_VPN,
                                "path": "result/network/interface/ethernet/entry/aggregate-group",
                                "configured_name": name,
                                "value": target,
                            },
                        }
                    )
                if family == "aggregate-ethernet":
                    if mode in {"layer2", "layer3"}:
                        rows.append(_row(name, family, mode, entry, _branch(entry, mode)))
                    else:
                        unresolved.append(
                            {
                                "name": name,
                                "reason": "Aggregate mode has no reviewed native mapping",
                            }
                        )
                if mode in {"layer2", "layer3"}:
                    for child_name, child in _entries(_branch(entry, mode + "/units")):
                        kind = (
                            "ethernet-subinterface"
                            if family == "ethernet"
                            else "aggregate-subinterface"
                        )
                        rows.append(_row(child_name, kind, mode, child, child, name))
        for kind in ("loopback", "tunnel"):
            for name, entry in _entries(_branch(interface, kind + "/units")):
                rows.append(_row(name, kind, "layer3", entry, entry))
    if len({row["name"] for row in rows}) != len(rows):
        raise DiscoveryError("PAN-OS logical interface names are duplicated")
    for row in rows:
        if row["enabled"] is None:
            unresolved.append(
                {"name": row["name"], "reason": "Unreviewed logical administrative control"}
            )
    return {
        "contract": CONTRACT,
        "interfaces": rows,
        "memberships": memberships,
        "unresolved": unresolved,
        "source": {"command": RUNNING_VPN, "path": "result/network/interface", "complete": True},
    }


def validate_logical_interfaces(facts):
    if (
        not isinstance(facts, dict)
        or facts.get("contract") != CONTRACT
        or facts.get("source")
        != {
            "command": RUNNING_VPN,
            "path": "result/network/interface",
            "complete": True,
        }
    ):
        return False
    rows, memberships = facts.get("interfaces"), facts.get("memberships")
    if (
        not isinstance(rows, list)
        or not isinstance(memberships, list)
        or not isinstance(facts.get("unresolved"), list)
    ):
        return False
    try:
        if any(
            not isinstance(row, dict) or row != canonical_row(row.get("source", {}).get("evidence"))
            for row in rows
        ):
            return False
        if len({row["name"] for row in rows}) != len(rows):
            return False
        names = set()
        for row in memberships:
            name, target = row.get("name"), row.get("lag_name")
            if (
                not isinstance(name, str)
                or not isinstance(target, str)
                or name in names
                or re.fullmatch(r"ethernet[0-9]+/[0-9]+(?:/[0-9]+)?", name) is None
                or re.fullmatch(r"ae[0-9]+", target) is None
            ):
                return False
            names.add(name)
            if row != {
                "name": name,
                "lag_name": target,
                "source": {
                    "contract": CONTRACT,
                    "command": RUNNING_VPN,
                    "path": "result/network/interface/ethernet/entry/aggregate-group",
                    "configured_name": name,
                    "value": target,
                },
            }:
                return False
    except (DiscoveryError, TypeError, AttributeError):
        return False
    return True
