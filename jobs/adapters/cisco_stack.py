"""StackWise member identities from structured Cisco RESTCONF operational data.

NtC Device Onboarding 5.6 names the VirtualChassis after the hostname and
nonactive Devices ``hostname:position``. Membership uses explicit serial
joins here, never upstream's CLI list order or an inventory physical index.
https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-stack-oper.yang
"""

import re

from ..transport_restconf import RestconfError

STACK_PATH = "/data/Cisco-IOS-XE-stack-oper:stack-oper-data"
STACK_FIELDS = (
    "stack-info(size;ring-status;stack-mac-address);"
    "stack-node(chassis-number;priority;serial-number;role;node-state;stack-mode)"
)
HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
ABSENT_STATES = frozenset(("state-provisioned", "state-removed", "state-unprovisioned"))
ROLES = frozenset(("role-active", "role-standby", "role-member"))
DEFERRED_PLACEMENT = (
    "Physical member ownership for serialized components, console connectors, and dedicated "
    "management ports requires a reviewed stack placement profile; existing records are preserved"
)


class StackDiscoveryError(ValueError):
    """Stack identities cannot be safely reconciled with physically present hardware."""


def _value(mapping, name, module):
    if not isinstance(mapping, dict):
        return None
    matches = [(key, value) for key, value in mapping.items() if key.split(":")[-1] == name]
    if len(matches) > 1 or any(key not in (name, module + ":" + name) for key, _ in matches):
        raise StackDiscoveryError("Stack identity has ambiguous or unexpected YANG namespaces")
    return matches[0][1] if matches else None


def _text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise StackDiscoveryError("Stack identity leaves must be structured strings")
    return value.strip() or None


def _enum(value):
    text = _text(value)
    return text.split(":")[-1] if text else None


def _integer(value, label, *, optional=False):
    if optional and value is None:
        return None
    if type(value) is not int or not 0 <= value <= 255:
        raise StackDiscoveryError("Stack %s must be a uint8 integer" % label)
    if label == "chassis-number" and value == 0:
        raise StackDiscoveryError("Stack chassis-number must be positive")
    return value


def _inventory(inventory):
    chassis, serials = [], set()
    for row in inventory:
        if _enum(row.get("hw-type")) != "hw-type-chassis":
            continue
        serial, model = _text(row.get("serial-number")), _text(row.get("part-number"))
        if serial is None or model is None:
            raise StackDiscoveryError(
                "Chassis inventory lacks structured part-number or serial-number"
            )
        if serial in serials:
            raise StackDiscoveryError("Hardware inventory repeats a chassis serial-number")
        serials.add(serial)
        chassis.append({"serial": serial, "model": model, "row": row})
    if not chassis:
        raise StackDiscoveryError("Hardware inventory contains no physical chassis")
    return chassis


def collect(client, inventory, *, hostname, warnings):
    """Collect ready members; missing optional data never changes a lone Device."""
    chassis = _inventory(inventory)
    result = {
        "schema_version": 1,
        "name": hostname,
        "is_stack": False,
        "active_position": None,
        "active_identity": None,
        "members": [],
        "absent_members": [],
        "observations": {},
        "unresolved": [],
        "source": {"module": "Cisco-IOS-XE-stack-oper", "path": STACK_PATH, "fields": STACK_FIELDS},
    }
    try:
        try:
            payload = client.get(STACK_PATH + "?fields=" + STACK_FIELDS)
        except RestconfError as exc:
            if exc.status_code != 400:
                raise
            warnings.append("Stack fields filter rejected (HTTP 400); unfiltered JSON read used")
            payload = client.get(STACK_PATH)
    except RestconfError as exc:
        if len(chassis) > 1:
            raise StackDiscoveryError(
                "Multiple chassis require the structured stack-oper source"
            ) from None
        result["unresolved"].append(
            {
                "reason": "Optional standalone stack-oper source is unavailable",
                "http_status": exc.status_code,
            }
        )
        return result
    container = _value(payload, "stack-oper-data", "Cisco-IOS-XE-stack-oper")
    rows = _value(container, "stack-node", "Cisco-IOS-XE-stack-oper")
    if not isinstance(container, dict) or rows is None:
        if len(chassis) > 1:
            raise StackDiscoveryError("Multiple chassis require structured stack-node identities")
        result["unresolved"].append(
            {"reason": "Optional standalone stack-node evidence is unavailable"}
        )
        return result
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise StackDiscoveryError("Stack-node must be a structured list of objects")
    info = _value(container, "stack-info", "Cisco-IOS-XE-stack-oper")
    if info is not None and not isinstance(info, dict):
        raise StackDiscoveryError("Stack-info must be a structured object")
    result["observations"]["stack_info"] = info or {}
    by_serial = {entry["serial"]: entry for entry in chassis}
    nodes, serial_holders = {}, {}
    for row in rows:
        position = _integer(
            _value(row, "chassis-number", "Cisco-IOS-XE-stack-oper"), "chassis-number"
        )
        if position in nodes:
            raise StackDiscoveryError("Stack-oper repeats a chassis-number")
        serial = _text(_value(row, "serial-number", "Cisco-IOS-XE-stack-oper"))
        role = _enum(_value(row, "role", "Cisco-IOS-XE-stack-oper"))
        state = _enum(_value(row, "node-state", "Cisco-IOS-XE-stack-oper"))
        mode = _enum(_value(row, "stack-mode", "Cisco-IOS-XE-stack-oper"))
        priority = _integer(
            _value(row, "priority", "Cisco-IOS-XE-stack-oper"), "priority", optional=True
        )
        node = {
            "position": position,
            "serial": serial,
            "role": role,
            "state": state,
            "stack_mode": mode,
            "priority": priority,
        }
        nodes[position] = node
        if serial is not None:
            if serial in serial_holders:
                raise StackDiscoveryError("Stack-oper repeats serial-number across chassis nodes")
            serial_holders[serial] = position
        if state in ABSENT_STATES:
            if serial is not None and serial in by_serial:
                raise StackDiscoveryError(
                    "An absent stack node contradicts physical chassis inventory"
                )
            result["absent_members"].append(
                {**node, "reason": "Device reports an absent or provisioned slot"}
            )
            continue
        if state != "state-ready" or role not in ROLES or mode != "mode-stackwise-rear":
            if len(chassis) > 1:
                raise StackDiscoveryError(
                    "Physical stack members require ready state, known role, "
                    "and StackWise rear mode"
                )
            result["unresolved"].append(
                {**node, "reason": "Stack node has no reviewed ready StackWise rear interpretation"}
            )
            continue
        hardware = by_serial.get(serial) if serial is not None else None
        if hardware is None:
            raise StackDiscoveryError(
                "Ready stack-node serial does not uniquely match physical chassis inventory"
            )
        name = _text(hardware["row"].get("dev-name"))
        named = re.fullmatch(r"Switch\s+(\d+)", name or "", re.IGNORECASE)
        if named and int(named.group(1)) != position:
            raise StackDiscoveryError("Stack member position contradicts the hardware Switch name")
        facts = {
            **node,
            "serial": hardware["serial"],
            "model": hardware["model"],
            "sources": {
                "membership": {
                    **result["source"],
                    "chassis_number": position,
                    "fields": {
                        "position": "chassis-number",
                        "priority": "priority",
                        "role": "role",
                        "state": "node-state",
                        "serial": "serial-number",
                        "stack_mode": "stack-mode",
                    },
                },
                "identity": {
                    "module": "Cisco-IOS-XE-device-hardware-oper",
                    "path": HARDWARE_PATH,
                    "field": "device-hardware/device-inventory[hw-type=hw-type-chassis]",
                    "join_rule": (
                        "unique trimmed chassis serial-number equals stack-node serial-number"
                    ),
                    "dev_name": name,
                    "inventory_index": hardware["row"].get("hw-dev-index"),
                    "fields": {"model": "part-number", "serial": "serial-number"},
                },
            },
        }
        result["members"].append(facts)
    if len(chassis) > 1 and len(result["members"]) != len(chassis):
        raise StackDiscoveryError(
            "Every physical stack chassis requires a validated ready stack-node"
        )
    active = [row for row in result["members"] if row["role"] == "role-active"]
    if result["members"] and len(active) != 1:
        raise StackDiscoveryError("Stack-oper must identify exactly one active physical chassis")
    if active:
        result["active_position"] = active[0]["position"]
        result["active_identity"] = {
            "model": active[0]["model"],
            "serial": active[0]["serial"],
            "position": active[0]["position"],
            "sources": active[0]["sources"],
        }
    result["is_stack"] = len(result["members"]) >= 2
    result["members"].sort(key=lambda row: row["position"])
    result["absent_members"].sort(key=lambda row: row["position"])
    return result


def inventory_for_member(inventory, member):
    """Select explicit Switch/member names; physical inventory indexes are not joins."""
    result = []
    position = member["position"]
    for row in inventory:
        name = _text(row.get("dev-name")) or ""
        chassis = _enum(row.get("hw-type")) == "hw-type-chassis"
        same_chassis = chassis and _text(row.get("serial-number")) == member["serial"]
        named = re.match(r"^Switch\s+(\d+)(?:\s|$)", name, re.IGNORECASE)
        interface = re.fullmatch(r"[A-Za-z][A-Za-z-]*(\d+)/(\d+)/(\d+)", name)
        if (
            same_chassis
            or (named and int(named.group(1)) == position)
            or (interface and int(interface.group(1)) == position)
        ):
            result.append(row)
    return result


def add_revisions(result, modules):
    """Attach successfully retrieved module revisions without changing evidence."""
    result["source"]["revision"] = modules.get("Cisco-IOS-XE-stack-oper")
    for member in result["members"]:
        for source in member["sources"].values():
            source["revision"] = modules.get(source["module"])
