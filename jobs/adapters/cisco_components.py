"""Reviewed serialized Cisco components, collected only from RESTCONF JSON.

Identity comes from device-hardware-oper; platform-oper corroborates identity
and supplies placement. Numeric inventory indexes are evidence, never joins.
The first profile covers a C9300-48UXM, C3850-NM-4-1G uplink and
PWR-C1-1100WAC-P power supplies. Unknown parts remain explicit observations.

Platform fields are documented in Cisco's published YANG model:
https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17111/Cisco-IOS-XE-platform-oper.yang
"""

import re
from collections import Counter

from ..transport_restconf import RestconfError

HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
PLATFORM_PATH = "/data/Cisco-IOS-XE-platform-oper:components"
INTERFACES_PATH = "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
PLATFORM_FIELDS = (
    "component(cname;state(type;id;description;serial-no;part-no;version;location;"
    "empty;removable;parent;status;status-desc);platform-subcomponents)"
)
PROFILE = "c9300-48uxm-serialized-components-v1"
CATALOG = {
    "C3850-NM-4-1G": ("network-module", "hw-type-pim"),
    "PWR-C1-1100WAC-P": ("power-supply", "hw-type-pem"),
}


class ComponentDiscoveryError(ValueError):
    """Serialized identity is malformed or cannot be uniquely corroborated."""


def _value(mapping, name):
    if not isinstance(mapping, dict):
        return None
    return next((value for key, value in mapping.items() if key.split(":")[-1] == name), None)


def _text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ComponentDiscoveryError("Component identity and placement leaves must be strings")
    text = value.strip()
    return text if text and text != "NULL" else None


def _enum(value):
    text = _text(value)
    return text.split(":")[-1] if text else None


def _rows(value):
    if value is None:
        return []
    rows = value if isinstance(value, list) else [value]
    if any(not isinstance(row, dict) for row in rows):
        raise ComponentDiscoveryError("Platform components must contain structured objects")
    return rows


def _flat_fact(row):
    return {
        "name": _text(row.get("dev-name")),
        "hw_type": _enum(row.get("hw-type")),
        "hardware_class": _enum(row.get("hw-class")),
        "inventory_index": row.get("hw-dev-index"),
        "model": _text(row.get("part-number")),
        "serial": _text(row.get("serial-number")),
        "hardware_revision": _text(row.get("version")),
        "field_replaceable": row.get("field-replaceable"),
    }


def _platform_fact(row):
    state = _value(row, "state")
    if not isinstance(state, dict):
        raise ComponentDiscoveryError("Platform component lacks structured state")
    fact = {
        "name": _text(_value(row, "cname")),
        "model": _text(_value(state, "part-no")),
        "serial": _text(_value(state, "serial-no")),
        "hardware_revision": _text(_value(state, "version")),
        "platform_type": _enum(_value(state, "type")),
        "platform_id": _text(_value(state, "id")),
        "parent": _text(_value(state, "parent")),
        "location": _text(_value(state, "location")),
        "empty": _value(state, "empty"),
        "removable": _value(state, "removable"),
        "oper_status": _enum(_value(state, "status")),
        "status_description": _enum(_value(state, "status-desc")),
    }
    if not fact["name"]:
        raise ComponentDiscoveryError("Platform component lacks a structured name")
    for key in ("empty", "removable"):
        if fact[key] is not None and not isinstance(fact[key], bool):
            raise ComponentDiscoveryError("Platform component %s must be a boolean" % key)
    return fact


def _identity_source(fact):
    return {
        "module": "Cisco-IOS-XE-device-hardware-oper",
        "path": HARDWARE_PATH,
        "field": "device-hardware/device-inventory",
        "hw_type": fact["hw_type"],
        "inventory_index": fact["inventory_index"],
        "fields": {
            "model": "part-number",
            "serial": "serial-number",
            "hardware_revision": "version",
        },
    }


def _placement_source(fact):
    return {
        "module": "Cisco-IOS-XE-platform-oper",
        "path": PLATFORM_PATH,
        "component": fact["name"],
        "fields": {
            "parent": "state/parent",
            "location": "state/location",
            "hardware_revision": "state/version",
        },
        "identity_join_rule": "unique trimmed part-number/part-no and serial-number/serial-no",
        "profile": PROFILE,
    }


def _profile_placement(fact, member):
    if fact["parent"] != "Switch%d" % member:
        return None, "Platform parent does not match the reviewed chassis component"
    if fact["empty"] is not False or fact["removable"] is not True:
        return None, "Serialized component presence/removability needs review"
    if fact["model"] == "C3850-NM-4-1G":
        expected_name = "FRUUplinkModule%d/1" % member
        if fact["name"] != expected_name or fact["location"] != "%d/0/1/1" % member:
            return None, "Uplink placement does not match the reviewed slot-1 profile"
        # The lab reports comp-port for this module. Accept that specific
        # reviewed quirk and the model's proper module/FRU classifications.
        if fact["platform_type"] not in ("comp-port", "comp-module", "comp-fru"):
            return None, "Uplink platform classification needs review"
        return {
            "key": "uplink:%d/1" % member,
            "bay": {"name": "Uplink Module 1", "position": "1", "label": "Uplink Module 1"},
        }, None
    match = re.fullmatch(r"PowerSupply(\d+)/([AB])", fact["name"])
    if match is None or int(match.group(1)) != member:
        return None, "Power-supply name does not identify a reviewed chassis bay"
    slot = match.group(2)
    if fact["location"] != "%d/0/%s/0" % (member, slot):
        return None, "Power-supply location does not match the reviewed bay profile"
    if fact["platform_type"] != "comp-power-supply":
        return None, "Power-supply platform classification needs review"
    return {
        "key": "psu:%d/%s" % (member, slot),
        "bay": {
            "name": "Power Supply %s" % slot,
            "position": "PSU-%s" % slot,
            "label": "Power Supply %s" % slot,
        },
    }, None


def _expected_platform_name(fact, member):
    if (
        fact["model"] == "C3850-NM-4-1G"
        and fact["name"] == "Switch %d FRU Uplink Module 1" % member
    ):
        return "FRUUplinkModule%d/1" % member
    match = re.fullmatch(r"Switch (\d+) - Power Supply ([AB])", fact["name"] or "")
    if fact["model"] == "PWR-C1-1100WAC-P" and match and int(match.group(1)) == member:
        return "PowerSupply%d/%s" % (member, match.group(2))
    return None


def collect(client, inventory, *, chassis_model, chassis_serial, member, interfaces, warnings):
    """Return reviewed items and visible unresolved/excluded observations."""
    result = {"schema_version": 1, "items": [], "unresolved": [], "excluded": []}
    flat = []
    for row in inventory:
        fact = _flat_fact(row)
        if fact["hw_type"] == "hw-type-chassis":
            result["excluded"].append(
                {**fact, "reason": "Chassis is represented by the existing Device"}
            )
        elif (
            chassis_model == "C9300-48UXM"
            and fact["hw_type"] == "hw-type-emmc"
            and fact["hardware_class"] == "hw-class-physical"
            and fact["name"] == "c93xx Stack"
            and fact["model"] == chassis_model
            and fact["serial"] == chassis_serial
            and fact["field_replaceable"] is False
        ):
            result["excluded"].append(
                {**fact, "reason": "Reviewed stack aggregate alias repeats the chassis identity"}
            )
        elif (
            fact["hw_type"] in ("hw-type-cpu", "hw-type-dram", "hw-type-flash")
            and not fact["serial"]
        ):
            result["excluded"].append(
                {**fact, "reason": "Internal component has no serialized identity"}
            )
        else:
            flat.append(fact)
    try:
        payload = client.get(PLATFORM_PATH + "?fields=" + PLATFORM_FIELDS)
    except RestconfError as exc:
        if exc.status_code == 400:
            warnings.append(
                "Component platform fields filter rejected (HTTP 400); unfiltered JSON read used"
            )
            try:
                payload = client.get(PLATFORM_PATH)
            except RestconfError:
                payload = None
        else:
            payload = None
    container = _value(payload, "components")
    platform = []
    if container is None:
        warnings.append(
            "Component placement source unavailable; serialized components remain unresolved"
        )
    elif not isinstance(container, dict):
        raise ComponentDiscoveryError("Platform components reply must be a structured container")
    else:
        platform = [_platform_fact(row) for row in _rows(_value(container, "component"))]
    names = Counter(fact["name"] for fact in platform)
    if any(count > 1 for count in names.values()):
        raise ComponentDiscoveryError("Platform component names are ambiguous")
    expected_root = "Switch%d" % member
    root = next((fact for fact in platform if fact["name"] == expected_root), None)
    if root and (root["model"] != chassis_model or root["serial"] != chassis_serial):
        raise ComponentDiscoveryError("Platform chassis identity contradicts hardware inventory")
    pairs = Counter(
        (fact["model"], fact["serial"]) for fact in flat if fact["model"] and fact["serial"]
    )
    handled_platform_names = set()
    for fact in flat:
        unresolved = {**fact, "source": {"identity": _identity_source(fact)}}
        if not fact["model"] or not fact["serial"]:
            reason = "Serialized component model or serial number is unavailable"
        elif chassis_model != "C9300-48UXM" or fact["model"] not in CATALOG:
            reason = "Serialized part or chassis has no reviewed component profile"
        else:
            kind, expected_type = CATALOG[fact["model"]]
            if (
                fact["hw_type"] != expected_type
                or fact["hardware_class"] != "hw-class-physical"
                or fact["field_replaceable"] is not True
            ):
                raise ComponentDiscoveryError(
                    "Reviewed serialized part has contradictory hardware classification"
                )
            if pairs[(fact["model"], fact["serial"])] != 1:
                raise ComponentDiscoveryError(
                    "Reviewed serialized identity occurs in multiple inventory entries"
                )
            matches = [
                part
                for part in platform
                if (part["model"], part["serial"]) == (fact["model"], fact["serial"])
            ]
            if len(matches) > 1:
                raise ComponentDiscoveryError(
                    "Serialized identity matches multiple platform components"
                )
            if not matches:
                expected_name = _expected_platform_name(fact, member)
                at_expected_bay = next(
                    (part for part in platform if part["name"] == expected_name), None
                )
                if at_expected_bay and at_expected_bay["model"] and at_expected_bay["serial"]:
                    raise ComponentDiscoveryError(
                        "Serialized inventory and platform identities disagree at a reviewed bay"
                    )
                reason = "No unique platform identity match establishes component placement"
            elif root is None:
                reason = "Platform chassis identity is unavailable for parent validation"
            else:
                part = matches[0]
                handled_platform_names.add(part["name"])
                unresolved["observations"] = part
                unresolved["source"]["placement"] = _placement_source(part)
                placement, reason = _profile_placement(part, member)
                if placement is not None:
                    ownership = {
                        "method": "reviewed-profile",
                        "profile": PROFILE,
                        "rule": "C3850-NM-4-1G in uplink slot 1 owns GigabitEthernet<member>/1/1-4"
                        if kind == "network-module"
                        else "Power supply has no network interfaces",
                        "module": "Cisco-IOS-XE-interfaces-oper",
                        "path": INTERFACES_PATH,
                        "meaning": (
                            "Interface ownership follows the reviewed hardware/slot profile; "
                            "the platform does not report the child relationship"
                        ),
                    }
                    expected_ports = (
                        ["GigabitEthernet%d/1/%d" % (member, port) for port in range(1, 5)]
                        if kind == "network-module"
                        else []
                    )
                    observed_names = {interface["name"] for interface in interfaces}
                    owned_ports = [name for name in expected_ports if name in observed_names]
                    missing_ports = [name for name in expected_ports if name not in observed_names]
                    if missing_ports:
                        result["unresolved"].append(
                            {
                                "component_key": placement["key"],
                                "interfaces": missing_ports,
                                "reason": (
                                    "Expected module interfaces are absent "
                                    "from eligible observations"
                                ),
                            }
                        )
                    result["items"].append(
                        {
                            **placement,
                            "kind": kind,
                            "manufacturer": "Cisco",
                            "model": fact["model"],
                            "part_number": fact["model"],
                            "serial": fact["serial"],
                            "hardware_revision": fact["hardware_revision"]
                            or part["hardware_revision"],
                            "parent_key": None,
                            "interfaces": owned_ports,
                            "source": {
                                "identity": _identity_source(fact),
                                "placement": _placement_source(part),
                                "ownership": ownership,
                            },
                            "observations": part,
                        }
                    )
                    continue
        result["unresolved"].append({**unresolved, "reason": reason})
    flat_pairs = {
        (fact["model"], fact["serial"]) for fact in flat if fact["model"] and fact["serial"]
    }
    for part in platform:
        if part["name"] in handled_platform_names:
            continue
        if part["model"] and part["serial"]:
            if part["name"] == expected_root:
                continue
            if (
                chassis_model == "C9300-48UXM"
                and part["name"] == "c93xx Stack"
                and part["model"] == chassis_model
                and part["serial"] == chassis_serial
                and part["removable"] is False
                and part["platform_type"] == "comp-chassis"
            ):
                result["excluded"].append(
                    {**part, "reason": "Reviewed platform stack aggregate aliases the chassis"}
                )
            elif (part["model"], part["serial"]) not in flat_pairs:
                result["unresolved"].append(
                    {
                        **part,
                        "source": {"placement": _placement_source(part)},
                        "reason": (
                            "Serialized platform component has no hardware inventory identity match"
                        ),
                    }
                )
        elif part["platform_type"] in ("comp-fan", "comp-power-supply"):
            result["unresolved"].append(
                {
                    **part,
                    "source": {"placement": _placement_source(part)},
                    "reason": (
                        "Component identity is unavailable; presence or occupancy "
                        "is not inferred from operational state"
                    ),
                }
            )
    result["items"].sort(key=lambda item: item["key"])
    for collection in ("unresolved", "excluded"):
        result[collection].sort(
            key=lambda item: (
                item.get("component_key") or "",
                item.get("name") or "",
                item.get("model") or "",
                item.get("serial") or "",
                item["reason"],
            )
        )
    return result


def add_revisions(components, modules):
    """Annotate provenance after the shared YANG-library evidence read."""
    for collection in ("items", "unresolved", "excluded"):
        for item in components[collection]:
            for source in item.get("source", {}).values():
                if isinstance(source, dict) and source.get("module"):
                    source["revision"] = modules.get(source["module"])
