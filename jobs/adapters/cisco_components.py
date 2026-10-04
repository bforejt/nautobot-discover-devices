"""Reviewed serialized Cisco components, collected only from RESTCONF JSON.

Identity comes from device-hardware-oper; platform-oper corroborates identity
and supplies placement. Numeric inventory indexes are evidence, never joins.
The uplink/transceiver profile covers a C9300-48UXM and C3850-NM-4-1G.
Separate documented Catalyst 9300 PSU profiles establish chassis bays even
when occupant identity is unavailable, and resolve serialized supplies to
verified standalone or stack-member owners. The reviewed network module and its
nested transceivers use those same physical owners. Unknown parts remain observations.

Platform fields are documented in Cisco's published YANG model:
https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17111/Cisco-IOS-XE-platform-oper.yang
"""

import re
from collections import Counter
from copy import deepcopy
from decimal import Decimal, InvalidOperation

from ..transport_restconf import RestconfError
from . import cisco_psu_profiles as psu_profiles

HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
PLATFORM_PATH = "/data/Cisco-IOS-XE-platform-oper:components"
INTERFACES_PATH = "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
PLATFORM_FIELDS = (
    "component(cname;state(type;id;description;mfg-name;serial-no;part-no;version;location;"
    "empty;removable;parent;status;status-desc);platform-subcomponents;"
    "platform-properties/platform-property(name;value;configurable))"
)
PROFILE = "c9300-48uxm-serialized-components-v1"
TRANSCEIVER_PROFILE = "c9300-48uxm-c3850-nm-4-1g-transceivers-v1"
STACK_INTERFACE_DOCUMENT = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-18/configuration_guide/int_hw/"
    "b_1718_int_and_hw_9300_cg/configuring_interface_characteristics.html"
)
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


def _platform_properties(row, component):
    """Keep optional operational properties independent of identity validation."""
    properties = _value(row, "platform-properties")
    if properties is None:
        return None, []
    retained, errors = [], []
    source = {
        "module": "Cisco-IOS-XE-platform-oper",
        "path": PLATFORM_PATH,
        "component": component,
        "field": "platform-properties/platform-property",
        "meaning": "Raw typed property; units/interpretation are not inferred",
    }
    if not isinstance(properties, dict):
        return [], [{"reason": "Platform properties must be structured objects", "source": source}]
    values = _value(properties, "platform-property")
    rows = values if isinstance(values, list) else [values] if values is not None else []
    seen = set()
    for index, prop in enumerate(rows):
        name = None
        try:
            if not isinstance(prop, dict):
                raise ComponentDiscoveryError("Platform property must be a structured object")
            name = _text(_value(prop, "name"))
            value = _value(prop, "value")
            if not name or not isinstance(value, dict):
                raise ComponentDiscoveryError("Platform property lacks structured name/value")
            choices = [(key.split(":")[-1], value) for key, value in value.items()]
            if len(choices) != 1 or choices[0][0] not in (
                "string",
                "boolean",
                "intsixfour",
                "uintsixfour",
                "decimal",
            ):
                raise ComponentDiscoveryError(
                    "Platform property must contain one YANG value choice"
                )
            choice, leaf = choices[0]
            if choice == "string" and not isinstance(leaf, str):
                raise ComponentDiscoveryError("Platform string property has a non-string value")
            if choice == "boolean" and type(leaf) is not bool:
                raise ComponentDiscoveryError("Platform boolean property has a non-boolean value")
            if choice in ("intsixfour", "uintsixfour"):
                if type(leaf) is int:
                    integer = leaf
                elif isinstance(leaf, str) and re.fullmatch(r"-?\d+", leaf):
                    integer = int(leaf)
                else:
                    raise ComponentDiscoveryError("Platform integer property has an invalid value")
                minimum, maximum = (
                    (-(2**63), 2**63 - 1) if choice == "intsixfour" else (0, 2**64 - 1)
                )
                if not minimum <= integer <= maximum:
                    raise ComponentDiscoveryError(
                        "Platform integer property exceeds its YANG range"
                    )
            if choice == "decimal":
                if type(leaf) not in (str, int, float):
                    raise ComponentDiscoveryError("Platform decimal property has an invalid value")
                try:
                    valid_decimal = Decimal(str(leaf)).is_finite()
                except InvalidOperation:
                    valid_decimal = False
                if not valid_decimal:
                    raise ComponentDiscoveryError("Platform decimal property has an invalid value")
            configurable = _value(prop, "configurable")
            if configurable is not None and type(configurable) is not bool:
                raise ComponentDiscoveryError("Platform property configurable must be a boolean")
            if name in seen:
                retained = [item for item in retained if item["name"] != name]
                raise ComponentDiscoveryError("Platform property name is ambiguous")
            seen.add(name)
            retained.append(
                {
                    "name": name,
                    "value": {choice: deepcopy(leaf)},
                    "configurable": configurable,
                    "source": deepcopy(source),
                }
            )
        except ComponentDiscoveryError as exc:
            errors.append(
                {"property": name, "index": index, "reason": str(exc), "source": deepcopy(source)}
            )
    return sorted(retained, key=lambda prop: prop["name"]), errors


def _platform_fact(row):
    state = _value(row, "state")
    if not isinstance(state, dict):
        raise ComponentDiscoveryError("Platform component lacks structured state")
    fact = {
        "name": _text(_value(row, "cname")),
        "model": _text(_value(state, "part-no")),
        "serial": _text(_value(state, "serial-no")),
        "manufacturer": _text(_value(state, "mfg-name")),
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
    properties, errors = _platform_properties(row, fact["name"])
    if properties is not None:
        fact["platform_properties"] = properties
    if errors:
        fact["platform_property_errors"] = errors
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


def _placement_source(fact, *, profile=PROFILE):
    return {
        "module": "Cisco-IOS-XE-platform-oper",
        "path": PLATFORM_PATH,
        "component": fact["name"],
        "fields": {
            "parent": "state/parent",
            "location": "state/location",
            "hardware_revision": "state/version",
            "manufacturer": "state/mfg-name",
        },
        "identity_join_rule": "unique trimmed part-number/part-no and serial-number/serial-no",
        "profile": profile,
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


def _collect_transceivers(result, flat, platform, pairs, owners, *, interfaces):
    """Resolve SFP assets after their reviewed uplink parent, independent of input order.

    The observed platform component describes the optic as comp-port and reports
    removable=False even though hardware inventory explicitly identifies a physical,
    field-replaceable transceiver. Preserve those observations. The shared platform
    location corroborates uplink slot 1; only matching structured interface names
    establish an individual SFP port, never numeric inventory indexes or location
    segment guesses. Existing host Interface Device and Module ownership is preserved.
    """
    from .cisco_iosxe import canonical_interface_name

    handled = set()
    for fact in flat:
        if fact["hw_type"] != "hw-type-transceiver":
            continue
        unresolved = {**fact, "source": {"identity": _identity_source(fact)}}
        name = canonical_interface_name(fact["name"])
        match = re.fullmatch(r"GigabitEthernet(\d+)/1/([1-4])", name or "")
        owner = owners.get(int(match.group(1))) if match else None
        member = owner["position"] if owner else None
        parent_key = "uplink:%d/1" % member if owner else None
        parents = [item for item in result["items"] if item["key"] == parent_key]
        if not fact["model"] or not fact["serial"]:
            reason = "Serialized transceiver model or serial number is unavailable"
        elif owner is None or owner["model"] != "C9300-48UXM":
            reason = "Transceiver chassis or port has no reviewed nested placement profile"
        elif fact["hardware_class"] is None or fact["field_replaceable"] is None:
            reason = "Transceiver physical or field-replaceable classification is unavailable"
        else:
            if (
                fact["hardware_class"] != "hw-class-physical"
                or fact["field_replaceable"] is not True
            ):
                raise ComponentDiscoveryError(
                    "Reviewed transceiver has contradictory hardware classification"
                )
            if pairs[(fact["model"], fact["serial"])] != 1:
                raise ComponentDiscoveryError(
                    "Reviewed serialized transceiver identity occurs in multiple inventory entries"
                )
            matches = [
                part
                for part in platform
                if (part["model"], part["serial"]) == (fact["model"], fact["serial"])
            ]
            if len(matches) > 1:
                raise ComponentDiscoveryError(
                    "Serialized transceiver identity matches multiple platform components"
                )
            if not matches:
                expected = next((part for part in platform if part["name"] == name), None)
                if expected and expected["model"] and expected["serial"]:
                    raise ComponentDiscoveryError(
                        "Serialized transceiver inventory and platform identities "
                        "disagree at a reviewed port"
                    )
                reason = "No unique platform identity match establishes transceiver placement"
            else:
                part = matches[0]
                handled.add(part["name"])
                unresolved["observations"] = part
                unresolved["source"]["placement"] = _placement_source(
                    part, profile=TRANSCEIVER_PROFILE
                )
                if part["name"] != name:
                    raise ComponentDiscoveryError(
                        "Serialized transceiver identity names different "
                        "hardware and platform ports"
                    )
                if owner["root"] is None:
                    reason = (
                        "Platform chassis identity is unavailable for transceiver parent validation"
                    )
                elif part["parent"] != "Switch%d" % member:
                    reason = "Transceiver platform parent does not match the reviewed chassis"
                elif part["location"] != "%d/0/1/1" % member:
                    reason = "Transceiver platform location does not match the reviewed uplink slot"
                elif part["platform_type"] != "comp-port":
                    reason = "Transceiver platform classification has no reviewed placement profile"
                elif part["empty"] is not False or part["removable"] is not False:
                    reason = "Transceiver presence or platform removability needs review"
                elif part["manufacturer"] is None:
                    reason = (
                        "Transceiver manufacturer is unavailable from structured platform state"
                    )
                elif len(parents) != 1 or parents[0]["model"] != "C3850-NM-4-1G":
                    reason = "Transceiver parent uplink module is not uniquely established"
                elif name not in parents[0]["interfaces"]:
                    reason = (
                        "Transceiver port is not an eligible observed interface "
                        "of the parent uplink"
                    )
                else:
                    observed = [interface for interface in interfaces if interface["name"] == name]
                    if len(observed) != 1:
                        raise ComponentDiscoveryError(
                            "Transceiver port has ambiguous eligible interface observations"
                        )
                    if (
                        observed[0].get("type") != "1000base-x-sfp"
                        or observed[0].get("type_source")
                        != "Installed C3850-NM-4-1G 4x1G SFP uplink module"
                        or observed[0].get("stack_member", member) != member
                    ):
                        reason = (
                            "Transceiver port lacks the reviewed physical SFP capability evidence"
                        )
                    else:
                        result["items"].append(
                            {
                                "key": "transceiver:%d/1/%s" % (member, match.group(2)),
                                "kind": "transceiver",
                                "manufacturer": part["manufacturer"],
                                "model": fact["model"],
                                "part_number": fact["model"],
                                "serial": fact["serial"],
                                "hardware_revision": fact["hardware_revision"]
                                or part["hardware_revision"],
                                "device_serial": owner["serial"],
                                "member": member,
                                "chassis_model": owner["model"],
                                "parent_key": parent_key,
                                "bay": {
                                    "name": "SFP %s" % name,
                                    "position": match.group(2),
                                    "label": name,
                                },
                                "interfaces": [],
                                "source": {
                                    **_owner_sources(owner),
                                    "identity": {
                                        **_identity_source(fact),
                                        "hardware_class": fact["hardware_class"],
                                        "field_replaceable": fact["field_replaceable"],
                                        "interface_name": fact["name"],
                                    },
                                    "placement": _placement_source(
                                        part, profile=TRANSCEIVER_PROFILE
                                    ),
                                    "manufacturer": {
                                        "module": "Cisco-IOS-XE-platform-oper",
                                        "path": PLATFORM_PATH,
                                        "field": "state/mfg-name",
                                        "component": part["name"],
                                        "value": part["manufacturer"],
                                        "profile": TRANSCEIVER_PROFILE,
                                    },
                                    "ownership": {
                                        "method": "reviewed-profile",
                                        "profile": TRANSCEIVER_PROFILE,
                                        "rule": (
                                            "C3850-NM-4-1G uplink slot 1 contains SFP bays "
                                            "for GigabitEthernet<member>/1/1-4"
                                        ),
                                        "parent_key": parent_key,
                                        "device_serial": owner["serial"],
                                        "member": member,
                                        "chassis_model": owner["model"],
                                        "parent_model": parents[0]["model"],
                                        "parent_serial": parents[0]["serial"],
                                        "interface": name,
                                        "module": "Cisco-IOS-XE-interfaces-oper",
                                        "path": INTERFACES_PATH,
                                        "documentation": STACK_INTERFACE_DOCUMENT,
                                        "meaning": (
                                            "Matching structured hardware dev-name and platform "
                                            "cname associate the optic with a reviewed "
                                            "uplink port; "
                                            "nested bay ownership follows the hardware profile. "
                                            "Existing host Interface Device and Module ownership "
                                            "is preserved"
                                        ),
                                    },
                                },
                                "observations": part,
                            }
                        )
                        continue
        result["unresolved"].append({**unresolved, "reason": reason})
    return handled


def _component_owners(inventory, platform, *, chassis_model, chassis_serial, member, stack):
    """Join physical chassis, validated stack membership and platform roots."""
    hardware = [_flat_fact(row) for row in inventory]
    chassis = [fact for fact in hardware if fact["hw_type"] == "hw-type-chassis"]
    members = stack.get("members", []) if isinstance(stack, dict) else []
    candidates = members or [{"model": chassis_model, "serial": chassis_serial, "position": member}]
    owners = {}
    for candidate in candidates:
        position, serial, model = (
            candidate.get("position"),
            candidate.get("serial"),
            candidate.get("model"),
        )
        if type(position) is not int or not 1 <= position <= 255:
            raise ComponentDiscoveryError(
                "Component owner needs a validated positive member position"
            )
        matches = [fact for fact in chassis if (fact["model"], fact["serial"]) == (model, serial)]
        if len(matches) != 1 or not serial or not model:
            raise ComponentDiscoveryError(
                "Component owner must uniquely match physical chassis identity"
            )
        named = re.fullmatch(r"Switch\s+(\d+)", matches[0]["name"] or "", re.IGNORECASE)
        if named and int(named.group(1)) != position:
            raise ComponentDiscoveryError(
                "Component owner position contradicts physical chassis name"
            )
        root = next((part for part in platform if part["name"] == "Switch%d" % position), None)
        if root and (root["model"] != model or root["serial"] != serial):
            raise ComponentDiscoveryError(
                "Platform chassis identity contradicts hardware inventory"
            )
        if position in owners or serial in {owner["serial"] for owner in owners.values()}:
            raise ComponentDiscoveryError(
                "Component owner identity or member position is ambiguous"
            )
        owners[position] = {
            "model": model,
            "serial": serial,
            "position": position,
            "root": root,
            "identity_source": _identity_source(matches[0]),
            "membership_source": deepcopy(candidate.get("sources", {}).get("membership")),
        }
    return owners


def _owner_sources(owner):
    """Retain explicit physical identity and StackWise membership provenance."""
    sources = {"chassis_identity": deepcopy(owner["identity_source"])}
    if owner["membership_source"]:
        sources["membership"] = deepcopy(owner["membership_source"])
    return sources


def _psu_observations(part):
    if part is None:
        return {"reported_presence": "unknown", "oper_status": None, "status_description": None}
    presence = (
        "reported-empty"
        if part["empty"] is True
        else "reported-nonempty"
        if part["empty"] is False
        else "unknown"
    )
    return {
        "reported_presence": presence,
        "empty": part["empty"],
        "oper_status": part["oper_status"],
        "status_description": part["status_description"],
        **(
            {"platform_properties": deepcopy(part["platform_properties"])}
            if "platform_properties" in part
            else {}
        ),
        **(
            {"platform_property_errors": deepcopy(part["platform_property_errors"])}
            if "platform_property_errors" in part
            else {}
        ),
        "meaning": "Reported occupancy and operational power state do not establish asset identity",
    }


def _psu_bay_part(part, owner, slot):
    return (
        part["name"] == "PowerSupply%d/%s" % (owner["position"], slot)
        and part["parent"] == "Switch%d" % owner["position"]
        and part["location"] == "%d/0/%s/0" % (owner["position"], slot)
        and part["platform_type"] == "comp-power-supply"
    )


def _collect_power_supplies(result, flat, platform, pairs, owners, *, use_ntc_defaults):
    """Separate documented chassis bay existence from serialized PSU identity."""
    handled = set()
    for owner in owners.values():
        if psu_profiles.family_for_chassis(owner["model"]) is None:
            continue
        for slot in ("A", "B"):
            part = next((part for part in platform if _psu_bay_part(part, owner, slot)), None)
            source = {
                "documentation": {
                    "method": "reviewed-profile",
                    "profile": psu_profiles.PROFILE,
                    "documentation": psu_profiles.OVERVIEW_URL,
                    "section": "Switch Models and Power Supply Modules: two internal supply slots",
                    "meaning": "Physical bay exists independently of the identity of its occupant",
                },
                "bay_labels": {
                    "method": "reviewed-profile",
                    "profile": psu_profiles.PROFILE,
                    "documentation": psu_profiles.BAY_LABELS_URL,
                    "section": "StackPower verification: PSU slot A/B naming",
                    "meaning": "A is the left PSU slot; B is the right slot at the chassis edge",
                },
                "identity": deepcopy(owner["identity_source"]),
            }
            if owner["membership_source"]:
                source["membership"] = deepcopy(owner["membership_source"])
            if part:
                source["observations"] = _placement_source(part, profile=psu_profiles.PROFILE)
            result["physical_bays"].append(
                {
                    "key": "psu:%d/%s" % (owner["position"], slot),
                    "device_serial": owner["serial"],
                    "member": owner["position"],
                    "chassis_model": owner["model"],
                    "bay": psu_profiles.bay(slot),
                    "source": source,
                    "observations": _psu_observations(part),
                }
            )
    for fact in flat:
        if fact["hw_type"] != "hw-type-pem" and fact["model"] not in psu_profiles.PSU_CONNECTORS:
            continue
        if fact["model"] in CATALOG and CATALOG[fact["model"]][1] != fact["hw_type"]:
            raise ComponentDiscoveryError(
                "Reviewed serialized part has contradictory hardware classification"
            )
        unresolved = {**fact, "source": {"identity": _identity_source(fact)}}
        named = re.fullmatch(r"Switch (\d+) - Power Supply ([AB])", fact["name"] or "")
        owner = owners.get(int(named.group(1))) if named else None
        slot = named.group(2) if named else None
        if not fact["model"] or not fact["serial"]:
            reason = "Serialized component model or serial number is unavailable"
        elif owner is None or not psu_profiles.supported_psu(owner["model"], fact["model"]):
            reason = "Serialized PSU part or chassis has no reviewed component profile"
        else:
            if (
                fact["hw_type"] != "hw-type-pem"
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
                expected = next(
                    (
                        part
                        for part in platform
                        if part["name"] == "PowerSupply%d/%s" % (owner["position"], slot)
                    ),
                    None,
                )
                if expected and expected["model"] and expected["serial"]:
                    raise ComponentDiscoveryError(
                        "Serialized inventory and platform identities disagree at a reviewed bay"
                    )
                reason = "No unique platform identity match establishes component placement"
            elif owner["root"] is None:
                reason = "Platform chassis identity is unavailable for parent validation"
            else:
                part = matches[0]
                handled.add(part["name"])
                unresolved["observations"] = part
                unresolved["source"]["placement"] = _placement_source(
                    part, profile=psu_profiles.PROFILE
                )
                if not _psu_bay_part(part, owner, slot):
                    reason = "Power-supply placement does not match the verified member and bay"
                elif part["empty"] is not False or part["removable"] is not True:
                    reason = "Serialized component presence/removability needs review"
                else:
                    power_port = psu_profiles.power_port(fact["model"])
                    if use_ntc_defaults:
                        power_port["power_factor"] = "0.95"
                        power_port["source"]["inference"] = {
                            "policy": "ntc-power-factor-default",
                            "value": "0.95",
                            "source": (
                                "https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/"
                                "dcim/models/device_components.py"
                            ),
                            "meaning": (
                                "Nautobot model default; not a measured or documented PSU value"
                            ),
                        }
                    result["items"].append(
                        {
                            "key": "psu:%d/%s" % (owner["position"], slot),
                            "kind": "power-supply",
                            "manufacturer": "Cisco",
                            "model": fact["model"],
                            "part_number": fact["model"],
                            "serial": fact["serial"],
                            "hardware_revision": fact["hardware_revision"]
                            or part["hardware_revision"],
                            "device_serial": owner["serial"],
                            "member": owner["position"],
                            "bay": psu_profiles.bay(slot),
                            "parent_key": None,
                            "interfaces": [],
                            "power_ports": [power_port],
                            "source": {
                                "identity": _identity_source(fact),
                                "placement": _placement_source(part, profile=psu_profiles.PROFILE),
                                "ownership": {
                                    "method": "reviewed-profile",
                                    "profile": psu_profiles.PROFILE,
                                    "rule": "Power supply has no network interfaces",
                                    "device_serial": owner["serial"],
                                    "member": owner["position"],
                                },
                            },
                            "observations": part,
                        }
                    )
                    continue
        result["unresolved"].append({**unresolved, "reason": reason})
    return handled


def collect(
    client,
    inventory,
    *,
    chassis_model,
    chassis_serial,
    member,
    interfaces,
    warnings,
    stack=None,
    use_ntc_defaults=False,
):
    """Return reviewed items and visible unresolved/excluded observations."""
    result = {
        "schema_version": 1,
        "items": [],
        "physical_bays": [],
        "unresolved": [],
        "excluded": [],
    }
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
    for part in platform:
        for error in part.get("platform_property_errors", []):
            result["unresolved"].append(
                {
                    "name": part["name"],
                    "model": part["model"],
                    "serial": part["serial"],
                    "property": error.get("property"),
                    "reason": "Optional operational property skipped: " + error["reason"],
                    "source": {"observation": deepcopy(error["source"])},
                }
            )
    names = Counter(fact["name"] for fact in platform)
    if any(count > 1 for count in names.values()):
        raise ComponentDiscoveryError("Platform component names are ambiguous")
    pairs = Counter(
        (fact["model"], fact["serial"]) for fact in flat if fact["model"] and fact["serial"]
    )
    owners = _component_owners(
        inventory,
        platform,
        chassis_model=chassis_model,
        chassis_serial=chassis_serial,
        member=member,
        stack=stack,
    )
    handled_platform_names = _collect_power_supplies(
        result,
        flat,
        platform,
        pairs,
        owners,
        use_ntc_defaults=use_ntc_defaults,
    )
    for fact in flat:
        if fact["hw_type"] == "hw-type-pem" or fact["model"] in psu_profiles.PSU_CONNECTORS:
            continue
        if fact["hw_type"] == "hw-type-transceiver":
            continue
        unresolved = {**fact, "source": {"identity": _identity_source(fact)}}
        named = re.fullmatch(r"Switch (\d+) FRU Uplink Module 1", fact["name"] or "")
        owner = owners.get(int(named.group(1))) if named else None
        member_position = owner["position"] if owner else None
        if not fact["model"] or not fact["serial"]:
            reason = "Serialized component model or serial number is unavailable"
        elif owner is None or owner["model"] != "C9300-48UXM" or fact["model"] != "C3850-NM-4-1G":
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
                expected_name = _expected_platform_name(fact, member_position)
                at_expected_bay = next(
                    (part for part in platform if part["name"] == expected_name), None
                )
                if at_expected_bay and at_expected_bay["model"] and at_expected_bay["serial"]:
                    raise ComponentDiscoveryError(
                        "Serialized inventory and platform identities disagree at a reviewed bay"
                    )
                reason = "No unique platform identity match establishes component placement"
            elif owner["root"] is None:
                reason = "Platform chassis identity is unavailable for parent validation"
            else:
                part = matches[0]
                handled_platform_names.add(part["name"])
                unresolved["observations"] = part
                unresolved["source"]["placement"] = _placement_source(part)
                expected_name = _expected_platform_name(fact, member_position)
                if part["name"] != expected_name:
                    raise ComponentDiscoveryError(
                        "Serialized network module identity names different "
                        "hardware and platform bays"
                    )
                placement, reason = _profile_placement(part, member_position)
                if placement is not None:
                    ownership = {
                        "method": "reviewed-profile",
                        "profile": PROFILE,
                        "rule": "C3850-NM-4-1G in uplink slot 1 owns GigabitEthernet<member>/1/1-4"
                        if kind == "network-module"
                        else "Power supply has no network interfaces",
                        "module": "Cisco-IOS-XE-interfaces-oper",
                        "path": INTERFACES_PATH,
                        "documentation": STACK_INTERFACE_DOCUMENT,
                        "device_serial": owner["serial"],
                        "member": member_position,
                        "chassis_model": owner["model"],
                        "meaning": (
                            "Port association follows the reviewed hardware/slot profile; "
                            "the platform does not report the child relationship. Observed names "
                            "corroborate physical placement; existing Interface Device ownership "
                            "is preserved"
                        ),
                    }
                    expected_ports = (
                        ["GigabitEthernet%d/1/%d" % (member_position, port) for port in range(1, 5)]
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
                            "device_serial": owner["serial"],
                            "member": member_position,
                            "chassis_model": owner["model"],
                            "parent_key": None,
                            "interfaces": owned_ports,
                            "source": {
                                **_owner_sources(owner),
                                "identity": _identity_source(fact),
                                "placement": _placement_source(part),
                                "ownership": ownership,
                            },
                            "observations": part,
                        }
                    )
                    continue
        result["unresolved"].append({**unresolved, "reason": reason})
    handled_platform_names.update(
        _collect_transceivers(
            result,
            flat,
            platform,
            pairs,
            owners,
            interfaces=interfaces,
        )
    )
    flat_pairs = {
        (fact["model"], fact["serial"]) for fact in flat if fact["model"] and fact["serial"]
    }
    for part in platform:
        if part["name"] in handled_platform_names:
            continue
        if part["model"] and part["serial"]:
            if part["name"] in {"Switch%d" % position for position in owners}:
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
                        "PSU serialized identity is unavailable; occupancy is retained from empty "
                        "and asset identity is not inferred from operational power state"
                        if part["platform_type"] == "comp-power-supply"
                        else "Component identity is unavailable; presence or occupancy "
                        "is not inferred from operational state"
                    ),
                }
            )
    result["items"].sort(key=lambda item: item["key"])
    result["physical_bays"].sort(key=lambda item: item["key"])
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
    for collection in ("items", "physical_bays", "unresolved", "excluded"):
        for item in components.get(collection, []):
            for source in item.get("source", {}).values():
                if isinstance(source, dict) and source.get("module"):
                    source["revision"] = modules.get(source["module"])
            observations = item.get("observations", {})
            for prop in observations.get("platform_properties", []):
                prop["source"]["revision"] = modules.get(prop["source"]["module"])
            for error in observations.get("platform_property_errors", []):
                error["source"]["revision"] = modules.get(error["source"]["module"])
