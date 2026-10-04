"""Discover reported serialized hardware without a product compatibility matrix.

The published inventory and platform YANG schemas establish identity and class.
Exact parent component references establish containment; component names remain
opaque identifiers, never parsed slot numbers. Only observed installed objects
receive attachment bays. Capability, empty bays, connectors and interface
ownership are deliberately absent when runtime data does not establish them.
"""

import json
import re
from collections import Counter
from copy import deepcopy

PROFILE = "cisco-reported-components-v1"
HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
PLATFORM_PATH = "/data/Cisco-IOS-XE-platform-oper:components"
INTERFACES_PATH = "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
DOCUMENTS = [
    "https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/"
    "Cisco-IOS-XE-device-hardware-oper.yang",
    "https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/"
    "Cisco-IOS-XE-platform-oper.yang",
]
# These are schema enumeration meanings, rather than product/PID mappings.
HARDWARE_KINDS = {
    "hw-type-pim": "network-module",
    "hw-type-transceiver": "transceiver",
    "hw-type-pem": "power-supply",
    "hw-type-fantray": "fan-tray",
    "hw-type-ssd": "storage",
}
PLATFORM_CLASSES = {
    "network-module": {"comp-module", "comp-linecard", "comp-fru", "comp-controller-card"},
    "transceiver": {"comp-transceiver"},
    "power-supply": {"comp-power-supply", "comp-fru"},
    "fan-tray": {"comp-fan", "comp-fru"},
    "storage": {"comp-sed", "comp-fru"},
}


def _opaque_key(prefix, values):
    return prefix + ":" + json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _pair(fact):
    return fact.get("model"), fact.get("serial")


def _identity_source(fact):
    return {
        "module": "Cisco-IOS-XE-device-hardware-oper",
        "path": HARDWARE_PATH,
        "field": "device-hardware/device-inventory",
        "hw_type": fact.get("hw_type"),
        "inventory_index": fact.get("inventory_index"),
        "hardware_class": fact.get("hardware_class"),
        "field_replaceable": fact.get("field_replaceable"),
        "interface_name": fact.get("name"),
        "fields": {
            "model": "part-number",
            "serial": "serial-number",
            "hardware_revision": "version",
        },
    }


def _placement_source(part):
    return {
        "module": "Cisco-IOS-XE-platform-oper",
        "path": PLATFORM_PATH,
        "component": part["name"],
        "fields": {
            "parent": "state/parent",
            "name": "cname",
            "empty": "state/empty",
            "removable": "state/removable",
            "platform_type": "state/type",
        },
        "identity_join_rule": "unique trimmed part-number/part-no and serial-number/serial-no",
        "method": "reported-parent-reference",
        "profile": PROFILE,
        "documentation": list(DOCUMENTS),
        "meaning": (
            "Exact reported parent component reference establishes containment; "
            "reported cname identifies the observed attachment, not a decoded physical slot"
        ),
    }


def _identity(fact, part, kind):
    return {
        "key": _opaque_key("identity", [kind, fact["model"], fact["serial"]]),
        "kind": kind,
        "manufacturer": part["manufacturer"],
        "model": fact["model"],
        "part_number": fact["model"],
        "serial": fact["serial"],
        # Platform state/version can describe hardware, firmware or software.
        # Only inventory's explicit hardware version supplies hardware revision.
        "hardware_revision": fact.get("hardware_revision"),
        "source": {
            "identity": _identity_source(fact),
            "manufacturer": {
                "module": "Cisco-IOS-XE-platform-oper",
                "path": PLATFORM_PATH,
                "field": "state/mfg-name",
                "component": part["name"],
                "value": part["manufacturer"],
                "profile": PROFILE,
            },
            "placement": _placement_source(part),
        },
        "observations": deepcopy(part),
        "hardware_observations": deepcopy(fact),
    }


def _reviewed_block(fact, existing_unresolved):
    """Do not replace an evaluated reviewed rule with a more permissive fallback."""
    for row in existing_unresolved:
        if _pair(row) != _pair(fact) or row.get("name") != fact.get("name"):
            continue
        placement = row.get("source", {}).get("placement", {})
        if placement.get("profile") and placement["profile"] != PROFILE:
            return "Existing reviewed placement remains unresolved: " + row["reason"]
        if row.get("reason") in (
            "Documented uplink port is copper and cannot establish an optical cage",
            "Transceiver port has no reviewed physical uplink capability",
        ):
            return "Existing reviewed capability remains unresolved: " + row["reason"]
    return None


def _placement_problem(fact, part, kind, existing_unresolved, interfaces):
    blocked = _reviewed_block(fact, existing_unresolved)
    if blocked:
        return blocked
    if fact.get("field_replaceable") is not True:
        return "Reported field-replaceable classification does not establish an installable module"
    if part.get("platform_type") not in PLATFORM_CLASSES[kind]:
        return "Hardware and platform classifications do not establish compatible containment"
    if part.get("empty") is not False or part.get("removable") is not True:
        return "Reported component presence/removability does not establish an installed module"
    if not part.get("parent"):
        return "Reported parent component reference is unavailable"
    if kind == "transceiver":
        from .cisco_iosxe import _PHYSICAL_ETHERNET_NAME, canonical_interface_name

        name = canonical_interface_name(fact.get("name"))
        if not name or name != canonical_interface_name(part["name"]):
            return "Transceiver hardware and platform names do not identify the same interface"
        if not _PHYSICAL_ETHERNET_NAME.fullmatch(name):
            return "Transceiver name does not establish a supported physical Ethernet attachment"
        observed = [
            interface
            for interface in interfaces
            if canonical_interface_name(interface.get("name")) == name
        ]
        if len(observed) != 1:
            return "Transceiver interface must have one exact observed interface name match"
        if observed[0].get("type") in ("virtual", "lag") or observed[0].get("present") is False:
            return "Transceiver interface observation does not establish a present physical port"
        source = observed[0].get("physical_ethernet_source")
        if (
            observed[0].get("physical_ethernet") is not True
            or not isinstance(source, dict)
            or source.get("module") != "Cisco-IOS-XE-interfaces-oper"
            or source.get("path") != "interfaces/interface/interface-type"
            or source.get("value") != "iana-iftype-ethernet-csmacd"
            or source.get("name") != name
        ):
            return "Transceiver interface lacks corroborated reported IANA physical Ethernet class"
    return None


def collect(
    flat,
    platform,
    owners,
    *,
    interfaces,
    existing_items,
    existing_unresolved,
):
    """Return catalogs, placed assets, unresolved facts and internal handled sets.

    Identity catalog entries survive unavailable containment. Only unique physical
    hardware identities corroborated by an explicitly reported manufacturer enter
    the catalog. Reviewed assets retain their existing keys and relationships.
    ``handled_hardware`` and ``handled_platform_names`` are integration bookkeeping
    and must not be copied into the JSON discovery report.
    """
    result = {
        "identities": [],
        "items": [],
        "unresolved": [],
        "handled_hardware": set(),
        "handled_platform_names": set(),
    }
    hardware_pairs = Counter(_pair(fact) for fact in flat if all(_pair(fact)))
    platform_pairs = Counter(_pair(part) for part in platform if all(_pair(part)))
    platform_names = Counter(part["name"] for part in platform)
    parts = {part["name"]: part for part in platform if platform_names[part["name"]] == 1}
    existing_pairs = {_pair(item) for item in existing_items}
    candidates = {}

    for fact in flat:
        kind = HARDWARE_KINDS.get(fact.get("hw_type"))
        if kind is None or _pair(fact) in existing_pairs:
            continue
        result["handled_hardware"].add((fact.get("name"), *_pair(fact)))
        unresolved = {
            **deepcopy(fact),
            "source": {"identity": _identity_source(fact)},
        }
        pair = _pair(fact)
        if not all(pair):
            reason = "Serialized component model or serial number is unavailable"
        elif fact.get("hardware_class") != "hw-class-physical":
            reason = "Reported hardware classification does not establish a physical component"
        elif hardware_pairs[pair] != 1 or platform_pairs[pair] > 1:
            reason = "Serialized identity must uniquely match hardware and platform observations"
        elif platform_pairs[pair] == 0:
            reason = "No unique platform identity corroborates the serialized component"
        else:
            part = next(part for part in platform if _pair(part) == pair)
            unresolved["observations"] = deepcopy(part)
            unresolved["source"]["placement"] = _placement_source(part)
            result["handled_platform_names"].add(part["name"])
            if platform_names[part["name"]] != 1:
                reason = "Reported platform component name is ambiguous"
            elif not part.get("manufacturer"):
                reason = _reviewed_block(fact, existing_unresolved) or (
                    "Reported component manufacturer is unavailable"
                )
            else:
                identity = _identity(fact, part, kind)
                result["identities"].append(identity)
                candidates[part["name"]] = {
                    "fact": fact,
                    "part": part,
                    "identity": identity,
                    "unresolved": unresolved,
                    "problem": _placement_problem(
                        fact, part, kind, existing_unresolved, interfaces
                    ),
                }
                continue
        result["unresolved"].append({**unresolved, "reason": reason})

    roots = {}
    for name, root in parts.items():
        if root.get("platform_type") != "comp-chassis" or root.get("empty") is not False:
            continue
        matches = [
            owner
            for owner in owners.values()
            if _pair(root) == (owner.get("model"), owner.get("serial"))
        ]
        if len(matches) == 1:
            roots[name] = matches[0]
    # Exact parent references select opaque root names. Multiple names can alias
    # the same uniquely verified physical chassis without creating another owner.
    placed = {}
    for item in existing_items:
        name = item.get("source", {}).get("placement", {}).get("component")
        name = name or item.get("observations", {}).get("name")
        owner_matches = {
            (owner["serial"], owner["position"]): owner
            for owner in roots.values()
            if owner["serial"] == item.get("device_serial")
            and owner["position"] == item.get("member")
        }
        if name in parts and _pair(parts[name]) == _pair(item) and len(owner_matches) == 1:
            placed[name] = (next(iter(owner_matches.values())), item["key"])

    failures = {}

    def resolve(name, visiting):
        if name in roots:
            return roots[name], None
        if name in placed:
            return placed[name]
        if name in failures:
            return None
        if name not in candidates:
            failures[name] = "Reported parent is not a uniquely resolved chassis or module"
            return None
        candidate = candidates[name]
        if candidate["problem"]:
            failures[name] = candidate["problem"]
            return None
        if name in visiting:
            failures[name] = "Reported component parent references contain a cycle"
            return None
        owner_parent = resolve(candidate["part"]["parent"], {*visiting, name})
        if owner_parent is None:
            failures.setdefault(name, "Reported parent containment could not be established")
            return None
        owner, parent_key = owner_parent
        if candidate["identity"]["kind"] == "transceiver":
            from .cisco_iosxe import canonical_interface_name

            observed = next(
                interface
                for interface in interfaces
                if canonical_interface_name(interface.get("name"))
                == canonical_interface_name(candidate["fact"]["name"])
            )
            if observed.get("stack_member") not in (None, owner["position"]):
                failures[name] = (
                    "Reported transceiver parent and observed interface owners disagree"
                )
                return None
            interface_name = canonical_interface_name(candidate["fact"]["name"])
            if len(interface_name.split("/")) == 3:
                member = int(re.search(r"(\d+)/\d+/\d+$", interface_name).group(1))
                if member != owner["position"]:
                    failures[name] = (
                        "Transceiver physical interface member and reported parent owner disagree"
                    )
                    return None
        item = deepcopy(candidate["identity"])
        item.update(
            {
                "key": _opaque_key("component", [name]),
                "device_serial": owner["serial"],
                "member": owner["position"],
                "chassis_model": owner["model"],
                "parent_key": parent_key,
                "bay": {"name": name, "position": name, "label": ""},
                "interfaces": [],
            }
        )
        item["source"]["chassis_identity"] = deepcopy(owner["identity_source"])
        if candidate["identity"]["kind"] == "transceiver":
            item["source"]["interface_classification"] = deepcopy(
                observed["physical_ethernet_source"]
            )
        if owner.get("membership_source"):
            item["source"]["membership"] = deepcopy(owner["membership_source"])
        item["source"]["ownership"] = {
            "method": "reported-parent-reference",
            "profile": PROFILE,
            "rule": "Exact state/parent resolves a unique reported physical owner",
            "component": name,
            "parent_component": candidate["part"]["parent"],
            "parent_key": parent_key,
            "device_serial": owner["serial"],
            "member": owner["position"],
            "meaning": (
                "Observed attachment cname is retained without interpreting physical slot, "
                "cage capability, connector specification or interface ownership"
            ),
        }
        result["items"].append(item)
        placed[name] = owner, item["key"]
        return placed[name]

    for name, candidate in sorted(candidates.items()):
        if resolve(name, set()) is None:
            result["unresolved"].append({**candidate["unresolved"], "reason": failures[name]})
    for collection in ("identities", "items"):
        result[collection].sort(key=lambda item: item["key"])
    result["unresolved"].sort(
        key=lambda item: (
            item.get("name") or "",
            item.get("model") or "",
            item.get("serial") or "",
            item["reason"],
        )
    )
    return result
