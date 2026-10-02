"""Configured copper duplex from complete native RESTCONF JSON reads.

Operational negotiated/MAC state never supplies this configured setting.
Defaults are limited to reviewed C9300-48UXM ports and release families.
"""

import re

from ..transport_restconf import RestconfError

NATIVE_PATH = "/data/Cisco-IOS-XE-native:native/interface"
FAMILIES = (
    "FastEthernet",
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
)
# This is an ethernet-module augmentation. A bare child filter can return
# HTTP 200 while silently omitting configured values, as with channel-group.
NATIVE_FIELDS = ";".join(family + "(name;Cisco-IOS-XE-ethernet:duplex)" for family in FAMILIES)
COPPER_TYPES = frozenset(("100base-tx", "1000base-t", "2.5gbase-t", "5gbase-t", "10gbase-t"))
PROFILE = "c9300-48uxm-configured-duplex-defaults-v1"
DOC_ROOT = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/%s/"


class DuplexDiscoveryError(ValueError):
    """Configured duplex data is malformed or has ambiguous identity."""


def _value(mapping, name, module="Cisco-IOS-XE-native"):
    if not isinstance(mapping, dict):
        return None
    matches = [(key, value) for key, value in mapping.items() if key.split(":")[-1] == name]
    if len(matches) > 1:
        raise DuplexDiscoveryError(
            "Configured duplex reply has duplicate namespace-qualified leaves"
        )
    if not matches:
        return None
    key, value = matches[0]
    if key not in (name, module + ":" + name):
        raise DuplexDiscoveryError(
            "Configured duplex field %s uses an unexpected YANG namespace" % name
        )
    return value


def _has(mapping, name):
    return any(key.split(":")[-1] == name for key in mapping)


def _read(client, warnings):
    request = NATIVE_PATH + "?fields=" + NATIVE_FIELDS
    try:
        return client.get(request), request
    except RestconfError as exc:
        if exc.status_code == 400:
            warnings.append(
                "%s: duplex fields filter rejected (HTTP 400); unfiltered JSON read used"
                % NATIVE_PATH
            )
            try:
                return client.get(NATIVE_PATH), NATIVE_PATH
            except RestconfError:
                pass
        warnings.append("Configured duplex source unavailable; existing fields are preserved")
        return None, request


def _native_rows(payload, canonical_name):
    if payload is None or payload == {}:
        return None
    if not isinstance(payload, dict):
        raise DuplexDiscoveryError("Configured duplex reply must be a structured object")
    container = _value(payload, "interface")
    if container is None:
        return None
    if not isinstance(container, dict):
        raise DuplexDiscoveryError(
            "Configured duplex interface scope must be a structured container"
        )
    indexed = {}
    for family in FAMILIES:
        rows = _value(container, family)
        if rows is None:
            if _has(container, family):
                raise DuplexDiscoveryError("Configured duplex native interface list cannot be null")
            continue
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise DuplexDiscoveryError(
                "Configured duplex native interface lists must contain objects"
            )
        for row in rows:
            suffix = _value(row, "name")
            if not isinstance(suffix, str) or not re.fullmatch(r"\d+(?:/\d+){0,2}", suffix):
                raise DuplexDiscoveryError(
                    "Configured duplex interface has an unsupported native key"
                )
            name = canonical_name(family + suffix)
            if name in indexed:
                raise DuplexDiscoveryError(
                    "Configured duplex has duplicate canonical interface %s" % name
                )
            raw = _value(row, "duplex", "Cisco-IOS-XE-ethernet")
            if _has(row, "duplex") and raw not in ("auto", "full", "half"):
                raise DuplexDiscoveryError(
                    "%s: configured duplex must be auto, full, or half" % name
                )
            indexed[name] = {"family": family, "name": suffix, "duplex": raw}
    return indexed


def _default_profile(name, type_, model, software_version, member):
    family = (
        ".".join(software_version.split(".")[:2]) if isinstance(software_version, str) else None
    )
    if (
        model != "C9300-48UXM"
        or family not in ("17.9", "17.12")
        or isinstance(member, bool)
        or member != 1
    ):
        return None
    fixed = re.fullmatch(r"TwoGigabitEthernet1/0/(\d+)", name)
    is_fixed = fixed and 1 <= int(fixed.group(1)) <= 36 and type_ == "2.5gbase-t"
    is_management = name == "GigabitEthernet0/0" and type_ == "1000base-t"
    if not is_fixed and not is_management:
        return None
    release = family.replace(".", "-")
    version = family.replace(".", "")
    root = DOC_ROOT % release
    return {
        "profile": PROFILE,
        "model": model,
        "software_family": family,
        "member": member,
        "value": "auto",
        "omitted_leaf": "duplex",
        "documents": [
            root
            + "configuration_guide/int_hw/b_%s_int_and_hw_9300_cg/" % version
            + "configuring_interface_characteristics.html",
            root + "command_reference/b_%s_9300_cr/interface_and_hardware_commands.html" % version,
        ],
        "meaning": (
            "Documented configured duplex default after a complete native read; "
            "10-Gigabit, optical, other members, and unreviewed ports are excluded"
        ),
    }


def collect(client, interfaces, *, model, software_version, member, canonical_name, warnings):
    """Enrich supported copper interfaces and retain the exact source of each setting."""
    payload, request = _read(client, warnings)
    indexed = _native_rows(payload, canonical_name)
    result = {
        "schema_version": 1,
        "source": {
            "module": "Cisco-IOS-XE-ethernet",
            "path": NATIVE_PATH,
            "request": request,
            "requested_fields": NATIVE_FIELDS,
            "complete": indexed is not None,
            "meaning": (
                "Configured duplex; negotiated and MAC duplex remain operational observations"
            ),
        },
        "interfaces": [],
        "unresolved": [],
    }
    if indexed is None and payload is not None:
        warnings.append(
            "Configured duplex reply lacks a complete native interface scope; fields are preserved"
        )
    seen = set()
    for interface in interfaces:
        name = interface["name"]
        if name in seen:
            raise DuplexDiscoveryError(
                "Configured duplex target interface identity is ambiguous: %s" % name
            )
        seen.add(name)
        if interface.get("type") not in COPPER_TYPES:
            continue
        row = indexed.get(name) if indexed is not None else None
        reason = None
        if indexed is None:
            reason = "Complete native duplex configuration is unavailable"
        elif row is None:
            reason = "Interface is missing from the native duplex configuration scope"
        if reason:
            result["unresolved"].append({"name": name, "reason": reason})
            continue
        value = row["duplex"]
        profile = None
        basis = "explicit"
        if value is None:
            profile = _default_profile(name, interface.get("type"), model, software_version, member)
            if profile is None:
                result["unresolved"].append(
                    {
                        "name": name,
                        "reason": "Omitted configured duplex has no reviewed default for this port",
                    }
                )
                continue
            value, basis = "auto", "documented-default"
        source = {
            **result["source"],
            "field": "%s[name=%s]/Cisco-IOS-XE-ethernet:duplex" % (row["family"], row["name"]),
            "basis": basis,
        }
        if profile:
            source["defaults"] = profile
        interface["duplex"] = value
        interface["duplex_source"] = source
        interface.setdefault("observations", {})["configured_duplex"] = {
            "value": value,
            "basis": basis,
        }
        result["interfaces"].append({"name": name, "duplex": value, "source": source})
    return result


def add_revisions(result, modules):
    """Annotate the native source after the shared YANG-library query."""
    revision = modules.get("Cisco-IOS-XE-ethernet")
    result["source"]["revision"] = revision
    for interface in result["interfaces"]:
        interface["source"]["revision"] = revision
