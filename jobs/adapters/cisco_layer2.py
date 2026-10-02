"""Configured 802.1Q facts from native RESTCONF JSON, with reviewed defaults.

No operational VLAN membership is used to infer a port's configured mode,
native VLAN, or allowed set. Only complete supported bundles are returned.
"""

import re

from ..transport_restconf import RestconfError

NATIVE_PATH = "/data/Cisco-IOS-XE-native:native/interface"
GLOBAL_PATH = "/data/Cisco-IOS-XE-native:native/vlan"
VLAN_PATH = "/data/Cisco-IOS-XE-vlan-oper:vlans"
FAMILIES = (
    "FastEthernet",
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
    "Port-channel",
)
# Request each complete switchport container so omitted leaves have a known
# scope. Augmentation-qualified child filters otherwise silently lose data.
NATIVE_FIELDS = ";".join(family + "(name;switchport-conf;switchport-config)" for family in FAMILIES)
VLAN_FIELDS = "vlan(id;name;status)"
PROFILE = "c9300-48uxm-ordinary-switchport-defaults-v1"
YANG_URL = (
    "https://raw.githubusercontent.com/YangModels/yang/main/"
    "vendor/cisco/xe/17131/Cisco-IOS-XE-switch.yang"
)
DOC_ROOT = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/%s/command_reference/b_%s_9300_cr/"
)


class Layer2DiscoveryError(ValueError):
    """Configured interface/VLAN facts are malformed or ambiguous."""


def _value(mapping, name):
    if not isinstance(mapping, dict):
        return None
    values = [v for k, v in mapping.items() if k.split(":")[-1] == name]
    if len(values) > 1:
        raise Layer2DiscoveryError("Layer2 reply has duplicate namespace-qualified leaves")
    return values[0] if values else None


def _has(mapping, name):
    return isinstance(mapping, dict) and any(k.split(":")[-1] == name for k in mapping)


def _object(value, label):
    if not isinstance(value, dict):
        raise Layer2DiscoveryError("%s must be a structured container" % label)
    return value


def _rows(value, label):
    if value is None:
        return []
    rows = value if isinstance(value, list) else [value]
    if any(not isinstance(row, dict) for row in rows):
        raise Layer2DiscoveryError("%s must contain structured objects" % label)
    return rows


def _vid(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
        raise Layer2DiscoveryError("Configured VLAN IDs must be integers from 1 to 4094")
    return value


def _empty(value, label):
    if value != [None]:
        raise Layer2DiscoveryError("%s must be a YANG empty leaf" % label)


def _vlan_set(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return [_vid(value)]
    if not isinstance(value, str) or not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise Layer2DiscoveryError("Allowed VLANs must be a structured numeric range expression")
    values = set()
    for token in value.split(","):
        ends = [int(part) for part in token.split("-")]
        first, last = ends[0], ends[-1]
        _vid(first)
        _vid(last)
        if first > last:
            raise Layer2DiscoveryError("Allowed VLAN range bounds are reversed")
        values.update(range(first, last + 1))
    return sorted(values)


def _read(client, path, fields, warnings):
    try:
        return client.get(path + "?fields=" + fields if fields else path), True
    except RestconfError as exc:
        if fields and exc.status_code == 400:
            warnings.append(
                "%s: fields filter rejected (HTTP 400); unfiltered JSON read used" % path
            )
            try:
                return client.get(path), True
            except RestconfError:
                pass
        warnings.append("Layer2 source unavailable: %s; existing fields are preserved" % path)
        return None, False


def _profile(model, version):
    family = ".".join(version.split(".")[:2]) if isinstance(version, str) else None
    if model != "C9300-48UXM" or family not in ("17.9", "17.12"):
        return None
    doc_root = DOC_ROOT % (family.replace(".", "-"), family.replace(".", ""))
    return {
        "profile": PROFILE,
        "model": model,
        "software_family": family,
        "native_vid": 1,
        "allowed_vlans": "all",
        "global_native_tagging": False,
        "documents": {
            "ordinary_trunk": doc_root + "vlan_commands.html",
            "global_native_tagging": doc_root + "vlan_commands.html",
        },
        "meaning": "Documented defaults apply only after successful complete scoped config reads",
    }


def _global_tagging(payload, read_ok, profile, status):
    if not read_ok:
        return None
    # An IOS XE 204 means the successful scoped configuration read has no
    # configured presence leaf. A 200 null/empty/wrong-envelope reply does not
    # establish the same fact and must not enable documented-default inference.
    if status == 204 and payload in (None, {}):
        return False if profile else None
    if payload is None:
        return None
    _object(payload, "Global VLAN reply")
    container = _value(payload, "vlan")
    if container is None:
        return None
    _object(container, "Global VLAN configuration")
    dot1q = _value(container, "dot1q")
    if dot1q is not None:
        _object(dot1q, "Global dot1q configuration")
    tag = _value(dot1q, "tag")
    if tag is not None:
        _object(tag, "Global native VLAN tagging")
    if _has(tag, "native"):
        _empty(_value(tag, "native"), "Global native tagging")
        return True
    return False if profile else None


def _response_status(client, path):
    for request in reversed(getattr(client, "trace", [])):
        if request.get("path", "").split("?", 1)[0] == path:
            return request.get("status")
    return None


def _allowed(trunk, profile):
    allowed = _value(trunk, "allowed")
    if allowed is None:
        return ("all", None, "documented-default") if profile else (None, None, None)
    _object(allowed, "Allowed VLAN configuration")
    newer = _value(allowed, "vlan-v2")
    node = newer if newer is not None else _value(allowed, "vlan")
    if node is None:
        return None, None, None
    _object(node, "Allowed VLAN selection")
    if any(_has(node, key) for key in ("add", "add-vlans", "except", "remove")):
        return None, None, "incremental VLAN modification requires review"
    choices = _value(node, "vlan-choices") if newer is not None else node
    if choices is None:
        return None, None, None
    _object(choices, "Allowed VLAN choices")
    selected = [key for key in ("vlans", "all", "none") if _has(choices, key)]
    if len(selected) > 1:
        raise Layer2DiscoveryError("Allowed VLAN choices are ambiguous")
    if not selected:
        return ("all", None, "documented-default") if profile else (None, None, None)
    key = selected[0]
    value = _value(choices, key)
    if key == "vlans":
        return "list", _vlan_set(value), "explicit"
    if key == "none":
        _empty(value, "Allowed VLAN none")
        return "list", [], "explicit-none"
    if newer is not None:
        if value is not True:
            raise Layer2DiscoveryError("Allowed VLAN all must be true")
    else:
        _empty(value, "Allowed VLAN all")
    return "all", None, "explicit-all"


def _bundle(switchport, profile, global_tagging):
    mode = _value(switchport, "mode")
    if mode is None:
        return None, "Configured switchport mode is absent; access/trunk is not inferred"
    _object(mode, "Switchport mode")
    options = [
        key
        for key in ("access", "trunk", "dynamic", "private-vlan", "dot1q-tunnel")
        if _has(mode, key)
    ]
    if len(options) > 1:
        raise Layer2DiscoveryError("Switchport mode choices are ambiguous")
    if options not in (["access"], ["trunk"]):
        return None, "Configured %s mode requires a reviewed 802.1Q mapping" % (
            options[0] if options else "unsupported switchport"
        )
    _object(_value(mode, options[0]), "Switchport mode presence")
    if _has(switchport, "voice"):
        return None, "Voice VLAN configuration requires a reviewed mixed tagged/untagged mapping"
    if _has(switchport, "private-vlan"):
        return None, "Private VLAN configuration requires another interpretation increment"
    if options == ["access"]:
        access = _value(_value(switchport, "access"), "vlan")
        vid = _value(access, "vlan")
        if vid is None:
            return None, "Access VLAN is absent; no access VLAN default is applied"
        if not isinstance(vid, int) or isinstance(vid, bool):
            return None, "Dynamic/named access VLAN requires a reviewed identity mapping"
        return {
            "mode": "access",
            "untagged_vid": _vid(vid),
            "tagged_vids": [],
            "observations": {"configured_mode": "access", "access_vid": vid},
        }, None
    trunk = _value(switchport, "trunk")
    if trunk is not None:
        _object(trunk, "Trunk configuration")
    encapsulation = _value(trunk, "encapsulation")
    if encapsulation not in (None, "dot1q"):
        return None, "Trunk encapsulation is not explicitly supported 802.1Q"
    if global_tagging is not False:
        return None, "Global native VLAN tagging is enabled or unavailable; mapping requires review"
    native = _value(_value(trunk, "native"), "vlan")
    if native is not None:
        _object(native, "Native VLAN configuration")
    native_tag = _value(native, "tag")
    if native_tag is not None and not isinstance(native_tag, bool):
        raise Layer2DiscoveryError("Native VLAN tagging override must be boolean")
    vid = _value(native, "vlan-id")
    native_source = "explicit"
    if vid is None:
        if not profile:
            return None, "Native VLAN is absent and no reviewed default profile applies"
        vid = profile["native_vid"]
        native_source = "documented-default"
    vid = _vid(vid)
    allowed_mode, allowed_vids, allowed_source = _allowed(trunk, profile)
    if allowed_mode is None:
        return None, allowed_source or "Allowed VLAN set is absent or unresolved"
    allowed = _value(trunk, "allowed")
    newer = _value(allowed, "vlan-v2")
    selected = _value(newer, "vlan-choices") if newer is not None else _value(allowed, "vlan")
    raw_allowed = {
        key: _value(selected, key) for key in ("vlans", "all", "none") if _has(selected, key)
    }
    return {
        "mode": "tagged-all" if allowed_mode == "all" else "tagged",
        "untagged_vid": vid,
        "tagged_vids": [value for value in (allowed_vids or []) if value != vid],
        "observations": {
            "configured_mode": "trunk",
            "native_vid": vid,
            "native_vid_source": native_source,
            "native_tag_override": native_tag,
            "global_native_tagging": global_tagging,
            "allowed_mode": allowed_mode,
            "allowed_vids": allowed_vids,
            "raw_allowed": raw_allowed,
            "allowed_source": allowed_source,
            "native_in_allowed": allowed_mode == "all" or vid in allowed_vids,
            "native_meaning": (
                "Configured native VLAN retained even when the allowed list excludes it"
            ),
        },
    }, None


def collect(client, interfaces, *, model, software_version, canonical_name, warnings):
    """Return complete configured layer2 bundles and unresolved observations."""
    result = {"schema_version": 1, "interfaces": [], "vlans": [], "unresolved": []}
    profile = _profile(model, software_version)
    native, native_ok = _read(client, NATIVE_PATH, NATIVE_FIELDS, warnings)
    global_payload, global_ok = _read(client, GLOBAL_PATH, None, warnings)
    global_status = _response_status(client, GLOBAL_PATH)
    vlan_payload, vlan_ok = _read(client, VLAN_PATH, VLAN_FIELDS, warnings)
    global_tagging = _global_tagging(global_payload, global_ok, profile, global_status)
    container = _value(native, "interface") if native_ok else None
    if container is not None:
        _object(container, "Native interface configuration")
    config = {}
    for family, rows in (container or {}).items():
        family = family.split(":")[-1]
        if family not in FAMILIES:
            continue
        for row in _rows(rows, "Native interface family"):
            name_value = _value(row, "name")
            if isinstance(name_value, bool) or not isinstance(name_value, (str, int)):
                raise Layer2DiscoveryError("Native interface requires a structured name")
            name = canonical_name(family + str(name_value))
            if name in config:
                raise Layer2DiscoveryError("Native interface canonical names are ambiguous")
            config[name] = row
    for interface in sorted(interfaces, key=lambda row: row["name"]):
        name = interface["name"]
        row = config.get(name)
        source = {
            "config": {
                "module": "Cisco-IOS-XE-switch",
                "container_module": "Cisco-IOS-XE-native",
                "path": NATIVE_PATH,
                "interface": name,
                "field": "switchport-config/switchport",
            }
        }
        if row is None:
            reason = "Scoped native configuration does not contain this interface"
            bundle = None
        else:
            enabled_container = _value(row, "switchport-conf")
            if enabled_container is not None:
                _object(enabled_container, "Native switchport enable configuration")
            enabled = _value(enabled_container, "switchport")
            if enabled is not None and not isinstance(enabled, bool):
                raise Layer2DiscoveryError("Native switchport enable must be boolean")
            switchport_container = _value(row, "switchport-config")
            if switchport_container is not None:
                _object(switchport_container, "Native switchport configuration")
            switchport = _value(switchport_container, "switchport")
            if enabled is False:
                bundle, reason = None, "Explicit no-switchport reports a routed interface"
            elif switchport is None:
                bundle, reason = (
                    None,
                    "Configured switchport mode is absent; access/trunk is not inferred",
                )
            else:
                _object(switchport, "Switchport configuration")
                bundle, reason = _bundle(switchport, profile, global_tagging)
        if bundle is None:
            result["unresolved"].append({"name": name, "reason": reason, "source": source})
            continue
        if bundle["observations"]["configured_mode"] == "trunk":
            source["global_tagging"] = {
                "module": "Cisco-IOS-XE-vlan",
                "path": GLOBAL_PATH,
                "field": "dot1q/tag/native",
                "enabled": global_tagging,
                "complete_read": global_ok,
                "http_status": global_status,
            }
            if profile:
                source["defaults"] = profile
        result["interfaces"].append({"name": name, **bundle, "source": source})
    if vlan_ok:
        vlans = _value(vlan_payload, "vlans")
        if vlans is not None:
            _object(vlans, "VLAN operational database")
            seen = set()
            for row in _rows(_value(vlans, "vlan"), "VLAN operational database"):
                vid = _vid(_value(row, "id"))
                if vid in seen:
                    raise Layer2DiscoveryError("VLAN operational database has ambiguous IDs")
                seen.add(vid)
                name = _value(row, "name")
                if name is None or name == "":
                    continue
                if not isinstance(name, str) or not name.strip():
                    raise Layer2DiscoveryError("VLAN names must be structured text")
                result["vlans"].append(
                    {
                        "vid": vid,
                        "name": name.strip(),
                        "source": {
                            "identity": {
                                "module": "Cisco-IOS-XE-vlan-oper",
                                "path": VLAN_PATH,
                                "field": "vlan[id]/name",
                            }
                        },
                        "observations": {"status": _value(row, "status")},
                    }
                )
        else:
            warnings.append(
                "VLAN identity source returned no database; missing VLAN records cannot be created"
            )
    result["vlans"].sort(key=lambda row: row["vid"])
    return result


def add_revisions(layer2, modules):
    """Annotate collected field provenance after the shared module-library read."""
    for collection in ("interfaces", "vlans", "unresolved"):
        for row in layer2[collection]:
            for source in row.get("source", {}).values():
                if isinstance(source, dict) and source.get("module"):
                    source["revision"] = modules.get(source["module"])
