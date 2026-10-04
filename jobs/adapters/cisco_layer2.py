"""Configured and directly reported operational 802.1Q facts from RESTCONF JSON.

No operational VLAN membership is used to infer a port's configured mode,
native VLAN, or allowed set. Independent settings survive incomplete mappings.
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
    "FiftyGigabitEthernet",
    "HundredGigE",
    "TwoHundredGigE",
    "FourHundredGigE",
    "Port-channel",
)
# Request each complete switchport container so omitted leaves have a known
# scope. Augmentation-qualified child filters otherwise silently lose data.
NATIVE_FIELDS = ";".join(family + "(name;switchport-conf;switchport-config)" for family in FAMILIES)
VLAN_FIELDS = "vlan(id;name;status)"
PROFILE = "c9300-48uxm-ordinary-switchport-defaults-v4"
YANG_URL = (
    "https://raw.githubusercontent.com/YangModels/yang/main/"
    "vendor/cisco/xe/17131/Cisco-IOS-XE-switch.yang"
)
DOC_ROOT = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/%s/command_reference/b_%s_9300_cr/"
)
CONFIG_DOC_ROOT = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/%s/configuration_guide/int_hw/b_%s_int_and_hw_9300_cg/"
)
NTC_DOWN_POLICY = "ntc-device-onboarding-5.4.1-dynamic-down-all"
NTC_DOWN_SOURCE = (
    "https://github.com/nautobot/nautobot-app-device-onboarding/blob/"
    "812746dc6f09077b8fe099da2318315e4e7cab23/"
    "nautobot_device_onboarding/jinja_filters.py#L95"
)
NTC_DOWN_STATES = ("if-oper-state-no-pass", "if-oper-state-lower-layer-down")


class Layer2DiscoveryError(ValueError):
    """Configured interface/VLAN facts are malformed or ambiguous."""


def _value(mapping, name, namespace="Cisco-IOS-XE-switch"):
    if not isinstance(mapping, dict):
        return None
    matches = [(key, value) for key, value in mapping.items() if key.split(":")[-1] == name]
    if any(":" in key and key.split(":", 1)[0] != namespace for key, _ in matches):
        raise Layer2DiscoveryError("Layer2 leaf belongs to an unexpected YANG module")
    values = [value for _, value in matches]
    if len(values) > 1:
        raise Layer2DiscoveryError("Layer2 reply has duplicate namespace-qualified leaves")
    return values[0] if values else None


def _has(mapping, name, namespace="Cisco-IOS-XE-switch"):
    _value(mapping, name, namespace)
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
    if model != "C9300-48UXM" or family not in ("17.9", "17.12", "17.15", "17.18"):
        return None
    doc_root = DOC_ROOT % (family.replace(".", "-"), family.replace(".", ""))
    config_root = CONFIG_DOC_ROOT % (family.replace(".", "-"), family.replace(".", ""))
    return {
        "profile": PROFILE,
        "model": model,
        "software_family": family,
        "configured_mode": "dynamic-auto",
        "access_vid": 1,
        "native_vid": 1,
        "allowed_vlans": "all",
        "global_native_tagging": False,
        "documents": {
            "ordinary_trunk": doc_root + "vlan_commands.html",
            "global_native_tagging": doc_root + "vlan_commands.html",
            "interface_defaults": config_root + "configuring_interface_characteristics.html",
            "management_interface": config_root + "configuring_ethernet_management_port.html",
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
    container = _value(payload, "vlan", "Cisco-IOS-XE-native")
    if _has(payload, "vlan", "Cisco-IOS-XE-native"):
        _object(container, "Global VLAN configuration")
    if container is None:
        return None
    _object(container, "Global VLAN configuration")
    dot1q = _container(container, "dot1q", "Global dot1q configuration", "Cisco-IOS-XE-vlan")
    tag = _container(dot1q, "tag", "Global native VLAN tagging", "Cisco-IOS-XE-vlan")
    if _has(tag, "native", "Cisco-IOS-XE-vlan"):
        _empty(_value(tag, "native", "Cisco-IOS-XE-vlan"), "Global native tagging")
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
        if _has(trunk, "allowed"):
            _object(allowed, "Allowed VLAN configuration")
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
    if selected and any(key.split(":")[-1] not in ("vlans", "all", "none") for key in choices):
        raise Layer2DiscoveryError("Allowed VLAN choices include an unsupported competing selector")
    if not selected:
        if choices:
            return None, None, "Unsupported allowed VLAN choice requires review"
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


def _configured_mode(switchport, profile, physical):
    mode = _value(switchport, "mode")
    if mode is None:
        if _has(switchport, "mode"):
            _object(mode, "Switchport mode")
        return (
            (profile["configured_mode"], "documented-default")
            if profile and physical
            else (
                None,
                None,
            )
        )
    _object(mode, "Switchport mode")
    options = [
        key
        for key in ("access", "trunk", "dynamic", "private-vlan", "dot1q-tunnel")
        if _has(mode, key)
    ]
    if len(options) > 1:
        raise Layer2DiscoveryError("Switchport mode choices are ambiguous")
    if options and any(
        key.split(":")[-1] not in ("access", "trunk", "dynamic", "private-vlan", "dot1q-tunnel")
        for key in mode
    ):
        raise Layer2DiscoveryError("Switchport mode includes an unsupported competing selector")
    if not options:
        # An unrecognized mode leaf is not evidence for an ordinary default.
        if not mode and profile and physical:
            return profile["configured_mode"], "documented-default"
        return None, None
    selected = options[0]
    value = _value(mode, selected)
    if selected == "dynamic":
        if value not in ("auto", "desirable"):
            raise Layer2DiscoveryError("Dynamic switchport mode must be auto or desirable")
        return "dynamic-" + value, "explicit"
    _object(value, "Switchport mode presence")
    return selected, "explicit"


def _container(parent, name, label, namespace="Cisco-IOS-XE-switch"):
    value = _value(parent, name, namespace)
    if _has(parent, name, namespace):
        _object(value, label)
    return value


def _settings(switchport, profile, global_tagging, physical):
    """Keep separate administrative facts, without inventing a forwarding mode."""
    mode, mode_source = _configured_mode(switchport, profile, physical)
    ordinary = mode in ("access", "trunk", "dynamic-auto", "dynamic-desirable", None)
    ordinary = ordinary and not any(_has(switchport, key) for key in ("voice", "private-vlan"))
    raw_mode = _value(switchport, "mode")
    if raw_mode and mode is None:
        ordinary = False
    trunk = _container(switchport, "trunk", "Trunk configuration")
    if _has(trunk, "encapsulation") and _value(trunk, "encapsulation") is None:
        raise Layer2DiscoveryError("Trunk encapsulation must not be null when present")
    ordinary = ordinary and _value(trunk, "encapsulation") in (None, "dot1q")
    defaults = profile if ordinary else None
    origins = {"configured_mode": mode_source} if mode_source else {}
    access = _container(switchport, "access", "Access configuration")
    access = _container(access, "vlan", "Access VLAN configuration")
    raw_access = _value(access, "vlan")
    access_vid = None
    if _has(access, "vlan"):
        if isinstance(raw_access, int) and not isinstance(raw_access, bool):
            access_vid = _vid(raw_access)
            origins["access_vid"] = "explicit"
        elif raw_access != "dynamic":
            raise Layer2DiscoveryError("Access VLAN must be a VLAN ID or dynamic selection")
    elif defaults:
        access_vid = defaults["access_vid"]
        origins["access_vid"] = "documented-default"
    native = _container(trunk, "native", "Native VLAN configuration")
    native = _container(native, "vlan", "Native VLAN configuration")
    native_vid = None
    if _has(native, "vlan-id"):
        native_vid = _vid(_value(native, "vlan-id"))
        origins["native_vid"] = "explicit"
    elif defaults:
        native_vid = defaults["native_vid"]
        origins["native_vid"] = "documented-default"
    native_override = _value(native, "tag")
    if _has(native, "tag") and not isinstance(native_override, bool):
        raise Layer2DiscoveryError("Native VLAN tagging override must be boolean")
    # Preserve an explicit override as evidence. Its interaction with the
    # global command has not been reviewed, so effective tagging stays unknown.
    native_tagging = global_tagging if native_override is None else None
    if native_tagging is not None:
        origins["native_tagging"] = "global-config"
    allowed_mode, allowed_vids, allowed_source = _allowed(trunk, defaults)
    if allowed_mode is not None:
        origins["allowed_mode"] = allowed_source
        if allowed_vids is not None:
            origins["allowed_vids"] = allowed_source
    allowed = _value(trunk, "allowed")
    newer = _value(allowed, "vlan-v2")
    choices = _value(newer, "vlan-choices") if newer is not None else _value(allowed, "vlan")
    raw_allowed = {
        key: _value(choices, key) for key in ("vlans", "all", "none") if _has(choices, key)
    }
    untagged = None
    if ordinary and mode == "access":
        untagged = access_vid
        if untagged is not None:
            origins["untagged_vid"] = "configured-access-vlan"
    elif ordinary and mode == "trunk" and native_tagging is False:
        untagged = native_vid
        if untagged is not None:
            origins["untagged_vid"] = "configured-native-vlan-with-tagging-disabled"
    elif (
        ordinary
        and mode in ("dynamic-auto", "dynamic-desirable")
        and access_vid is not None
        and access_vid == native_vid
        and native_tagging is False
    ):
        # Access or negotiated trunk would use the same untagged VLAN; this
        # establishes the VLAN without establishing which forwarding mode won.
        untagged = access_vid
        origins["untagged_vid"] = "equal-access-and-native-vlans-with-tagging-disabled"
    return {
        "configured_mode": mode,
        "access_vid": access_vid,
        "native_vid": native_vid,
        "native_tagging": native_tagging,
        "allowed_mode": allowed_mode,
        "allowed_vids": allowed_vids,
        "untagged_vid": untagged,
        "field_sources": origins,
        "observations": {
            "access_vlan_selection": raw_access,
            "native_tag_override": native_override,
            "global_native_tagging": global_tagging,
            "raw_allowed": raw_allowed,
            "allowed_unresolved_reason": allowed_source if allowed_mode is None else None,
            "voice_vlan_present": _has(switchport, "voice"),
            "private_vlan_present": _has(switchport, "private-vlan"),
            "trunk_encapsulation": _value(trunk, "encapsulation"),
            "untagged_meaning": (
                "Equal access/native VLAN settings establish untagged VLAN independently "
                "of negotiated access/trunk mode"
                if origins.get("untagged_vid")
                == "equal-access-and-native-vlans-with-tagging-disabled"
                else None
            ),
        },
    }


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
            if not profile:
                return None, "Access VLAN is absent and no reviewed default profile applies"
            vid = profile["access_vid"]
        if not isinstance(vid, int) or isinstance(vid, bool):
            return None, "Dynamic/named access VLAN requires a reviewed identity mapping"
        return {
            "mode": "access",
            "untagged_vid": _vid(vid),
            "tagged_vids": [],
            "observations": {
                "configured_mode": "access",
                "access_vid": vid,
                "access_vid_source": ("explicit" if _has(access, "vlan") else "documented-default"),
            },
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
    if native_tag is not None:
        return None, "Per-interface native tagging override requires a reviewed interpretation"
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


OPER_MODULE = "Cisco-IOS-XE-switchport-oper"
OPER_ADMIN = {
    "admin-stat-acc": "access",
    "admin-dyn-acc": "dynamic-access",
    "admin-trunk": "trunk",
    "admin-dyn-auto": "dynamic-auto",
    "admin-dyn-des": "dynamic-desirable",
}
DYNAMIC_MODES = ("dynamic-auto", "dynamic-desirable", "dynamic-access")


def _oper_enum(value):
    if not isinstance(value, str):
        return None
    if ":" not in value:
        return value
    module, local = value.split(":", 1)
    return local if module == OPER_MODULE else None


def _operational_bundle(
    settings, switchport, profile, global_tagging, fact, interface, lag, canonical_name
):
    """Resolve ordinary dynamic mode from the vendor's actual negotiated status.

    Administrative configuration and operational mode remain distinct facts.
    This increment uses configured VLAN policy for assignments; operational
    VLANs, voice states and aggregation context are retained as evidence.
    """
    operational = fact["operational_mode"]
    settings["operational_mode"] = operational
    settings["field_sources"]["operational_mode"] = "device-reported-after-negotiation"
    raw = fact["observations"]
    details = _value(raw, "port-details", OPER_MODULE) or {}
    observations = settings["observations"]
    observations["switchport_oper"] = raw
    admin = OPER_ADMIN.get(_oper_enum(fact["admin_mode"]))
    # An explicit reported administrative enum can establish an omitted mode
    # on an otherwise complete native row, without a model/release default.
    if (
        settings["configured_mode"] is None
        and not _value(switchport, "mode")
        and admin in DYNAMIC_MODES
    ):
        settings["configured_mode"] = admin
        settings["field_sources"]["configured_mode"] = "device-reported-admin-mode"
    blocked = None
    raw_oper = _oper_enum(_value(details, "oper-mode", OPER_MODULE))
    voice = _value(details, "voice-state", OPER_MODULE)
    access_state = _value(details, "access-state", OPER_MODULE)
    voice = _oper_enum(voice)
    access_state = _oper_enum(access_state)
    if _value(raw, "enabled", OPER_MODULE) != [None]:
        blocked = "Reported switchport row is routed rather than Layer 2"
    elif (
        observations["voice_vlan_present"]
        or observations["private_vlan_present"]
        or observations["trunk_encapsulation"] not in (None, "dot1q")
        or voice not in (None, "voice-none")
        or (_has(details, "voice-state", OPER_MODULE) and voice is None)
        or (_has(details, "access-state", OPER_MODULE) and access_state is None)
        or str(access_state or "").startswith("acc-pvlan-")
        or admin is None
        or (_has(details, "oper-mode", OPER_MODULE) and raw_oper is None)
        or raw_oper
        not in (None, "oper-unknown", "oper-down", "oper-stat-acc", "oper-dyn-acc", "oper-trunk")
    ):
        blocked = "Reported or configured switchport semantics require a separate VLAN mapping"
    agport = _value(details, "agport-if-name", OPER_MODULE)
    if _value(details, "is-agport-suspend", OPER_MODULE) is True:
        blocked = "Reported aggregate-port membership is suspended"
    elif agport and canonical_name(agport) != lag:
        blocked = "Reported aggregate-port name disagrees with configured membership"
    if blocked:
        observations["operational_mapping_blocked"] = True
        return None, blocked
    if settings["configured_mode"] not in DYNAMIC_MODES:
        return None, None
    if admin != settings["configured_mode"]:
        return None, "Reported administrative mode disagrees with native dynamic configuration"
    if operational not in ("access", "trunk"):
        return None, "Reported operational switchport mode is down, unknown, or unsupported"
    # A positive negotiated mode and a simultaneously down ordinary interface
    # are conflicting observations. Never convert this conflict into a guess.
    state = interface.get("observations", {}).get("oper_status")
    if state in NTC_DOWN_STATES:
        return None, "Reported switchport mode disagrees with the interface's down link state"
    # Preserve the configured VLAN policy and every existing safety check in
    # _bundle. Only the directly established access/trunk selector changes.
    resolved = dict(switchport)
    resolved["mode"] = {operational: {}}
    # Avoid duplicate qualified/unqualified mode members in copied config.
    for key in list(resolved):
        if key != "mode" and key.split(":")[-1] == "mode":
            del resolved[key]
    bundle, reason = _bundle(resolved, profile, global_tagging)
    if bundle is not None:
        bundle["observations"]["configured_mode"] = settings["configured_mode"]
        bundle["observations"]["operational_mode"] = operational
        bundle["observations"]["mode_meaning"] = "Device-reported actual mode after negotiation"
        # An actual access/trunk observation selects which independently known
        # VLAN setting supplies untagged traffic, rather than guessing a mode.
        settings["untagged_vid"] = bundle["untagged_vid"]
        settings["field_sources"]["untagged_vid"] = (
            "configured-access-vlan-with-reported-access-mode"
            if operational == "access"
            else "configured-native-vlan-with-reported-trunk-mode-and-tagging-disabled"
        )
    return bundle, reason


def _ntc_down_bundle(settings, interface, physical, reason):
    """Apply the explicitly opted-in NTC down-port policy, never a known mode."""
    operational = interface.get("observations")
    observed = operational.get("oper_status") if isinstance(operational, dict) else None
    observations = settings["observations"]
    literal_full_range = (
        settings["allowed_mode"] == "list"
        and observations["raw_allowed"].get("vlans") == "1-4094"
        and settings["allowed_vids"] == list(range(1, 4095))
    )
    if (
        not physical
        or settings["configured_mode"] not in ("dynamic-auto", "dynamic-desirable")
        or not (settings["allowed_mode"] == "all" or literal_full_range)
        or settings["native_vid"] is None
        or settings["native_tagging"] is not False
        or observations["native_tag_override"] is not None
        or observations["voice_vlan_present"]
        or observations["private_vlan_present"]
        or observations["trunk_encapsulation"] not in (None, "dot1q")
        or observed not in NTC_DOWN_STATES
    ):
        return None
    inference = {
        "policy": NTC_DOWN_POLICY,
        "upstream_url": NTC_DOWN_SOURCE,
        "module": "Cisco-IOS-XE-interfaces-oper",
        "path": "/data/Cisco-IOS-XE-interfaces-oper:interfaces",
        "field": "oper-status",
        "interface": interface["name"],
        "observed_oper_status": observed,
        "configured_mode": settings["configured_mode"],
        "inferred_fields": {"mode": "tagged-all", "untagged_vid": settings["native_vid"]},
        "allowed_vlan_evidence": {
            "configured_policy": settings["allowed_mode"],
            "raw_selection": dict(observations["raw_allowed"]),
            "source": settings["field_sources"].get("allowed_mode"),
            "validated_literal_full_range": literal_full_range,
        },
        "reason": reason,
        "meaning": (
            "Opt-in assumption using NTC Device Onboarding's dynamic/down/allowed-all fallback; "
            "the observed link state does not confirm the negotiated switchport mode"
        ),
    }
    settings["inference"] = inference
    return {
        "mode": "tagged-all",
        "untagged_vid": settings["native_vid"],
        "tagged_vids": [],
        "inferred": True,
        "observations": {
            "configured_mode": settings["configured_mode"],
            "native_vid": settings["native_vid"],
            "native_vid_source": settings["field_sources"].get("native_vid"),
            "global_native_tagging": settings["native_tagging"],
            "allowed_mode": settings["allowed_mode"],
            "allowed_vids": settings["allowed_vids"],
            "allowed_source": settings["field_sources"].get("allowed_mode"),
            "native_in_allowed": True,
        },
    }


def collect(
    client,
    interfaces,
    *,
    model,
    software_version,
    canonical_name,
    warnings,
    use_ntc_defaults=False,
    switchport_oper=None,
    lag_memberships=(),
):
    """Return modelable bundles, independent facts, and explicit applicability."""
    if type(use_ntc_defaults) is not bool:
        raise Layer2DiscoveryError("NTC default guessing requires an explicit boolean flag")
    result = {
        "schema_version": 1,
        "interfaces": [],
        "settings": [],
        "vlans": [],
        "catalog_complete": False,
        "unresolved": [],
        "not_applicable": [],
    }
    operational = switchport_oper or {"interfaces": []}
    result["operational_source"] = operational.get("source")
    result["operational_interfaces"] = list(operational["interfaces"])
    operational_invalid = (operational.get("source") or {}).get("status") == "invalid"
    operational_by_name = {row["name"]: row for row in operational["interfaces"]}
    lags = {row["member"]: canonical_name(row["lag"]) for row in lag_memberships}
    profile = _profile(model, software_version)
    native, native_ok = _read(client, NATIVE_PATH, NATIVE_FIELDS, warnings)
    global_payload, global_ok = _read(client, GLOBAL_PATH, None, warnings)
    global_status = _response_status(client, GLOBAL_PATH)
    vlan_payload, vlan_ok = _read(client, VLAN_PATH, VLAN_FIELDS, warnings)
    global_tagging = _global_tagging(global_payload, global_ok, profile, global_status)
    if native_ok and native is not None:
        _object(native, "Native interface reply")
    container = _value(native, "interface", "Cisco-IOS-XE-native") if native_ok else None
    if native_ok and _has(native, "interface", "Cisco-IOS-XE-native"):
        _object(container, "Native interface configuration")
    config = {}
    for family, rows in (container or {}).items():
        local_family = family.split(":")[-1]
        if local_family not in FAMILIES:
            continue
        if ":" in family and family.split(":", 1)[0] != "Cisco-IOS-XE-native":
            raise Layer2DiscoveryError(
                "Native interface family belongs to an unexpected YANG module"
            )
        family = local_family
        for row in _rows(rows, "Native interface family"):
            name_value = _value(row, "name", "Cisco-IOS-XE-native")
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
                "complete_read": native_ok and container is not None,
            }
        }
        if interface.get("type") in ("virtual", "bridge", "tunnel") or re.fullmatch(
            r"Vlan\d+", name
        ):
            result["not_applicable"].append(
                {
                    "name": name,
                    "category": "virtual-interface",
                    "reason": "Virtual/routed logical interface has no ordinary switchport mapping",
                    "source": source,
                }
            )
            continue
        if profile and name == "GigabitEthernet0/0":
            source["defaults"] = profile
            result["not_applicable"].append(
                {
                    "name": name,
                    "category": "dedicated-management",
                    "reason": "Documented dedicated Ethernet management port is not a switchport",
                    "source": source,
                }
            )
            continue
        category = "missing-data" if native_ok else "unavailable"
        if row is None:
            reason = "Scoped native configuration does not contain this interface"
            bundle = None
        else:
            enabled_container = _container(
                row,
                "switchport-conf",
                "Native switchport enable configuration",
                "Cisco-IOS-XE-native",
            )
            enabled = _value(enabled_container, "switchport", "Cisco-IOS-XE-native")
            if _has(enabled_container, "switchport", "Cisco-IOS-XE-native") and not isinstance(
                enabled, bool
            ):
                raise Layer2DiscoveryError("Native switchport enable must be boolean")
            if enabled is False:
                result["not_applicable"].append(
                    {
                        "name": name,
                        "category": "routed-interface",
                        "reason": "Explicit no-switchport reports a routed interface",
                        "source": source,
                    }
                )
                continue
            switchport_container = _container(
                row, "switchport-config", "Native switchport configuration", "Cisco-IOS-XE-native"
            )
            switchport = _container(
                switchport_container,
                "switchport",
                "Switchport configuration",
                "Cisco-IOS-XE-native",
            )
            physical = (
                re.fullmatch(r"(?:%s)\d+/\d+/\d+" % "|".join(FAMILIES[:-1]), name) is not None
            )
            # Default inference requires this exact structured row in a valid,
            # successfully read scope, and an ordinary documented interface.
            defaults = profile if physical or enabled is True or switchport is not None else None
            settings = _settings(switchport or {}, defaults, global_tagging, physical)
            source["global_tagging"] = {
                "module": "Cisco-IOS-XE-vlan",
                "path": GLOBAL_PATH,
                "field": "dot1q/tag/native",
                "enabled": global_tagging,
                "complete_read": global_ok,
                "http_status": global_status,
                "origin": (
                    "documented-default"
                    if global_tagging is False
                    else "explicit"
                    if global_tagging is True
                    else None
                ),
            }
            if defaults:
                source["defaults"] = defaults
            bundle, reason = _bundle(switchport or {}, defaults, global_tagging)
            operational_fact = operational_by_name.get(name)
            operational_reason = None
            if operational_invalid:
                settings["observations"]["operational_source_invalid"] = True
                operational_reason = (
                    "Optional operational switchport data was invalid; negotiated mode "
                    "and guessing remain unresolved"
                )
            if operational_fact is not None:
                source["operational_mode"] = operational_fact["source"]
                observed_bundle, operational_reason = _operational_bundle(
                    settings,
                    switchport or {},
                    defaults,
                    global_tagging,
                    operational_fact,
                    interface,
                    lags.get(name),
                    canonical_name,
                )
                if settings["observations"].get("operational_mapping_blocked"):
                    bundle, reason, category = None, operational_reason, "unsupported"
                elif observed_bundle is not None:
                    bundle, reason = observed_bundle, None
                    settings["operational_assignment_supported"] = True
            if bundle is None and settings["configured_mode"] in DYNAMIC_MODES:
                reason = (
                    "Administrative %s is known; negotiated access/trunk mode is not established"
                    % settings["configured_mode"]
                )
                if operational_reason:
                    reason = operational_reason
                if (
                    settings["access_vid"] is not None
                    and settings["native_vid"] is not None
                    and settings["allowed_mode"] is not None
                    and settings["native_tagging"] is not None
                    and not settings["observations"]["voice_vlan_present"]
                    and not settings["observations"]["private_vlan_present"]
                    and settings["observations"]["trunk_encapsulation"] in (None, "dot1q")
                    and not settings["observations"].get("operational_mapping_blocked")
                ):
                    category = "dynamic-mode"
            elif settings["configured_mode"] in ("private-vlan", "dot1q-tunnel") or any(
                settings["observations"][key]
                for key in ("voice_vlan_present", "private_vlan_present")
            ):
                category = "unsupported"
            elif "requires" in (reason or "") or "not explicitly supported" in (reason or ""):
                category = "unsupported"
            settings["unresolved_reason"] = reason
            # A reported positive/special/unknown mode must never be replaced
            # by NTC's link-down assumption. Only an actual down report may
            # participate, and the existing independent link-down guard holds.
            permit_inference = not operational_invalid and (
                operational_fact is None
                or (
                    operational_fact["operational_mode"] == "down"
                    and _oper_enum(operational_fact["admin_mode"])
                    in ("admin-dyn-auto", "admin-dyn-des")
                    and operational_reason
                    == "Reported operational switchport mode is down, unknown, or unsupported"
                )
            )
            if use_ntc_defaults and bundle is None and permit_inference:
                bundle = _ntc_down_bundle(settings, interface, physical, reason)
                if bundle is not None:
                    source["ntc_inference"] = settings["inference"]
            result["settings"].append({"name": name, **settings, "source": source})
        if bundle is None:
            result["unresolved"].append(
                {"name": name, "reason": reason, "category": category, "source": source}
            )
            continue
        result["interfaces"].append({"name": name, **bundle, "source": source})
    if vlan_ok:
        if vlan_payload is not None:
            _object(vlan_payload, "VLAN operational reply")
        vlans = _value(vlan_payload, "vlans", "Cisco-IOS-XE-vlan-oper")
        if _has(vlan_payload, "vlans", "Cisco-IOS-XE-vlan-oper"):
            _object(vlans, "VLAN operational database")
        if vlans is not None:
            _object(vlans, "VLAN operational database")
            if (
                _has(vlans, "vlan", "Cisco-IOS-XE-vlan-oper")
                and _value(vlans, "vlan", "Cisco-IOS-XE-vlan-oper") is None
            ):
                raise Layer2DiscoveryError("VLAN database rows must contain structured objects")
            seen = set()
            for row in _rows(
                _value(vlans, "vlan", "Cisco-IOS-XE-vlan-oper"), "VLAN operational database"
            ):
                vid = _vid(_value(row, "id", "Cisco-IOS-XE-vlan-oper"))
                if vid in seen:
                    raise Layer2DiscoveryError("VLAN operational database has ambiguous IDs")
                seen.add(vid)
                name = _value(row, "name", "Cisco-IOS-XE-vlan-oper")
                if name is None or name == "":
                    name = None
                elif not isinstance(name, str) or not name.strip():
                    raise Layer2DiscoveryError("VLAN names must be structured text")
                result["vlans"].append(
                    {
                        "vid": vid,
                        "name": name.strip() if name is not None else None,
                        "source": {
                            "identity": {
                                "module": "Cisco-IOS-XE-vlan-oper",
                                "path": VLAN_PATH,
                                "field": "vlan[id]/name",
                            }
                        },
                        "observations": {"status": _value(row, "status", "Cisco-IOS-XE-vlan-oper")},
                    }
                )
            result["catalog_complete"] = True
        else:
            warnings.append(
                "VLAN identity source returned no database; missing VLAN records cannot be created"
            )
    result["vlans"].sort(key=lambda row: row["vid"])
    return result


def add_revisions(layer2, modules):
    """Annotate collected field provenance after the shared module-library read."""
    for collection in ("interfaces", "settings", "vlans", "unresolved", "not_applicable"):
        for row in layer2.get(collection, []):
            for source in row.get("source", {}).values():
                if isinstance(source, dict) and source.get("module"):
                    source["revision"] = modules.get(source["module"])
