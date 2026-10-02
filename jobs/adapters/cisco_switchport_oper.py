"""Optional current switchport mode from Cisco RESTCONF operational JSON.

The Cisco model describes oper-mode as the actual status after negotiation.
Administrative mode is a separate observation and cannot substitute for it.
Neither operational VLAN ranges nor VLAN activity establish configured policy.
"""

from copy import deepcopy

from ..transport_restconf import RestconfError

MODULE = "Cisco-IOS-XE-switchport-oper"
PATH = "/data/%s:switchport-oper-data" % MODULE
FIELDS = "switchport-info(if-name;enabled;admin-mode;hardware-present;port-details)"
READ_TIMEOUT = 15
MODEL_URL = (
    "https://raw.githubusercontent.com/YangModels/yang/main/"
    "vendor/cisco/xe/17151/Cisco-IOS-XE-switchport-oper.yang"
)
ORDINARY_ADMIN = frozenset(
    ("admin-stat-acc", "admin-dyn-acc", "admin-trunk", "admin-dyn-auto", "admin-dyn-des")
)
OPERATIONAL_MODES = {
    "oper-stat-acc": "access",
    "oper-dyn-acc": "access",
    "oper-trunk": "trunk",
    "oper-down": "down",
}


class SwitchportOperDiscoveryError(ValueError):
    """Switchport operational facts or collector inputs are invalid."""


def _object(value, label):
    if not isinstance(value, dict):
        raise SwitchportOperDiscoveryError("%s must be a structured container" % label)
    names = set()
    for key in value:
        if not isinstance(key, str) or not key:
            raise SwitchportOperDiscoveryError("Switchport operational keys must be strings")
        if ":" in key:
            namespace, local = key.split(":", 1)
            if namespace != MODULE or not local or ":" in local:
                raise SwitchportOperDiscoveryError(
                    "Switchport operational leaf belongs to an unexpected YANG module"
                )
        else:
            local = key
        if local in names:
            raise SwitchportOperDiscoveryError(
                "Switchport operational reply has duplicate namespace-qualified leaves"
            )
        names.add(local)
    return value


def _value(mapping, name):
    return mapping.get(name, mapping.get(MODULE + ":" + name))


def _has(mapping, name):
    return name in mapping or MODULE + ":" + name in mapping


def _empty(mapping, name):
    if not _has(mapping, name):
        return False
    if _value(mapping, name) != [None]:
        raise SwitchportOperDiscoveryError("%s must be a YANG empty leaf" % name)
    return True


def _text(mapping, name):
    value = _value(mapping, name)
    if _has(mapping, name) and not isinstance(value, str):
        raise SwitchportOperDiscoveryError("%s must be a structured string" % name)
    return value


def _enum(mapping, name):
    value = _text(mapping, name)
    if value is None:
        return None
    # RFC7951 enumeration values are strings. A qualified value is accepted
    # only for this module; unrelated enum namespaces never acquire meaning.
    prefix, separator, local = value.partition(":")
    if separator:
        return local if prefix == MODULE else None
    return value


def _details(value):
    details = _object(value, "Switchport port-details")
    for name in (
        "oper-mode",
        "agport-if-name",
        "access-mode-name",
        "access-state",
        "trunk-nat-mode-name",
        "trunk-nat-state",
        "voice-name",
        "voice-state",
    ):
        _text(details, name)
    for name in ("access-mode-id", "trunk-nat-mode-id", "voice-id"):
        if _has(details, name):
            number = _value(details, name)
            if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 65535:
                raise SwitchportOperDiscoveryError("%s must be a YANG uint16" % name)
    if _has(details, "is-agport-suspend") and not isinstance(
        _value(details, "is-agport-suspend"), bool
    ):
        raise SwitchportOperDiscoveryError("is-agport-suspend must be a structured boolean")
    for name in ("trunk-vlan", "pruning-vlan"):
        if not _has(details, name):
            continue
        ranges = _value(details, name)
        if not isinstance(ranges, list):
            raise SwitchportOperDiscoveryError("%s must be a structured list" % name)
        for row in ranges:
            _object(row, name + " range")
            bounds = []
            for bound in ("start-id", "end-id"):
                number = _value(row, bound)
                if (
                    not _has(row, bound)
                    or isinstance(number, bool)
                    or not isinstance(number, int)
                    or not 0 <= number <= 65535
                ):
                    raise SwitchportOperDiscoveryError("%s range requires uint16 bounds" % name)
                bounds.append(number)
            if bounds[0] > bounds[1]:
                raise SwitchportOperDiscoveryError("%s range bounds are reversed" % name)
    return details


def _status(client, path):
    for record in reversed(getattr(client, "trace", [])):
        if record.get("path") == path:
            return record.get("status")
    return None


def _failure_status(status):
    if status in (404, 501):
        return "unsupported"
    # The transport rejects malformed JSON and non-object JSON with the
    # successful HTTP status attached. Rejected bodies must not look like
    # missing evidence and thereby enable the NTC down-port assumption.
    if status is not None and 200 <= status < 300:
        return "invalid"
    return "unavailable"


def _read(client, warnings):
    path = PATH + "?fields=" + FIELDS
    try:
        return client.get(path, timeout=READ_TIMEOUT), _status(client, path), True
    except RestconfError as exc:
        if exc.status_code == 400:
            warnings.append(
                "%s: fields filter rejected (HTTP 400); unfiltered JSON read used" % PATH
            )
            try:
                return client.get(PATH, timeout=READ_TIMEOUT), _status(client, PATH), True
            except RestconfError as fallback:
                exc = fallback
        status = " (HTTP %s)" % exc.status_code if exc.status_code else ""
        availability = _failure_status(exc.status_code)
        warnings.append(
            "Switchport operational source %s%s; existing interface modes are preserved"
            % (availability, status)
        )
        return None, exc.status_code, False


def collect(client, interfaces, *, canonical_name, revisions, warnings, excluded_interfaces=()):
    """Return applicable actual modes, retaining all distinct administrative facts.

    A known complete module map skips an absent module. An unreadable library
    is passed as None and triggers a bounded direct probe with unknown revision.
    Optional read or remote validation failures preserve other discovery, while
    invalid collector inputs and unexpected exceptions continue to propagate.
    """
    source = {"module": MODULE, "path": PATH, "revision": None, "model_url": MODEL_URL}
    result = {"schema_version": 1, "source": source, "interfaces": []}
    if revisions is not None and not isinstance(revisions, dict):
        raise SwitchportOperDiscoveryError("Switchport module revisions must be a mapping")
    source["capability_status"] = "unknown" if revisions is None else "advertised"
    source["probed_without_advertisement"] = revisions is None
    if revisions is not None and MODULE not in revisions:
        source["capability_status"] = "not-advertised"
        source["status"] = "not-advertised"
        return result
    revision = revisions[MODULE] if revisions is not None else None
    if revision is not None and not isinstance(revision, str):
        raise SwitchportOperDiscoveryError("Switchport module revision must be a string")
    source["revision"] = revision
    # These names come from mandatory core discovery, not optional remote
    # evidence. Invalid/ambiguous inputs must not be softened into a skipped read.
    eligible = set()
    for interface in interfaces:
        name = interface.get("name") if isinstance(interface, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise SwitchportOperDiscoveryError("Eligible interfaces require structured names")
        name = canonical_name(name)
        if not isinstance(name, str) or not name or name in eligible:
            raise SwitchportOperDiscoveryError("Eligible canonical interface names are ambiguous")
        eligible.add(name)
    excluded = {}
    for interface in excluded_interfaces:
        name = interface.get("name") if isinstance(interface, dict) else None
        reason = interface.get("reason") if isinstance(interface, dict) else None
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(reason, str)
            or not reason
        ):
            raise SwitchportOperDiscoveryError(
                "Excluded interfaces require structured names/reasons"
            )
        name = canonical_name(name)
        if not isinstance(name, str) or not name or name in eligible or name in excluded:
            raise SwitchportOperDiscoveryError("Excluded canonical interface names are ambiguous")
        excluded[name] = reason
    payload, status, read_ok = _read(client, warnings)
    source["http_status"] = status
    if not read_ok:
        source["status"] = _failure_status(status)
        if source["status"] == "invalid":
            source["reason"] = "Switchport operational response must be a structured JSON object"
        return result
    if status == 204 and payload == {}:
        source["status"] = "available"
        return result
    try:
        parsed = _parse(payload, eligible, excluded, canonical_name, revision)
    except SwitchportOperDiscoveryError as exc:
        # Validation messages contain only fixed schema labels; never retain
        # remote response bodies. Discard the entire source, including earlier
        # valid rows, so ambiguity cannot create partial assignments or guesses.
        source["status"] = "invalid"
        source["reason"] = str(exc)
        warnings.append(
            "Switchport operational source invalid; data discarded and negotiated-mode "
            "guessing disabled for this source: %s" % exc
        )
        return result
    source["status"] = "available"
    result["interfaces"] = parsed
    return result


def _parse(payload, eligible, excluded, canonical_name, revision):
    """Validate all remote rows before exposing any optional interface facts."""
    envelope = _object(payload, "Switchport operational reply")
    container = _object(_value(envelope, "switchport-oper-data"), "switchport-oper-data")
    rows = _value(container, "switchport-info")
    if not isinstance(rows, list):
        raise SwitchportOperDiscoveryError("switchport-info must be a structured list")
    parsed = []
    seen = set()
    for row in rows:
        row = _object(row, "switchport-info row")
        raw_name = _text(row, "if-name")
        if raw_name is None or not raw_name.strip():
            raise SwitchportOperDiscoveryError("Switchport operational row lacks if-name")
        name = canonical_name(raw_name)
        if name not in eligible and name not in excluded:
            raise SwitchportOperDiscoveryError(
                "Switchport operational row has no eligible canonical interface match"
            )
        if name in seen:
            raise SwitchportOperDiscoveryError("Duplicate canonical switchport interface name")
        seen.add(name)
        enabled = _empty(row, "enabled")
        hardware = _empty(row, "hardware-present")
        admin = _enum(row, "admin-mode")
        details = _details(_value(row, "port-details")) if _has(row, "port-details") else {}
        oper = _enum(details, "oper-mode")
        ordinary = admin in ORDINARY_ADMIN
        applicable = name in eligible
        usable = applicable and enabled and hardware and ordinary and oper in OPERATIONAL_MODES
        reason = None
        if not applicable:
            reason = excluded[name]
        elif not enabled:
            reason = "Switchport is disabled; interface is routed"
        elif not hardware:
            reason = "Switchport hardware is not reported present"
        elif not ordinary:
            reason = "Administrative mode is absent, unknown, or outside the ordinary profile"
        elif oper not in OPERATIONAL_MODES:
            reason = "Current operational mode is absent, unknown, or unsupported"
        parsed.append(
            {
                "name": name,
                "admin_mode": _value(row, "admin-mode"),
                "operational_mode": OPERATIONAL_MODES[oper] if usable else None,
                "applicability": {
                    "eligible": applicable,
                    "enabled": enabled,
                    "hardware_present": hardware,
                    "ordinary_admin": ordinary,
                    "usable": usable,
                    "reason": reason,
                },
                "observations": deepcopy(row),
                "source": {
                    "module": MODULE,
                    "path": PATH,
                    "revision": revision,
                    "field": "port-details/oper-mode",
                    "interface": raw_name,
                },
            }
        )
    return sorted(parsed, key=lambda row: row["name"])
