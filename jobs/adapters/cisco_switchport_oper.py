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
    """Advertised switchport operational facts are malformed or ambiguous."""


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


def _read(client, warnings):
    path = PATH + "?fields=" + FIELDS
    try:
        return client.get(path), _status(client, path), True
    except RestconfError as exc:
        if exc.status_code == 400:
            warnings.append(
                "%s: fields filter rejected (HTTP 400); unfiltered JSON read used" % PATH
            )
            try:
                return client.get(PATH), _status(client, PATH), True
            except RestconfError as fallback:
                exc = fallback
        status = " (HTTP %s)" % exc.status_code if exc.status_code else ""
        warnings.append(
            "Switchport operational source unavailable%s; existing interface modes are preserved"
            % status
        )
        return None, exc.status_code, False


def collect(client, interfaces, *, canonical_name, revisions, warnings):
    """Return applicable actual modes, retaining all distinct administrative facts.

    A known complete module map gates the GET. An unreadable library must be
    passed as None, which is different from a known absence of this module.
    Optional transport failures preserve other discovery. Malformed advertised
    data raises a specific error for the adapter's required validation boundary.
    """
    source = {"module": MODULE, "path": PATH, "revision": None, "model_url": MODEL_URL}
    result = {"schema_version": 1, "source": source, "interfaces": []}
    if revisions is None:
        source["status"] = "capability-unknown"
        return result
    if not isinstance(revisions, dict):
        raise SwitchportOperDiscoveryError("Switchport module revisions must be a mapping")
    if MODULE not in revisions:
        source["status"] = "not-advertised"
        return result
    revision = revisions[MODULE]
    if revision is not None and not isinstance(revision, str):
        raise SwitchportOperDiscoveryError("Switchport module revision must be a string")
    source["revision"] = revision
    payload, status, read_ok = _read(client, warnings)
    source["http_status"] = status
    if not read_ok:
        source["status"] = "unavailable"
        return result
    source["status"] = "available"
    if status == 204 and payload == {}:
        return result
    envelope = _object(payload, "Switchport operational reply")
    container = _object(_value(envelope, "switchport-oper-data"), "switchport-oper-data")
    rows = _value(container, "switchport-info")
    if not isinstance(rows, list):
        raise SwitchportOperDiscoveryError("switchport-info must be a structured list")
    eligible = set()
    for interface in interfaces:
        name = interface.get("name") if isinstance(interface, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise SwitchportOperDiscoveryError("Eligible interfaces require structured names")
        name = canonical_name(name)
        if not isinstance(name, str) or not name or name in eligible:
            raise SwitchportOperDiscoveryError("Eligible canonical interface names are ambiguous")
        eligible.add(name)
    seen = set()
    for row in rows:
        row = _object(row, "switchport-info row")
        raw_name = _text(row, "if-name")
        if raw_name is None or not raw_name.strip():
            raise SwitchportOperDiscoveryError("Switchport operational row lacks if-name")
        name = canonical_name(raw_name)
        if name not in eligible:
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
        usable = enabled and hardware and ordinary and oper in OPERATIONAL_MODES
        reason = None
        if not enabled:
            reason = "Switchport is disabled; interface is routed"
        elif not hardware:
            reason = "Switchport hardware is not reported present"
        elif not ordinary:
            reason = "Administrative mode is absent, unknown, or outside the ordinary profile"
        elif oper not in OPERATIONAL_MODES:
            reason = "Current operational mode is absent, unknown, or unsupported"
        result["interfaces"].append(
            {
                "name": name,
                "admin_mode": _value(row, "admin-mode"),
                "operational_mode": OPERATIONAL_MODES[oper] if usable else None,
                "applicability": {
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
    result["interfaces"].sort(key=lambda row: row["name"])
    return result
