"""Controller-scoped Catalyst 9800 AP observations from RESTCONF JSON.

Resource paths and filters are selectively adapted from nautobot-testsuite's
checks_iosxe_wireless.py (Apache-2.0). Its synthetic 17.12.1-shaped fixtures
support this provisional contract; they do not establish live release coverage.
This module retains physical identities and makes no inventory writes.
"""

import re
from datetime import datetime, timezone

from ..transport_restconf import RestconfError

CONTRACT = "cisco-9800-snapshot-v1"
HOSTNAME_PATH = "/data/Cisco-IOS-XE-native:native/hostname"
HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
YANG_LIBRARY_PATH = "/data/ietf-yang-library:modules-state"
AP_MODULE = "Cisco-IOS-XE-wireless-access-point-oper"
AP_BASE = "/data/%s:access-point-oper-data" % AP_MODULE
CAPWAP_PATH = AP_BASE + "/capwap-data"
MAC_MAP_PATH = AP_BASE + "/ap-name-mac-map"
ETHERNET_PATH = AP_BASE + "/ethernet-if-stats"
CDP_PATH = AP_BASE + "/cdp-cache-data"
LLDP_PATH = AP_BASE + "/lldp-neigh"
RADIO_PATH = AP_BASE + "/radio-oper-data"
JOIN_MODULE = "Cisco-IOS-XE-wireless-ap-global-oper"
JOIN_PATH = "/data/%s:ap-global-oper-data/ap-join-stats" % JOIN_MODULE
AP_CFG_MODULE = "Cisco-IOS-XE-wireless-ap-cfg"
AP_TAG_PATH = "/data/%s:ap-cfg-data/ap-tags/ap-tag" % AP_CFG_MODULE
CAPWAP_FIELDS = (
    "wtp-mac;name;device-detail(static-info(board-data(wtp-serial-num;wtp-enet-mac);"
    "ap-models(model));wtp-version(sw-version));ap-location(floor;location);"
    "tag-info(tag-source;resolved-tag-info;policy-tag-info;site-tag;rf-tag);ap-state"
)
MAC_MAP_FIELDS = "wtp-name;wtp-mac;eth-mac"
ETHERNET_FIELDS = "wtp-mac;if-index;if-name;oper-status;duplex;link-speed"
CDP_FIELDS = (
    "mac-addr;wtp-mac-addr;ap-name;cdp-cache-device-id;cdp-cache-device-port;"
    "cdp-cache-local-port;cdp-cache-platform;cdp-cache-ip-address-value;"
    "cdp-cache-duplex;cdp-cache-interface-speed;last-updated-time"
)
LLDP_FIELDS = "wtp-mac;neigh-mac;port-id;local-port;system-name;port-description;mgmt-addr"
JOIN_FIELDS = "wtp-mac;ap-join-info(ap-name;ap-ethernet-mac;is-joined)"
AP_TAG_FIELDS = "ap-mac;policy-tag;site-tag;rf-tag"
RADIO_FIELDS = (
    "wtp-mac;radio-slot-id;radio-type;admin-state;oper-state;radio-mode;radio-sub-mode;"
    "current-band-id;current-active-band;phy-ht-cfg(cfg-data(curr-freq;chan-width;"
    "phy-ht-cfg-config-type));radio-band-info(band-id;regulatory-domain;"
    "phy-tx-pwr-cfg(cfg-data(phy-tx-power-config-type;current-tx-power-level));"
    "phy-tx-pwr-lvl-cfg(cfg-data(curr-tx-power-in-dbm)));station-cfg(cfg-data(bssid))"
)
CURRENT_STATES = frozenset(("registered", "downloading"))
_MAC = re.compile(r"^[0-9a-fA-F]{12}$")
_REVISION = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class DiscoveryError(ValueError):
    """The required controller source is unverified, failed or incomplete."""


def _time():
    return datetime.now(timezone.utc).isoformat()


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _identifier(value):
    text = _text(value)
    if text and text.lower() not in ("unknown", "none", "n/a", "na", "not available", "0"):
        return text
    return None


def _leaf(value, *path):
    for name in path:
        if not isinstance(value, dict):
            return None
        value = value.get(name)
    return value


def _mac(value):
    """Validate common explicit 48-bit spellings; never derive another MAC."""
    text = _text(value)
    if text is None:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", text):
        digits = text.replace(":", "")
    elif re.fullmatch(r"[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}", text):
        digits = text.replace("-", "")
    elif re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", text):
        digits = text.replace(".", "")
    elif _MAC.fullmatch(text):
        digits = text
    else:
        return None
    if int(digits, 16) == 0 or int(digits[:2], 16) & 1:
        return None
    digits = digits.lower()
    return ":".join(digits[index : index + 2] for index in range(0, 12, 2))


def _uint(value, maximum=4294967295):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= maximum else None
    if isinstance(value, str) and len(value) <= 10 and re.fullmatch(r"\d+", value):
        parsed = int(value)
        return parsed if parsed <= maximum else None
    return None


def _boolean(value):
    return value if isinstance(value, bool) else None


def _int16(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and len(value) <= 6 and re.fullmatch(r"-?\d+", value):
        value = int(value)
    return value if isinstance(value, int) and -32768 <= value <= 32767 else None


def _date(value):
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return text if parsed.tzinfo is not None else None


def _node(payload, module, name, parent=None):
    """Require one recognized wrapper, including a known parent container."""
    if not isinstance(payload, dict):
        raise DiscoveryError("%s: JSON object required" % name)
    found = [payload[key] for key in (module + ":" + name, name) if key in payload]
    if parent:
        for key in (module + ":" + parent, parent):
            if key in payload:
                container = payload[key]
                if not isinstance(container, dict):
                    raise DiscoveryError("%s: malformed parent container" % name)
                found.extend(
                    container[key] for key in (module + ":" + name, name) if key in container
                )
    if len(found) != 1:
        raise DiscoveryError("%s: missing or ambiguous resource wrapper" % name)
    return found[0]


def _rows(payload, module, name, parent, limit):
    value = _node(payload, module, name, parent)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise DiscoveryError("%s: explicit JSON list of objects required" % name)
    if len(value) > limit:
        raise DiscoveryError("%s exceeds the configured row limit; roster is incomplete" % name)
    return value


def _filter_rejected(exc):
    # A generic HTTP 400 is not evidence that a fields filter is unsupported.
    return getattr(exc, "status_code", None) == 400 and (
        getattr(exc, "filter_rejected", False) is True
    )


def _resource(
    client,
    path,
    module,
    name,
    parent,
    fields,
    limit,
    required,
    resources,
    warnings,
    *,
    advertised=None,
):
    started = _time()
    requested = path + "?fields=" + fields if fields else path
    record = {
        "module": module,
        "path": path,
        "requested_path": requested,
        "observed_at": started,
        "required": required,
        "complete": False,
        "status": "unavailable",
        "semantics": "live",
        "filter_retry": False,
    }
    resources.append(record)
    if not required and advertised is not None and module not in advertised:
        record.update({"status": "not-advertised", "collected_at": _time()})
        warnings.append("Optional %s module is not advertised; observations are unknown" % name)
        return None
    try:
        try:
            payload = client.get(requested, timeout=120, ok_404=not required)
        except RestconfError as exc:
            if not fields or not _filter_rejected(exc):
                raise
            record["filter_retry"] = True
            record["requested_path"] = path
            warnings.append("%s: rejected fields filter; one unfiltered retry used" % name)
            payload = client.get(path, timeout=120, ok_404=not required)
        if payload is None:
            raise DiscoveryError("%s: resource not served" % name)
        rows = _rows(payload, module, name, parent, limit)
    except (RestconfError, DiscoveryError) as exc:
        record["collected_at"] = _time()
        record["status"] = "failed" if required else "unavailable"
        if required:
            raise DiscoveryError("Required %s read failed: %s" % (name, exc)) from exc
        warnings.append("Optional %s unavailable; associated observations are unknown" % name)
        return None
    record.update({"status": "available", "complete": True, "rows": len(rows)})
    record["collected_at"] = _time()
    return rows


def _verify_source(client, controller_id, policy, resources, warnings):
    if not isinstance(policy, dict) or policy.get("kind") not in ("physical", "logical"):
        raise DiscoveryError("An explicit physical or logical controller source policy is required")
    kind = policy["kind"]
    expected_model = _text(policy.get("expected_model"))
    expected_serial = _identifier(policy.get("expected_serial"))
    expected_hostname = _text(policy.get("expected_hostname"))
    if kind == "physical" and (not expected_serial or not expected_model):
        raise DiscoveryError("Physical controller source policy requires exact model and serial")
    if kind == "logical" and not expected_hostname:
        raise DiscoveryError(
            "Logical controller source policy requires an explicit expected hostname"
        )
    if not _text(controller_id):
        raise DiscoveryError("An explicit logical Controller ID is required")
    started = _time()
    hardware_complete = False
    try:
        hostname = _text(_node(client.get(HOSTNAME_PATH), "Cisco-IOS-XE-native", "hostname"))
        model = None
        serial = None
        hardware = None
        hardware_required = kind == "physical" or bool(expected_model)
        try:
            hardware = _node(
                client.get(HARDWARE_PATH, ok_404=not hardware_required),
                "Cisco-IOS-XE-device-hardware-oper",
                "device-hardware-data",
            )
            inventory = _leaf(hardware, "device-hardware", "device-inventory")
            if not isinstance(inventory, list) or any(
                not isinstance(row, dict) for row in inventory
            ):
                raise DiscoveryError("Controller hardware inventory is malformed")
            chassis = [row for row in inventory if row.get("hw-type") == "hw-type-chassis"]
            if len(chassis) != 1:
                raise DiscoveryError("Controller hardware must report exactly one endpoint chassis")
            model = _text(chassis[0].get("part-number"))
            serial = _identifier(chassis[0].get("serial-number"))
            hardware_complete = True
        except (DiscoveryError, RestconfError):
            if hardware_required:
                raise
            warnings.append(
                "Logical controller hardware facts are unresolved; hostname binding used"
            )
        if kind == "physical" and (not model or "9800" not in model.upper()):
            raise DiscoveryError("Physical controller source must report a Catalyst 9800 model")
        if expected_hostname and hostname != expected_hostname:
            raise DiscoveryError(
                "Controller endpoint hostname does not match the configured source"
            )
        if expected_model and model != expected_model:
            raise DiscoveryError("Controller endpoint model does not match the configured source")
        if kind == "physical" and serial != expected_serial:
            raise DiscoveryError("Controller endpoint serial does not match the configured source")
        if kind == "physical" and model and "9800-CL" in model.upper():
            raise DiscoveryError("C9800-CL requires a verified logical controller source policy")
        library = _node(client.get(YANG_LIBRARY_PATH), "ietf-yang-library", "modules-state")
        modules = _leaf(library, "module")
        if not isinstance(modules, list) or any(not isinstance(row, dict) for row in modules):
            raise DiscoveryError("Controller YANG module inventory is malformed")
        wireless = [row for row in modules if row.get("name") == AP_MODULE]
        if len(wireless) != 1:
            raise DiscoveryError("Controller must advertise exactly one wireless AP module")
        if wireless[0].get("conformance-type") == "import":
            raise DiscoveryError(
                "Controller wireless AP module is imported rather than implemented"
            )
        if not _text(wireless[0].get("revision")) or not _REVISION.fullmatch(
            wireless[0]["revision"]
        ):
            raise DiscoveryError("Advertised wireless AP module revision is missing or malformed")
        try:
            datetime.strptime(wireless[0]["revision"], "%Y-%m-%d")
        except ValueError as exc:
            raise DiscoveryError(
                "Advertised wireless AP module revision is not a valid date"
            ) from exc
        revisions = {
            row["name"]: _text(row.get("revision")) for row in modules if _text(row.get("name"))
        }
    except RestconfError as exc:
        raise DiscoveryError("Controller source identity read failed: %s" % exc) from exc
    collected = _time()
    for path, module in (
        (HOSTNAME_PATH, "Cisco-IOS-XE-native"),
        (HARDWARE_PATH, "Cisco-IOS-XE-device-hardware-oper"),
        (YANG_LIBRARY_PATH, "ietf-yang-library"),
    ):
        resources.append(
            {
                "path": path,
                "module": module,
                "revision": revisions.get(module),
                "required": path != HARDWARE_PATH or hardware_required,
                "complete": path != HARDWARE_PATH or hardware_complete,
                "status": "unavailable"
                if path == HARDWARE_PATH and not hardware_complete
                else "available",
                "observed_at": started,
                "collected_at": collected,
                "semantics": "live",
            }
        )
    return {
        "kind": kind,
        "controller_id": controller_id,
        "verified": True,
        "identity_verified": True,
        "hostname": hostname,
        "model": model,
        "serial": serial if kind == "physical" else None,
        "reported_serial": serial,
        "software_version": _text(
            _leaf(hardware, "device-hardware", "device-system-data", "software-version")
        ),
        "module_revisions": revisions,
        "implemented_modules": [
            row["name"]
            for row in modules
            if _text(row.get("name")) and row.get("conformance-type") != "import"
        ],
        "observed_at": started,
        "collected_at": collected,
        "semantics": "live",
        "coverage": "provisional; synthetic 17.12.1-shaped fixture contract",
    }


def _observation(resource, source):
    return {
        "controller_id": source["controller_id"],
        "module": resource["module"],
        "revision": source["module_revisions"].get(resource["module"]),
        "path": resource["path"],
        "observed_at": resource["observed_at"],
        "collected_at": resource["collected_at"],
        "complete": resource["complete"],
        "semantics": resource["semantics"],
    }


def _ap_row(row, resource, source, index):
    state = _text(_leaf(row, "ap-state", "ap-operation-state"))
    errors = []
    warnings = []
    serial = _identifier(_leaf(row, "device-detail", "static-info", "board-data", "wtp-serial-num"))
    model = _identifier(_leaf(row, "device-detail", "static-info", "ap-models", "model"))
    wtp_mac = _mac(row.get("wtp-mac"))
    ethernet_raw = _leaf(row, "device-detail", "static-info", "board-data", "wtp-enet-mac")
    ethernet_mac = _mac(ethernet_raw)
    if not serial:
        errors.append("Missing valid reported AP serial")
    if not model:
        errors.append("Missing valid reported AP model")
    if not wtp_mac:
        errors.append("Missing or invalid reported WTP MAC")
    if ethernet_raw is not None and not ethernet_mac:
        errors.append("Invalid reported AP Ethernet MAC")
    if state not in CURRENT_STATES:
        errors.append("Current AP state is missing or unsupported: %s" % (state or "unknown"))
    software = _text(_leaf(row, "device-detail", "wtp-version", "sw-version"))
    if not software:
        warnings.append("AP running software is unreported")
    floor_raw = _leaf(row, "ap-location", "floor")
    floor = _uint(floor_raw)
    if floor_raw is not None and floor is None:
        warnings.append("AP floor label is not a valid reported uint32")
    resolved = _leaf(row, "tag-info", "resolved-tag-info")
    resolved = resolved if isinstance(resolved, dict) else {}
    return {
        "name": _text(row.get("name")),
        "serial": serial,
        "model": model,
        "wtp_mac": wtp_mac,
        "ethernet_mac": ethernet_mac,
        "software_version": software,
        "state": state,
        "location_label": _text(_leaf(row, "ap-location", "location")),
        "floor_label": str(floor) if floor is not None else None,
        "tags": {
            "site": _text(resolved.get("resolved-site-tag")),
            "policy": _text(resolved.get("resolved-policy-tag")),
            "rf": _text(resolved.get("resolved-rf-tag")),
        },
        "ethernet_interfaces": [],
        "radios": [],
        "configured_tags": [],
        "attachments": [],
        "errors": errors,
        "warnings": warnings,
        "provenance": {"roster": _observation(resource, source), "row_index": index},
    }


def _mac_joins(aps, mappings, resource, source, warnings):
    by_wtp = {}
    by_eth = {}
    invalid = set()
    for row in mappings:
        wtp = _mac(row.get("wtp-mac"))
        eth = _mac(row.get("eth-mac"))
        name = _text(row.get("wtp-name"))
        if not wtp or not eth:
            warnings.append("AP MAC mapping contains invalid or missing identities")
            if wtp:
                invalid.add(wtp)
            continue
        by_wtp.setdefault(wtp, []).append((eth, name))
        by_eth.setdefault(eth, set()).add(wtp)
    for ap in aps:
        if ap["wtp_mac"] in invalid:
            ap["errors"].append("AP MAC mapping reports an invalid Ethernet identity")
            continue
        matches = by_wtp.get(ap["wtp_mac"], [])
        if not matches:
            ap["warnings"].append("No corroborating AP name/MAC mapping; roster identity retained")
            continue
        eth_values = {eth for eth, _ in matches}
        names = {name for _, name in matches if name}
        if len(eth_values) != 1 or any(len(by_eth[eth]) != 1 for eth in eth_values):
            ap["errors"].append("Contradictory reported WTP/Ethernet MAC mapping")
            continue
        mapped_eth = next(iter(eth_values))
        if ap["ethernet_mac"] and ap["ethernet_mac"] != mapped_eth:
            ap["errors"].append("CAPWAP and AP mapping report different Ethernet MACs")
            continue
        if len(names) > 1 or (ap["name"] and names and ap["name"] not in names):
            ap["errors"].append("AP mapping and roster changed or disagree on the AP label")
            continue
        ap["ethernet_mac"] = mapped_eth
        ap["provenance"]["mac_mapping"] = _observation(resource, source)


def _subjects(aps, *, include_ethernet=False):
    subjects = {}
    for ap in aps:
        for mac in set((ap["wtp_mac"], ap["ethernet_mac"] if include_ethernet else None)):
            if mac:
                subjects.setdefault(mac, []).append(ap)
    return subjects


def _optional_subject(subjects, wtp, warnings, label):
    matches = subjects.get(_mac(wtp), [])
    if len(matches) != 1:
        warnings.append("%s row has no unique current AP identity; observation deferred" % label)
        return None
    return matches[0]


def _ethernet(aps, rows, resource, source, warnings):
    subjects = _subjects(aps, include_ethernet=True)
    counts = {}
    for row in rows:
        identity = _mac(row.get("wtp-mac"))
        counts[identity] = counts.get(identity, 0) + 1
    for row in rows:
        ap = _optional_subject(subjects, row.get("wtp-mac"), warnings, "Ethernet")
        if ap is None:
            continue
        name = _text(row.get("if-name"))
        index = _uint(row.get("if-index"), 65535)
        speed = _uint(row.get("link-speed"))
        duplex = _uint(row.get("duplex"))
        if not name:
            ap["warnings"].append("Ethernet interface has no explicit name; interface deferred")
            continue
        if row.get("if-index") is not None and index is None:
            ap["warnings"].append("Ethernet interface index is invalid")
        if row.get("link-speed") is not None and speed is None:
            ap["warnings"].append("Ethernet negotiated speed is invalid")
        if row.get("duplex") is not None and duplex is None:
            ap["warnings"].append("Ethernet numeric duplex observation is invalid")
        identity = _mac(row.get("wtp-mac"))
        port_mac = (
            identity if identity == ap["ethernet_mac"] and counts.get(identity) == 1 else None
        )
        ap["ethernet_interfaces"].append(
            {
                "name": name,
                "if_index": index,
                "physical_ethernet": True,
                "mac_address": port_mac,
                "speed": None,
                "description": None,
                "oper_status": _text(row.get("oper-status")),
                "duplex": duplex,
                "negotiated_speed_mbps": speed,
                "admin_state": None,
                "capability": None,
                "reported_identity": identity,
                "provenance": _observation(resource, source),
            }
        )


def _radios(aps, rows, resource, source, warnings):
    subjects = _subjects(aps)
    for row in rows:
        ap = _optional_subject(subjects, row.get("wtp-mac"), warnings, "Radio")
        if ap is None:
            continue
        slot = _uint(row.get("radio-slot-id"), 255)
        if slot is None:
            ap["warnings"].append("Radio slot identity is invalid; radio observation deferred")
            continue
        ht = _leaf(row, "phy-ht-cfg", "cfg-data")
        ht = ht if isinstance(ht, dict) else {}
        bands = row.get("radio-band-info", [])
        band_observations = []
        if not isinstance(bands, list) or any(not isinstance(band, dict) for band in bands):
            ap["warnings"].append("Radio band list is malformed; band observations unknown")
            bands = []
        for band in bands:
            power = _leaf(band, "phy-tx-pwr-cfg", "cfg-data")
            power = power if isinstance(power, dict) else {}
            dbm_raw = _leaf(band, "phy-tx-pwr-lvl-cfg", "cfg-data", "curr-tx-power-in-dbm")
            dbm = _int16(dbm_raw)
            if dbm_raw is not None and dbm is None:
                ap["warnings"].append("Radio power in dBm is invalid; power remains unknown")
            band_observations.append(
                {
                    "band_id": _uint(band.get("band-id"), 255),
                    "regulatory_domain": _text(band.get("regulatory-domain")),
                    "tx_power_level": _uint(power.get("current-tx-power-level"), 65535),
                    "power_source": _text(power.get("phy-tx-power-config-type")),
                    "power_dbm": dbm,
                }
            )
        ap["radios"].append(
            {
                "wtp_mac": ap["wtp_mac"],
                "slot_id": slot,
                "radio_type": _text(row.get("radio-type")),
                "admin_state": _text(row.get("admin-state")),
                "oper_state": _text(row.get("oper-state")),
                "mode": _text(row.get("radio-mode")),
                "sub_mode": _text(row.get("radio-sub-mode")),
                "current_band_id": _uint(row.get("current-band-id"), 255),
                "current_active_band": _text(row.get("current-active-band")),
                "channel_number": _uint(ht.get("curr-freq"), 65535),
                "channel_width": _uint(ht.get("chan-width"), 255),
                "channel_width_units": "unspecified",
                "channel_source": _text(ht.get("phy-ht-cfg-config-type")),
                "bands": band_observations,
                "bssid": _mac(_leaf(row, "station-cfg", "cfg-data", "bssid")),
                "write_policy": "report-only; native radio mapping unreviewed",
                "provenance": _observation(resource, source),
            }
        )


def _configured_tags(aps, rows, resource, source, warnings):
    subjects = _subjects(aps, include_ethernet=True)
    for row in rows:
        ap = _optional_subject(subjects, row.get("ap-mac"), warnings, "Configured AP tag")
        if ap is None:
            continue
        observation = {
            "reported_mac": _mac(row.get("ap-mac")),
            "site": _text(row.get("site-tag")),
            "policy": _text(row.get("policy-tag")),
            "rf": _text(row.get("rf-tag")),
            "write_policy": "report-only; native assignment mapping unreviewed",
            "provenance": _observation(resource, source),
        }
        observation["provenance"]["semantics"] = "configuration-intent"
        ap["configured_tags"].append(observation)


def _attachments(aps, rows, resource, source, warnings, protocol):
    subjects = _subjects(aps)
    for row in rows:
        wtp = (
            row.get("wtp-mac-addr", row.get("mac-addr"))
            if protocol == "cdp"
            else row.get("wtp-mac")
        )
        ap = _optional_subject(subjects, wtp, warnings, protocol.upper())
        if ap is None:
            continue
        if protocol == "cdp":
            base_mac = _mac(row.get("mac-addr"))
            if row.get("mac-addr") is not None and base_mac is None:
                ap["warnings"].append("CDP radio identity is invalid; attachment deferred")
                continue
            if base_mac and base_mac != ap["wtp_mac"]:
                ap["warnings"].append("CDP radio identity conflicts; attachment deferred")
                continue
            attachment = {
                "protocol": protocol,
                "wtp_mac": ap["wtp_mac"],
                "ethernet_mac": ap["ethernet_mac"],
                "local_port": _text(row.get("cdp-cache-local-port")),
                "neighbor_name": _text(row.get("cdp-cache-device-id")),
                "neighbor_port": _text(row.get("cdp-cache-device-port")),
                "neighbor_mac": None,
                "neighbor_ip": _text(row.get("cdp-cache-ip-address-value")),
                "neighbor_platform": _text(row.get("cdp-cache-platform")),
                "last_updated_at": _date(row.get("last-updated-time")),
            }
        else:
            attachment = {
                "protocol": protocol,
                "wtp_mac": ap["wtp_mac"],
                "ethernet_mac": ap["ethernet_mac"],
                "local_port": _text(row.get("local-port")),
                "neighbor_name": _text(row.get("system-name")),
                "neighbor_port": _text(row.get("port-id")),
                "neighbor_mac": _mac(row.get("neigh-mac")),
                "neighbor_ip": _text(row.get("mgmt-addr")),
                "neighbor_platform": None,
                "last_updated_at": None,
            }
        attachment["freshness"] = "unknown; controller neighbor cache age is unreviewed"
        attachment["provenance"] = _observation(resource, source)
        attachment["provenance"]["semantics"] = "cached-unspecified"
        ap["attachments"].append(attachment)


def collect(client, *, controller_id, source_policy, max_aps=10000):
    """Collect one verified logical controller's full current AP roster.

    No name-based identity maps, client station reads or direct AP connections
    occur here. Invalid AP rows survive for the planner's explicit outcomes.
    """
    if isinstance(max_aps, bool) or not isinstance(max_aps, int) or max_aps < 1:
        raise DiscoveryError("max_aps must be a positive integer")
    resources = []
    warnings = ["Release coverage is provisional until field RESTCONF payloads are validated"]
    source = _verify_source(client, controller_id, source_policy, resources, warnings)
    rows = _resource(
        client,
        CAPWAP_PATH,
        AP_MODULE,
        "capwap-data",
        "access-point-oper-data",
        CAPWAP_FIELDS,
        max_aps,
        True,
        resources,
        warnings,
    )
    roster_resource = resources[-1]
    mappings = _resource(
        client,
        MAC_MAP_PATH,
        AP_MODULE,
        "ap-name-mac-map",
        "access-point-oper-data",
        MAC_MAP_FIELDS,
        max_aps,
        True,
        resources,
        warnings,
    )
    aps = [_ap_row(row, roster_resource, source, index) for index, row in enumerate(rows)]
    _mac_joins(aps, mappings, resources[-1], source, warnings)
    for path, name, fields, handler in (
        (ETHERNET_PATH, "ethernet-if-stats", ETHERNET_FIELDS, _ethernet),
        (CDP_PATH, "cdp-cache-data", CDP_FIELDS, None),
        (LLDP_PATH, "lldp-neigh", LLDP_FIELDS, None),
        (RADIO_PATH, "radio-oper-data", RADIO_FIELDS, _radios),
    ):
        optional = _resource(
            client,
            path,
            AP_MODULE,
            name,
            "access-point-oper-data",
            fields,
            max_aps * 16,
            False,
            resources,
            warnings,
        )
        if optional is not None:
            if handler:
                handler(aps, optional, resources[-1], source, warnings)
            else:
                _attachments(
                    aps,
                    optional,
                    resources[-1],
                    source,
                    warnings,
                    "cdp" if name == "cdp-cache-data" else "lldp",
                )
    joins = _resource(
        client,
        JOIN_PATH,
        JOIN_MODULE,
        "ap-join-stats",
        "ap-global-oper-data",
        JOIN_FIELDS,
        max_aps * 16,
        False,
        resources,
        warnings,
        advertised=source["implemented_modules"],
    )
    history = []
    for row in joins or []:
        info = row.get("ap-join-info")
        info = info if isinstance(info, dict) else {}
        joined = _boolean(info.get("is-joined"))
        if info.get("is-joined") is not None and joined is None:
            warnings.append("Join history has an invalid boolean; joined state remains unknown")
        history.append(
            {
                "wtp_mac": _mac(row.get("wtp-mac")),
                "ethernet_mac": _mac(info.get("ap-ethernet-mac")),
                "name": _text(info.get("ap-name")),
                "joined": joined,
                "provenance": _observation(resources[-1], source),
            }
        )
        history[-1]["provenance"]["semantics"] = "history"
    configured = _resource(
        client,
        AP_TAG_PATH,
        AP_CFG_MODULE,
        "ap-tag",
        "ap-tags",
        AP_TAG_FIELDS,
        max_aps * 16,
        False,
        resources,
        warnings,
        advertised=source["implemented_modules"],
    )
    if configured is not None:
        _configured_tags(aps, configured, resources[-1], source, warnings)
    for resource in resources:
        resource["revision"] = source["module_revisions"].get(resource["module"])
        if resource["path"] in (CDP_PATH, LLDP_PATH):
            resource["semantics"] = "cached-unspecified"
        if resource["path"] == JOIN_PATH:
            resource["semantics"] = "history"
        if resource["path"] == AP_TAG_PATH:
            resource["semantics"] = "configuration-intent"
    return {
        "contract": CONTRACT,
        "adapter": "cisco_9800",
        "controller_id": controller_id,
        "source": source,
        "complete": True,
        "aps": aps,
        "join_history": history,
        "resources": resources,
        "warnings": warnings,
    }
