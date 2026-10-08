"""Explicit native admission and placement policy for a complete WLC roster."""

import json
import re
from copy import deepcopy
from uuid import UUID

CONTRACT = "wireless-policy-v1"
TARGETS = ("manufacturer", "platform", "role", "status", "managed_group")
MATCH_FIELDS = {"serial", "site_tag", "location_label", "floor_label"}


def canonical_uuid(value):
    """Accept native UUID identities, never labels or sentinel identifiers."""
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    if parsed.int in (0, (1 << 128) - 1) or value.lower() != str(parsed):
        return None
    return str(parsed)


def canonical_mac(value):
    """Normalize a reported MAC without deriving any other interface identity."""
    if not isinstance(value, str):
        return None
    if not any(
        re.fullmatch(pattern, value)
        for pattern in (
            r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
            r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}",
            r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}",
            r"[0-9a-fA-F]{12}",
        )
    ):
        return None
    compact = value.replace(":", "").replace("-", "").replace(".", "").lower()
    if compact == "0" * 12 or int(compact[:2], 16) & 1:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def cisco_manufacturer(value):
    """Recognize reviewed native manufacturer labels for Cisco-reported APs."""
    name = value.lower() if isinstance(value, str) else ""
    name = name.replace(" ", "").replace(",", "").replace(".", "")
    return name in ("cisco", "ciscosystems", "ciscosystemsinc")


def native_macs(device):
    """Read independently configured native interfaces for explicit bindings."""
    addresses = device.get("mac_addresses", [])
    interfaces = device.get("interfaces", [])
    values = list(addresses) if isinstance(addresses, list) else []
    if isinstance(interfaces, list):
        values.extend(row.get("mac_address") for row in interfaces if isinstance(row, dict))
    return {mac for value in values if (mac := canonical_mac(value)) is not None}


def _text(value, label):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("Wireless %s must be nonblank structured text" % label)
    return value


def _resolve(resolver, kind, value):
    identifier = canonical_uuid(value)
    if identifier is None:
        raise ValueError("Wireless %s requires an existing native UUID" % kind)
    result = resolver(kind, identifier)
    if not isinstance(result, dict) or canonical_uuid(result.get("id")) != identifier:
        raise ValueError("The selected wireless %s is missing or ambiguous" % kind)
    return deepcopy(result)


def normalize_wireless_policy(value, resolver, *, controller_id):
    """Resolve only explicit existing records; partial policy permits existing APs."""
    controller_id = canonical_uuid(str(controller_id))
    if controller_id is None:
        raise ValueError("Wireless policy requires an existing logical Controller UUID")
    if value is None or (isinstance(value, str) and not value.strip()):
        value = {}
    elif isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise ValueError("Wireless policy must be a valid JSON object") from None
    if not isinstance(value, dict) or set(value) - (
        set(TARGETS) | {"naming", "locations", "identity_bindings", "ethernet_enabled"}
    ):
        raise ValueError("Wireless policy contains unsupported fields or is not an object")
    if "naming" in value and value["naming"] != "reported":
        raise ValueError("Wireless naming currently supports only the explicit reported policy")
    if "ethernet_enabled" in value and type(value["ethernet_enabled"]) is not bool:
        raise ValueError("Wireless ethernet_enabled must be an explicit Boolean")
    locations, bindings = value.get("locations", []), value.get("identity_bindings", [])
    if not isinstance(locations, list) or len(locations) > 4096:
        raise ValueError("Wireless locations must contain at most 4096 explicit mappings")
    if not isinstance(bindings, list) or len(bindings) > 4096:
        raise ValueError("Wireless identity bindings must contain at most 4096 mappings")
    # Validate the complete input shape before performing native lookups.
    parsed_locations = []
    for row in locations:
        if not isinstance(row, dict) or set(row) != {"match", "location"}:
            raise ValueError("Wireless placement requires only match and location")
        match = row["match"]
        if not isinstance(match, dict) or not match or set(match) - MATCH_FIELDS:
            raise ValueError(
                "Wireless placement requires explicit supported identity/label matches"
            )
        match = {key: _text(item, "placement match") for key, item in match.items()}
        if canonical_uuid(row["location"]) is None:
            raise ValueError("Wireless placement requires an existing Location UUID")
        parsed_locations.append((match, row["location"]))
    parsed_bindings = []
    serials, device_ids = set(), set()
    for row in bindings:
        if (
            not isinstance(row, dict)
            or not {"serial", "device"}.issubset(row)
            or set(row) - {"serial", "device", "wtp_mac", "ethernet_mac"}
        ):
            raise ValueError("Wireless identity binding requires serial, device and optional MACs")
        serial = _text(row["serial"], "binding serial")
        device_id = canonical_uuid(row["device"])
        if device_id is None or device_id in device_ids or serial in serials:
            raise ValueError("Wireless identity bindings contain an invalid or duplicate identity")
        macs = {}
        for key in ("wtp_mac", "ethernet_mac"):
            if key in row:
                mac = canonical_mac(row[key])
                if mac is None:
                    raise ValueError("Wireless identity binding has an invalid MAC")
                macs[key] = mac
        serials.add(serial)
        device_ids.add(device_id)
        parsed_bindings.append((serial, device_id, macs))
    for key in TARGETS:
        if key in value and canonical_uuid(value[key]) is None:
            raise ValueError("Wireless %s requires an existing native UUID" % key)
    result = {
        "contract": CONTRACT,
        "controller_id": controller_id,
        "locations": [],
        "identity_bindings": [],
    }
    for key in TARGETS:
        if key in value:
            result[key] = _resolve(resolver, key, value[key])
    group = result.get("managed_group")
    if group and group.get("controller_id") != controller_id:
        raise ValueError("Wireless admission group must belong to the collecting Controller")
    manufacturer = result.get("manufacturer")
    if manufacturer and not cisco_manufacturer(manufacturer.get("name")):
        raise ValueError("Wireless AP admission requires the reviewed Cisco Manufacturer")
    platform = result.get("platform")
    if (
        manufacturer
        and platform
        and platform.get("manufacturer_id") not in (None, manufacturer["id"])
    ):
        raise ValueError("Wireless AP Platform belongs to a different Manufacturer")
    for key in ("naming", "ethernet_enabled"):
        if key in value:
            result[key] = value[key]
    for match, location_id in parsed_locations:
        result["locations"].append(
            {"match": match, "location": _resolve(resolver, "location", location_id)}
        )
    for serial, device_id, macs in parsed_bindings:
        device = _resolve(resolver, "device", device_id)
        existing_serial = device.get("serial")
        if existing_serial is not None and not isinstance(existing_serial, str):
            raise ValueError("Wireless native Device serial must be structured text")
        if existing_serial and existing_serial.strip() != serial:
            raise ValueError("Wireless identity binding conflicts with the Device's serial")
        if not (existing_serial or "").strip() and not (set(macs.values()) & native_macs(device)):
            raise ValueError(
                "A blank-serial AP binding requires an independently recorded "
                "matching interface MAC"
            )
        result["identity_bindings"].append({"serial": serial, "device": device, **macs})
    return result
