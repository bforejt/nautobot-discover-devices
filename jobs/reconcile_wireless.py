"""Pure controller-wide AP plans with narrow, evidence-backed replacement rules."""

import re
from collections import Counter, defaultdict
from copy import deepcopy

from .wireless_policy import CONTRACT as POLICY_CONTRACT
from .wireless_policy import (
    MATCH_FIELDS,
    TARGETS,
    canonical_mac,
    canonical_uuid,
    cisco_manufacturer,
    native_macs,
)

CONTRACT = "wireless-plan-v1"
SNAPSHOT_CONTRACT = "cisco-9800-snapshot-v1"
# The reviewed current CAPWAP contract includes software downloads, not join history.
CURRENT_STATES = frozenset(("registered", "downloading"))
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z][A-Za-z0-9]*)?(?:\.[0-9]+)*")


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _text(value):
    return value if isinstance(value, str) and value.strip() == value and value else None


def _policy_errors(policy, controller_id):
    if not isinstance(policy, dict) or policy.get("contract") != POLICY_CONTRACT:
        return ["Wireless admission policy has an invalid contract"]
    if policy.get("controller_id") != controller_id:
        return ["Wireless policy belongs to a different Controller"]
    errors = []
    if set(policy) - (
        set(TARGETS)
        | {
            "contract",
            "controller_id",
            "naming",
            "locations",
            "identity_bindings",
            "ethernet_enabled",
        }
    ):
        errors.append("Wireless policy contains unsupported normalized fields")
    for key in TARGETS:
        if key in policy and (
            not isinstance(policy[key], dict) or canonical_uuid(policy[key].get("id")) is None
        ):
            errors.append("Wireless policy has an invalid native %s target" % key)
    group = policy.get("managed_group")
    if isinstance(group, dict) and group.get("controller_id") != controller_id:
        errors.append("Wireless admission group belongs to a different Controller")
    manufacturer = policy.get("manufacturer")
    if isinstance(manufacturer, dict) and not cisco_manufacturer(manufacturer.get("name")):
        errors.append("Wireless AP admission requires the reviewed Cisco Manufacturer")
    if "naming" in policy and policy["naming"] != "reported":
        errors.append("Wireless policy has an unsupported naming policy")
    if "ethernet_enabled" in policy and type(policy["ethernet_enabled"]) is not bool:
        errors.append("Wireless interface admission requires an explicit Boolean")
    if not isinstance(policy.get("locations"), list) or not isinstance(
        policy.get("identity_bindings"), list
    ):
        errors.append("Wireless policy lacks structured placement/identity mappings")
        return errors
    for row in policy["locations"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"match", "location"}
            or not isinstance(row["match"], dict)
            or not row["match"]
            or set(row["match"]) - MATCH_FIELDS
            or any(_text(value) is None for value in row["match"].values())
            or not isinstance(row["location"], dict)
            or canonical_uuid(row["location"].get("id")) is None
        ):
            errors.append("Wireless policy has an invalid explicit Location mapping")
    for row in policy["identity_bindings"]:
        if (
            not isinstance(row, dict)
            or not {"serial", "device"}.issubset(row)
            or set(row) - {"serial", "device", "wtp_mac", "ethernet_mac"}
            or _text(row.get("serial")) is None
            or not isinstance(row.get("device"), dict)
            or canonical_uuid(row["device"].get("id")) is None
            or any(
                canonical_mac(row[key]) is None for key in ("wtp_mac", "ethernet_mac") if key in row
            )
        ):
            errors.append("Wireless policy has an invalid explicit identity binding")
    if not errors:
        for key in ("serial", "device"):
            values = [
                row["device"]["id"] if key == "device" else row[key]
                for row in policy["identity_bindings"]
            ]
            if len(set(values)) != len(values):
                errors.append("Wireless policy contains duplicate bound AP identities")
    return errors


def _location(ap, inventory, policy, result):
    observations = {
        "serial": ap.get("serial"),
        "site_tag": (ap.get("tags") or {}).get("site"),
        "location_label": ap.get("location_label"),
        "floor_label": ap.get("floor_label"),
    }
    matches = [
        row
        for row in policy["locations"]
        if isinstance(row, dict)
        and isinstance(row.get("match"), dict)
        and row["match"]
        and all(observations.get(key) == value for key, value in row["match"].items())
    ]
    identifiers = {
        row.get("location", {}).get("id")
        for row in matches
        if isinstance(row.get("location"), dict)
    }
    if len(identifiers) > 1:
        result["unresolved"].append("Conflicting explicit Location mappings")
        return None
    if not identifiers:
        result["unresolved"].append("No explicit Location mapping matches this AP")
        return None
    identifier = next(iter(identifiers))
    if (
        canonical_uuid(identifier) is None
        or sum(row.get("id") == identifier for row in inventory.get("locations", [])) != 1
    ):
        result["unresolved"].append("The explicitly mapped native Location is missing or ambiguous")
        return None
    result["location_source"] = {
        "controller_id": policy["controller_id"],
        "rules": deepcopy(matches),
    }
    return identifier


def _compatible(ap, device, policy):
    return (
        device.get("model") == ap.get("model")
        and device.get("manufacturer_id") is not None
        and (
            device["manufacturer_id"] == policy["manufacturer"]["id"]
            if "manufacturer" in policy
            else cisco_manufacturer(device.get("manufacturer_name"))
        )
    )


def _existing(ap, devices, policy, result):
    matches = [
        row
        for row in devices
        if isinstance(row.get("serial"), str) and row["serial"].strip() == ap["serial"]
    ]
    if len(matches) > 1:
        result["errors"].append("Several Devices claim this AP serial")
        return None
    if matches:
        if any(
            row.get("serial") == ap["serial"]
            and row.get("device", {}).get("id") != matches[0].get("id")
            for row in policy["identity_bindings"]
        ):
            result["errors"].append("AP serial and explicit source binding claim different Devices")
            return None
        if not _compatible(ap, matches[0], policy):
            result["errors"].append("Reported AP serial conflicts with native manufacturer/model")
            return None
        return matches[0]
    bindings = [row for row in policy["identity_bindings"] if row.get("serial") == ap["serial"]]
    if not bindings:
        return None
    if len(bindings) != 1:
        result["errors"].append("Several source identity bindings claim this AP")
        return None
    binding = bindings[0]
    bound = [row for row in devices if row.get("id") == binding.get("device", {}).get("id")]
    if len(bound) != 1:
        result["errors"].append("The explicitly bound AP Device is missing or ambiguous")
        return None
    device = bound[0]
    valid_macs = {
        canonical_mac(binding[key])
        for key in ("wtp_mac", "ethernet_mac")
        if key in binding and canonical_mac(binding[key]) == canonical_mac(ap.get(key))
    } - {None}
    if (
        not _blank(device.get("serial"))
        or not _compatible(ap, device, policy)
        or not valid_macs.intersection(native_macs(device))
    ):
        result["errors"].append(
            "AP identity binding lacks independent matching native MAC evidence"
        )
        return None
    return device


def _software(ap, device, inventory, result):
    version = ap.get("software_version")
    if _blank(version):
        result["unresolved"].append(
            "AP running software is unavailable; existing software preserved"
        )
        return
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        result["unresolved"].append("AP running software token requires a reviewed exact format")
        return
    platform_id = device.get("platform_id")
    if canonical_uuid(platform_id) is None:
        result["unresolved"].append("AP requires its own configured Platform for running software")
        return
    if device.get("software_version") == version:
        return
    matches = [
        row
        for row in inventory.get("software_versions", [])
        if row.get("platform_id") == platform_id and row.get("version") == version
    ]
    if len(matches) > 1:
        result["unresolved"].append("Several SoftwareVersion records claim this exact AP release")
        return
    existing_id = matches[0]["id"] if matches else None
    result["software"] = {
        "platform_id": platform_id,
        "version": version,
        "existing_id": existing_id,
        "create": not matches,
    }
    result["updates"].append(
        {
            "field": "software_version_id",
            "before": device.get("software_version_id"),
            "after": existing_id,
            "before_version": device.get("software_version"),
            "after_version": version,
            "source": deepcopy(ap.get("provenance", {})),
            "reason": "Verified AP running software in its own Platform; downgrades are permitted",
        }
    )


def _interfaces(ap, device, policy, result):
    rows = ap.get("ethernet_interfaces", [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        result["unresolved"].append("AP Ethernet observations are not a structured list")
        return
    counts = Counter(row.get("name") for row in rows if _text(row.get("name")))
    existing = defaultdict(list)
    for row in device.get("interfaces", []):
        existing[row.get("name")].append(row)
    for row in rows:
        name = _text(row.get("name"))
        if not name or counts[name] != 1 or row.get("physical_ethernet") is not True:
            result["unresolved"].append("AP Ethernet identity/capability evidence is incomplete")
            continue
        values = {"type": "other", "mac_address": canonical_mac(row.get("mac_address"))}
        if type(row.get("speed")) is int and row["speed"] > 0:
            values["speed"] = row["speed"]
        if _text(row.get("description")):
            values["description"] = row["description"]
        if len(existing[name]) > 1:
            result["unresolved"].append("Several native AP interfaces have name %s" % name)
            continue
        if not existing[name]:
            if "ethernet_enabled" not in policy:
                result["unresolved"].append(
                    "%s: explicit Ethernet administrative admission state is required" % name
                )
                continue
            result["interface_creates"].append(
                {
                    "name": name,
                    "enabled": policy["ethernet_enabled"],
                    **values,
                    "source": deepcopy(row.get("provenance", {})),
                }
            )
        else:
            current = existing[name][0]
            changes = [
                {"field": field, "before": current.get(field), "after": value}
                for field, value in values.items()
                if field != "type" and value is not None and _blank(current.get(field))
            ]
            if changes:
                result["interface_updates"].append(
                    {
                        "id": current["id"],
                        "name": name,
                        "changes": changes,
                        "source": deepcopy(row.get("provenance", {})),
                    }
                )


def build_wireless_plan(discovery, inventory, policy):
    """Plan eligible AP graphs independently; never reinterpret a failed roster as empty."""
    controller_id = discovery.get("controller_id") if isinstance(discovery, dict) else None
    plan = {
        "contract": CONTRACT,
        "controller_id": controller_id,
        "policy": deepcopy(policy),
        "source_binding": deepcopy(discovery.get("source_binding"))
        if isinstance(discovery, dict)
        else None,
        "aps": [],
        "errors": [],
        "summary": {
            "observed": 0,
            "eligible": 0,
            "created": 0,
            "updated": 0,
            "unchanged": 0,
            "unresolved": 0,
            "failed": 0,
            "location_updates": 0,
            "software_updates": 0,
            "interface_creates": 0,
            "interface_updates": 0,
        },
    }
    if not isinstance(discovery, dict) or (
        discovery.get("contract") != SNAPSHOT_CONTRACT
        or discovery.get("adapter") != "cisco_9800"
        or canonical_uuid(controller_id) is None
        or discovery.get("complete") is not True
        or not isinstance(discovery.get("source"), dict)
        or discovery["source"].get("verified") is not True
        or discovery["source"].get("controller_id", controller_id) != controller_id
        or discovery.get("errors")
        or not isinstance(discovery.get("aps"), list)
        or len(discovery["aps"]) > 65535
        or any(not isinstance(row, dict) for row in discovery["aps"])
    ):
        plan["errors"].append("A verified, complete structured Controller roster is required")
        return plan
    if (
        not isinstance(inventory, dict)
        or inventory.get("supported") is not True
        or any(
            not isinstance(inventory.get(key), list)
            or any(not isinstance(row, dict) for row in inventory[key])
            for key in ("devices", "device_types", "software_versions", "locations")
        )
    ):
        plan["errors"].append("Installed native wireless inventory capability is unavailable")
        return plan
    plan["errors"].extend(_policy_errors(policy, controller_id))
    if plan["errors"]:
        return plan
    aps = discovery["aps"]
    plan["summary"]["observed"] = len(aps)
    duplicate_fields = {
        field: Counter(
            canonical_mac(row.get(field)) if field.endswith("mac") else _text(row.get(field))
            for row in aps
        )
        for field in ("name", "serial", "wtp_mac", "ethernet_mac")
    }
    devices = inventory.get("devices", [])
    mac_claims = Counter(
        mac
        for ap in aps
        for mac in {canonical_mac(ap.get(key)) for key in ("wtp_mac", "ethernet_mac")} - {None}
    )
    claimed_devices = set()
    for index, ap in enumerate(aps):
        result = {
            "key": ap.get("serial") or "unresolved-row-%s" % index,
            "identity": {
                key: ap.get(key) for key in ("name", "serial", "model", "wtp_mac", "ethernet_mac")
            },
            "device_id": None,
            "create": False,
            "device": None,
            "updates": [],
            "software": None,
            "interface_creates": [],
            "interface_updates": [],
            "errors": list(ap.get("errors", []))
            if isinstance(ap.get("errors", []), list)
            else ["AP source errors must be a structured list"],
            "unresolved": [],
            "warnings": list(ap.get("warnings", []))
            if isinstance(ap.get("warnings", []), list)
            else [],
            "outcome": "unresolved",
        }
        plan["aps"].append(result)
        for field in ("serial", "model"):
            if _text(ap.get(field)) is None:
                result["errors"].append("AP lacks a valid structured %s" % field)
        if _text(ap.get("state")) not in CURRENT_STATES:
            result["errors"].append("AP lacks reviewed current connected/download state evidence")
        if canonical_mac(ap.get("wtp_mac")) is None:
            result["errors"].append("AP lacks a valid reported WTP MAC identity")
        if not _blank(ap.get("ethernet_mac")) and canonical_mac(ap.get("ethernet_mac")) is None:
            result["errors"].append("AP reports an invalid Ethernet MAC identity")
        if "tags" in ap and not isinstance(ap["tags"], dict):
            result["errors"].append("AP effective tags must be a structured object")
        for field, counts in duplicate_fields.items():
            value = canonical_mac(ap.get(field)) if field.endswith("mac") else _text(ap.get(field))
            if value is not None and counts[value] > 1:
                result["errors"].append("Controller roster repeats AP %s" % field)
        if any(
            mac_claims[mac] > 1
            for mac in {canonical_mac(ap.get(key)) for key in ("wtp_mac", "ethernet_mac")} - {None}
        ):
            result["errors"].append("Several APs claim the same physical MAC identity")
        if not result["errors"]:
            device = _existing(ap, devices, policy, result)
            location_id = _location(ap, inventory, policy, result)
            if device is None and not result["errors"]:
                missing = [key for key in TARGETS if key not in policy]
                if policy.get("naming") != "reported":
                    missing.append("naming")
                if _text(ap.get("name")) is None:
                    missing.append("reported AP name")
                if missing:
                    result["unresolved"].append(
                        "New AP admission requires: %s" % ", ".join(missing)
                    )
                types = [
                    row
                    for row in inventory.get("device_types", [])
                    if row.get("model") == ap["model"]
                    and row.get("manufacturer_id") == policy.get("manufacturer", {}).get("id")
                ]
                if len(types) != 1:
                    result["unresolved"].append(
                        "Exact AP Manufacturer/DeviceType catalog is missing or ambiguous"
                    )
                if _text(ap.get("name")) and any(row.get("name") == ap["name"] for row in devices):
                    result["errors"].append("Reported new AP name collides with an existing Device")
                if not missing and len(types) == 1 and location_id and not result["errors"]:
                    device = {
                        "name": ap["name"],
                        "serial": ap["serial"],
                        "device_type_id": types[0]["id"],
                        "manufacturer_id": policy["manufacturer"]["id"],
                        "platform_id": policy["platform"]["id"],
                        "role_id": policy["role"]["id"],
                        "status_id": policy["status"]["id"],
                        "location_id": location_id,
                        "controller_managed_device_group_id": policy["managed_group"]["id"],
                    }
                    result.update(create=True, device=deepcopy(device))
            if device is not None and not result["errors"]:
                result["device_id"] = device.get("id")
                if result["device_id"] in claimed_devices:
                    result["errors"].append("Several AP observations resolve to the same Device")
                elif result["device_id"]:
                    claimed_devices.add(result["device_id"])
                if not result["create"]:
                    if _blank(device.get("name")):
                        if _text(ap.get("name")) is None:
                            result["unresolved"].append(
                                "Reported AP name unavailable; native blank name preserved"
                            )
                        elif any(
                            row.get("name") == ap["name"] and row.get("id") != device.get("id")
                            for row in devices
                        ):
                            result["errors"].append("Reported AP name collides with another Device")
                        else:
                            result["updates"].append(
                                {
                                    "field": "name",
                                    "before": device.get("name"),
                                    "after": ap["name"],
                                    "source": deepcopy(ap.get("provenance", {})),
                                    "reason": "Verified AP identity supplies its blank name",
                                }
                            )
                    elif _text(ap.get("name")) is None:
                        result["warnings"].append(
                            "Reported AP name unavailable; existing operator name preserved"
                        )
                    if _blank(device.get("serial")):
                        result["updates"].append(
                            {
                                "field": "serial",
                                "before": device.get("serial"),
                                "after": ap["serial"],
                                "source": deepcopy(ap.get("provenance", {})),
                                "reason": "AP identity corroborated by explicit native MAC binding",
                            }
                        )
                    if location_id and location_id != device.get("location_id"):
                        result["updates"].append(
                            {
                                "field": "location_id",
                                "before": device.get("location_id"),
                                "after": location_id,
                                "source": result["location_source"],
                                "reason": "Unique explicit controller-scoped Location mapping",
                            }
                        )
                    group_id = policy.get("managed_group", {}).get("id")
                    if group_id and device.get("controller_managed_device_group_id") != group_id:
                        result["warnings"].append(
                            "Existing configured controller/group preserved; "
                            "observed source differs"
                        )
                _software(ap, device, inventory, result)
                _interfaces(ap, device, policy, result)
        work = (
            result["create"]
            or result["updates"]
            or result["interface_creates"]
            or result["interface_updates"]
        )
        if result["errors"]:
            result.update(
                outcome="failed",
                create=False,
                device=None,
                updates=[],
                software=None,
                interface_creates=[],
                interface_updates=[],
            )
        elif work:
            result["outcome"] = "eligible"
        elif result["device_id"] and not result["unresolved"]:
            result["outcome"] = "unchanged"
        summary = plan["summary"]
        summary[result["outcome"]] += 1
        if result["outcome"] == "eligible":
            summary["created" if result["create"] else "updated"] += 1
            summary["location_updates"] += sum(
                row["field"] == "location_id" for row in result["updates"]
            )
            summary["software_updates"] += result["software"] is not None
            summary["interface_creates"] += len(result["interface_creates"])
            summary["interface_updates"] += len(result["interface_updates"])
    return plan
