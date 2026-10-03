"""Pure, scoped VLAN reconciliation with atomic interface switching bundles."""

from collections import defaultdict

from .adapters.cisco_iosxe import canonical_interface_name

MODES = {"access", "tagged", "tagged-all"}


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _vid(value):
    return type(value) is int and 1 <= value <= 4094


def _id(value):
    return str(value) if value is not None else None


def _finish(plan):
    plan["summary"] = {
        "vlans_created": sum(row["create"] for row in plan["catalog"]),
        "vlans_updated": sum(bool(row["changes"]) for row in plan["catalog"]),
        "interface_vlan_assignments_updated": len(plan["assignments"]),
        "unresolved_switching": sum(
            row.get("category") != "dynamic-mode" for row in plan["unresolved"]
        ),
        "switching_not_applicable": len(plan["not_applicable"]),
        "switching_defaults": sum(
            "documented-default" in row.get("field_sources", {}).values()
            for row in plan["settings"]
        ),
        "switching_dynamic": sum(
            row.get("configured_mode") in ("dynamic-auto", "dynamic-desirable", "dynamic-access")
            for row in plan["settings"]
        ),
        "switching_operational": sum(
            row.get("operational_mode") in ("access", "trunk")
            for row in plan.get("operational_interfaces", [])
        ),
        "switching_dynamic_resolved": sum(
            row.get("operational_assignment_supported") is True for row in plan["settings"]
        ),
        "switching_inferred": sum(
            isinstance(row.get("inference"), dict) for row in plan["settings"]
        ),
        "interface_vlan_assignments_inferred": sum(
            row.get("inferred", False) for row in plan["assignments"]
        ),
    }
    return plan


def plan_vlans(discovery, existing, interface_plan=None):
    """Fill VLAN identities and complete switching bundles within one group.

    VLAN identity is selected group plus VID. A populated interface mode,
    native VLAN, or tagged set is preserved when discovery differs. No part
    of an incompatible interface bundle is proposed. A verified complete VLAN
    catalog is reconciled independently of interface assignments. Tagged-all
    remains a mode, without M2M range expansion.
    """
    plan = {
        "schema_version": 1,
        "catalog": [],
        "assignments": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "unresolved": [],
        "settings": [],
        "not_applicable": [],
    }
    if "layer2" not in discovery:
        return _finish(plan)
    source = discovery["layer2"]
    if (
        not isinstance(source, dict)
        or type(source.get("schema_version")) is not int
        or source["schema_version"] != 1
    ):
        plan["errors"].append("Unsupported switching discovery schema")
        return _finish(plan)
    if not all(isinstance(source.get(field), list) for field in ("interfaces", "vlans")):
        plan["errors"].append("Switching interfaces and VLANs must be structured lists")
        return _finish(plan)
    if not isinstance(source.get("unresolved", []), list):
        plan["errors"].append("Unresolved switching evidence must be a structured list")
        return _finish(plan)
    for key in ("settings", "not_applicable", "unresolved", "operational_interfaces"):
        rows = source.get(key, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            plan["errors"].append("Switching %s evidence must be structured objects" % key)
            return _finish(plan)
        plan[key] = list(rows)
    operational_source = source.get("operational_source")
    if operational_source is not None and not isinstance(operational_source, dict):
        plan["errors"].append("Switchport operational source must be a structured object")
        return _finish(plan)
    plan["operational_source"] = operational_source
    for row in plan["settings"]:
        if not isinstance(row.get("field_sources", {}), dict):
            plan["settings"] = []
            plan["errors"].append("Switching field provenance must be a structured object")
            return _finish(plan)
        if "inference" in row and not isinstance(row["inference"], dict):
            plan["settings"] = []
            plan["errors"].append("Switching inference provenance must be a structured object")
            return _finish(plan)
    if type(source.get("catalog_complete", False)) is not bool:
        plan["errors"].append("VLAN catalog completeness must be an explicit boolean")
        return _finish(plan)

    def error(message):
        plan["errors"].append(message)

    def unresolved(fact, reason):
        plan["unresolved"].append(
            {
                "name": fact["name"],
                "reason": reason,
                "source": fact.get("source", {}),
            }
        )

    def conflict(scope, name, field, before, observed, reason):
        return {
            "scope": scope,
            "name": name,
            "field": field,
            "before": before,
            "observed": observed,
            "reason": reason,
        }

    observed_vlans = {}
    invalid_vids = set()
    for row in source["vlans"]:
        if (
            not isinstance(row, dict)
            or not _vid(row.get("vid"))
            or (row.get("name") is not None and not isinstance(row["name"], str))
        ):
            error("Discovered VLAN requires an integer VID in 1..4094 and a structured name")
            continue
        vid = row["vid"]
        if vid in observed_vlans:
            error("Several discovered VLAN rows use VID %s" % vid)
            invalid_vids.add(vid)
        observed_vlans[vid] = _text(row.get("name"))

    facts, invalid_names = {}, set()
    for row in source["interfaces"]:
        if not isinstance(row, dict) or _text(row.get("name")) is None:
            error("Switching interface rows require a structured interface name")
            continue
        name = canonical_interface_name(row["name"])
        if name in facts:
            error("Several switching rows normalize to interface %s" % name)
            invalid_names.add(name)
            continue
        mode, native, tagged = row.get("mode"), row.get("untagged_vid"), row.get("tagged_vids")
        if not isinstance(mode, str) or mode not in MODES:
            error("Interface %s has an unsupported switching mode" % name)
            continue
        inferred = row.get("inferred", False)
        if (
            type(inferred) is not bool
            or inferred
            and not isinstance(
                row.get("source", {}).get("ntc_inference")
                if isinstance(row.get("source", {}), dict)
                else None,
                dict,
            )
        ):
            error("Interface %s requires explicit inference provenance" % name)
            continue
        if (
            "untagged_vid" not in row
            or (native is not None and not _vid(native))
            or not isinstance(tagged, list)
            or any(not _vid(vid) for vid in tagged)
            or not isinstance(row.get("source", {}), dict)
            or not isinstance(row.get("observations", {}), dict)
        ):
            error(
                "Interface %s requires integer VLAN IDs in 1..4094 and structured evidence" % name
            )
            continue
        if (
            len(set(tagged)) != len(tagged)
            or native in tagged
            or mode == "access"
            and (native is None or tagged)
            or mode == "tagged-all"
            and tagged
        ):
            error("Interface %s has an inconsistent access/native/tagged VLAN bundle" % name)
            continue
        facts[name] = {**row, "name": name, "tagged_vids": sorted(tagged)}

    inventory = existing.get("vlan_inventory", {})
    group = inventory.get("group")
    if not inventory.get("supported", False) or not isinstance(group, dict) or not group.get("id"):
        reason = (
            "Select a VLAN Group before loading switching inventory"
            if inventory.get("supported", False)
            else "This Nautobot inventory does not support scoped VLAN discovery"
        )
        for name, fact in sorted(facts.items()):
            if name not in invalid_names:
                unresolved(fact, reason)
        if facts or source.get("catalog_complete") and observed_vlans:
            plan["warnings"].append(reason)
            if not facts:
                plan["unresolved"].append(
                    {"scope": "vlan", "name": "VLAN catalog", "reason": reason}
                )
        return _finish(plan)
    allowed = inventory.get("allowed_vids")
    if not isinstance(allowed, list) or any(not _vid(vid) for vid in allowed):
        error("Selected VLAN Group requires an explicit integer VID range within 1..4094")
        return _finish(plan)
    allowed = set(allowed)
    group_id = _id(group["id"])
    catalog_by_vid, catalog_by_name = defaultdict(list), defaultdict(list)
    for row in inventory.get("vlans", []):
        catalog_by_vid[row["vid"]].append(row)
        if _text(row.get("name")):
            catalog_by_name[_text(row["name"])].append(row)
    interfaces = defaultdict(list)
    for row in existing.get("interfaces", []):
        effective = dict(row)
        for update in (interface_plan or {}).get("interface_updates", []):
            if _id(update["id"]) == _id(row["id"]):
                for change in update["changes"]:
                    effective[change["field"]] = change["after"]
        interfaces[canonical_interface_name(row["name"])].append(effective)
    planned_interfaces = defaultdict(list)
    for row in (interface_plan or {}).get("interface_creates", []):
        planned_interfaces[canonical_interface_name(row["name"])].append(row)
    proposed_catalog = {}

    def resolve_vlan(vid):
        if vid in invalid_vids:
            return None, None, "Discovered VLAN identity is ambiguous"
        if vid not in allowed:
            return None, None, "VID %s is outside the selected VLAN Group range" % vid
        matches = catalog_by_vid[vid]
        if len(matches) > 1:
            error("Several existing VLANs use VID %s in the selected group" % vid)
            return None, None, "Existing VLAN identity is ambiguous"
        row = matches[0] if matches else None
        if row is not None and not row.get("applicable", False):
            return None, None, "VID %s is not applicable to the Device location" % vid
        observed_name = observed_vlans.get(vid)
        before = row.get("name") if row else None
        name = before if not _blank(before) else observed_name
        if _blank(name):
            return None, None, "VID %s has no existing identity or unique structured name" % vid
        changes, name_conflict = [], None
        if row and observed_name is not None:
            if _blank(before):
                changes.append({"field": "name", "before": before, "after": observed_name})
            elif _text(before) != observed_name:
                name_conflict = conflict(
                    "vlan",
                    str(vid),
                    "name",
                    before,
                    observed_name,
                    "Preserving populated VLAN name",
                )
        return (
            {
                "key": str(vid),
                "id": _id(row["id"]) if row else None,
                "vid": vid,
                "name": name,
                "create": row is None,
                "changes": changes,
                "group_id": group_id,
            },
            name_conflict,
            None,
        )

    for name, fact in sorted(facts.items()):
        if name in invalid_names:
            continue
        matches, planned = interfaces[name], planned_interfaces[name]
        if len(matches) > 1 or len(planned) > 1 or matches and planned:
            error("Switching interface %s has ambiguous existing/planned identity" % name)
            continue
        endpoint = matches[0] if matches else planned[0] if planned else None
        if endpoint is None:
            unresolved(fact, "Interface is neither existing nor planned for creation")
            continue
        if endpoint.get("type") in {"virtual", "bridge", "tunnel"}:
            unresolved(fact, "Logical interface does not support this switching assignment")
            continue
        before_mode = endpoint.get("mode")
        before_native = _id(endpoint.get("untagged_vlan_id"))
        before_tagged = {_id(value) for value in endpoint.get("tagged_vlan_ids", [])}
        if before_tagged and before_mode != "tagged":
            plan["conflicts"].append(
                conflict(
                    "interface",
                    endpoint["name"],
                    "mode",
                    before_mode,
                    fact["mode"],
                    "Preserving manual tagged VLANs on an interface whose mode is not tagged",
                )
            )
            continue
        if not _blank(before_mode) and before_mode != fact["mode"]:
            plan["conflicts"].append(
                conflict(
                    "interface",
                    endpoint["name"],
                    "mode",
                    before_mode,
                    fact["mode"],
                    "Preserving populated interface switching mode",
                )
            )
            continue
        needed = set(fact["tagged_vids"])
        if fact["untagged_vid"] is not None:
            needed.add(fact["untagged_vid"])
        refs, catalog_conflicts, failure = {}, [], None
        for vid in sorted(needed):
            spec, name_conflict, reason = resolve_vlan(vid)
            if reason:
                failure = reason
                break
            refs[vid] = spec
            if name_conflict:
                catalog_conflicts.append(name_conflict)
        if failure:
            unresolved(fact, failure)
            continue
        native = refs.get(fact["untagged_vid"])
        if before_native is not None and (native is None or native["id"] != before_native):
            plan["conflicts"].append(
                conflict(
                    "interface",
                    endpoint["name"],
                    "untagged_vlan",
                    before_native,
                    str(fact["untagged_vid"]) if fact["untagged_vid"] is not None else None,
                    "Preserving populated untagged VLAN; skipping complete switching bundle",
                )
            )
            continue
        tagged_refs = [refs[vid] for vid in fact["tagged_vids"]]
        desired_tagged_ids = {spec["id"] for spec in tagged_refs}
        if before_tagged and desired_tagged_ids != before_tagged:
            plan["conflicts"].append(
                conflict(
                    "interface",
                    endpoint["name"],
                    "tagged_vlans",
                    sorted(before_tagged),
                    [spec["key"] for spec in tagged_refs],
                    "Preserving populated tagged set; skipping complete switching bundle",
                )
            )
            continue
        duplicate_name = False
        for spec in refs.values():
            if spec["create"] or spec["changes"]:
                other_existing = [
                    row for row in catalog_by_name[_text(spec["name"])] if row["vid"] != spec["vid"]
                ]
                other_proposed = [
                    row
                    for row in list(proposed_catalog.values()) + list(refs.values())
                    if row["vid"] != spec["vid"] and _text(row["name"]) == _text(spec["name"])
                ]
                if other_existing or other_proposed:
                    error(
                        "Proposed VLAN name %r represents several VIDs in the selected group"
                        % spec["name"]
                    )
                    duplicate_name = True
        if duplicate_name:
            continue
        for spec in refs.values():
            if spec["key"] not in proposed_catalog:
                proposed_catalog[spec["key"]] = spec
                plan["catalog"].append(spec)
        for row in catalog_conflicts:
            if row not in plan["conflicts"]:
                plan["conflicts"].append(row)
        changes = []
        if _blank(before_mode):
            changes.append({"field": "mode", "before": before_mode, "after": fact["mode"]})
        if native is not None and before_native is None:
            changes.append({"field": "untagged_vlan", "before": None, "after": native["key"]})
        tagged_keys = (
            [spec["key"] for spec in tagged_refs] if tagged_refs and not before_tagged else None
        )
        if changes or tagged_keys is not None:
            plan["assignments"].append(
                {
                    "id": _id(endpoint.get("id")),
                    "name": endpoint["name"],
                    "mode": fact["mode"],
                    "changes": changes,
                    "tagged_vlan_keys": tagged_keys,
                    "source": fact.get("source", {}),
                }
            )
            if fact.get("inferred", False):
                plan["assignments"][-1]["inferred"] = True
    # A complete device VLAN database is useful inventory independently of
    # whether any interface currently references a VLAN. Older discovery
    # reports without this marker keep the original referenced-only policy.
    if source.get("catalog_complete", False):
        for vid in sorted(observed_vlans):
            if str(vid) in proposed_catalog:
                continue
            spec, name_conflict, reason = resolve_vlan(vid)
            if reason:
                plan["unresolved"].append(
                    {
                        "scope": "vlan",
                        "name": "VLAN %s" % vid,
                        "vid": vid,
                        "category": "catalog-identity",
                        "reason": reason,
                    }
                )
                continue
            if spec["create"] or spec["changes"]:
                peers = catalog_by_name[_text(spec["name"])] + list(proposed_catalog.values())
                if any(
                    row["vid"] != vid and _text(row["name"]) == _text(spec["name"]) for row in peers
                ):
                    error(
                        "Proposed VLAN name %r represents several VIDs in the selected group"
                        % spec["name"]
                    )
                    continue
            proposed_catalog[spec["key"]] = spec
            plan["catalog"].append(spec)
            if name_conflict and name_conflict not in plan["conflicts"]:
                plan["conflicts"].append(name_conflict)
    plan["catalog"].sort(key=lambda row: row["vid"])
    return _finish(plan)
