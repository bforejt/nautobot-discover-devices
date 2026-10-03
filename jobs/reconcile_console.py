"""Pure reconciliation of console connectors from reviewed chassis documentation."""

from collections import defaultdict

PROFILE = "c9300-48uxm-access-ports-v1"
MODEL = "C9300-48UXM"
CONNECTORS = {"console:rj45": "rj-45", "console:usb": "usb-mini-b"}
DOCUMENTS = {
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/Product-overview.html",
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/connector-cable-specs.html",
}


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _name(value):
    return value.strip().casefold() if isinstance(value, str) else None


def reviewed_profile(source, model, member=1):
    """Accept the documented connector profile for a validated physical member."""
    return (
        isinstance(source, dict)
        and source.get("method") == "reviewed-hardware-profile"
        and source.get("profile") == PROFILE
        and source.get("model") == model == MODEL
        and type(source.get("member")) is int
        and type(member) is int
        and 1 <= member <= 255
        and source["member"] == member
        and isinstance(source.get("documents"), list)
        and all(isinstance(url, str) for url in source["documents"])
        and bool(DOCUMENTS.intersection(source["documents"]))
    )


def _finish(plan):
    plan["summary"] = {
        "console_ports_created": len(plan["creates"]),
        "console_ports_updated": len(plan["updates"]),
        "unresolved_console_ports": len(plan["unresolved"]),
    }
    return plan


def _plan_console_ports(discovery, existing, *, member=1):
    """Fill native connector fields while preserving existing identity and cabling.

    A reviewed profile establishes one connector of each supported type. A
    unique matching chassis connector can therefore retain its operator name.
    Templates supply names, not new hardware evidence. Ambiguous records are
    never renamed, attached to a different parent, or duplicated.
    """
    plan = {
        "schema_version": 1,
        "creates": [],
        "updates": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "unresolved": [],
        "observations": {},
    }
    source = discovery.get("console_ports")
    if source is None:
        return _finish(plan)
    if (
        not isinstance(source, dict)
        or type(source.get("schema_version")) is not int
        or source["schema_version"] != 1
        or not isinstance(source.get("items"), list)
        or not isinstance(source.get("unresolved", []), list)
        or not isinstance(source.get("observations", {}), dict)
    ):
        plan["errors"].append("Unsupported serialized console connector schema")
        return _finish(plan)
    plan["unresolved"] = list(source.get("unresolved", []))
    plan["observations"] = source.get("observations", {})
    catalog = existing.get("console_inventory", {})
    if not catalog.get("supported", False):
        plan["unresolved"].extend(
            {"key": item.get("key"), "reason": "Console port inventory is unavailable"}
            for item in source["items"]
            if isinstance(item, dict)
        )
        if source["items"]:
            plan["warnings"].append("This Nautobot release does not support console port discovery")
        return _finish(plan)
    rows = catalog.get("ports", [])
    templates = catalog.get("templates", [])
    by_name = defaultdict(list)
    for row in rows:
        by_name[_name(row["name"])].append(row)
    seen_keys, seen_names, used_ids = set(), set(), set()

    def unresolved(item, reason):
        plan["unresolved"].append({"key": item["key"], "name": item["name"], "reason": reason})

    def conflict(item, row, field, observed, reason):
        plan["conflicts"].append(
            {
                "scope": "console_port",
                "name": row["name"],
                "field": field,
                "before": row.get(field),
                "observed": observed,
                "reason": reason,
                "source": item["source"],
            }
        )

    for item in source["items"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("key"), str)
            or item.get("key") not in CONNECTORS
            or item.get("type") != CONNECTORS[item["key"]]
            or not _name(item.get("name"))
            or not reviewed_profile(item.get("source"), discovery["identity"].get("model"), member)
            or any(
                item.get(field) is not None and not isinstance(item[field], str)
                for field in ("label", "description")
            )
        ):
            plan["errors"].append("Console connector has invalid identity or reviewed provenance")
            continue
        key, name, connector = item["key"], item["name"].strip(), item["type"]
        if key in seen_keys or _name(name) in seen_names:
            plan["errors"].append("Several discovered console connectors have the same identity")
            continue
        seen_keys.add(key)
        seen_names.add(_name(name))
        matching_templates = [row for row in templates if row.get("type") == connector]
        if len(matching_templates) > 1:
            unresolved(item, "Several DeviceType templates represent this console connector")
            plan["errors"].append("Ambiguous console connector templates for %s" % connector)
            continue
        template = matching_templates[0] if matching_templates else None
        preferred = template["name"] if template is not None else name
        names = {_name(name), _name(preferred)}
        named = [row for match in names for row in by_name[match]]
        typed = [row for row in rows if row.get("type") == connector]
        candidates = {str(row["id"]): row for row in named + typed}
        if any(row.get("module_id") is not None for row in candidates.values()):
            for row in candidates.values():
                if row.get("module_id") is not None:
                    conflict(item, row, "module_id", None, "Preserve existing Module ownership")
            unresolved(item, "A matching console port belongs to a Module")
            continue
        if len(candidates) > 1:
            unresolved(item, "Several existing console ports could represent this connector")
            plan["errors"].append("Ambiguous existing console connector %s" % connector)
            continue
        if candidates:
            row = next(iter(candidates.values()))
            if str(row["id"]) in used_ids:
                plan["errors"].append(
                    "An existing console port matches several physical connectors"
                )
                unresolved(item, "One existing port cannot represent two connectors")
                continue
            used_ids.add(str(row["id"]))
            if not _blank(row.get("type")) and row["type"] != connector:
                conflict(item, row, "type", connector, "Preserve populated connector type")
                unresolved(item, "Existing console connector type disagrees with hardware evidence")
                continue
            changes = []
            for field in ("type", "label", "description"):
                after = item.get(field)
                before = row.get(field)
                if _blank(after):
                    continue
                if _blank(before):
                    changes.append({"field": field, "before": before, "after": after})
                elif before != after:
                    conflict(item, row, field, after, "Preserve populated operator value")
            if changes:
                plan["updates"].append(
                    {
                        "id": str(row["id"]),
                        "key": key,
                        "name": row["name"],
                        "changes": changes,
                        "source": item["source"],
                    }
                )
            continue
        unidentified = [
            row
            for row in rows
            if row.get("module_id") is None
            and (_blank(row.get("type")) or row.get("type") == "other")
            and str(row["id"]) not in used_ids
        ]
        if unidentified:
            unresolved(item, "Existing console ports have unresolved connector types")
            continue
        plan["creates"].append(
            {
                "key": key,
                "name": preferred,
                "type": connector,
                "label": item.get("label"),
                "description": item.get("description"),
                "source": item["source"],
                "name_source": "existing DeviceType console template"
                if template
                else "discovery-standardized connector name",
            }
        )
    return _finish(plan)


def plan_console_ports(discovery, existing, *, stack_plan=None):
    """Reconcile physical connectors independently within each validated Device."""
    source = discovery.get("console_ports")
    stack_source = discovery.get("stack")
    if (
        not isinstance(stack_source, dict)
        or stack_source.get("is_stack") is not True
        or not isinstance(source, dict)
        or not isinstance(source.get("items"), list)
        or not source["items"]
    ):
        return _plan_console_ports(discovery, existing)
    empty = {**discovery, "console_ports": {**source, "items": []}}
    plan = _plan_console_ports(empty, existing)
    if plan["errors"]:
        return plan
    if (
        not isinstance(stack_plan, dict)
        or stack_plan.get("errors")
        or not stack_plan.get("virtual_chassis")
        or not isinstance(stack_plan.get("members"), list)
        or len(stack_plan["members"]) < 2
    ):
        plan["errors"].append("Console placement requires a validated physical stack plan")
        return _finish(plan)
    owners = {row["serial"]: row for row in stack_plan["members"]}
    groups = defaultdict(list)
    for item in source["items"]:
        owner = owners.get(item.get("device_serial")) if isinstance(item, dict) else None
        evidence = item.get("source") if isinstance(item, dict) else None
        if (
            owner is None
            or item.get("member") != owner["position"]
            or type(item.get("member")) is not int
            or item.get("chassis_model") != owner["model"]
            or not isinstance(evidence, dict)
            or evidence.get("device_serial") != owner["serial"]
            or not isinstance(evidence.get("identity"), dict)
            or not isinstance(evidence.get("membership"), dict)
            or not evidence["identity"]
            or not evidence["membership"]
        ):
            plan["errors"].append("Console connector ownership disagrees with the physical member")
            continue
        groups[owner["serial"]].append(item)
    if plan["errors"]:
        return _finish(plan)
    catalog = existing.get("console_inventory", {})
    type_ids = {row["model"]: row.get("existing_id") for row in stack_plan["device_types"]}
    template_map = catalog.get("templates_by_device_type", {})
    for serial in sorted(groups):
        owner = owners[serial]
        device_id = owner.get("existing_id")
        rows = [
            row
            for row in catalog.get("ports", [])
            if device_id is not None
            and (
                str(row.get("device_id")) == str(device_id)
                or owner["selected"]
                and row.get("device_id") is None
            )
        ]
        templates = template_map.get(type_ids[owner["model"]], [])
        if not template_map and owner["selected"]:
            templates = catalog.get("templates", [])
        scoped = _plan_console_ports(
            {
                **discovery,
                "identity": {**discovery["identity"], "model": owner["model"]},
                "console_ports": {
                    **source,
                    "items": groups[serial],
                    "unresolved": [],
                    "observations": {},
                },
            },
            {
                **existing,
                "console_inventory": {
                    "supported": catalog.get("supported", False),
                    "ports": rows,
                    "templates": templates,
                },
            },
            member=owner["position"],
        )
        for field in ("creates", "updates", "conflicts", "errors", "warnings", "unresolved"):
            for row in scoped[field]:
                if isinstance(row, dict):
                    row = {
                        **row,
                        "device_serial": serial,
                        "device_id": device_id,
                        "member_position": owner["position"],
                    }
                plan[field].append(row)
    return _finish(plan)
