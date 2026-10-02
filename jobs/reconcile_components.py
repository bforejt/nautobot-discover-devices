"""Pure, fill-only reconciliation of serialized modules and physical bays."""

import json
from collections import defaultdict

from .adapters.cisco_iosxe import canonical_interface_name


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _id(value):
    return str(value) if value is not None else None


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _finish(plan):
    plan["summary"] = {
        "manufacturers_created": len(plan["manufacturers"]),
        "modules_created": sum(row["create"] for row in plan["modules"]),
        "modules_updated": sum(bool(row["changes"]) for row in plan["modules"]),
        "module_types_created": sum(row["create"] for row in plan["module_types"]),
        "module_types_updated": sum(bool(row["changes"]) for row in plan["module_types"]),
        "module_bays_created": sum(row["create"] for row in plan["bays"]),
        "module_bays_updated": sum(bool(row["changes"]) for row in plan["bays"]),
        "interface_modules_updated": len(plan["interface_assignments"]),
        "unresolved_components": len(plan["unresolved"]),
    }
    return plan


def plan_components(discovery, existing, interface_plan=None):
    """Plan ModuleTypes, bays, modules, and in-place interface ownership fills.

    The serialized asset key is a resolved ModuleType plus serial, never a
    globally unique serial. Placement is immediate parent plus bay name;
    position, labels, and device inventory indexes are descriptive evidence.
    Populated ownership, serial, and type disagreements preserve existing
    records. Source ambiguity is an error that the caller must reject before
    saving any part of its combined discovery plan.
    """
    plan = {
        "schema_version": 1,
        "manufacturers": [],
        "module_types": [],
        "bays": [],
        "modules": [],
        "interface_assignments": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "missing_modules": [],
        "unresolved": [],
        "excluded": [],
    }
    if "components" not in discovery:
        return _finish(plan)
    source = discovery["components"]
    if (
        not isinstance(source, dict)
        or type(source.get("schema_version")) is not int
        or source["schema_version"] != 1
    ):
        plan["errors"].append("Unsupported serialized component schema")
        return _finish(plan)
    if "items" not in source:
        plan["errors"].append("Component items must be provided as a structured list")
        return _finish(plan)
    for field in ("items", "unresolved", "excluded"):
        if not isinstance(source.get(field, []), list):
            plan["errors"].append("Component %s must be a structured list" % field)
    if plan["errors"]:
        return _finish(plan)
    plan["unresolved"] = list(source.get("unresolved", []))
    plan["excluded"] = list(source.get("excluded", []))
    catalog = existing.get("components", {})
    if not catalog.get("supported", False):
        if source.get("items"):
            plan["warnings"].append("This Nautobot inventory does not support module discovery")
            plan["unresolved"].extend(
                {"key": item.get("key"), "reason": "Module inventory is unavailable"}
                for item in source["items"]
                if isinstance(item, dict)
            )
        return _finish(plan)

    def error(message):
        plan["errors"].append(message)

    def unresolved(item, reason):
        plan["unresolved"].append({"key": item["key"], "reason": reason})

    def conflict(scope, name, field, before, observed, reason):
        plan["conflicts"].append(
            {
                "scope": scope,
                "name": name,
                "field": field,
                "before": before,
                "observed": observed,
                "reason": reason,
            }
        )

    items = {}
    invalid_keys = set()
    asset_claims = defaultdict(list)
    bay_claims = defaultdict(list)
    interface_claims = defaultdict(list)
    type_claims = defaultdict(list)
    pid_claims = defaultdict(list)
    for raw in source.get("items", []):
        if not isinstance(raw, dict):
            error("Serialized component items must be structured objects")
            continue
        key = _text(raw.get("key"))
        required = ("kind", "manufacturer", "model", "part_number", "serial")
        if key is None or any(_text(raw.get(field)) is None for field in required):
            error("Serialized component requires key, kind, manufacturer, model, PID, and serial")
            continue
        if key in items:
            error("Several discovered components use key %s" % key)
            invalid_keys.add(key)
            continue
        item = {**raw, **{field: _text(raw[field]) for field in required}, "key": key}
        bay = item.get("bay")
        parent = item.get("parent_key")
        names = item.get("interfaces", [])
        if (
            not isinstance(bay, dict)
            or _text(bay.get("name")) is None
            or (parent is not None and _text(parent) is None)
            or not isinstance(names, list)
            or any(_text(name) is None for name in names)
            or not isinstance(item.get("source", {}), dict)
            or not isinstance(item.get("observations", {}), dict)
            or any(
                bay.get(field) is not None and not isinstance(bay[field], str)
                for field in ("position", "label")
            )
        ):
            error("Component %s has invalid structured placement or interface evidence" % key)
            continue
        item["parent_key"] = _text(parent)
        item["bay"] = {**bay, "name": _text(bay["name"])}
        item["interfaces"] = [canonical_interface_name(name) for name in names]
        items[key] = item
        asset_key = (item["manufacturer"].casefold(), item["part_number"], item["serial"])
        asset_claims[asset_key].append(key)
        type_claims[(item["manufacturer"].casefold(), item["model"])].append(key)
        pid_claims[(item["manufacturer"].casefold(), item["part_number"])].append(key)
        bay_claims[(item["parent_key"], item["bay"]["name"])].append(key)
        for name in item["interfaces"]:
            interface_claims[name].append(key)

    for label, claims in (
        ("serialized identity", asset_claims),
        ("physical bay", bay_claims),
        ("interface ownership", interface_claims),
    ):
        for keys in claims.values():
            if len(keys) > 1:
                error(
                    "Several discovered components claim the same %s: %s" % (label, ", ".join(keys))
                )
                invalid_keys.update(keys)
    for keys in type_claims.values():
        if len({items[key]["part_number"] for key in keys}) > 1:
            error("Discovered components disagree on one ModuleType's PID: %s" % ", ".join(keys))
            invalid_keys.update(keys)
    for keys in pid_claims.values():
        if len({items[key]["model"] for key in keys}) > 1:
            error("Discovered PID claims several ModuleType models: %s" % ", ".join(keys))
            invalid_keys.update(keys)
    for key, item in items.items():
        parent, visited = item["parent_key"], {key}
        while parent is not None:
            if parent in visited:
                error("Component %s has cyclic parent placement" % key)
                invalid_keys.update(visited)
                break
            if parent not in items:
                error("Component %s has unknown parent %s" % (key, parent))
                invalid_keys.add(key)
                break
            visited.add(parent)
            parent = items[parent]["parent_key"]

    manufacturers = defaultdict(list)
    for row in catalog.get("manufacturers", []):
        if _text(row.get("name")):
            manufacturers[row["name"].strip().casefold()].append(row)
    types = catalog.get("module_types", [])
    bays = catalog.get("module_bays", [])
    modules = catalog.get("modules", [])
    modules_by_bay = defaultdict(list)
    for row in modules:
        if row.get("parent_module_bay_id") is not None:
            modules_by_bay[_id(row["parent_module_bay_id"])].append(row)
    interfaces = defaultdict(list)
    for row in existing.get("interfaces", []):
        interfaces[canonical_interface_name(row["name"])].append(row)
    planned_interfaces = {
        canonical_interface_name(row["name"]): row
        for row in (interface_plan or {}).get("interface_creates", [])
    }
    device_id = _id(existing["device"]["id"])
    planned_modules, planned_types, planned_manufacturers = {}, {}, {}
    seen_module_ids = set()

    def resolve_type(item):
        matches = manufacturers[item["manufacturer"].casefold()]
        if len(matches) > 1:
            error(
                "Component %s requires one existing Manufacturer %s"
                % (item["key"], item["manufacturer"])
            )
            return None
        manufacturer_id = _id(matches[0]["id"]) if matches else None
        manufacturer_key = manufacturer_id or "reported:" + item["manufacturer"].casefold()
        if not matches:
            evidence = item.get("source", {}).get("manufacturer")
            if not (
                isinstance(evidence, dict)
                and evidence.get("module") == "Cisco-IOS-XE-platform-oper"
                and evidence.get("path") == "/data/Cisco-IOS-XE-platform-oper:components"
                and evidence.get("field") == "state/mfg-name"
                and _text(evidence.get("value")) == item["manufacturer"]
                and _text(evidence.get("component")) is not None
            ):
                error(
                    "Component %s requires one existing Manufacturer %s or reviewed source evidence"
                    % (item["key"], item["manufacturer"])
                )
                return None
        candidates = [
            row
            for row in types
            if manufacturer_id is not None and _id(row["manufacturer_id"]) == manufacturer_id
        ]
        by_model = [row for row in candidates if _text(row["model"]) == item["model"]]
        by_part = [
            row for row in candidates if _text(row.get("part_number")) == item["part_number"]
        ]
        choices = {_id(row["id"]): row for row in by_model + by_part}
        if len(by_model) > 1 or len(by_part) > 1 or len(choices) > 1:
            error("Component %s has ambiguous ModuleType model/PID matches" % item["key"])
            return None
        selected = next(iter(choices.values()), None)
        changes = []
        if selected:
            before = selected.get("part_number")
            if _blank(before):
                changes.append(
                    {"field": "part_number", "before": before, "after": item["part_number"]}
                )
            elif _text(before) != item["part_number"]:
                conflict(
                    "module_type",
                    item["key"],
                    "part_number",
                    before,
                    item["part_number"],
                    "Populated catalog identity differs",
                )
                return None
        model = selected["model"] if selected else item["model"]
        return {
            "key": "%s:%s" % (manufacturer_id, model)
            if manufacturer_id is not None
            else json.dumps([manufacturer_key, model]),
            "id": _id(selected["id"]) if selected else None,
            "manufacturer_id": manufacturer_id,
            "manufacturer_key": manufacturer_key,
            "model": model,
            "part_number": item["part_number"],
            "create": selected is None,
            "changes": changes,
        }

    pending = sorted(items)
    while pending:
        progressed = False
        for key in list(pending):
            item = items[key]
            parent_key = item["parent_key"]
            if key in invalid_keys:
                unresolved(item, "Ambiguous or invalid component evidence")
                pending.remove(key)
                progressed = True
                continue
            if parent_key in pending:
                continue
            pending.remove(key)
            progressed = True
            if parent_key is not None and parent_key not in planned_modules:
                unresolved(item, "Parent module could not be reconciled")
                continue
            module_type = resolve_type(item)
            if module_type is None:
                unresolved(item, "ModuleType identity could not be reconciled")
                continue
            parent_id = planned_modules[parent_key]["id"] if parent_key else None
            existing_bays = [
                row
                for row in bays
                if _text(row["name"]) == item["bay"]["name"]
                and (
                    parent_key is None
                    and row.get("parent_module_id") is None
                    and _id(row.get("parent_device_id")) == device_id
                    or parent_key is not None
                    and parent_id is not None
                    and _id(row.get("parent_module_id")) == parent_id
                )
            ]
            if len(existing_bays) > 1:
                error("Component %s has ambiguous existing physical bays" % key)
                unresolved(item, "Several existing bays have the same parent and name")
                continue
            bay = existing_bays[0] if existing_bays else None
            bay_id = _id(bay["id"]) if bay else None
            occupants = modules_by_bay[bay_id] if bay_id else []
            identities = [
                row
                for row in modules
                if module_type["id"] is not None
                and _id(row["module_type_id"]) == module_type["id"]
                and _text(row.get("serial")) == item["serial"]
            ]
            if len(occupants) > 1 or len(identities) > 1:
                error("Component %s has ambiguous existing serialized module records" % key)
                unresolved(item, "Several existing modules match placement or identity")
                continue
            occupant = occupants[0] if occupants else None
            match = identities[0] if identities else None
            if occupant and _id(occupant["module_type_id"]) != module_type["id"]:
                conflict(
                    "module",
                    key,
                    "module_type",
                    _id(occupant["module_type_id"]),
                    module_type["key"],
                    "Replacement requires review",
                )
                unresolved(item, "The physical bay already contains a different module type")
                continue
            if (
                occupant
                and not _blank(occupant.get("serial"))
                and _text(occupant["serial"]) != item["serial"]
            ):
                conflict(
                    "module",
                    key,
                    "serial",
                    occupant["serial"],
                    item["serial"],
                    "Replacement requires review",
                )
                unresolved(item, "The physical bay already contains a different serialized module")
                continue
            if match and (occupant is None or _id(match["id"]) != _id(occupant["id"])):
                conflict(
                    "module",
                    key,
                    "parent_module_bay",
                    _id(match.get("parent_module_bay_id")),
                    bay_id or key,
                    "Existing serialized module relocation requires review",
                )
                unresolved(item, "The serialized module is already recorded in another placement")
                continue

            bay_changes = []
            for field in ("position", "label"):
                after = _text(item["bay"].get(field))
                before = bay.get(field) if bay else None
                if bay and after is not None:
                    if _blank(before):
                        bay_changes.append({"field": field, "before": before, "after": after})
                    elif _text(before) != after:
                        conflict(
                            "module_bay",
                            key,
                            field,
                            before,
                            after,
                            "Preserving populated bay metadata",
                        )
            module = {
                "key": key,
                "id": _id(occupant["id"]) if occupant else None,
                "module_type_key": module_type["key"],
                "bay_key": key,
                "serial": item["serial"],
                "create": occupant is None,
                "changes": [],
            }
            if occupant and _blank(occupant.get("serial")):
                module["changes"].append(
                    {"field": "serial", "before": occupant.get("serial"), "after": item["serial"]}
                )
            if module["id"] is not None:
                seen_module_ids.add(module["id"])
            if module_type["key"] not in planned_types:
                planned_types[module_type["key"]] = module_type
                plan["module_types"].append(module_type)
            if module_type["manufacturer_id"] is None:
                manufacturer_key = module_type["manufacturer_key"]
                if manufacturer_key not in planned_manufacturers:
                    manufacturer = {
                        "key": manufacturer_key,
                        "name": item["manufacturer"],
                        "source": item["source"]["manufacturer"],
                    }
                    planned_manufacturers[manufacturer_key] = manufacturer
                    plan["manufacturers"].append(manufacturer)
            plan["bays"].append(
                {
                    "key": key,
                    "id": bay_id,
                    "parent_key": parent_key,
                    "name": bay["name"] if bay else item["bay"]["name"],
                    "position": _text(item["bay"].get("position")) or "",
                    "label": _text(item["bay"].get("label")) or "",
                    "create": bay is None,
                    "changes": bay_changes,
                }
            )
            plan["modules"].append(module)
            planned_modules[key] = module
            for name in sorted(item["interfaces"]):
                matches = interfaces[name]
                if len(matches) > 1:
                    error("Component %s has ambiguous existing interface %s" % (key, name))
                    continue
                interface = matches[0] if matches else None
                if interface is None and name not in planned_interfaces:
                    plan["warnings"].append(
                        "Component %s: interface %s is neither existing nor planned" % (key, name)
                    )
                    continue
                interface_type = (
                    interface.get("type") if interface else planned_interfaces[name].get("type")
                )
                if interface_type in {"virtual", "bridge", "lag", "tunnel"}:
                    plan["warnings"].append(
                        "Component %s: preserving logical interface %s without module ownership"
                        % (key, name)
                    )
                    continue
                before = _id(interface.get("module_id")) if interface else None
                if before is not None:
                    if before != module["id"]:
                        conflict(
                            "interface",
                            interface["name"],
                            "module",
                            before,
                            module["id"] or key,
                            "Preserving populated interface ownership",
                        )
                    continue
                plan["interface_assignments"].append(
                    {
                        "id": _id(interface["id"]) if interface else None,
                        "name": interface["name"] if interface else name,
                        "module_key": key,
                        "module_id": module["id"],
                    }
                )
        if not progressed:
            error("Serialized component parents cannot be resolved")
            break

    target_bay_ids = {
        _id(row["id"]) for row in bays if _id(row.get("parent_device_id")) == device_id
    }
    plan["missing_modules"] = [
        {
            "id": _id(row["id"]),
            "serial": row.get("serial"),
            "module_type_id": _id(row["module_type_id"]),
            "parent_module_bay_id": _id(row.get("parent_module_bay_id")),
        }
        for row in sorted(modules, key=lambda row: _id(row["id"]))
        if _id(row["id"]) not in seen_module_ids
        and (
            _id(row.get("device_id")) == device_id
            or _id(row.get("parent_module_bay_id")) in target_bay_ids
        )
    ]
    return _finish(plan)
