"""Pure, fill-only reconciliation of serialized modules and physical bays."""

import json
from collections import defaultdict
from decimal import Decimal, InvalidOperation

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
        "power_ports_created": sum(row["create"] for row in plan["power_ports"]),
        "power_ports_updated": sum(bool(row["changes"]) for row in plan["power_ports"]),
        "power_ports_inferred": sum(
            bool(row.get("inference"))
            and (
                row["create"] or any(change["field"] == "power_factor" for change in row["changes"])
            )
            for row in plan["power_ports"]
        ),
        "unresolved_components": len(plan["unresolved"]),
    }
    return plan


def plan_components(discovery, existing, interface_plan=None, stack_plan=None):
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
        "power_ports": [],
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
    for field in ("items", "physical_bays", "unresolved", "excluded"):
        if not isinstance(source.get(field, []), list):
            plan["errors"].append("Component %s must be a structured list" % field)
    if plan["errors"]:
        return _finish(plan)
    plan["unresolved"] = list(source.get("unresolved", []))
    plan["excluded"] = list(source.get("excluded", []))
    if source.get("writes_deferred_reason") is not None:
        if (
            not _text(source["writes_deferred_reason"])
            or source["items"]
            or source.get("physical_bays")
        ):
            plan["errors"].append("Deferred component placement cannot include resolved items")
        # No placement inventory was collected. Do not claim that existing
        # modules disappeared merely because their ownership remains unresolved.
        return _finish(plan)
    catalog = existing.get("components", {})
    if not catalog.get("supported", False):
        if source.get("items") or source.get("physical_bays"):
            plan["warnings"].append("This Nautobot inventory does not support module discovery")
            plan["unresolved"].extend(
                {"key": item.get("key"), "reason": "Module inventory is unavailable"}
                for item in source["items"] + source.get("physical_bays", [])
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

    if stack_plan is not None and not isinstance(stack_plan, dict):
        error("Component ownership requires a structured stack plan")
        return _finish(plan)
    identity = discovery.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    stack_source = discovery.get("stack")
    stack_source = stack_source if isinstance(stack_source, dict) else {}
    device_id = _id(existing["device"]["id"])
    selected_serial = _text(existing["device"].get("serial"))
    if selected_serial is None:
        selected_serial = _text((stack_plan or {}).get("identity", {}).get("serial")) or _text(
            identity.get("serial")
        )
    selected_owner = {
        "device_id": device_id,
        "device_serial": selected_serial,
        "member_position": None,
    }
    single_members = stack_source.get("members", [])
    if (
        isinstance(single_members, list)
        and len(single_members) == 1
        and stack_source.get("is_stack") is False
    ):
        single = single_members[0]
        if (
            isinstance(single, dict)
            and _text(single.get("serial")) == selected_serial
            and type(single.get("position")) is int
            and 1 <= single["position"] <= 255
        ):
            selected_owner["member_position"] = single["position"]
    owners = {selected_serial: selected_owner} if selected_serial else {}
    owner_models = {
        selected_serial: _text(existing["device"].get("model")) or _text(identity.get("model"))
    }
    members = (stack_plan or {}).get("members", [])
    if not isinstance(members, list):
        error("Component ownership requires a structured stack member list")
        return _finish(plan)
    if members and (stack_plan or {}).get("errors"):
        error("Component ownership requires a validated stack plan")
        return _finish(plan)
    positions, ids, member_serials = set(), set(), set()
    for member in members:
        serial = _text(member.get("serial")) if isinstance(member, dict) else None
        position = member.get("position") if isinstance(member, dict) else None
        member_id = _id(member.get("existing_id")) if isinstance(member, dict) else None
        if (
            serial is None
            or type(position) is not int
            or not 1 <= position <= 255
            or type(member.get("create")) is not bool
            or (member["create"] == (member_id is not None))
            or position in positions
            or serial in member_serials
            or serial in owners
            and owners[serial]["device_id"] != member_id
            or member_id is not None
            and member_id in ids
        ):
            error("Component ownership has invalid or ambiguous stack members")
            continue
        positions.add(position)
        member_serials.add(serial)
        if member_id:
            ids.add(member_id)
        owners[serial] = {
            "device_id": member_id,
            "device_serial": serial,
            "member_position": position,
        }
        owner_models[serial] = _text(member.get("model"))
        if member_id == device_id:
            selected_owner = owners[serial]
    if plan["errors"]:
        return _finish(plan)

    def owner_for(raw, inherited=None):
        serial = raw.get("device_serial")
        member = raw.get("member")
        if serial is None:
            if member is not None:
                error("Component %s requires a chassis serial for member placement" % raw["key"])
                return None
            return inherited or selected_owner
        if _text(serial) != serial or serial not in owners:
            error("Component %s has an unresolved chassis owner" % raw["key"])
            return None
        owner = owners[serial]
        if member is not None and (
            type(member) is not int
            or not 1 <= member <= 255
            or owner["member_position"] is not None
            and member != owner["member_position"]
        ):
            error("Component %s disagrees with validated member placement" % raw["key"])
            return None
        if inherited and owner["device_serial"] != inherited["device_serial"]:
            error("Component %s and its parent belong to different chassis" % raw["key"])
            return None
        return owner

    items = {}
    invalid_keys = set()
    asset_claims = defaultdict(list)
    bay_claims = defaultdict(list)
    interface_claims = defaultdict(list)
    type_claims = defaultdict(list)
    pid_claims = defaultdict(list)

    def valid_power_port(raw):
        if not isinstance(raw, dict) or _text(raw.get("name")) is None:
            return False
        if raw.get("type") is not None and _text(raw["type"]) != raw["type"]:
            return False
        if not isinstance(raw.get("source", {}), dict):
            return False
        inference = raw.get("inference") or raw.get("source", {}).get("inference")
        if inference is not None and (not isinstance(inference, dict) or not inference):
            return False
        for field in ("maximum_draw", "allocated_draw"):
            if raw.get(field) is not None and (type(raw[field]) is not int or raw[field] < 0):
                return False
        if raw.get("power_factor") is not None:
            if type(raw["power_factor"]) not in (int, float, str):
                return False
            try:
                factor = Decimal(str(raw["power_factor"]))
            except InvalidOperation:
                return False
            if not factor.is_finite() or not 0 < factor <= 1 or factor.as_tuple().exponent < -2:
                return False
        return True

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
        power_ports = item.get("power_ports", [])
        if (
            not isinstance(bay, dict)
            or _text(bay.get("name")) is None
            or (parent is not None and _text(parent) is None)
            or not isinstance(names, list)
            or any(_text(name) is None for name in names)
            or not isinstance(item.get("source", {}), dict)
            or not isinstance(item.get("observations", {}), dict)
            or not isinstance(power_ports, list)
            or any(not valid_power_port(row) for row in power_ports)
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
        item["power_ports"] = power_ports
        port_names = [_text(port["name"]) for port in power_ports]
        if (
            len(port_names) != len(set(port_names))
            or power_ports
            and item["kind"] not in {"psu", "power-supply"}
        ):
            error("Component %s has duplicate or unsupported power inlet claims" % key)
            invalid_keys.add(key)
        item["owner"] = owner_for(item)
        if item["owner"] is None:
            invalid_keys.add(key)
        items[key] = item
        asset_key = (item["manufacturer"].casefold(), item["part_number"], item["serial"])
        asset_claims[asset_key].append(key)
        type_claims[(item["manufacturer"].casefold(), item["model"])].append(key)
        pid_claims[(item["manufacturer"].casefold(), item["part_number"])].append(key)
        for name in item["interfaces"]:
            interface_claims[name].append(key)

    for label, claims in (
        ("serialized identity", asset_claims),
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
        if key not in invalid_keys:
            root = item
            while root["parent_key"] is not None:
                root = items[root["parent_key"]]
            owner = root["owner"]
            if owner is not None:
                owner = owner_for(item, owner)
            if owner is None:
                invalid_keys.add(key)
            else:
                item["owner"] = owner
                owner_key = owner["device_serial"] or owner["device_id"]
                bay_claims[(owner_key, item["parent_key"], item["bay"]["name"])].append(key)
    for keys in bay_claims.values():
        if len(keys) > 1:
            error("Several discovered components claim the same physical bay: %s" % ", ".join(keys))
            invalid_keys.update(keys)

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
    planned_modules, planned_types, planned_manufacturers = {}, {}, {}
    planned_bays = {}
    seen_module_ids = set()

    def physical_bay(
        key,
        evidence,
        owner,
        parent_key=None,
        parent_id=None,
        *,
        include=True,
        position_identity=False,
    ):
        identity = (owner["device_serial"] or owner["device_id"], parent_key, evidence["name"])
        if identity in planned_bays:
            return planned_bays[identity]
        parent_bays = [
            row
            for row in bays
            if (
                parent_key is None
                and row.get("parent_module_id") is None
                and owner["device_id"] is not None
                and _id(row.get("parent_device_id")) == owner["device_id"]
                or parent_key is not None
                and parent_id is not None
                and _id(row.get("parent_module_id")) == parent_id
            )
        ]
        candidates = [row for row in parent_bays if _text(row["name"]) == evidence["name"]]
        position = _text(evidence.get("position"))
        positioned = (
            [
                row
                for row in parent_bays
                if position is not None and _text(row.get("position")) == position
            ]
            if position_identity
            else []
        )
        if (
            len(positioned) > 1
            or candidates
            and positioned
            and _id(candidates[0]["id"]) != _id(positioned[0]["id"])
        ):
            error("Component %s has ambiguous existing PSU bay positions" % key)
            return None
        if not candidates and len(positioned) == 1:
            candidates = positioned
            conflict(
                "module_bay",
                key,
                "name",
                positioned[0]["name"],
                evidence["name"],
                "Preserving operator bay name for the documented physical slot",
            )
        if len(candidates) > 1:
            error("Component %s has ambiguous existing physical bays" % key)
            return None
        bay = candidates[0] if candidates else None
        changes = []
        for field in ("position", "label"):
            after = _text(evidence.get(field))
            before = bay.get(field) if bay else None
            if bay and after is not None:
                if _blank(before):
                    changes.append({"field": field, "before": before, "after": after})
                elif _text(before) != after:
                    conflict(
                        "module_bay", key, field, before, after, "Preserving populated bay metadata"
                    )
        spec = {
            "key": key,
            "id": _id(bay["id"]) if bay else None,
            "parent_key": parent_key,
            "name": bay["name"] if bay else evidence["name"],
            "position": _text(evidence.get("position")) or "",
            "label": _text(evidence.get("label")) or "",
            "create": bay is None,
            "changes": changes,
            **owner,
        }
        if bay and bay.get("module_family_id") is not None:
            spec["module_family_id"] = _id(bay["module_family_id"])
        if include:
            planned_bays[identity] = spec
            plan["bays"].append(spec)
        return spec

    physical_keys, physical_claims, physical_positions = set(), set(), set()
    observed_bays = {}
    for raw in source.get("physical_bays", []):
        if not isinstance(raw, dict):
            error("Physical bay evidence must be structured objects")
            continue
        key, bay = _text(raw.get("key")), raw.get("bay")
        if (
            key is None
            or _text(raw.get("device_serial")) is None
            or type(raw.get("member")) is not int
            or not 1 <= raw["member"] <= 255
            or _text(raw.get("chassis_model")) is None
            or not isinstance(bay, dict)
            or _text(bay.get("name")) is None
            or any(
                bay.get(field) is not None and not isinstance(bay[field], str)
                for field in ("position", "label")
            )
            or not isinstance(raw.get("source"), dict)
            or not raw["source"]
            or not isinstance(raw.get("observations", {}), dict)
        ):
            error("Physical bay requires reviewed structured chassis and placement evidence")
            continue
        owner = owner_for(raw)
        if owner is None:
            unresolved(raw, "Physical bay chassis ownership could not be reconciled")
            continue
        if owner_models.get(owner["device_serial"]) not in (None, raw["chassis_model"]):
            error("Physical bay %s disagrees with its validated chassis model" % key)
            continue
        bay = {**bay, "name": _text(bay["name"])}
        identity = (owner["device_serial"] or owner["device_id"], bay["name"])
        position_identity = (identity[0], _text(bay.get("position")))
        if (
            key in physical_keys
            or identity in physical_claims
            or position_identity[1] is not None
            and position_identity in physical_positions
        ):
            error("Several physical bay observations claim the same key or placement")
            continue
        physical_keys.add(key)
        physical_claims.add(identity)
        if position_identity[1] is not None:
            physical_positions.add(position_identity)
        if key in items and (
            items[key]["parent_key"] is not None
            or items[key]["owner"] != owner
            or items[key]["bay"] != bay
        ):
            error("Physical bay %s disagrees with serialized component placement" % key)
            invalid_keys.add(key)
            continue
        spec = physical_bay(key, bay, owner, position_identity=True)
        if spec is None:
            unresolved(raw, "Physical bay placement could not be reconciled")
        elif spec["id"] is not None:
            observed_bays[spec["id"]] = raw.get("observations", {})

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

    def plan_power_ports(item, module, module_type):
        observed_ports = item["power_ports"]
        if not observed_ports:
            return
        module_ports = [
            row
            for row in catalog.get("power_ports", [])
            if module["id"] is not None and _id(row.get("module_id")) == module["id"]
        ]
        templates = next(
            (
                row.get("power_port_templates", [])
                for row in types
                if _id(row["id"]) == module_type["id"]
            ),
            [],
        )
        claimed_ids = set()
        for port in observed_ports:
            name = _text(port["name"])
            key = "%s:power:%s" % (item["key"], name)
            matches = [row for row in module_ports if _text(row.get("name")) == name]
            if not matches and len(observed_ports) == len(module_ports) == 1:
                matches = module_ports
            if len(matches) > 1:
                error("Component %s has ambiguous existing power inlets" % item["key"])
                unresolved({"key": key}, "Several module-owned power ports match the inlet")
                continue
            before = matches[0] if matches else None
            if before and _id(before["id"]) in claimed_ids:
                error("Several discovered inlets claim the same existing PowerPort")
                continue
            if before:
                claimed_ids.add(_id(before["id"]))
                if _id(before.get("device_id")) not in (None, item["owner"]["device_id"]):
                    error("Component %s has a power inlet on a different Device" % item["key"])
                    continue
            if before is None and module_ports:
                unresolved(
                    {"key": key}, "Existing module-owned power inlets cannot be uniquely matched"
                )
                continue
            if before is None and port.get("power_factor") is None:
                unresolved(
                    {"key": key},
                    "New PowerPort requires a power factor; "
                    "no documented value or enabled NtC default is available",
                )
                continue
            template = None
            if before is None and module["create"] and templates:
                candidates = [row for row in templates if _text(row.get("name")) == name]
                if not candidates and len(observed_ports) == len(templates) == 1:
                    candidates = templates
                if len(candidates) != 1:
                    unresolved(
                        {"key": key}, "ModuleType power inlet templates cannot be uniquely matched"
                    )
                    continue
                template = candidates[0]
                if not valid_power_port(template):
                    error(
                        "Component %s has an invalid ModuleType power inlet template" % item["key"]
                    )
                    continue
                if "{" in template["name"] or "}" in template["name"]:
                    unresolved(
                        {"key": key},
                        "ModuleType inlet name requires native template rendering; "
                        "preserving the template until its position mapping is reviewed",
                    )
                    continue
            fields, changes, incompatible = {}, [], False
            for field in ("type", "maximum_draw", "allocated_draw", "power_factor"):
                observed = port.get(field)
                prior = (before or template or {}).get(field)
                differs = prior != observed
                if field == "power_factor" and observed is not None and not _blank(prior):
                    differs = Decimal(str(prior)) != Decimal(str(observed))
                if observed is not None and not _blank(prior) and differs:
                    conflict(
                        "power_port",
                        key,
                        field,
                        prior,
                        observed,
                        "Preserving populated power inlet metadata",
                    )
                    if template is not None:
                        incompatible = True
                if before is not None:
                    if observed is not None and _blank(prior):
                        changes.append({"field": field, "before": prior, "after": observed})
                    fields[field] = prior
                else:
                    fields[field] = prior if not _blank(prior) else observed
            if incompatible:
                unresolved(
                    {"key": key},
                    "Documented inlet conflicts with existing ModuleType template values",
                )
                continue
            plan["power_ports"].append(
                {
                    "key": key,
                    "module_key": item["key"],
                    "module_id": module["id"],
                    "id": _id(before["id"]) if before else None,
                    "name": (before or template or {}).get("name") or name,
                    "create": before is None,
                    "changes": changes,
                    "source": port.get("source", {}),
                    "inference": port.get("inference") or port.get("source", {}).get("inference"),
                    **item["owner"],
                    **fields,
                }
            )

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
            bay = physical_bay(
                key,
                item["bay"],
                item["owner"],
                parent_key,
                parent_id,
                include=False,
                position_identity=item["kind"] in {"psu", "power-supply"},
            )
            if bay is None:
                unresolved(item, "Several existing bays have the same parent and name")
                continue
            bay_id = bay["id"]
            if bay.get("module_family_id") is not None:
                resolved_type = next(
                    (row for row in types if _id(row["id"]) == module_type["id"]), {}
                )
                if _id(resolved_type.get("module_family_id")) != bay["module_family_id"]:
                    error("Component %s is incompatible with the bay's ModuleFamily" % key)
                    unresolved(item, "ModuleType and physical bay family are incompatible")
                    continue
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

            module = {
                "key": key,
                "id": _id(occupant["id"]) if occupant else None,
                "module_type_key": module_type["key"],
                "bay_key": bay["key"],
                "serial": item["serial"],
                "create": occupant is None,
                "changes": [],
                **item["owner"],
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
            bay_identity = (
                item["owner"]["device_serial"] or item["owner"]["device_id"],
                parent_key,
                item["bay"]["name"],
            )
            if bay_identity not in planned_bays:
                planned_bays[bay_identity] = bay
                plan["bays"].append(bay)
            plan["modules"].append(module)
            planned_modules[key] = module
            plan_power_ports(item, module, module_type)
            for name in sorted(item["interfaces"]):
                matches = interfaces[name]
                if len(matches) > 1:
                    error("Component %s has ambiguous existing interface %s" % (key, name))
                    continue
                interface = matches[0] if matches else None
                interface_owner = _id(interface.get("device_id")) if interface else None
                if item["owner"]["device_id"] != (interface_owner or device_id):
                    plan["warnings"].append(
                        "Component %s: preserving interface %s on its existing Device" % (key, name)
                    )
                    continue
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

    target_device_ids = {owner["device_id"] for owner in owners.values() if owner["device_id"]}
    target_device_ids.add(device_id)
    target_bay_ids = {
        _id(row["id"]) for row in bays if _id(row.get("parent_device_id")) in target_device_ids
    }
    plan["missing_modules"] = [
        {
            "id": _id(row["id"]),
            "serial": row.get("serial"),
            "module_type_id": _id(row["module_type_id"]),
            "parent_module_bay_id": _id(row.get("parent_module_bay_id")),
            "reason": (
                "Bay is reported nonempty but source identity could not be reconciled; "
                "existing asset is preserved"
                if observed_bays.get(_id(row.get("parent_module_bay_id")), {}).get(
                    "reported_presence"
                )
                == "reported-nonempty"
                else "Physical bay was observed without a reconciled serialized identity; "
                "existing asset is preserved"
                if _id(row.get("parent_module_bay_id")) in observed_bays
                else "Existing asset was not identified by this discovery; it is preserved"
            ),
        }
        for row in sorted(modules, key=lambda row: _id(row["id"]))
        if _id(row["id"]) not in seen_module_ids
        and (
            _id(row.get("device_id")) in target_device_ids
            or _id(row.get("parent_module_bay_id")) in target_bay_ids
        )
    ]
    return _finish(plan)
