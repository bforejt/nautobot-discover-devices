"""Fill-only native planning for reviewed PAN logical interfaces and relations."""

from copy import deepcopy

from .adapters.panos_logical import CONTRACT, validate_logical_interfaces

FIELDS = (
    "type",
    "enabled",
    "description",
    "mtu",
    "mac_address",
    "speed",
    "duplex",
    "port_type",
    "mgmt_only",
)


def _blank(value):
    return value is None or isinstance(value, str) and not value.strip()


def plan_panos_interfaces(discovery, existing, interface_plan=None, *, identity_verified=False):
    """Return ordinary interface candidates plus a separate relationship plan.

    ``interface_plan`` may contain the base planner's prospective creates/updates;
    this lets direct parent and aggregation references resolve without premature
    database writes. Existing populated values and ownership always win.
    """
    plan = {
        "contract": CONTRACT,
        "creates": [],
        "updates": [],
        "parents": [],
        "lag_assignments": [],
        "unresolved": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "summary": {
            "logical_interfaces_created": 0,
            "logical_interfaces_updated": 0,
            "interface_parents_assigned": 0,
            "panos_lag_assignments": 0,
            "unresolved_logical_interfaces": 0,
        },
    }
    if discovery.get("adapter") != "panos" or "logical_interfaces" not in discovery:
        return plan
    facts = discovery["logical_interfaces"]
    if not validate_logical_interfaces(facts):
        plan["errors"].append("PAN-OS logical interface source provenance is invalid")
        return plan
    plan["unresolved"] = deepcopy(facts["unresolved"])
    native = existing.get("panos_interface_inventory", {})
    capabilities = native.get("capabilities", {})
    relations = {row["name"]: row for row in native.get("interfaces", [])}
    rows = existing.get("interfaces", [])
    by_name = {}
    for row in rows:
        if row.get("name") in by_name:
            plan["errors"].append("Selected Device has ambiguous logical interface names")
            return plan
        by_name[row.get("name")] = deepcopy(row)
    interface_plan = interface_plan or {}
    base_creates = interface_plan.get("interface_creates", interface_plan.get("creates", []))
    base_updates = interface_plan.get("interface_updates", interface_plan.get("updates", []))
    for row in base_creates:
        if row["name"] in by_name:
            plan["errors"].append("Prospective interface name already exists")
            return plan
        by_name[row["name"]] = {
            **deepcopy(row),
            "device_id": existing.get("device", {}).get("id"),
            "id": None,
        }
    for row in base_updates:
        if row["name"] in by_name:
            for change in row["changes"]:
                by_name[row["name"]][change["field"]] = change["after"]
    device_id = existing.get("device", {}).get("id")

    def unresolved(name, reason, **extra):
        plan["unresolved"].append({"name": name, "reason": reason, **extra})

    pending_parents = []
    for fact in facts["interfaces"]:
        name, expected_type = fact["name"], fact["type"]
        reason = None
        if identity_verified is not True:
            reason = "Validated selected PAN-OS Device identity is required"
        elif native.get("supported") is not True:
            reason = "Native PAN logical-interface capabilities are unavailable"
        elif expected_type not in capabilities.get("types", []):
            reason = "Reviewed logical interface type is unavailable in this Nautobot release"
        elif fact["enabled"] is None:
            reason = "Logical administrative semantics are unreviewed"
        if reason:
            unresolved(name, reason, source=deepcopy(fact["source"]))
            continue
        before = by_name.get(name)
        if before is None:
            create = {field: None for field in FIELDS}
            create.update(
                name=name,
                type=expected_type,
                enabled=fact["enabled"],
                description=fact["description"],
                mtu=fact["mtu"],
                type_source="Applied PAN-OS " + fact["kind"] + " schema",
                source=deepcopy(fact["source"]),
            )
            unsupported = set(existing.get("unsupported_interface_fields", []))
            for field in unsupported:
                if field in create:
                    create[field] = None
            if create["type"] is None or type(create["enabled"]) is not bool:
                unresolved(name, "Native type and administrative fields are required")
                continue
            plan["creates"].append(create)
            before = {**deepcopy(create), "id": None, "device_id": device_id, "module_id": None}
            by_name[name] = before
        else:
            if before.get("device_id") != device_id or before.get("module_id") is not None:
                unresolved(name, "Interface is not directly owned by the selected Device")
                continue
            if before.get("type") != expected_type:
                plan["conflicts"].append(
                    {
                        "scope": "interface",
                        "name": name,
                        "field": "type",
                        "before": before.get("type"),
                        "after": expected_type,
                    }
                )
                unresolved(name, "Populated interface type conflicts with reviewed logical kind")
                continue
            changes = []
            for field in ("enabled", "description", "mtu"):
                after = fact[field]
                if after is None or field in existing.get("unsupported_interface_fields", []):
                    continue
                if _blank(before.get(field)):
                    changes.append(
                        {
                            "field": field,
                            "before": before.get(field),
                            "after": after,
                            "source": deepcopy(fact["source"]),
                        }
                    )
                    before[field] = after
                elif type(before.get(field)) is not type(after) or before[field] != after:
                    plan["conflicts"].append(
                        {
                            "scope": "interface",
                            "name": name,
                            "field": field,
                            "before": before[field],
                            "after": after,
                        }
                    )
            if changes:
                if before.get("id") is None:
                    unresolved(name, "Logical fields overlap another prospective create")
                else:
                    plan["updates"].append({"id": before["id"], "name": name, "changes": changes})
        if fact["parent_name"] is not None:
            pending_parents.append(fact)
    for fact in pending_parents:
        name, parent_name = fact["name"], fact["parent_name"]
        parent = by_name.get(parent_name)
        before = relations.get(name, {}).get("parent_interface_id")
        before_name = relations.get(name, {}).get("parent_interface_name")
        if capabilities.get("parent_interface") is not True:
            unresolved(
                name, "Native parent-interface field is unavailable", parent_name=parent_name
            )
        elif (
            parent is None
            or parent.get("device_id") != device_id
            or parent.get("module_id") is not None
        ):
            unresolved(
                name,
                "Direct configured parent is not available on the selected Device",
                parent_name=parent_name,
            )
        elif before is not None:
            if before_name != parent_name:
                plan["conflicts"].append(
                    {
                        "scope": "interface",
                        "name": name,
                        "field": "parent_interface",
                        "before": before_name,
                        "after": parent_name,
                    }
                )
        else:
            plan["parents"].append(
                {
                    "name": name,
                    "parent_name": parent_name,
                    "before_id": None,
                    "source": deepcopy(fact["source"]),
                }
            )
    for membership in facts["memberships"]:
        name, lag_name = membership["name"], membership["lag_name"]
        member, lag = by_name.get(name), by_name.get(lag_name)
        if (
            identity_verified is not True
            or native.get("supported") is not True
            or capabilities.get("lag") is not True
        ):
            unresolved(
                name,
                "Native aggregation relationship capability or identity is unavailable",
                lag_name=lag_name,
            )
        elif member is None or lag is None:
            unresolved(name, "Configured aggregation endpoint is unavailable", lag_name=lag_name)
        elif any(
            row.get("device_id") != device_id or row.get("module_id") is not None
            for row in (member, lag)
        ):
            unresolved(
                name,
                "Aggregation endpoints must be directly owned by the selected Device",
                lag_name=lag_name,
            )
        elif lag.get("type") != "lag" or member.get("type") in {
            None,
            "",
            "virtual",
            "lag",
            "tunnel",
            "bridge",
        }:
            unresolved(
                name,
                "Native aggregation requires a physical member; virtual vNICs retain their type",
                lag_name=lag_name,
            )
        elif relations.get(name, {}).get("lag_id") is not None:
            if relations[name].get("lag_name") != lag_name:
                plan["conflicts"].append(
                    {
                        "scope": "interface",
                        "name": name,
                        "field": "lag",
                        "before": relations[name].get("lag_name"),
                        "after": lag_name,
                    }
                )
        else:
            plan["lag_assignments"].append(
                {
                    "name": name,
                    "lag_name": lag_name,
                    "before_id": None,
                    "source": deepcopy(membership["source"]),
                }
            )
    plan["summary"].update(
        logical_interfaces_created=len(plan["creates"]),
        logical_interfaces_updated=len(plan["updates"]),
        interface_parents_assigned=len(plan["parents"]),
        panos_lag_assignments=len(plan["lag_assignments"]),
        unresolved_logical_interfaces=len(plan["unresolved"]),
    )
    return plan
