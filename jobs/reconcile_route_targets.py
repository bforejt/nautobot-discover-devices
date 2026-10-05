"""Pure, conservative projection of explicit VRF route targets into native fields."""

import re
from collections import defaultdict
from ipaddress import IPv4Address


def canonical_route_target(value):
    """Normalize reviewed RFC 4360/5668 literals without inferring an auto value.

    ASDOT with a nonzero high component identifies the four-octet ASN form.
    ASDOT 0.x is deferred because converting it could erase the wire encoding
    distinction between two-octet and four-octet AS extended communities.
    """
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("Route target must be an explicit ASN:number or IPv4:number literal")
    administrator, assigned = value.strip().split(":")
    if not re.fullmatch(r"[0-9]+", assigned):
        raise ValueError("Route target local administrator must be an unsigned decimal integer")
    suffix = int(assigned)
    if re.fullmatch(r"[0-9]+", administrator):
        asn = int(administrator)
        if not 1 <= asn <= 4294967295:
            raise ValueError("Route target ASN is outside the reviewed range")
        maximum = 4294967295 if asn <= 65535 else 65535
        administrator = str(asn)
    elif re.fullmatch(r"[0-9]+\.[0-9]+", administrator):
        high, low = (int(part) for part in administrator.split("."))
        if not 1 <= high <= 65535 or not 0 <= low <= 65535:
            raise ValueError("Route target ASDOT encoding is unsupported or outside its range")
        administrator = str((high << 16) + low)
        maximum = 65535
    else:
        try:
            address = IPv4Address(administrator)
        except ValueError as exc:
            raise ValueError("Route target global administrator is unsupported") from exc
        if address.is_multicast or address.is_unspecified or int(address) == 4294967295:
            raise ValueError("Route target IPv4 administrator must be unicast")
        administrator = str(address)
        maximum = 65535
    if suffix > maximum:
        raise ValueError("Route target local administrator exceeds its encoded width")
    return "%s:%s" % (administrator, suffix)


def _id(value):
    return str(value) if value is not None else None


def route_target_adoption_reason(observation, vrf, catalog):
    """Prevent a new Device assignment from inheriting unconfirmed shared policy.

    Existing assignments retain their routing identity and report differences.
    A new assignment must confirm every populated canonical target direction
    before it can adopt that VRF; otherwise its interfaces would implicitly
    inherit a policy that the Device did not report.
    """
    directions = {
        direction: vrf.get("%s_target_ids" % direction, []) for direction in ("import", "export")
    }
    if not any(directions.values()):
        return None
    facts = observation.get("route_targets")
    if (
        not isinstance(facts, dict)
        or facts.get("status") != "available"
        or not isinstance(facts.get("source"), dict)
        or facts["source"].get("complete") is not True
        or not isinstance(catalog, list)
    ):
        return "New Device assignment would inherit unconfirmed canonical VRF route targets"
    targets = {_id(row.get("id")): row.get("name") for row in catalog if isinstance(row, dict)}
    for direction, target_ids in directions.items():
        if not isinstance(target_ids, list) or not isinstance(facts.get(direction), list):
            return "Canonical VRF target policy lacks complete structured evidence"
        if not target_ids:
            continue
        try:
            before = {canonical_route_target(targets[_id(value)]) for value in target_ids}
            observed = {canonical_route_target(value) for value in facts[direction]}
        except (KeyError, TypeError, ValueError):
            return "Canonical VRF target policy cannot be compared without guessing"
        if before != observed:
            return "New Device assignment would inherit conflicting canonical VRF route targets"
    return None


def _finish(plan):
    plan["summary"] = {
        "route_targets_created": sum(row["create"] for row in plan["route_targets"]),
        "vrf_import_targets_added": sum(
            len(row["add_target_keys"])
            for row in plan["vrf_route_targets"]
            if row["direction"] == "import"
        ),
        "vrf_export_targets_added": sum(
            len(row["add_target_keys"])
            for row in plan["vrf_route_targets"]
            if row["direction"] == "export"
        ),
        "unresolved_route_targets": len(plan["unresolved"]),
    }
    return plan


def plan_route_targets(discovery, existing, ipam_plan):
    """Fill empty directions on resolved non-management VRFs; preserve filled sets.

    VRF identity comes exclusively from the existing IPAM planner. Route target
    values never establish that two devices share a VRF. A blank shared VRF
    direction cannot be populated from one device when other devices or VMs
    already use that VRF, because their route policies have not been observed.
    """
    plan = {
        "route_targets": [],
        "vrf_route_targets": [],
        "errors": [],
        "warnings": [],
        "conflicts": [],
        "unresolved": [],
        "sources": [],
    }
    source = discovery.get("ipam")
    inventory = existing.get("ipam_inventory", {})
    if not isinstance(source, dict) or not isinstance(source.get("vrfs"), list):
        return _finish(plan)
    observations = [
        row for row in source["vrfs"] if isinstance(row, dict) and "route_targets" in row
    ]
    if not observations:
        return _finish(plan)
    catalog = inventory.get("route_targets")
    vrf_rows = {_id(row.get("id")): row for row in inventory.get("vrfs", [])}
    resolved = defaultdict(list)
    for row in ipam_plan.get("vrf_device_assignments", []):
        resolved[row.get("name")].append(row)
    planned_vrfs = {row["key"]: row for row in ipam_plan.get("vrfs", [])}
    existing_targets, targets_by_id = defaultdict(list), {}
    snapshot_valid = isinstance(catalog, list)
    if snapshot_valid:
        for row in catalog:
            if (
                not isinstance(row, dict)
                or not row.get("id")
                or not isinstance(row.get("name"), str)
            ):
                snapshot_valid = False
                break
            targets_by_id[_id(row["id"])] = row
            try:
                name = canonical_route_target(row["name"])
            except ValueError:
                continue  # An unrelated operator-owned target is preserved.
            existing_targets[name].append(row)
    target_specs, direction_requests = {}, defaultdict(list)

    def unresolved(name, reason, **extra):
        plan["unresolved"].append(
            {"scope": "vrf_route_targets", "name": name, "reason": reason, **extra}
        )

    for observation in observations:
        name = observation.get("name")
        if name == "Mgmt-vrf":
            continue
        facts = observation["route_targets"]
        if not isinstance(facts, dict) or facts.get("status") != "available":
            reason = facts.get("reason") if isinstance(facts, dict) else None
            unresolved(name, reason or "Complete explicit route target policy is unavailable")
            continue
        if (
            not isinstance(facts.get("source"), dict)
            or facts["source"].get("complete") is not True
            or any(not isinstance(facts.get(direction), list) for direction in ("import", "export"))
        ):
            unresolved(name, "Route target policy lacks complete structured source evidence")
            continue
        try:
            values = {
                direction: sorted({canonical_route_target(value) for value in facts[direction]})
                for direction in ("import", "export")
            }
        except (TypeError, ValueError) as exc:
            unresolved(name, "Unsupported route target literal: %s" % exc)
            continue
        if len(resolved[name]) != 1 or resolved[name][0].get("vrf_key") not in planned_vrfs:
            unresolved(name, "Device-local VRF identity is unresolved")
            continue
        assignment = resolved[name][0]
        vrf = planned_vrfs[assignment["vrf_key"]]
        if _id(assignment.get("device_id")) != _id(inventory.get("device", {}).get("id")):
            unresolved(name, "Resolved VRF assignment belongs to a different Device")
            continue
        if not snapshot_valid:
            unresolved(name, "Complete native route target catalog is unavailable")
            continue
        current = vrf_rows.get(_id(vrf.get("id"))) if not vrf["create"] else None
        if not vrf["create"] and (
            current is None or _id(current.get("namespace_id")) != _id(vrf.get("namespace_id"))
        ):
            unresolved(name, "Native VRF identity or Namespace does not match the resolved plan")
            continue
        for direction in ("import", "export"):
            direction_requests[(vrf["key"], direction)].append(
                {
                    "name": name,
                    "values": values[direction],
                    "source": facts["source"],
                    "vrf": vrf,
                    "current": current,
                }
            )

    for (vrf_key, direction), requests in sorted(direction_requests.items()):
        observed_sets = {tuple(request["values"]) for request in requests}
        names = sorted({request["name"] for request in requests})
        if len(observed_sets) != 1:
            for name in names:
                unresolved(
                    name,
                    "Several local VRFs resolve to one native VRF with different target policies",
                    direction=direction,
                )
            continue
        request = requests[0]
        values, vrf, current = request["values"], request["vrf"], request["current"]
        field = "%s_target_ids" % direction
        before = [] if current is None else current.get(field)
        if not isinstance(before, list) or any(_id(value) not in targets_by_id for value in before):
            unresolved(
                request["name"],
                "Complete native VRF target direction snapshot is unavailable",
                direction=direction,
            )
            continue
        try:
            before_values = sorted(
                {canonical_route_target(targets_by_id[_id(value)]["name"]) for value in before}
            )
        except ValueError:
            before_values = None
        if before:
            if before_values != values:
                plan["conflicts"].append(
                    {
                        "scope": "vrf_route_targets",
                        "name": request["name"],
                        "field": "%s_targets" % direction,
                        "before": sorted(targets_by_id[_id(value)]["name"] for value in before),
                        "observed": values,
                        "reason": "Preserve the complete populated native VRF target direction",
                    }
                )
            continue
        if not values:
            continue
        other_assignments = [
            row
            for row in inventory.get("vrf_device_assignments", [])
            if _id(row.get("vrf_id")) == _id(vrf.get("id"))
            and not vrf["create"]
            and (
                row.get("virtual_machine_id")
                or row.get("virtual_device_context_id")
                or _id(row.get("device_id")) != _id(inventory.get("device", {}).get("id"))
            )
        ]
        if other_assignments:
            unresolved(
                request["name"],
                "Other endpoints share this VRF; one Device cannot establish "
                "its complete empty target direction",
                direction=direction,
            )
            continue
        if any(len(existing_targets[value]) > 1 for value in values):
            unresolved(
                request["name"],
                "Several native route targets have the same normalized literal",
                direction=direction,
            )
            continue
        keys = []
        for value in values:
            key = "route-target:%s" % value
            row = existing_targets[value][0] if existing_targets[value] else None
            target_specs[key] = {
                "key": key,
                "id": _id(row["id"]) if row else None,
                "create": row is None,
                "name": row["name"] if row else value,
                "literal": value,
            }
            keys.append(key)
        plan["vrf_route_targets"].append(
            {
                "vrf_key": vrf_key,
                "vrf_id": _id(vrf.get("id")),
                "namespace_id": _id(vrf["namespace_id"]),
                "local_name": request["name"],
                "direction": direction,
                "add_target_keys": keys,
                "before_target_ids": [],
                "source": request["source"],
            }
        )
        plan["sources"].append(request["source"])
    plan["route_targets"] = [target_specs[key] for key in sorted(target_specs)]
    return _finish(plan)
