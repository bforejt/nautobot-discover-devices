"""Pure, namespace-scoped static addressing and routing-domain reconciliation."""

from collections import defaultdict
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Interface,
    collapse_addresses,
    ip_address,
    ip_network,
)

from .adapters.cisco_iosxe import canonical_interface_name
from .reconcile_route_targets import route_target_adoption_reason

RFC1918 = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
COLLECTIONS = (
    "vrfs",
    "vrf_device_assignments",
    "interface_vrfs",
    "prefixes",
    "ip_addresses",
    "ip_assignments",
)


def _id(value):
    return str(value) if value is not None else None


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _finish(plan):
    plan["summary"] = {
        "vrfs_created": sum(row["create"] for row in plan["vrfs"]),
        "vrf_device_assignments_created": sum(
            row["create"] for row in plan["vrf_device_assignments"]
        ),
        "vrf_device_assignments_updated": sum(
            bool(row["changes"]) for row in plan["vrf_device_assignments"]
        ),
        "interface_vrfs_updated": len(plan["interface_vrfs"]),
        "prefixes_created": sum(row["create"] for row in plan["prefixes"]),
        "prefix_vrf_associations_created": sum(
            len(row["add_vrf_keys"]) for row in plan["prefixes"]
        ),
        "ip_addresses_created": sum(row["create"] for row in plan["ip_addresses"]),
        "ip_assignments_created": sum(row["create"] for row in plan["ip_assignments"]),
        "unresolved_ipam": len(plan["unresolved"]),
    }
    return plan


def _network(row):
    return ip_network(row["prefix"], strict=True)


def _host(row):
    return ip_address(str(row["host"]).split("/", 1)[0])


def _range(row):
    return (
        int(ip_address(str(row["start_address"]).split("/", 1)[0])),
        int(ip_address(str(row["end_address"]).split("/", 1)[0])),
    )


def _range_version(row):
    return ip_address(str(row["start_address"]).split("/", 1)[0]).version


def _subnet_of(network, parent):
    return network.version == parent.version and network.subnet_of(parent)


def _overlap(start, end, network):
    return start <= int(network.broadcast_address) and end >= int(network.network_address)


def _namespace(network, policy, overrides):
    """Classify the complete connected prefix, never just its interface host."""
    default = policy["default_namespace"]
    override = policy.get("override_namespace")
    if override is None or _id(default["id"]) == _id(override["id"]):
        return default, "default", None
    intersections = [
        value for value in overrides if value.version == network.version and value.overlaps(network)
    ]
    if not intersections:
        return default, "default", None
    if not any(network.subnet_of(value) for value in intersections):
        return None, None, "Connected prefix crosses incompatible namespace policy boundaries"
    matched = (
        "RFC1918"
        if policy.get("override_rfc1918") and any(_subnet_of(network, value) for value in RFC1918)
        else "additional override network"
    )
    return override, matched, None


def _parse_ipv6(row, name, plan):
    """Resolve literal configured hosts only; generated and scoped addresses stay observations."""
    addresses, seen = [], set()
    addressing = row.get("addressing", {})
    for address in row.get("ipv6", []):
        try:
            if not isinstance(address, dict) or not _text(address.get("method")):
                raise ValueError("Missing structured IPv6 addressing method")
            reason = None
            scope = addressing.get("ipv6_vrf_scope")
            if scope in ("unresolved-legacy-vrf", "unresolved-inactive-vrf-family"):
                reason = _text(addressing.get("ipv6_vrf_reason")) or (
                    "Legacy single-protocol VRF forwarding does not establish "
                    "a compatible native IPv6 routing context"
                    if scope == "unresolved-legacy-vrf"
                    else "Complete named VRF definition does not enable the IPv6 address family"
                )
            elif address["method"] != "configured":
                reason = "Generated, named-prefix or link-local IPv6 is observation-only"
            elif any(type(address.get(flag)) is not bool for flag in ("eui_64", "anycast")):
                raise ValueError("Configured IPv6 address flags must be explicit booleans")
            elif address["eui_64"] or address["anycast"]:
                reason = (
                    "Generated or anycast IPv6 requires additional identity or sharing evidence"
                )
            else:
                value = address.get("configured_prefix")
                if not isinstance(value, str) or "/" not in value or "%" in value:
                    raise ValueError("Missing literal IPv6 host and prefix length")
                configured = IPv6Interface(value)
                host = configured.ip
                if host.is_unspecified or host.is_multicast:
                    raise ValueError("Configured IPv6 address must be an ordinary unicast host")
                if host.is_link_local:
                    reason = "Link-local IPv6 requires interface-scoped identity"
                else:
                    if host in seen:
                        raise ValueError("Duplicate interface address")
                    seen.add(host)
                    addresses.append(
                        {
                            **address,
                            "host": str(host),
                            "prefix": str(configured.network),
                            "prefix_length": configured.network.prefixlen,
                            "secondary": False,
                            "secondary_known": False,
                        }
                    )
            if reason and not any(
                observation.get("name") == name and observation.get("ipv6") == address
                for observation in plan["unresolved"]
            ):
                plan["unresolved"].append(
                    {
                        "scope": "interface",
                        "name": name,
                        "reason": reason,
                        "ipv6": dict(address),
                        "source": row.get("source", {}),
                        **(
                            {"ipv6_routing": row["ipv6_routing"]} if row.get("ipv6_routing") else {}
                        ),
                    }
                )
        except (ValueError, TypeError) as exc:
            plan["errors"].append("Interface %s has invalid static IPv6 evidence: %s" % (name, exc))
    return addresses


def _parse_source(source, plan, canonical_name=canonical_interface_name):
    if (
        not isinstance(source, dict)
        or type(source.get("schema_version")) is not int
        or source["schema_version"] != 1
        or any(not isinstance(source.get(key), list) for key in ("interfaces", "vrfs"))
        or any(not isinstance(source.get(key, []), list) for key in ("unresolved", "sources"))
    ):
        plan["errors"].append("Unsupported structured IPAM discovery schema")
        return {}, {}
    if any(not isinstance(row, dict) for row in source.get("unresolved", [])):
        plan["errors"].append("Unresolved IPAM observations must be structured objects")
        return {}, {}
    if any(not isinstance(row, dict) for row in source.get("sources", [])):
        plan["errors"].append("IPAM sources must be structured objects")
        return {}, {}
    plan["unresolved"] = list(source.get("unresolved", []))
    plan["sources"] = list(source.get("sources", []))
    vrfs, facts = {}, {}
    for row in source["vrfs"]:
        if (
            not isinstance(row, dict)
            or not _text(row.get("name"))
            or row.get("rd") is not None
            and not _text(row["rd"])
            or not isinstance(row.get("source", {}), dict)
            or not isinstance(row.get("address_families", []), list)
            or any(not _text(value) for value in row.get("address_families", []))
        ):
            plan["errors"].append("Discovered VRFs require explicit names and structured evidence")
            continue
        name = row["name"].strip()
        if name in vrfs:
            plan["errors"].append("Several discovered VRFs use local name %s" % name)
        vrfs[name] = {**row, "name": name}
    for row in source["interfaces"]:
        if (
            not isinstance(row, dict)
            or not _text(row.get("name"))
            or row.get("vrf") is not None
            and not _text(row["vrf"])
            or not isinstance(row.get("ipv4"), list)
            or not isinstance(row.get("ipv6", []), list)
            or not isinstance(row.get("addressing", {}), dict)
            or not isinstance(row.get("ipv6_routing", {}), dict)
            or not isinstance(row.get("source", {}), dict)
        ):
            plan["errors"].append("IPAM interface observations require structured configuration")
            continue
        name = canonical_name(row["name"])
        if name in facts:
            plan["errors"].append("Several IPAM rows normalize to interface %s" % name)
        local_vrf = _text(row.get("vrf"))
        if local_vrf is not None and local_vrf not in vrfs:
            plan["errors"].append("Interface %s refers to an undiscovered named VRF" % name)
        addresses, seen = [], set()
        for address in row["ipv4"]:
            try:
                if (
                    not isinstance(address, dict)
                    or not isinstance(address.get("address"), str)
                    or not isinstance(address.get("mask"), str)
                    or type(address.get("prefix_length")) is not int
                    or type(address.get("secondary")) is not bool
                    or address.get("method") != "configured-static"
                ):
                    raise ValueError("Missing configured static address and mask")
                host = IPv4Address(address["address"])
                network = IPv4Network("%s/%s" % (host, address["mask"]), strict=False)
                if (
                    str(network.netmask) != address["mask"]
                    or network.prefixlen != address["prefix_length"]
                ):
                    raise ValueError("Inconsistent mask and prefix length")
                if host in seen:
                    raise ValueError("Duplicate interface address")
                seen.add(host)
                addresses.append({**address, "host": str(host), "prefix": str(network)})
            except (ValueError, TypeError) as exc:
                plan["errors"].append(
                    "Interface %s has invalid static IPv4 evidence: %s" % (name, exc)
                )
        facts[name] = {
            **row,
            "name": name,
            "vrf": local_vrf,
            "ipv4": addresses,
            "ipv6": _parse_ipv6(row, name, plan),
        }
    return facts, vrfs


def _explicit_routing_refs(targets, inventory, plan):
    """Bind operator-selected existing VRFs without local-name/RD inference."""
    catalog, references, assignments = {}, {}, {}
    for name, target in sorted(targets.items()):
        namespace = target.get("namespace") if isinstance(target, dict) else None
        vrf_target = target.get("vrf") if isinstance(target, dict) else None
        if (
            not isinstance(namespace, dict)
            or not namespace.get("id")
            or not isinstance(target, dict)
            or "vrf" not in target
        ):
            plan["errors"].append(
                "Explicit routing target requires a Namespace and VRF or global selection"
            )
            continue
        if vrf_target is None:
            references[name] = None
            continue
        if not isinstance(vrf_target, dict) or not vrf_target.get("id"):
            plan["errors"].append("Explicit routing target requires an existing VRF identity")
            continue
        matches = [row for row in inventory["vrfs"] if _id(row["id"]) == _id(vrf_target["id"])]
        if len(matches) != 1 or _id(matches[0]["namespace_id"]) != _id(namespace["id"]):
            plan["errors"].append("Explicit existing VRF identity or Namespace is invalid")
            continue
        vrf = matches[0]
        device_id, vrf_id = _id(inventory["device"]["id"]), _id(vrf["id"])
        bound = [
            row
            for row in inventory["vrf_device_assignments"]
            if _id(row.get("device_id")) == device_id and _id(row["vrf_id"]) == vrf_id
        ]
        if len(bound) > 1:
            plan["unresolved"].append(
                {
                    "scope": "interface",
                    "name": name,
                    "reason": (
                        "Several existing Device assignments match the explicitly selected VRF"
                    ),
                }
            )
            continue
        if bound and (
            bound[0].get("virtual_machine_id") is not None
            or bound[0].get("virtual_device_context_id") is not None
        ):
            plan["errors"].append("Explicit Device VRF assignment has unsupported ownership scope")
            continue
        key = "vrf-existing:%s" % vrf_id
        catalog[key] = {
            "key": key,
            "id": vrf_id,
            "create": False,
            "name": vrf["name"],
            "namespace_id": _id(vrf["namespace_id"]),
            "rd": vrf.get("rd"),
            "changes": [],
        }
        references[name] = key
        assignment = bound[0] if bound else None
        assignments[key] = {
            "key": "vrf-device-explicit:%s:%s" % (device_id, vrf_id),
            "id": _id(assignment["id"]) if assignment else None,
            "create": assignment is None,
            "vrf_key": key,
            "device_id": device_id,
            "name": assignment.get("name") if assignment else "",
            "rd": assignment.get("rd") if assignment else None,
            "changes": [],
        }
    plan["vrf_device_assignments"].extend(assignments.values())
    return catalog, references


def plan_ipam(
    discovery,
    existing,
    interface_plan=None,
    *,
    canonical_name=canonical_interface_name,
    routing_targets=None,
):
    """Build a dependency graph without importing models or mutating the snapshot.

    The namespace policy is organizational intent, never a transport default.
    Existing assignments establish device-local VRF identity before names are
    considered. New namespaces, dynamic addresses, primary device addresses,
    sharing assumptions and destructive changes are outside this planner.
    """
    plan = {
        "schema_version": 1,
        **{key: [] for key in COLLECTIONS},
        "errors": [],
        "warnings": [],
        "conflicts": [],
        "unresolved": [],
        "settings": [],
        "sources": [],
        "policy": None,
    }
    if discovery.get("ipam") is None:
        return _finish(plan)
    facts, observed_vrfs = _parse_source(discovery["ipam"], plan, canonical_name)
    if plan["errors"]:
        return _finish(plan)
    inventory = existing.get("ipam_inventory", {})
    policy = inventory.get("policy")
    plan["policy"] = policy

    def unresolved(scope, name, reason, **values):
        plan["unresolved"].append({"scope": scope, "name": name, "reason": reason, **values})

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

    if not inventory.get("supported", False) or policy is None:
        reason = (
            "Select a default namespace before loading IPAM inventory"
            if inventory.get("supported", False)
            else inventory.get("reason") or "IPAM inventory is unavailable"
        )
        for name, row in facts.items():
            plan["settings"].append(
                {"name": name, "vrf": row["vrf"], "ipv4": row["ipv4"], "ipv6": row["ipv6"]}
            )
            if row["ipv4"] or row["ipv6"] or row["vrf"]:
                unresolved("interface", name, reason)
        for name in observed_vrfs:
            unresolved("vrf", name, reason)
        if facts or observed_vrfs:
            plan["warnings"].append(reason)
        return _finish(plan)
    try:
        if not isinstance(policy, dict):
            raise ValueError("An explicit IPAM policy is required")
        if routing_targets is None:
            if not isinstance(policy.get("default_namespace"), dict):
                raise ValueError("A selected default namespace is required")
            if not policy["default_namespace"].get("id"):
                raise ValueError("A selected default namespace ID is required")
        elif not isinstance(routing_targets, dict):
            raise ValueError("Explicit routing targets must be name-keyed objects")
        override = policy.get("override_namespace")
        if override is not None and (not isinstance(override, dict) or not override.get("id")):
            raise ValueError("The override namespace requires an explicit identity")
        for flag in ("override_rfc1918", "create_missing_prefixes", "group_user_vrfs"):
            if type(policy.get(flag, False)) is not bool:
                raise ValueError("Namespace and VRF policy flags must be explicit booleans")
        if not isinstance(policy.get("override_networks", []), list) or not isinstance(
            policy.get("local_vrf_names", []), list
        ):
            raise ValueError("Override networks and local VRF names must be lists")
        if any(not _text(value) for value in policy.get("local_vrf_names", [])):
            raise ValueError("Device-local VRF exceptions require nonblank names")
        networks = [ip_network(value, strict=True) for value in policy.get("override_networks", [])]
        if override is not None and policy.get("override_rfc1918"):
            networks.extend(RFC1918)
        if override is None and networks:
            raise ValueError("An override namespace is required when override matches are enabled")
        # collapse_addresses rejects mixed families; organizational overrides
        # form separate, explicit IPv4 and IPv6 policy unions.
        overrides = [
            value
            for version in (4, 6)
            for value in collapse_addresses(item for item in networks if item.version == version)
        ]
        device = inventory["device"]
        if not device.get("id") or not _text(device.get("name")):
            raise ValueError("The existing Device requires an explicit identity")
        for field in (
            "vrfs",
            "vrf_device_assignments",
            "prefixes",
            "ip_addresses",
            "ip_assignments",
            "ip_ranges",
        ):
            if not isinstance(inventory.get(field), list):
                raise ValueError("IPAM inventory requires a complete %s snapshot" % field)
    except (KeyError, TypeError, ValueError) as exc:
        plan["errors"].append("Invalid IPAM policy or snapshot: %s" % exc)
        return _finish(plan)

    prefixes = inventory["prefixes"]
    ip_addresses = inventory["ip_addresses"]
    ip_ranges = inventory["ip_ranges"]

    interfaces = defaultdict(list)
    for row in existing.get("interfaces", []):
        interfaces[canonical_name(row["name"])].append(row)
    for row in (interface_plan or {}).get("interface_creates", []):
        interfaces[canonical_name(row["name"])].append({**row, "id": None, "vrf_id": None})
    vrf_by_id = {_id(row["id"]): row for row in inventory["vrfs"]}
    prefix_by_id = {_id(row["id"]): row for row in prefixes}
    all_prefix_by_id = {_id(row["id"]): row for row in inventory["prefixes"]}
    ip_by_id = {_id(row["id"]): row for row in inventory["ip_addresses"]}
    assignments_by_local = defaultdict(list)
    for row in inventory["vrf_device_assignments"]:
        if _id(row["device_id"]) != _id(device["id"]):
            continue
        vrf = vrf_by_id.get(_id(row["vrf_id"]))
        local_name = row.get("effective_name") or _text(row.get("name")) or (vrf or {}).get("name")
        assignments_by_local[local_name].append(row)
    classified, namespace_by_vrf, blocked_vrfs = {}, {}, set()
    for name, fact in sorted(facts.items()):
        classified[name] = []
        for address in fact["ipv4"] + fact["ipv6"]:
            if routing_targets is None:
                namespace, match, reason = _namespace(
                    ip_network(address["prefix"]), policy, overrides
                )
            else:
                target = routing_targets.get(name)
                namespace = target.get("namespace") if isinstance(target, dict) else None
                match = "explicit routing-domain binding"
                reason = (
                    None
                    if isinstance(namespace, dict) and namespace.get("id")
                    else "Interface has no explicit existing Namespace routing target"
                )
            setting = {
                "name": name,
                "vrf": fact["vrf"],
                "address": address["host"],
                "mask_length": address["prefix_length"],
                "prefix": address["prefix"],
                "namespace": namespace,
                "matched_rule": match,
                "source": fact.get("source", {}),
            }
            plan["settings"].append(setting)
            if reason:
                unresolved("interface", name, reason, address=address["host"])
                if fact["vrf"]:
                    blocked_vrfs.add(fact["vrf"])
                continue
            classified[name].append({**address, "namespace": namespace})
            if fact["vrf"]:
                previous = namespace_by_vrf.setdefault(fact["vrf"], namespace)
                if _id(previous["id"]) != _id(namespace["id"]):
                    blocked_vrfs.add(fact["vrf"])
    for name in blocked_vrfs:
        unresolved("vrf", name, "Named VRF cannot span incompatible selected namespaces")
    vrf_catalog, local_refs = {}, {}
    explicit_refs = {}
    if routing_targets is not None:
        vrf_catalog, explicit_refs = _explicit_routing_refs(
            {name: target for name, target in routing_targets.items() if name in facts},
            inventory,
            plan,
        )
    else:
        for local_name, observation in sorted(observed_vrfs.items()):
            if local_name in blocked_vrfs:
                continue
            namespace = namespace_by_vrf.get(local_name, policy["default_namespace"])
            namespace_id = _id(namespace["id"])
            assignments = assignments_by_local[local_name]
            if len(assignments) > 1:
                unresolved(
                    "vrf",
                    local_name,
                    "Several Device assignments match the reported local VRF name",
                )
                continue
            assignment = assignments[0] if assignments else None
            vrf = vrf_by_id.get(_id(assignment["vrf_id"])) if assignment else None
            if assignment and vrf is None:
                plan["errors"].append("An existing VRF Device assignment refers to a missing VRF")
                continue
            if vrf and local_name not in namespace_by_vrf:
                # No address evidence exists to contradict this established device
                # assignment. The default namespace applies only to a new VRF.
                namespace_id = _id(vrf["namespace_id"])
            if vrf and _id(vrf["namespace_id"]) != namespace_id:
                conflict(
                    "vrf",
                    local_name,
                    "namespace_id",
                    _id(vrf["namespace_id"]),
                    namespace_id,
                    "Preserve existing Device VRF assignment namespace",
                )
                unresolved(
                    "vrf",
                    local_name,
                    "Existing Device VRF assignment conflicts with namespace policy",
                )
                continue
            shared = policy.get("group_user_vrfs", False) and local_name not in policy.get(
                "local_vrf_names", ["Mgmt-vrf"]
            )
            output_vrf_name = local_name if shared else "%s / %s" % (device["name"], local_name)
            if vrf is None:
                matches = [
                    row
                    for row in inventory["vrfs"]
                    if _id(row["namespace_id"]) == namespace_id and row["name"] == output_vrf_name
                ]
                if len(matches) > 1 or matches and not shared:
                    unresolved(
                        "vrf",
                        local_name,
                        "Canonical VRF name collides with an unassigned existing routing domain",
                    )
                    continue
                vrf = matches[0] if matches else None
            output_vrf_name = vrf["name"] if vrf else output_vrf_name
            if assignment is None and vrf:
                adoption_reason = route_target_adoption_reason(
                    observation, vrf, inventory.get("route_targets")
                )
                if adoption_reason:
                    unresolved("vrf", local_name, adoption_reason)
                    continue
            if assignment is None and vrf and vrf.get("rd") and not observation.get("rd"):
                unresolved(
                    "vrf",
                    local_name,
                    "New Device assignment would inherit an unreported canonical VRF RD",
                )
                continue
            if len(output_vrf_name) > 255:
                unresolved(
                    "vrf",
                    local_name,
                    "Canonical device-local VRF name exceeds the native field length",
                )
                continue
            key = "vrf:%s:%s" % (namespace_id, output_vrf_name)
            spec = {
                "key": key,
                "id": _id(vrf["id"]) if vrf else None,
                "create": vrf is None,
                "name": output_vrf_name,
                "namespace_id": namespace_id,
                "rd": vrf.get("rd") if vrf else None,
                "changes": [],
            }
            rd = observation.get("rd")
            changes = []
            if assignment:
                inherited_rd = (
                    assignment.get("effective_rd") or assignment.get("rd") or vrf.get("rd")
                )
                if rd and inherited_rd and inherited_rd != rd:
                    conflict(
                        "vrf_device_assignment",
                        local_name,
                        "rd",
                        inherited_rd,
                        rd,
                        "Preserve populated Device assignment RD",
                    )
                elif rd and not inherited_rd:
                    changes.append({"field": "rd", "before": assignment.get("rd"), "after": rd})
            vrf_catalog[key] = spec
            local_refs[local_name] = key
            plan["vrf_device_assignments"].append(
                {
                    "key": "vrf-device:%s:%s" % (device["id"], local_name),
                    "id": _id(assignment["id"]) if assignment else None,
                    "create": assignment is None,
                    "vrf_key": key,
                    "device_id": _id(device["id"]),
                    "name": local_name,
                    "rd": assignment.get("rd") if assignment else rd,
                    "changes": changes,
                }
            )
    plan["vrfs"] = list(vrf_catalog.values())
    prefix_requests, address_requests = {}, []
    observed_hosts = defaultdict(set)
    for name, fact in sorted(facts.items()):
        rows = interfaces[name]
        if len(rows) != 1:
            unresolved("interface", name, "Interface identity is missing or ambiguous")
            continue
        interface = rows[0]
        vrf_key = (
            explicit_refs.get(name)
            if routing_targets is not None
            else local_refs.get(fact["vrf"])
            if fact["vrf"]
            else None
        )
        if routing_targets is not None and name not in explicit_refs:
            unresolved("interface", name, "Explicit routing target is unresolved")
            continue
        if routing_targets is None and fact["vrf"] and vrf_key is None:
            unresolved("interface", name, "Named routing context is unresolved")
            continue
        expected_vrf_id = vrf_catalog[vrf_key]["id"] if vrf_key else None
        current_vrf_id = _id(interface.get("vrf_id"))
        if current_vrf_id and current_vrf_id != expected_vrf_id:
            conflict(
                "interface",
                interface["name"],
                "vrf_id",
                current_vrf_id,
                expected_vrf_id,
                "Preserve populated interface VRF",
            )
            unresolved(
                "interface", name, "Existing interface routing context differs from discovery"
            )
            continue
        target_assignments = [
            row
            for row in inventory["ip_assignments"]
            if interface.get("id") and _id(row.get("interface_id")) == _id(interface["id"])
        ]
        allowed_ns = {_id(row["namespace"]["id"]) for row in classified[name]}
        if vrf_key:
            allowed_ns.add(vrf_catalog[vrf_key]["namespace_id"])
        wrong_namespace = False
        for assigned in target_assignments:
            current_ip = ip_by_id.get(_id(assigned["ip_address_id"]))
            if current_ip is None:
                continue
            if vrf_key:
                wrong_namespace |= _id(current_ip["namespace_id"]) not in allowed_ns
            else:
                wrong_namespace |= any(
                    str(_host(current_ip)) == address["host"]
                    and _id(current_ip["namespace_id"]) != _id(address["namespace"]["id"])
                    for address in classified[name]
                )
        if wrong_namespace:
            unresolved(
                "interface",
                name,
                "Existing interface IP assignments conflict with selected namespaces",
            )
            continue
        if (
            vrf_key
            and current_vrf_id is None
            and any(
                expected_vrf_id is None
                or expected_vrf_id
                not in {
                    _id(value)
                    for value in all_prefix_by_id.get(
                        _id(ip_by_id.get(_id(assigned["ip_address_id"]), {}).get("parent_id")), {}
                    ).get("vrf_ids", [])
                }
                for assigned in target_assignments
            )
        ):
            unresolved(
                "interface",
                name,
                "Filling interface VRF would conflict with existing IP routing associations",
            )
            continue
        if vrf_key and current_vrf_id is None:
            plan["interface_vrfs"].append(
                {
                    "id": _id(interface.get("id")),
                    "name": interface["name"],
                    "vrf_key": vrf_key,
                    "changes": [{"field": "vrf_id", "before": None, "after": vrf_key}],
                }
            )
        for address in classified[name]:
            namespace_id = _id(address["namespace"]["id"])
            identity = (namespace_id, address["host"])
            observed_hosts[identity].add(name)
            prefix_key = "prefix:%s:%s" % (namespace_id, address["prefix"])
            request = prefix_requests.setdefault(
                prefix_key,
                {
                    "namespace_id": namespace_id,
                    "prefix": address["prefix"],
                    "vrf_keys": set(),
                    "interfaces": set(),
                    "global_context": False,
                },
            )
            if vrf_key:
                request["vrf_keys"].add(vrf_key)
            else:
                request["global_context"] = True
            request["interfaces"].add(name)
            address_requests.append(
                {
                    **address,
                    "name": name,
                    "interface": interface,
                    "namespace_id": namespace_id,
                    "parent_key": prefix_key,
                }
            )

    prefix_catalog = {}
    for key, request in sorted(prefix_requests.items()):
        network = ip_network(request["prefix"])
        namespace_id = request["namespace_id"]
        if request["global_context"] and request["vrf_keys"]:
            unresolved(
                "prefix",
                request["prefix"],
                "Connected prefix is reported in both global and named routing contexts",
            )
            continue
        matches = [
            row
            for row in prefixes
            if _id(row["namespace_id"]) == namespace_id and _network(row) == network
        ]
        if len(matches) > 1:
            unresolved(
                "prefix",
                request["prefix"],
                "Several existing prefixes share the selected namespace identity",
            )
            continue
        row = matches[0] if matches else None
        if row is None and any(
            _id(value["namespace_id"]) == namespace_id
            and value.get("is_exclusive", False)
            and _range_version(value) == network.version
            and _overlap(*_range(value), network)
            for value in ip_ranges
        ):
            unresolved(
                "prefix",
                request["prefix"],
                "Connected prefix overlaps an exclusive IP range",
            )
            continue
        if row and row.get("type") != "network":
            conflict(
                "prefix",
                request["prefix"],
                "type",
                row.get("type"),
                "network",
                "Preserve existing Prefix type",
            )
            unresolved(
                "prefix", request["prefix"], "Connected network conflicts with existing Prefix type"
            )
            continue
        if row is None and not policy.get("create_missing_prefixes", True):
            unresolved(
                "prefix", request["prefix"], "Creating missing connected networks is disabled"
            )
            continue
        location_id = _id((policy.get("location") or {}).get("id"))
        if row is None and location_id is None:
            unresolved(
                "prefix",
                request["prefix"],
                policy.get("location_reason")
                or "New connected networks require a Location that supports Prefix associations",
            )
            continue
        locations = {_id(value) for value in (row or {}).get("location_ids", [])}
        if row and locations and location_id not in locations:
            unresolved(
                "prefix",
                request["prefix"],
                "Existing prefix belongs to another Location; preserve its scope",
            )
            continue
        old_vrfs = {_id(value) for value in (row or {}).get("vrf_ids", [])}
        additions = sorted(
            value for value in request["vrf_keys"] if vrf_catalog[value]["id"] not in old_vrfs
        )
        desired_tokens = {"id:" + value for value in old_vrfs} | {
            "id:" + vrf_catalog[value]["id"] if vrf_catalog[value]["id"] else "key:" + value
            for value in additions
        }
        parent_candidates = [
            value
            for value in prefixes
            if _id(value["namespace_id"]) == namespace_id
            and network != _network(value)
            and _subnet_of(network, _network(value))
        ]
        parent = max(parent_candidates, key=lambda value: _network(value).prefixlen, default=None)
        affected_ips, affected_prefixes, affected_ranges, reason = [], [], [], None
        if row is None or additions:
            for ip in ip_addresses:
                if _id(ip["namespace_id"]) != namespace_id or _host(ip) not in network:
                    continue
                current_parent = prefix_by_id.get(_id(ip.get("parent_id")))
                if current_parent and _network(current_parent).prefixlen > network.prefixlen:
                    continue
                if row and _id(ip.get("parent_id")) != _id(row["id"]):
                    continue
                before_tokens = {
                    "id:" + _id(value) for value in (current_parent or {}).get("vrf_ids", [])
                }
                if before_tokens != desired_tokens:
                    reason = (
                        "Prefix change would alter existing IP address inherited VRF associations"
                    )
                    break
                if row is None:
                    affected_ips.append(_id(ip["id"]))
            for ip_range in ip_ranges:
                if (
                    reason
                    or _id(ip_range["namespace_id"]) != namespace_id
                    or _range_version(ip_range) != network.version
                ):
                    continue
                start, end = _range(ip_range)
                if not _overlap(start, end, network):
                    continue
                current_parent = prefix_by_id.get(_id(ip_range.get("parent_id")))
                if current_parent and _network(current_parent).prefixlen > network.prefixlen:
                    continue
                if row and _id(ip_range.get("parent_id")) != _id(row["id"]):
                    continue
                if start < int(network.network_address) or end > int(network.broadcast_address):
                    reason = "Connected prefix would split an existing IP range across parents"
                    break
                before_tokens = {
                    "id:" + _id(value) for value in (current_parent or {}).get("vrf_ids", [])
                }
                if before_tokens != desired_tokens:
                    reason = (
                        "Prefix change would alter existing IP range inherited VRF associations"
                    )
                    break
                if row is None:
                    affected_ranges.append(_id(ip_range["id"]))
            if row is None:
                for child in prefixes:
                    if _id(child["namespace_id"]) != namespace_id or not _subnet_of(
                        _network(child), network
                    ):
                        continue
                    old_parent = prefix_by_id.get(_id(child.get("parent_id")))
                    if old_parent is None or _network(old_parent).prefixlen < network.prefixlen:
                        affected_prefixes.append(_id(child["id"]))
        if reason:
            unresolved("prefix", request["prefix"], reason)
            continue
        prefix_catalog[key] = {
            "key": key,
            "id": _id(row["id"]) if row else None,
            "create": row is None,
            "prefix": request["prefix"],
            "namespace_id": namespace_id,
            "type": "network",
            "location_id": location_id if row is None else None,
            "vrf_keys": sorted(request["vrf_keys"]),
            "vrf_ids": sorted(old_vrfs),
            "add_vrf_keys": additions,
            "parent_id": _id(parent["id"]) if parent else None,
            "affected_ip_ids": sorted(affected_ips),
            "affected_prefix_ids": sorted(affected_prefixes),
            "affected_range_ids": sorted(affected_ranges),
            "changes": [],
        }
    # Account for unsaved nested connected prefixes as well as database parents.
    for key, spec in prefix_catalog.items():
        network = ip_network(spec["prefix"])
        candidates = [
            value
            for other, value in prefix_catalog.items()
            if other != key
            and value["namespace_id"] == spec["namespace_id"]
            and _subnet_of(network, ip_network(value["prefix"]))
        ]
        parent = max(
            candidates, key=lambda value: ip_network(value["prefix"]).prefixlen, default=None
        )
        actual_parent = prefix_by_id.get(spec["parent_id"])
        spec["parent_key"] = (
            parent["key"]
            if parent
            and (
                actual_parent is None
                or ip_network(parent["prefix"]).prefixlen > _network(actual_parent).prefixlen
            )
            else None
        )
    plan["prefixes"] = sorted(
        prefix_catalog.values(),
        key=lambda row: (row["namespace_id"], ip_network(row["prefix"]).prefixlen, row["prefix"]),
    )
    ip_catalog = {}
    for request in address_requests:
        name, host, namespace_id = request["name"], request["host"], request["namespace_id"]
        if request["parent_key"] not in prefix_catalog:
            unresolved("ip_address", host, "Connected prefix is unresolved", interface=name)
            continue
        if len(observed_hosts[(namespace_id, host)]) > 1:
            unresolved(
                "ip_address",
                host,
                "Same address is configured on multiple interfaces "
                "without explicit sharing semantics",
                interface=name,
            )
            continue
        matches = [
            row
            for row in ip_addresses
            if _id(row["namespace_id"]) == namespace_id and str(_host(row)) == host
        ]
        if len(matches) > 1:
            unresolved(
                "ip_address", host, "Existing IP address identity is ambiguous", interface=name
            )
            continue
        ip = matches[0] if matches else None
        if ip and ip.get("mask_length") != request["prefix_length"]:
            conflict(
                "ip_address",
                host,
                "mask_length",
                ip.get("mask_length"),
                request["prefix_length"],
                "Preserve existing IP address mask",
            )
            unresolved(
                "ip_address",
                host,
                "Configured mask conflicts with existing IP address",
                interface=name,
            )
            continue
        if ip and ip.get("type", "host") != "host":
            unresolved(
                "ip_address",
                host,
                "Existing IP address type requires explicit sharing semantics",
                interface=name,
            )
            continue
        assignments = [
            row
            for row in inventory["ip_assignments"]
            if ip and _id(row["ip_address_id"]) == _id(ip["id"])
        ]
        interface_id = _id(request["interface"].get("id"))
        foreign = [row for row in assignments if _id(row.get("interface_id")) != interface_id]
        if foreign:
            unresolved(
                "ip_address",
                host,
                "Address is assigned elsewhere; shared addressing is not inferred",
                interface=name,
            )
            continue
        if (
            assignments
            and request.get("secondary_known", True)
            and type(assignments[0].get("is_secondary")) is bool
            and (assignments[0]["is_secondary"] != request["secondary"])
        ):
            conflict(
                "ip_assignment",
                host,
                "is_secondary",
                assignments[0]["is_secondary"],
                request["secondary"],
                "Preserve existing primary/secondary assignment setting",
            )
        exclusive = [
            row
            for row in ip_ranges
            if _id(row["namespace_id"]) == namespace_id
            and row.get("is_exclusive", False)
            and _range_version(row) == ip_address(host).version
            and _range(row)[0] <= int(ip_address(host)) <= _range(row)[1]
        ]
        if exclusive:
            unresolved(
                "ip_address", host, "Address falls within an exclusive IP range", interface=name
            )
            continue
        # A mask can differ from the closest actual parent; namespace and host identify the IP.
        parents = [
            row
            for row in prefixes
            if _id(row["namespace_id"]) == namespace_id and ip_address(host) in _network(row)
        ]
        staged = [
            row
            for row in prefix_catalog.values()
            if row["namespace_id"] == namespace_id and ip_address(host) in ip_network(row["prefix"])
        ]
        closest = max(
            [(ip_network(row["prefix"]).prefixlen, "key", row) for row in staged]
            + [(_network(row).prefixlen, "id", row) for row in parents],
            key=lambda value: value[0],
        )
        actual_prefix = closest[2]
        if closest[1] == "key":
            parent_key = actual_prefix["key"]
            effective_vrfs = set(actual_prefix["vrf_ids"]) | {
                vrf_catalog[value]["id"] or "key:" + value
                for value in actual_prefix["add_vrf_keys"]
            }
        else:
            parent_key = "prefix-existing:%s" % actual_prefix["id"]
            effective_vrfs = {_id(value) for value in actual_prefix.get("vrf_ids", [])}
            if parent_key not in prefix_catalog:
                prefix_catalog[parent_key] = {
                    "key": parent_key,
                    "id": _id(actual_prefix["id"]),
                    "create": False,
                    "prefix": actual_prefix["prefix"],
                    "namespace_id": namespace_id,
                    "type": actual_prefix["type"],
                    "location_id": None,
                    "vrf_keys": [],
                    "vrf_ids": sorted(effective_vrfs),
                    "add_vrf_keys": [],
                    "parent_id": _id(actual_prefix.get("parent_id")),
                    "parent_key": None,
                    "affected_ip_ids": [],
                    "affected_prefix_ids": [],
                    "affected_range_ids": [],
                    "changes": [],
                }
        local_vrf = facts[name]["vrf"]
        local_key = (
            explicit_refs.get(name) if routing_targets is not None else local_refs.get(local_vrf)
        )
        intended_vrf = vrf_catalog[local_key]["id"] or "key:" + local_key if local_key else None
        if intended_vrf and intended_vrf not in effective_vrfs:
            unresolved(
                "ip_address",
                host,
                "Closest actual parent prefix lacks the discovered VRF association",
                interface=name,
            )
            continue
        if intended_vrf is None and effective_vrfs:
            unresolved(
                "ip_address",
                host,
                "Global routing context conflicts with closest parent prefix VRF associations",
                interface=name,
            )
            continue
        key = "ip:%s:%s" % (namespace_id, host)
        ip_catalog[key] = {
            "key": key,
            "id": _id(ip["id"]) if ip else None,
            "create": ip is None,
            "host": host,
            "mask_length": request["prefix_length"],
            "address": "%s/%s" % (host, request["prefix_length"]),
            "namespace_id": namespace_id,
            "parent_key": parent_key,
            "changes": [],
        }
        if not assignments:
            plan["ip_assignments"].append(
                {
                    "key": "ip-interface:%s:%s" % (key, name),
                    "id": None,
                    "create": True,
                    "ip_key": key,
                    "interface_id": interface_id,
                    "name": request["interface"]["name"],
                    "is_secondary": request["secondary"],
                }
            )
    plan["ip_addresses"] = list(ip_catalog.values())
    plan["prefixes"] = sorted(
        prefix_catalog.values(),
        key=lambda row: (row["namespace_id"], ip_network(row["prefix"]).prefixlen, row["prefix"]),
    )
    return _finish(plan)
