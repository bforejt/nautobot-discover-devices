"""Configured PAN-OS VPN inventory planning, independent of Nautobot imports."""

from copy import deepcopy
from ipaddress import ip_address, ip_interface, ip_network

from .transport_ssh import RUNNING_VPN

CONTRACT = "panos-native-vpn-v1"
MODELS = (
    "VPN",
    "VPNProfile",
    "VPNPhase1Policy",
    "VPNPhase2Policy",
    "VPNTunnel",
    "VPNTunnelEndpoint",
    "VPNProfilePhase1PolicyAssignment",
    "VPNProfilePhase2PolicyAssignment",
)
COLLECTIONS = {
    "ike_gateways": "result/network/ike/gateway",
    "ipsec_tunnels": "result/network/tunnel/ipsec",
    "ike_crypto_profiles": "result/network/ike/crypto-profiles/ike-crypto-profiles",
    "ipsec_crypto_profiles": "result/network/ike/crypto-profiles/ipsec-crypto-profiles",
}


def crypto_policy_name(device_id, kind, name, version=None):
    """Scope crypto identity to the selected Device and exact applied profile."""
    return "PAN-" + device_id + " " + kind + " " + name + (" " + version if version else "")


def _blank(value):
    return value is None or value == ""


def _source(discovery):
    observations = discovery.get("observations", {})
    vpn = observations.get("vpn", {}) if isinstance(observations, dict) else {}
    configuration = vpn.get("configuration") if isinstance(vpn, dict) else None
    if (
        not isinstance(configuration, dict)
        or configuration.get("contract") != "panos-vpn-config-v1"
    ):
        raise ValueError("PAN-OS native VPN requires reviewed applied configuration")
    sources = configuration.get("sources", {})
    for name, path in COLLECTIONS.items():
        source = sources.get(name)
        rows = configuration.get(name)
        if (
            not isinstance(source, dict)
            or source.get("command") != RUNNING_VPN
            or source.get("path") != path
            or type(source.get("present")) is not bool
            or not isinstance(rows, list)
            or any(
                not isinstance(row, dict) or not isinstance(row.get("name"), str) for row in rows
            )
            or len({row["name"] for row in rows}) != len(rows)
            or rows
            and source["present"] is not True
        ):
            raise ValueError("PAN-OS native VPN configuration provenance is invalid")
    return configuration


def _ordered_algorithms(values, allowed, *, groups=False):
    if values is None:
        return None
    if not isinstance(values, list) or not values:
        raise ValueError("VPN algorithms require an explicit nonempty ordered list")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("VPN algorithm contains an unsupported value")
        candidate = value[5:] if groups and value.startswith("group") else value.upper()
        if candidate not in allowed or candidate in result:
            raise ValueError("VPN algorithm is unsupported or duplicated by the native model")
        result.append(candidate)
    return result


def _seconds(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"seconds", "minutes", "hours", "days"}:
        raise ValueError("VPN lifetime has incompatible unit metadata")
    observed = [(name, raw) for name, raw in value.items() if raw is not None]
    if not observed:
        return None
    if len(observed) != 1 or type(observed[0][1]) is not int or observed[0][1] <= 0:
        raise ValueError("VPN lifetime requires one explicit positive time quantity")
    unit, raw = observed[0]
    return raw * {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}[unit]


def _native_algorithms(values, capabilities, field, *, groups=False):
    ordered = _ordered_algorithms(values, capabilities["choices"][field], groups=groups)
    if ordered is None or field in capabilities.get("collections", ()):
        return ordered
    if len(ordered) != 1:
        raise ValueError("Installed native VPN field cannot represent an ordered algorithm list")
    return ordered[0]


def _phase1(row, version, capabilities, exchange_mode=None):
    native = capabilities["VPNPhase1Policy"]
    choices = native["choices"]
    native_version = {"ikev1": "IKEv1", "ikev2": "IKEv2"}.get(version)
    if native_version not in choices["ike_version"]:
        raise ValueError("Applied IKE version has no exact native representation")
    if version == "ikev1" and exchange_mode not in {"main", "aggressive"}:
        raise ValueError("IKEv1 requires an explicit main or aggressive exchange mode")
    return {
        "ike_version": native_version,
        "aggressive_mode": version == "ikev1" and exchange_mode == "aggressive",
        "encryption_algorithm": _native_algorithms(
            row.get("encryption"), native, "encryption_algorithm"
        ),
        "integrity_algorithm": _native_algorithms(row.get("hash"), native, "integrity_algorithm"),
        "dh_group": _native_algorithms(row.get("dh_groups"), native, "dh_group", groups=True),
        "lifetime_seconds": _seconds(row.get("lifetime")),
    }


def _phase2(row, capabilities):
    native = capabilities["VPNPhase2Policy"]
    esp, ah = row.get("esp"), row.get("ah")
    if (
        not isinstance(esp, dict)
        or not isinstance(ah, dict)
        or ah.get("authentication") is not None
    ):
        raise ValueError("Only explicit ESP crypto profiles have a reviewed native policy mapping")
    group = row.get("dh_group")
    if group == "no-pfs":
        pfs = [] if "pfs_group" in native.get("collections", ()) else ""
    elif group is not None:
        pfs = _native_algorithms([group], native, "pfs_group", groups=True)
    else:
        pfs = None
    return {
        "encryption_algorithm": _native_algorithms(
            esp.get("encryption"), native, "encryption_algorithm"
        ),
        "integrity_algorithm": _native_algorithms(
            esp.get("authentication"), native, "integrity_algorithm"
        ),
        "pfs_group": pfs,
        "lifetime": _seconds(row.get("lifetime")),
    }


def plan_panos_vpn(discovery, existing, policy=None):
    """Plan selected applied tunnels; retain unresolved relationships as facts."""
    inventory = existing.get("panos_vpn_inventory", {})
    policy = policy if policy is not None else inventory.get("policy")
    plan = {
        "contract": CONTRACT,
        "policy": deepcopy(policy),
        "catalog": [],
        "assignments": [],
        "prefix_assignments": [],
        "unresolved": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "summary": {
            "vpn_objects_created": 0,
            "vpn_objects_updated": 0,
            "vpn_policy_assignments_created": 0,
            "vpn_prefix_assignments_created": 0,
            "unresolved_vpn": 0,
        },
    }
    if discovery.get("adapter") != "panos" or policy is None:
        return plan
    if inventory.get("supported") is not True:
        plan["unresolved"].append(
            {"reason": inventory.get("reason") or "Native VPN capability unavailable"}
        )
        plan["summary"]["unresolved_vpn"] = 1
        return plan
    try:
        configuration = _source(discovery)
        if policy.get("contract") != "panos-vpn-policy-v1" or not isinstance(
            policy.get("tunnels"), list
        ):
            raise ValueError("PAN-OS VPN processing requires explicit tunnel mappings")
        device = existing["device"]
        capabilities = inventory["capabilities"]
        catalog = inventory["catalog"]
        source_maps = {
            name: {row["name"]: row for row in configuration[name]} for name in COLLECTIONS
        }
        wan_tunnels = {}
        for observed_tunnel in configuration["ipsec_tunnels"]:
            observed_auto = observed_tunnel.get("auto_key") or {}
            for gateway_name in observed_auto.get("ike_gateways") or []:
                observed_gateway = source_maps["ike_gateways"].get(gateway_name, {})
                wan = observed_gateway.get("local_address", {}).get("interface")
                if wan and observed_tunnel.get("tunnel_interface"):
                    wan_tunnels.setdefault(wan, set()).add(observed_tunnel["tunnel_interface"])
        pending = {}

        def unresolved(name, reason):
            plan["unresolved"].append({"tunnel": name, "reason": reason})

        def record(model, name, values=None, relations=None, *, candidates=None):
            values, relations = deepcopy(values or {}), deepcopy(relations or {})
            key = model + ":" + name
            if key in pending:
                return key
            rows = (
                candidates
                if candidates is not None
                else [row for row in catalog.get(model, []) if row.get("name") == name]
            )
            if len(rows) > 1:
                raise ValueError("Native VPN identity is ambiguous")
            current = rows[0] if rows else None
            changes, relation_changes = [], []
            if current:
                for field, after in values.items():
                    before = current.get(field)
                    if after is None or before == after:
                        continue
                    if _blank(before):
                        changes.append(
                            {"field": field, "before": deepcopy(before), "after": deepcopy(after)}
                        )
                    else:
                        plan["conflicts"].append(
                            {
                                "model": model,
                                "name": name,
                                "field": field,
                                "before": deepcopy(before),
                                "observed": deepcopy(after),
                            }
                        )
                for field, reference in relations.items():
                    before = current.get(field + "_id")
                    after = reference.get("id") or pending[reference["key"]].get("id")
                    if before is None:
                        relation_changes.append(field)
                    elif after is None or str(before) != str(after):
                        plan["conflicts"].append(
                            {
                                "model": model,
                                "name": name,
                                "field": field,
                                "before": str(before),
                                "observed": deepcopy(reference),
                            }
                        )
            else:
                values["name"] = name
            spec = {
                "key": key,
                "model": model,
                "name": name,
                "id": current.get("id") if current else None,
                "create": current is None,
                "values": values,
                "relations": relations,
                "changes": changes,
                "relation_changes": relation_changes,
                "source": {"command": RUNNING_VPN, "device_id": device["id"]},
            }
            pending[key] = spec
            plan["catalog"].append(spec)
            return key

        def exact_interface(name):
            matches = [
                row
                for row in inventory["interfaces"]
                if row["name"] == name and row["device_id"] == device["id"]
            ]
            return matches[0] if len(matches) == 1 else None

        def address(raw, namespace):
            if raw is None or namespace is None:
                return None
            parsed = ip_interface(raw)
            matches = [
                row
                for row in inventory["ip_addresses"]
                if row["namespace_id"] == namespace["id"]
                and ip_address(row["host"]) == parsed.ip
                and ("/" not in raw or row.get("mask_length") == parsed.network.prefixlen)
            ]
            return matches[0] if len(matches) == 1 else None

        seen = set()
        for mapping in policy["tunnels"]:
            name = mapping["tunnel"]
            if name in seen:
                raise ValueError("PAN-OS VPN mappings repeat a source tunnel")
            seen.add(name)
            for field in ("vpn_name", "tunnel_name", "profile_name"):
                if (
                    not isinstance(mapping.get(field), str)
                    or not mapping[field]
                    or mapping[field] != mapping[field].strip()
                ):
                    raise ValueError(
                        "VPN mappings require exact native service, tunnel and profile names"
                    )
            tunnel = source_maps["ipsec_tunnels"].get(name)
            if tunnel is None:
                unresolved(name, "Explicitly mapped tunnel is absent from applied configuration")
                continue
            auto = tunnel.get("auto_key")
            if tunnel.get("mode") != "auto-key" or not isinstance(auto, dict):
                unresolved(name, "Only reviewed auto-key IPsec tunnels have a native mapping")
                continue
            gateway_names = auto.get("ike_gateways")
            if not isinstance(gateway_names, list) or len(gateway_names) != 1:
                unresolved(name, "An unambiguous single applied IKE gateway is required")
                continue
            gateway = source_maps["ike_gateways"].get(gateway_names[0])
            if gateway is None:
                unresolved(
                    name, "Applied IKE gateway does not exist in the complete configured collection"
                )
                continue
            protocol = gateway.get("protocol", {})
            version = protocol.get("version")
            if version not in {"ikev1", "ikev2"}:
                unresolved(
                    name, "An explicit single IKE version is required for native policy assignment"
                )
                continue
            ike_name = protocol.get(version + "_profile")
            ike = source_maps["ike_crypto_profiles"].get(ike_name)
            ipsec = source_maps["ipsec_crypto_profiles"].get(auto.get("crypto_profile"))
            if ike is None or ipsec is None:
                unresolved(name, "Referenced applied crypto profiles are unresolved")
                continue
            try:
                phase1, phase2 = (
                    _phase1(ike, version, capabilities, protocol.get("exchange_mode")),
                    _phase2(ipsec, capabilities),
                )
            except ValueError as exc:
                unresolved(name, str(exc))
                continue
            if isinstance(ipsec.get("lifesize"), dict) and any(
                value is not None for value in ipsec["lifesize"].values()
            ):
                unresolved(name, "Applied IPsec lifesize has no reviewed native Phase 2 field")
            p1 = record(
                "VPNPhase1Policy",
                crypto_policy_name(device["id"], "IKE", ike_name, version),
                phase1,
            )
            p2 = record(
                "VPNPhase2Policy", crypto_policy_name(device["id"], "IPsec", ipsec["name"]), phase2
            )
            profiles = [
                row
                for row in catalog.get("VPNProfile", [])
                if row.get("name") == mapping["profile_name"]
            ]
            profile = None
            if profiles:
                profile = record("VPNProfile", mapping["profile_name"])
            else:
                unresolved(
                    name,
                    "Mapped native Profile must already exist: its required keepalive and "
                    "NAT traversal booleans have no reviewed PAN-OS mapping; profile "
                    "relationships and policy assignments remain unresolved",
                )
            for model, field, key in (
                ("VPNProfilePhase1PolicyAssignment", "vpn_phase1_policy", p1),
                ("VPNProfilePhase2PolicyAssignment", "vpn_phase2_policy", p2),
            ):
                if profile is None:
                    continue
                profile_id, policy_id = pending[profile].get("id"), pending[key].get("id")
                joins = [
                    row for row in catalog.get(model, []) if row.get("vpn_profile_id") == profile_id
                ]
                matching = [
                    row
                    for row in joins
                    if row.get(field + "_id") == policy_id and policy_id is not None
                ]
                if matching:
                    continue
                if joins:
                    unresolved(name, "Existing ordered profile policy assignments are preserved")
                    continue
                identity = (profile, key, model)
                if not any(
                    (row["profile_key"], row["policy_key"], row["model"]) == identity
                    for row in plan["assignments"]
                ):
                    plan["assignments"].append(
                        {
                            "model": model,
                            "profile_key": profile,
                            "policy_key": key,
                            "policy_field": field,
                            "weight": 100,
                            "weight_source": (
                                "Native default ordering for a single policy; "
                                "not a PAN-OS observation"
                            ),
                        }
                    )
            service_values = (
                {"service_type": "ipsec"} if "service_type" in capabilities["VPN"]["fields"] else {}
            )
            vpn = record(
                "VPN",
                mapping["vpn_name"],
                service_values,
                {"vpn_profile": {"key": profile}} if profile is not None else {},
            )
            endpoints = {}
            local = gateway.get("local_address", {})
            local_interface = exact_interface(local.get("interface"))
            tunnel_interface = exact_interface(tunnel.get("tunnel_interface"))
            local_ip = address(local.get("ip"), mapping.get("local_namespace"))
            assigned = (
                local_interface is not None
                and local_ip is not None
                and any(
                    row["interface_id"] == local_interface["id"]
                    and row["ip_address_id"] == local_ip["id"]
                    for row in inventory["ip_assignments"]
                )
            )
            if local.get("floating_ip") is not None:
                unresolved(
                    name, "Floating local VPN addresses require an explicit ownership policy"
                )
            elif local_interface is None or tunnel_interface is None or not assigned:
                unresolved(
                    name,
                    "Local source/tunnel interfaces and exact IP assignment must exist "
                    "for native endpoint validation",
                )
            else:
                shared_wan = len(wan_tunnels.get(local.get("interface"), ())) > 1
                identity = "local:" + ":".join(
                    (device["id"], local_ip["id"], tunnel_interface["id"])
                )
                candidates = [
                    row
                    for row in catalog.get("VPNTunnelEndpoint", [])
                    if row.get("tunnel_interface_id") == tunnel_interface["id"]
                    or (
                        not shared_wan
                        and row.get("source_interface_id") == local_interface["id"]
                        and row.get("tunnel_interface_id") is None
                    )
                ]
                expected = {
                    "device_id": device["id"],
                    "source_ipaddress_id": local_ip["id"],
                    "tunnel_interface_id": tunnel_interface["id"],
                }
                incompatible = any(
                    row.get(field) is not None and row[field] != value
                    for row in candidates
                    for field, value in expected.items()
                ) or any(
                    row.get("source_interface_id") not in (None, local_interface["id"])
                    or bool(row.get("source_fqdn"))
                    for row in candidates
                )
                staged_key = "VPNTunnelEndpoint:" + identity
                staged = pending.get(staged_key)
                incompatible = (
                    incompatible
                    or (
                        staged is not None
                        and (
                            any(
                                staged["relations"].get(field.removesuffix("_id"), {}).get("id")
                                != value
                                for field, value in expected.items()
                            )
                            or staged.get("source_binding", {}).get("source_interface_id")
                            != local_interface["id"]
                        )
                    )
                    or any(
                        key != staged_key
                        and spec["model"] == "VPNTunnelEndpoint"
                        and spec["relations"].get("tunnel_interface", {}).get("id")
                        == tunnel_interface["id"]
                        for key, spec in pending.items()
                    )
                )
                if incompatible:
                    unresolved(
                        name, "Populated or foreign endpoint interface ownership is preserved"
                    )
                    candidates = None
                if candidates is not None:
                    source_occupied = any(
                        row.get("source_interface_id") == local_interface["id"]
                        and row not in candidates
                        for row in catalog.get("VPNTunnelEndpoint", [])
                    ) or any(
                        key != staged_key
                        and spec["model"] == "VPNTunnelEndpoint"
                        and spec["relations"].get("source_interface", {}).get("id")
                        == local_interface["id"]
                        for key, spec in pending.items()
                    )
                    source_relation = (
                        {}
                        if shared_wan or source_occupied
                        else {"source_interface": {"id": local_interface["id"]}}
                    )
                    endpoints["endpoint_a"] = record(
                        "VPNTunnelEndpoint",
                        identity,
                        {},
                        {
                            "device": {"id": device["id"]},
                            **source_relation,
                            "source_ipaddress": {"id": local_ip["id"]},
                            "tunnel_interface": {"id": tunnel_interface["id"]},
                            **({"vpn_profile": {"key": profile}} if profile is not None else {}),
                        },
                        candidates=candidates,
                    )
                    pending[endpoints["endpoint_a"]]["source_binding"] = {
                        **expected,
                        "source_interface_id": local_interface["id"],
                        "namespace_id": mapping["local_namespace"]["id"],
                        "source_address": local["ip"],
                    }
                    pending[endpoints["endpoint_a"]]["source"][
                        "source_interface_representation"
                    ] = (
                        "Observed WAN binding independently verified; native source_interface "
                        "is unset because its OneToOne relation cannot represent WAN sharing"
                        if not source_relation
                        else "Observed WAN Interface bound directly"
                    )
            peer = gateway.get("peer_address", {})
            profile_id = pending[profile]["id"] if profile is not None else None
            peer_scope = ":profile:" + profile_id if profile_id is not None else ""

            def peer_candidates(rows, selected_profile_id=profile_id):
                exact = [row for row in rows if row.get("vpn_profile_id") == selected_profile_id]
                return exact or (
                    [row for row in rows if row.get("vpn_profile_id") is None]
                    if selected_profile_id is not None
                    else []
                )

            if peer.get("kind") == "fqdn" and isinstance(peer.get("fqdn"), str) and peer["fqdn"]:
                candidates = peer_candidates(
                    [
                        row
                        for row in catalog.get("VPNTunnelEndpoint", [])
                        if row.get("source_fqdn") == peer["fqdn"]
                        and row.get("device_id") is None
                        and row.get("source_interface_id") is None
                    ]
                )
                if len(candidates) > 1:
                    unresolved(name, "Native FQDN peer endpoint identity is ambiguous")
                else:
                    endpoints["endpoint_z"] = record(
                        "VPNTunnelEndpoint",
                        "fqdn:" + peer["fqdn"] + peer_scope,
                        {"source_fqdn": peer["fqdn"]},
                        {"vpn_profile": {"key": profile}} if profile is not None else {},
                        candidates=candidates,
                    )
            elif peer.get("kind") == "ip":
                peer_ip = address(peer.get("ip"), mapping.get("remote_namespace"))
                if peer_ip is None:
                    unresolved(
                        name,
                        "Literal peer IP requires an existing exact IPAddress "
                        "in its explicit Namespace",
                    )
                else:
                    candidates = peer_candidates(
                        [
                            row
                            for row in catalog.get("VPNTunnelEndpoint", [])
                            if row.get("source_ipaddress_id") == peer_ip["id"]
                            and row.get("device_id") is None
                            and row.get("source_interface_id") is None
                            and not row.get("source_fqdn")
                        ]
                    )
                    if len(candidates) > 1:
                        unresolved(name, "Native literal-IP peer endpoint identity is ambiguous")
                    else:
                        endpoints["endpoint_z"] = record(
                            "VPNTunnelEndpoint",
                            "ip:" + peer_ip["id"] + peer_scope,
                            {},
                            {
                                "source_ipaddress": {"id": peer_ip["id"]},
                                **(
                                    {"vpn_profile": {"key": profile}} if profile is not None else {}
                                ),
                            },
                            candidates=candidates,
                        )
            else:
                unresolved(name, "Dynamic or absent peers cannot become a native endpoint")
            status = mapping.get("status")
            if not isinstance(status, dict) or not status.get("id"):
                unresolved(name, "An explicit applicable native Tunnel Status is required")
            else:
                relations = {
                    "vpn": {"key": vpn},
                    **({"vpn_profile": {"key": profile}} if profile is not None else {}),
                    "status": {"id": status["id"]},
                }
                relations.update({field: {"key": key} for field, key in endpoints.items()})
                record(
                    "VPNTunnel",
                    mapping["tunnel_name"],
                    {"encapsulation": "IPsec-Tunnel"},
                    relations,
                )
            selectors = (auto.get("selectors_ipv4") or []) + (auto.get("selectors_ipv6") or [])
            for selector in selectors:
                if selector.get("protocol", {}).get("kind") != "any":
                    unresolved(
                        name,
                        "Protocol/port-restricted selectors cannot become whole protected Prefixes",
                    )
                    continue
                for side, endpoint in (("local", "endpoint_a"), ("remote", "endpoint_z")):
                    namespace = mapping.get(side + "_protected_namespace")
                    if endpoint not in endpoints or namespace is None or selector.get(side) is None:
                        unresolved(
                            name,
                            "Protected selector requires an exact endpoint and explicit Namespace",
                        )
                        continue
                    prefix = str(ip_network(selector[side], strict=False))
                    matches = [
                        row
                        for row in inventory["prefixes"]
                        if row["namespace_id"] == namespace["id"] and row["prefix"] == prefix
                    ]
                    if len(matches) != 1:
                        unresolved(
                            name,
                            "Protected selector Prefix must already exist "
                            "in its explicit Namespace",
                        )
                        continue
                    key, prefix_id = endpoints[endpoint], matches[0]["id"]
                    spec = pending[key]
                    before = next(
                        (
                            row.get("protected_prefix_ids", [])
                            for row in catalog.get("VPNTunnelEndpoint", [])
                            if row["id"] == spec.get("id")
                        ),
                        [],
                    )
                    if prefix_id in before:
                        continue
                    if before:
                        unresolved(name, "Populated protected-prefix sets are preserved")
                        continue
                    candidate = {"endpoint_key": key, "prefix_id": prefix_id}
                    if candidate not in plan["prefix_assignments"]:
                        plan["prefix_assignments"].append(candidate)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        plan["errors"].append(
            str(exc)
            if isinstance(exc, ValueError)
            else "PAN-OS native VPN facts or mapping are invalid"
        )
    plan["summary"] = {
        "vpn_objects_created": sum(spec["create"] for spec in plan["catalog"]),
        "vpn_objects_updated": sum(
            bool(spec["changes"] or spec["relation_changes"])
            for spec in plan["catalog"]
            if not spec["create"]
        ),
        "vpn_policy_assignments_created": len(plan["assignments"]),
        "vpn_prefix_assignments_created": len(plan["prefix_assignments"]),
        "unresolved_vpn": len(plan["unresolved"]),
    }
    return plan
