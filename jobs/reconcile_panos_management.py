"""Fill dedicated management inventory without treating leases as static config."""

from copy import deepcopy
from ipaddress import ip_interface

from .adapters.panos import DiscoveryError
from .adapters.panos_management import CONTRACT, canonical_management
from .reconcile_ipam import plan_ipam
from .transport_ssh import MANAGEMENT_INTERFACE, RUNNING_HA


def plan_panos_management(discovery, existing, interface_plan, *, identity_verified=False):
    plan = {
        "creates": [],
        "updates": [],
        "primary_updates": [],
        "unresolved": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "ipam": None,
        "ipam_input": None,
        "summary": {},
    }
    facts = discovery.get("management") if discovery.get("adapter") == "panos" else None
    if facts is None:
        return _finish(plan)
    try:
        facts = canonical_management(facts, discovery["identity"]["model"])
        row = facts["interface"]
        source = row["source"]
        fields = source["fields"]
        if (
            facts["contract"] != CONTRACT
            or source["command"] != MANAGEMENT_INTERFACE
            or (
                source["path"] != "result/info"
                or source["applied_command"] != RUNNING_HA
                or fields["name"] != row["name"]
                or not isinstance(facts["addresses"], list)
            )
        ):
            raise ValueError("Management provenance is invalid")
        enabled = (
            False
            if fields["state_c"] == "down"
            else (
                True
                if fields["state_c"] == "up"
                or (fields["state_c"] == "auto" and fields["state"] == "up")
                else None
            )
        )
        if row["enabled"] is not enabled or (
            row["type"] is not None
            and (
                row["type"] != "virtual"
                or source["model"] != "PA-VM"
                or discovery["identity"]["model"] != "PA-VM"
            )
        ):
            raise ValueError("Management state or type is not corroborated")
        if (
            row["mac_address"] is not None
            and row["mac_address"] != (fields["hwaddr"] or "").lower()
        ):
            raise ValueError("Management MAC is not corroborated")
        if row["mtu"] is not None and str(row["mtu"]) != source["mtu"]:
            raise ValueError("Management MTU is not corroborated")
    except (KeyError, TypeError, ValueError, DiscoveryError) as exc:
        plan["errors"].append("Invalid management facts: %s" % exc)
        return _finish(plan)
    if not identity_verified:
        plan["unresolved"].append(
            {
                "scope": "management",
                "name": row["name"],
                "reason": "Device identity is not verified",
            }
        )
        return _finish(plan)
    plan["unresolved"].extend(deepcopy(facts.get("unresolved", [])))
    matches = [v for v in existing["interfaces"] if v["name"] == row["name"]]
    if len(matches) > 1:
        plan["errors"].append("Management interface name is ambiguous")
        return _finish(plan)
    old = matches[0] if matches else None
    type_value = row["type"]
    if type_value is None:
        templates = [v for v in existing.get("interface_templates", []) if v["name"] == row["name"]]
        if len(templates) == 1:
            type_value = templates[0]["type"]
    values = {
        "name": row["name"],
        "type": type_value,
        "enabled": row["enabled"],
        "description": None,
        "mtu": row["mtu"],
        "mac_address": row["mac_address"],
        "speed": None,
        "duplex": None,
        "port_type": None,
        "mgmt_only": True,
    }
    if old is None:
        if not type_value or type(row["enabled"]) is not bool:
            plan["unresolved"].append(
                {
                    "scope": "management_interface",
                    "name": row["name"],
                    "reason": "New management interface requires reviewed type and enabled state",
                }
            )
        else:
            plan["creates"].append({**values, "source": deepcopy(source)})
    else:
        unsafe = any(
            old.get(v)
            for v in (
                "lag_id",
                "parent_interface_id",
                "module_id",
                "mode",
                "untagged_vlan_id",
                "tagged_vlan_ids",
            )
        )
        changes = []
        if unsafe:
            plan["unresolved"].append(
                {
                    "scope": "management_interface",
                    "name": row["name"],
                    "reason": (
                        "Existing ownership or switching relationships prevent "
                        "management classification"
                    ),
                }
            )
            return _finish(plan)
        for field, value in values.items():
            if field == "name" or value is None:
                continue
            before = old.get(field)
            equal = (
                str(before).lower() == str(value).lower()
                if field == "mac_address"
                else before == value
            )
            if equal:
                continue
            # mgmt_only is an affirmative classification, not an inferred default.
            if before in (None, "") or field == "mgmt_only" and before is False:
                changes.append({"field": field, "before": before, "after": value})
            else:
                plan["conflicts"].append(
                    {
                        "scope": "interface",
                        "name": row["name"],
                        "field": field,
                        "before": before,
                        "observed": value,
                    }
                )
        if changes:
            plan["updates"].append({"id": old["id"], "name": row["name"], "changes": changes})
    policy = (existing.get("ipam_inventory", {}).get("policy") or {}).get("panos_management")
    approved = []
    for address in facts["addresses"]:
        try:
            literal = ip_interface(address["address"])
            evidence = address["source"]
            mode = address["method"]
            if (
                literal.version != address["version"]
                or evidence["command"] != MANAGEMENT_INTERFACE
                or (
                    evidence["applied_command"] != RUNNING_HA
                    or literal.ip.is_link_local
                    or mode not in ("static", "dhcp-client")
                    or literal
                    != ip_interface(
                        evidence["host"]
                        if literal.version == 6
                        else "%s/%s" % (evidence["host"], evidence["mask"])
                    )
                )
            ):
                raise ValueError("Management address provenance is invalid")
            if mode == "static" and literal != ip_interface(
                evidence["configured_host"]
                if literal.version == 6
                else "%s/%s" % (evidence["configured_host"], evidence["configured_mask"])
            ):
                raise ValueError("Management static address lacks applied corroboration")
        except (KeyError, TypeError, ValueError) as exc:
            plan["errors"].append("Invalid management address: %s" % exc)
            continue
        if policy is None or mode == "dhcp-client" and not policy["include_dhcp"]:
            plan["unresolved"].append(
                {
                    "scope": "management_address",
                    "name": str(literal),
                    "reason": (
                        "Select a management Namespace and explicitly opt in to "
                        "DHCP lease inventory"
                    )
                    if mode == "dhcp-client"
                    else "Select a management Namespace",
                }
            )
            continue
        if mode == "dhcp-client":
            inventory = existing["ipam_inventory"]
            if "ip_address_types" in inventory and "dhcp" not in inventory["ip_address_types"]:
                plan["unresolved"].append(
                    {
                        "scope": "management_address",
                        "name": str(literal),
                        "reason": (
                            "Installed IPAddress model cannot represent an observed DHCP lease"
                        ),
                    }
                )
                continue
            assigned_ids = {
                str(v["ip_address_id"])
                for v in inventory.get("ip_assignments", [])
                if old and str(v.get("interface_id")) == str(old["id"])
            }
            if any(
                str(v["id"]) in assigned_ids
                and v["host"] != str(literal.ip)
                and ip_interface(v["host"]).version == literal.version
                for v in inventory.get("ip_addresses", [])
            ):
                plan["unresolved"].append(
                    {
                        "scope": "management_address",
                        "name": str(literal),
                        "reason": (
                            "Management lease changed; preserve existing "
                            "assignments and primary IP for review"
                        ),
                    }
                )
                continue
        approved.append((address, literal))
    if not policy or not approved or (not old and not plan["creates"]):
        return _finish(plan)
    ipv4, ipv6 = [], []
    for address, literal in approved:
        if literal.version == 4:
            ipv4.append(
                {
                    "address": str(literal.ip),
                    "mask": str(literal.network.netmask),
                    "prefix_length": literal.network.prefixlen,
                    "secondary": False,
                    "secondary_known": False,
                    "method": "observed-dhcp-lease"
                    if address["method"] == "dhcp-client"
                    else "configured-static",
                    "source": deepcopy(address["source"]),
                }
            )
        else:
            ipv6.append(
                {
                    "configured_prefix": str(literal),
                    "method": "configured",
                    "eui_64": False,
                    "anycast": False,
                    "source": deepcopy(address["source"]),
                }
            )
    working = deepcopy(existing)
    working["ipam_inventory"]["policy"] = {
        "default_namespace": policy["namespace"],
        "create_missing_prefixes": policy["create_missing_prefixes"],
        "location": policy["location"],
        "location_reason": policy["location_reason"],
    }
    prospective = {
        **interface_plan,
        "interface_creates": interface_plan["interface_creates"] + plan["creates"],
        "interface_updates": interface_plan["interface_updates"] + plan["updates"],
    }
    shared_interface = {"name": row["name"], "vrf": None, "ipv4": ipv4, "ipv6": ipv6}
    plan["ipam_input"] = {
        "interface": deepcopy(shared_interface),
        "target": {"namespace": deepcopy(policy["namespace"]), "vrf": None},
    }
    plan["ipam"] = plan_ipam(
        {
            "ipam": {
                "schema_version": 1,
                "vrfs": [],
                "interfaces": [shared_interface],
            }
        },
        working,
        prospective,
        canonical_name=lambda value: value,
        allowed_ipv4_methods=frozenset({"configured-static", "observed-dhcp-lease"}),
    )
    plan["ipam"]["adapter"] = "panos"
    if policy["fill_primary"]:
        for _address, literal in approved:
            field = "primary_ip%s" % literal.version
            candidates = [
                v
                for v in working["ipam_inventory"]["ip_addresses"]
                if v["host"] == str(literal.ip)
                and str(v["namespace_id"]) == str(policy["namespace"]["id"])
                and v["mask_length"] == literal.network.prefixlen
            ]
            if not any(
                v["host"] == str(literal.ip) and v["namespace_id"] == str(policy["namespace"]["id"])
                for v in plan["ipam"]["ip_addresses"]
            ):
                plan["unresolved"].append(
                    {
                        "scope": "management_primary_ip",
                        "name": str(literal),
                        "reason": (
                            "Management IPAM ownership or routing validation did "
                            "not approve this address"
                        ),
                    }
                )
                continue
            if (
                len(candidates) != 1
                or not old
                or not any(
                    str(v.get("interface_id")) == str(old["id"])
                    and str(v["ip_address_id"]) == str(candidates[0]["id"])
                    for v in working["ipam_inventory"]["ip_assignments"]
                )
            ):
                plan["unresolved"].append(
                    {
                        "scope": "management_primary_ip",
                        "name": str(literal),
                        "reason": (
                            "Primary IP requires a persisted management address "
                            "assignment; repeat discovery after applying inventory"
                        ),
                    }
                )
                continue
            before = existing["device"].get(field + "_id")
            if before is None:
                plan["primary_updates"].append(
                    {
                        "field": field,
                        "before": None,
                        "after": str(candidates[0]["id"]),
                        "host": str(literal.ip),
                    }
                )
            elif str(before) != str(candidates[0]["id"]):
                plan["conflicts"].append(
                    {
                        "scope": "device",
                        "name": existing["device"]["name"],
                        "field": field,
                        "before": before,
                        "observed": str(candidates[0]["id"]),
                    }
                )
    return _finish(plan)


def _finish(plan):
    plan["summary"] = {
        "panos_management_interfaces_created": len(plan["creates"]),
        "panos_management_interfaces_updated": len(plan["updates"]),
        "panos_primary_ips_updated": len(plan["primary_updates"]),
        "unresolved_panos_management": len(plan["unresolved"]),
    }
    return plan
