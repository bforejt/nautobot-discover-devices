"""Explicit PAN-OS routing bindings over the shared static IPAM staging engine.

PAN virtual routers and vsys names are source identities, never native VRF
names. Only literal applied addresses on exact existing logical Interfaces (or
an already approved Ethernet create) enter staging. HA address sharing remains
unresolved until a separate sharing policy is reviewed.
"""

from copy import deepcopy
from ipaddress import ip_interface

from .reconcile_ipam import _finish, plan_ipam
from .transport_ssh import HA_STATE, MANAGEMENT_INTERFACE, RUNNING_HA, RUNNING_VPN, RUNNING_VSYS

CONTRACT = "panos-ipam-v1"
POLICY_CONTRACT = "panos-ipam-policy-v1"
VR_PATH = "result/network/virtual-router/entry/interface/member"
VSYS_PATH = "result/vsys/entry/import/network/interface/member"
VSYS_ROUTER_PATH = "result/vsys/entry/import/network/virtual-router/member"
VSYS_LOGICAL_ROUTER_PATH = "result/vsys/entry/import/network/logical-router/member"
_DYNAMIC_PATHS = {
    "ipv4_dhcp": "dhcp-client",
    "ipv4_pppoe": "pppoe",
    "ipv6_dhcp": "ipv6/dhcp-client",
    "ipv6_pppoe": "ipv6/pppoe",
    "ipv6_inherited": "ipv6/inherited",
}


def canonical_panos_ipam_name(value):
    """Use exact PAN-OS identities, without Cisco abbreviations or case folding."""
    return value if _label(value) else None


def _label(value):
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= 1024
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _membership(source, field, command, path, identity, name):
    observed = source.get(field)
    if identity is None:
        return observed is None
    return (
        isinstance(observed, dict)
        and observed.get("command") == command
        and observed.get("path") == path
        and observed.get("interface") == name
        and observed.get("router" if field == "vr_membership" else "vsys") == identity
    )


def _catalog(raw):
    """Corroborate complete applied member lists and their independent owners."""
    catalogs, owners = {}, {}
    for section, command, path, fields in (
        ("routers", RUNNING_VPN, "result/network/virtual-router/entry", {"interfaces": VR_PATH}),
        (
            "vsys",
            RUNNING_VSYS,
            "result/vsys/entry",
            {
                "imported_interfaces": VSYS_PATH,
                "imported_virtual_routers": VSYS_ROUTER_PATH,
                "imported_logical_routers": VSYS_LOGICAL_ROUTER_PATH,
            },
        ),
    ):
        catalog = {}
        for row in raw[section]:
            name, source = row.get("name"), row.get("source")
            if (
                not _label(name)
                or name in catalog
                or not isinstance(source, dict)
                or source.get("contract") != CONTRACT
                or source.get("command") != command
                or source.get("path") != path
                or source.get("configured_name") != name
                or not isinstance(source.get("fields"), dict)
            ):
                raise ValueError("Routing-domain catalog provenance is invalid")
            catalog[name] = row
            for field, member_path in fields.items():
                members, evidence = row.get(field), source["fields"].get(field)
                if (
                    not isinstance(members, list)
                    or not all(_label(member) for member in members)
                    or len(set(members)) != len(members)
                    or not isinstance(evidence, dict)
                    or evidence.get("path") != member_path
                    or evidence.get("presence") not in {"absent", "value"}
                    or evidence["presence"] == "absent"
                    and members
                ):
                    raise ValueError("Routing-domain catalog member coverage is invalid")
                field_owners = owners.setdefault(field, {})
                for member in members:
                    if member in field_owners:
                        raise ValueError("Routing-domain catalog member ownership is ambiguous")
                    field_owners[member] = name
        catalogs[section] = catalog
    routers = catalogs["routers"]
    imported_routers = owners.get("imported_virtual_routers", {})
    if imported_routers.keys() - routers.keys():
        raise ValueError("Imported virtual-router configuration is missing")
    for name, router in routers.items():
        owner = imported_routers.get(name)
        evidence = router["source"].get("vsys_import")
        if (
            router.get("vsys") != owner
            or (owner is None and evidence is not None)
            or (
                owner is not None
                and (
                    not isinstance(evidence, dict)
                    or evidence.get("command") != RUNNING_VSYS
                    or evidence.get("path") != VSYS_ROUTER_PATH
                    or evidence.get("vsys") != owner
                    or evidence.get("router") != name
                )
            )
        ):
            raise ValueError("Applied virtual-router import provenance is invalid")
    return routers, owners


def _field(source, field, path, value, *, marker=False):
    fields = source.get("fields") if isinstance(source, dict) else None
    entry = fields.get(field) if isinstance(fields, dict) else None
    if not isinstance(entry, dict) or entry.get("path") != path:
        return False
    if marker:
        return (value is None and entry.get("presence") == "absent") or (
            value is True and entry.get("presence") == "marker"
        )
    return (value is None and entry.get("presence") == "absent") or (
        type(value) is bool and entry.get("presence") == "value"
    )


def _address(address, row, version):
    if not isinstance(address, dict) or not isinstance(address.get("address"), str):
        raise ValueError("Malformed literal address")
    literal = address["address"]
    if "/" not in literal or "%" in literal:
        raise ValueError("Literal host and prefix length required")
    configured = ip_interface(literal)
    if configured.version != version or configured.ip.is_unspecified or configured.ip.is_multicast:
        raise ValueError("Invalid address family or host")
    source = address.get("source")
    path = row["source"]["path"] + ("/ip/entry" if version == 4 else "/ipv6/address/entry")
    if (
        not isinstance(source, dict)
        or source.get("contract") != CONTRACT
        or source.get("command") != RUNNING_VPN
        or source.get("path") != path
        or source.get("configured_name") != literal
        or source.get("interface") != row["name"]
        or address.get("host") != str(configured.ip)
        or type(address.get("prefix_length")) is not int
        or address["prefix_length"] != configured.network.prefixlen
        or address.get("network") != str(configured.network)
    ):
        raise ValueError("Literal address provenance is invalid")
    if version == 4:
        return {
            "address": str(configured.ip),
            "mask": str(configured.network.netmask),
            "prefix_length": configured.network.prefixlen,
            "method": "configured-static",
            "secondary": False,
            "secondary_known": False,
            "source": deepcopy(source),
        }
    for field, suffix, marker in (
        ("enable_on_interface", "/enable-on-interface", False),
        ("prefix", "/prefix", True),
        ("anycast", "/anycast", True),
    ):
        if not _field(source, field, path + suffix, address.get(field), marker=marker):
            raise ValueError("IPv6 address flag provenance is invalid")
    return {
        "configured_prefix": literal,
        "method": "configured",
        "eui_64": False,
        "anycast": False,
        "source": deepcopy(source),
    }


def _review_row(row, paths):
    if not isinstance(row, dict) or not _label(row.get("name")):
        raise ValueError("Interface identity is invalid")
    source = row.get("source")
    if (
        row.get("kind") not in paths
        or row.get("mode") != "layer3"
        or not isinstance(source, dict)
        or source.get("contract") != CONTRACT
        or source.get("network_command") != RUNNING_VPN
        or source.get("path") != paths[row["kind"]]
        or source.get("configured_name") != row["name"]
        or not isinstance(source.get("fields"), dict)
        or not isinstance(row.get("ipv4"), list)
        or not isinstance(row.get("ipv6"), list)
        or not isinstance(row.get("addressing"), dict)
    ):
        raise ValueError("Interface applied provenance is invalid")
    for identity in ("virtual_router", "vsys"):
        if row.get(identity) is not None and not _label(row[identity]):
            raise ValueError("Routing-domain identity is invalid")
    if not _membership(
        source, "vr_membership", RUNNING_VPN, VR_PATH, row.get("virtual_router"), row["name"]
    ) or not _membership(
        source, "vsys_import", RUNNING_VSYS, VSYS_PATH, row.get("vsys"), row["name"]
    ):
        raise ValueError("Routing-domain membership provenance is invalid")
    if not _field(
        source, "ipv6_enabled", source["path"] + "/ipv6/enabled", row.get("ipv6_enabled")
    ):
        raise ValueError("IPv6 interface flag provenance is invalid")
    parent = source.get("parent_name")
    if (
        row["kind"] in {"ethernet-subinterface", "aggregate-subinterface"}
        and not _label(parent)
        or row["kind"] not in {"ethernet-subinterface", "aggregate-subinterface"}
        and parent is not None
    ):
        raise ValueError("Applied interface parent provenance is invalid")
    for field, branch in _DYNAMIC_PATHS.items():
        setting = row["addressing"].get(field)
        evidence = setting.get("source") if isinstance(setting, dict) else None
        if (
            not isinstance(setting, dict)
            or type(setting.get("present")) is not bool
            or setting.get("enabled") is not None
            and type(setting["enabled"]) is not bool
            or setting["present"] is False
            and setting.get("enabled") is not None
            or not isinstance(evidence, dict)
            or evidence.get("contract") != CONTRACT
            or evidence.get("command") != RUNNING_VPN
            or evidence.get("path") != source["path"] + "/" + branch
            or evidence.get("configured_name") != row["name"]
        ):
            raise ValueError("Dynamic-addressing evidence is invalid")
    addresses = {}
    for version in (4, 6):
        addresses[version] = [_address(value, row, version) for value in row["ipv%d" % version]]
    return addresses


def _ha_reason(discovery, sharing=None):
    ha = discovery.get("observations", {}).get("ha", {})
    states = []
    for section, command, path in (
        ("configuration", RUNNING_HA, "result/deviceconfig/high-availability/enabled"),
        ("runtime", HA_STATE, "result/enabled"),
    ):
        fact = ha.get(section, {}) if isinstance(ha, dict) else {}
        source = fact.get("source", {}) if isinstance(fact, dict) else {}
        if not isinstance(source, dict):
            source = {}
        enabled = fact.get("enabled") if isinstance(fact, dict) else None
        if enabled is True:
            if (
                isinstance(sharing, dict)
                and sharing.get("contract") == "panos-ha-sharing-v1"
                and isinstance(sharing.get("addresses"), list)
            ):
                return None
            return "HA address sharing requires an explicit reviewed sharing policy"
        if (
            enabled is False
            and source.get("contract") == "panos-ha-v1"
            and source.get("command") == command
            and _field(source, "enabled", path, enabled)
        ):
            states.append(False)
    return (
        None if states else "HA sharing state is unresolved; explicit disabled evidence is required"
    )


def _targets(policy, inventory):
    if policy is None:
        return {}
    if not isinstance(policy, dict) or policy.get("contract") != POLICY_CONTRACT:
        raise ValueError("Unsupported explicit PAN-OS IPAM policy")
    bindings = policy.get("panos_routing_domains")
    if not isinstance(bindings, list):
        raise ValueError("Explicit routing-domain mappings require a list")
    targets = {}
    for binding in bindings:
        if (
            not isinstance(binding, dict)
            or not all(_label(binding.get(key)) for key in ("vsys", "virtual_router"))
            or "vrf" not in binding
        ):
            raise ValueError(
                "Mapping requires exact vsys/router and explicit VRF or global selection"
            )
        key = (binding["vsys"], binding["virtual_router"])
        if key in targets:
            raise ValueError("Several mappings select the same PAN-OS routing domain")
        namespace = binding.get("namespace")
        if not isinstance(namespace, dict) or not namespace.get("id"):
            raise ValueError("Mapping requires an existing Namespace identity")
        matched = [
            row for row in inventory.get("namespaces", []) if str(row["id"]) == str(namespace["id"])
        ]
        if len(matched) != 1:
            raise ValueError("Selected Namespace is missing or ambiguous in the native snapshot")
        vrf = binding["vrf"]
        if vrf is not None:
            if not isinstance(vrf, dict) or not vrf.get("id"):
                raise ValueError(
                    "Mapping requires an existing VRF identity or explicit global selection"
                )
            matched_vrf = [
                row for row in inventory.get("vrfs", []) if str(row["id"]) == str(vrf["id"])
            ]
            if len(matched_vrf) != 1 or str(matched_vrf[0]["namespace_id"]) != str(namespace["id"]):
                raise ValueError("Selected existing VRF and Namespace do not match")
            vrf = matched_vrf[0]
        targets[key] = {"namespace": deepcopy(matched[0]), "vrf": deepcopy(vrf)}
    return targets


def _management_input(value, inventory):
    """Review the canonical management row at the single shared graph boundary."""
    if not isinstance(value, dict) or set(value) != {"interface", "target"}:
        raise ValueError("Management IPAM input requires an exact Interface and target")
    row, target = value["interface"], value["target"]
    if (
        not isinstance(row, dict)
        or not _label(row.get("name"))
        or row.get("vrf") is not None
        or not isinstance(row.get("ipv4"), list)
        or not isinstance(row.get("ipv6"), list)
        or not isinstance(target, dict)
        or set(target) != {"namespace", "vrf"}
        or target["vrf"] is not None
        or not isinstance(target["namespace"], dict)
        or not target["namespace"].get("id")
    ):
        raise ValueError("Management IPAM input requires an exact global Namespace selection")
    namespaces = [
        namespace
        for namespace in inventory.get("namespaces", [])
        if str(namespace["id"]) == str(target["namespace"]["id"])
    ]
    if len(namespaces) != 1:
        raise ValueError("Management Namespace is missing or ambiguous in the native snapshot")
    for version in (4, 6):
        for address in row["ipv%d" % version]:
            source = address.get("source") if isinstance(address, dict) else None
            method = address.get("method") if isinstance(address, dict) else None
            if (
                not isinstance(source, dict)
                or source.get("command") != MANAGEMENT_INTERFACE
                or source.get("applied_command") != RUNNING_HA
                or source.get("path") != "result/info/" + ("ip" if version == 4 else "ipv6")
                or method
                not in (
                    {"configured-static", "observed-dhcp-lease"} if version == 4 else {"configured"}
                )
            ):
                raise ValueError(
                    "Only canonical reviewed management addresses enter the shared graph"
                )
            applied_path = "result/deviceconfig/system/"
            if method == "observed-dhcp-lease":
                applied_path += "type/dhcp-client"
                if source.get("applied_dhcp_client_present") is not True:
                    raise ValueError("Management DHCP lease lacks explicit applied mode evidence")
            else:
                applied_path += "ip-address" if version == 4 else "ipv6-address"
            if source.get("applied_path") != applied_path:
                raise ValueError(
                    "Management address method does not match applied source provenance"
                )
    return deepcopy(row), {"namespace": deepcopy(namespaces[0]), "vrf": None}


def plan_panos_ipam(
    discovery, existing, interface_plan=None, *, ha_plan=None, management_input=None
):
    """Validate explicit PAN evidence, then delegate all static staging to plan_ipam."""
    plan = plan_ipam({"ipam": None}, existing)
    plan["adapter"] = "panos"
    raw = discovery.get("ipam")
    if raw is None:
        return plan
    from .adapters.panos_ipam import INTERFACE_PATHS, reviewed_interface_identity

    if (
        not isinstance(raw, dict)
        or raw.get("contract") != CONTRACT
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
        or any(
            not isinstance(raw.get(field), list)
            for field in ("interfaces", "routers", "vsys", "unresolved", "excluded", "sources")
        )
        or any(
            not isinstance(row, dict)
            for field in ("routers", "vsys", "unresolved", "excluded", "sources")
            for row in raw.get(field, [])
        )
    ):
        plan["errors"].append("Unsupported PAN-OS structured IPAM evidence")
        return _finish(plan)
    plan["sources"] = deepcopy(raw["sources"])
    plan["unresolved"] = deepcopy(raw["unresolved"])
    reviewed, names = [], set()
    try:
        expected = {(RUNNING_VPN, "result/network"), (RUNNING_VSYS, "result/vsys")}
        if (
            len(raw["sources"]) != 2
            or {
                (source.get("command"), source.get("path"))
                for source in raw["sources"]
                if source.get("contract") == CONTRACT
            }
            != expected
        ):
            raise ValueError("Complete applied source provenance is invalid")
        routers, owners = _catalog(raw)
        for row in raw["interfaces"]:
            addresses = _review_row(row, INTERFACE_PATHS)
            if not reviewed_interface_identity(row):
                plan["unresolved"].append(
                    {
                        "scope": "interface",
                        "name": row["name"],
                        "reason": (
                            "Configured Interface family or parent identity "
                            "is outside the reviewed contract"
                        ),
                        "source": deepcopy(row["source"]),
                    }
                )
                continue
            if row["name"] in names:
                raise ValueError("Duplicate exact interface identity")
            names.add(row["name"])
            if row.get("virtual_router") != owners.get("interfaces", {}).get(row["name"]):
                raise ValueError("Applied virtual-router member coverage is invalid")
            if row.get("vsys") != owners.get("imported_interfaces", {}).get(row["name"]):
                raise ValueError("Applied vsys import coverage is invalid")
            router_vsys = routers.get(row.get("virtual_router"), {}).get("vsys")
            if (
                row.get("vsys") is not None
                and router_vsys is not None
                and row["vsys"] != router_vsys
            ):
                raise ValueError("Applied interface and router imports disagree")
            reviewed.append((row, addresses))
    except (ValueError, TypeError, KeyError):
        plan["errors"].append("PAN-OS IPAM source has malformed or ambiguous applied provenance")
        return _finish(plan)
    inventory = existing.get("ipam_inventory", {})
    plan["policy"] = inventory.get("policy")
    if not inventory.get("supported", False):
        reason = inventory.get("reason") or "IPAM inventory is unavailable"
        for row, _ in reviewed:
            plan["unresolved"].append({"scope": "interface", "name": row["name"], "reason": reason})
        return _finish(plan)
    try:
        bindings = _targets(inventory.get("policy"), inventory)
    except (ValueError, TypeError, KeyError):
        plan["errors"].append(
            "PAN-OS IPAM mappings do not identify existing unambiguous native targets"
        )
        return _finish(plan)
    eligible = {}
    for interface in existing.get("interfaces", []):
        name = canonical_panos_ipam_name(interface.get("name"))
        eligible[name] = eligible.get(name, 0) + 1
    approved_creates = {
        canonical_panos_ipam_name(row.get("name"))
        for row in (interface_plan or {}).get("interface_creates", [])
    }
    from .adapters.panos_logical import canonical_row

    reviewed_logical_creates = {}
    for create in (interface_plan or {}).get("interface_creates", []):
        source = create.get("source") or {}
        if source.get("contract") != "panos-logical-interfaces-v1":
            continue
        try:
            fact = canonical_row(source.get("evidence"))
            if (
                source == fact["source"]
                and create.get("name") == fact["name"]
                and create.get("type") == fact["type"]
                and type(create.get("enabled")) is bool
                and create["enabled"] is fact["enabled"]
            ):
                reviewed_logical_creates[fact["name"]] = fact
        except (KeyError, TypeError, ValueError):
            continue
    normalized, routing_targets = [], {}
    sharing = None
    if ha_plan is not None:
        from .reconcile_panos_ha import plan_panos_ha

        # A supplied sharing list is never trusted as a Boolean override. Its
        # complete pair/UUID/applied-address/native-interface proof must still
        # produce exactly the proposed sharing list against this same snapshot.
        reviewed_ha = plan_panos_ha(discovery, existing, identity_verified=True)
        if (
            not isinstance(ha_plan, dict)
            or ha_plan.get("contract") != "panos-native-ha-v1"
            or reviewed_ha["errors"]
            or ha_plan.get("sharing") != reviewed_ha["sharing"]
        ):
            plan["errors"].append(
                "PAN-OS HA sharing policy does not match independently reviewed pair provenance"
            )
            return _finish(plan)
        sharing = reviewed_ha["sharing"]
    ha_reason = _ha_reason(discovery, sharing)
    shared = (
        {
            (str(row["namespace_id"]), row["host"], row["mask_length"], row["interface_name"])
            for row in sharing["addresses"]
        }
        if sharing is not None
        else set()
    )
    for row, addresses in reviewed:
        name = row["name"]
        setting = {
            key: deepcopy(row.get(key))
            for key in ("name", "vsys", "virtual_router", "ipv4", "ipv6", "source")
        }
        plan["settings"].append(setting)
        if not row["ipv4"] and not row["ipv6"]:
            continue
        reason = ha_reason
        if reason is None and (row.get("vsys") is None or row.get("virtual_router") is None):
            reason = "Applied interface requires unambiguous vsys and virtual-router membership"
        target = bindings.get((row.get("vsys"), row.get("virtual_router")))
        if reason is None and target is None:
            reason = (
                "Select an explicit existing Namespace and VRF or global routing-domain mapping"
            )
        if reason is None and not (
            eligible.get(name) == 1
            or (
                eligible.get(name, 0) == 0
                and name in approved_creates
                and (
                    row["kind"] == "ethernet"
                    or (
                        name in reviewed_logical_creates
                        and row["kind"] == reviewed_logical_creates[name]["kind"]
                        and row["mode"] == reviewed_logical_creates[name]["mode"]
                    )
                )
            )
        ):
            reason = "IPAM requires an exact existing Interface or reviewed interface create"
        if reason:
            plan["unresolved"].append({"scope": "interface", "name": name, "reason": reason})
            continue
        allowed = {4: [], 6: []}
        for version in (4, 6):
            dynamic = [
                value
                for key, value in row["addressing"].items()
                if key.startswith("ipv%d_" % version)
            ]
            blocked = any(
                value["enabled"] is True or (value["present"] and value["enabled"] is None)
                for value in dynamic
            )
            if version == 6 and row.get("ipv6_enabled") is not True:
                blocked = True
            for original, address in zip(row["ipv%d" % version], addresses[version]):
                if (
                    blocked
                    or version == 6
                    and (
                        original.get("enable_on_interface") is not True
                        or original.get("prefix") is True
                        or original.get("anycast") is True
                    )
                ):
                    plan["unresolved"].append(
                        {
                            "scope": "ip_address",
                            "name": original["address"],
                            "interface": name,
                            "reason": (
                                "Dynamic, disabled, generated or shared address "
                                "evidence is observation-only"
                            ),
                            "source": deepcopy(original["source"]),
                        }
                    )
                else:
                    configured = ip_interface(original["address"])
                    if (
                        sharing is not None
                        and (
                            str(target["namespace"]["id"]),
                            str(configured.ip),
                            configured.network.prefixlen,
                            name,
                        )
                        not in shared
                    ):
                        plan["unresolved"].append(
                            {
                                "scope": "ip_address",
                                "name": original["address"],
                                "interface": name,
                                "reason": (
                                    "HA address ownership is not independently proven "
                                    "on both selected peers"
                                ),
                                "source": deepcopy(original["source"]),
                            }
                        )
                        continue
                    allowed[version].append(address)
        if not allowed[4] and not allowed[6]:
            continue
        normalized.append(
            {
                "name": name,
                "vrf": None,
                "ipv4": allowed[4],
                "ipv6": allowed[6],
                "source": deepcopy(row["source"]),
            }
        )
        routing_targets[name] = target
    if management_input is not None:
        try:
            management_row, management_target = _management_input(management_input, inventory)
        except (ValueError, TypeError, KeyError):
            plan["errors"].append(
                "Management IPAM input lacks reviewed source or native target provenance"
            )
            return _finish(plan)
        if management_row["name"] in routing_targets:
            plan["errors"].append("Management and data-plane Interface identities are ambiguous")
            return _finish(plan)
        normalized.append(management_row)
        routing_targets[management_row["name"]] = management_target
        plan["sources"].append({"command": MANAGEMENT_INTERFACE, "path": "result/info"})
    options = {}
    if management_input is not None:
        options["allowed_ipv4_methods"] = frozenset({"configured-static", "observed-dhcp-lease"})
    delegated = plan_ipam(
        {
            "ipam": {
                "schema_version": 1,
                "interfaces": normalized,
                "vrfs": [],
                "unresolved": plan["unresolved"],
                "sources": plan["sources"],
            }
        },
        existing,
        interface_plan,
        canonical_name=canonical_panos_ipam_name,
        routing_targets=routing_targets,
        approved_shared_assignments=sharing["addresses"] if sharing is not None else (),
        **options,
    )
    delegated["adapter"] = "panos"
    delegated["settings"] = plan["settings"] + delegated["settings"]
    return _finish(delegated)
