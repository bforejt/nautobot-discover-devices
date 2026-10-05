"""Source-bound PAN-OS HA relationships and narrowly reviewed shared addresses.

This planner is independent of models and transport. A selected peer is never
derived from its name, management address, HA link address or blank serial.
"""

import ipaddress
import re
from copy import deepcopy

from .adapters.panos import canonical_vm_uuid
from .panos_ha_policy import CONTRACT as POLICY_CONTRACT
from .transport_ssh import HA_STATE, RUNNING_HA, RUNNING_VPN, RUNNING_VSYS, SYSTEM_INFO

CONTRACT = "panos-native-ha-v1"
PAIR_CONTRACT = "panos-ha-pair-v1"
SHARING_CONTRACT = "panos-ha-sharing-v1"
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
_CONFIG = "result/deviceconfig/high-availability/"


def _field(source, name, path):
    entry = source.get("fields", {}).get(name)
    if not isinstance(entry, dict) or entry.get("path") != path or entry.get("presence") != "value":
        raise ValueError("PAN-OS HA required field lacks exact explicit source provenance")


def _source(fact, command, path):
    source = fact.get("source") if isinstance(fact, dict) else None
    if (
        not isinstance(source, dict)
        or source.get("contract") != "panos-ha-v1"
        or source.get("command") != command
        or source.get("path") != path
        or not isinstance(source.get("fields"), dict)
    ):
        raise ValueError("PAN-OS HA source provenance is invalid")
    return source


def _host(value):
    if not isinstance(value, str) or not value or "%" in value:
        raise ValueError("PAN-OS HA requires explicit literal link identities")
    parsed = ipaddress.ip_interface(value) if "/" in value else ipaddress.ip_address(value)
    address = (
        parsed.ip
        if isinstance(parsed, (ipaddress.IPv4Interface, ipaddress.IPv6Interface))
        else parsed
    )
    if address.is_unspecified or address.is_multicast:
        raise ValueError("PAN-OS HA has an unsupported link or management identity")
    return str(address)


def _identity(discovery, native, expected_uuid=None):
    if not isinstance(discovery, dict) or discovery.get("adapter") != "panos":
        raise ValueError("PAN-OS HA peer requires independent Palo discovery")
    identity = discovery.get("identity", {})
    binding = discovery.get("identity_binding", {})
    source = discovery.get("sources", {}).get("identity", {})
    system = discovery.get("observations", {}).get("system", {})
    if not all(isinstance(value, dict) for value in (identity, binding, source, system, native)):
        raise ValueError("PAN-OS HA VM identity provenance is invalid")
    manufacturer = str(native.get("manufacturer_name") or "").lower()
    manufacturer = manufacturer.replace(" ", "").replace("-", "")
    driver = str(native.get("platform_network_driver") or "").lower()
    platform = str(native.get("platform_name") or "").lower()
    platform = platform.replace("-", "").replace("_", "").replace(" ", "")
    if manufacturer not in {"paloalto", "paloaltonetworks"} or not (
        driver in {"paloalto_panos", "panos"}
        or not driver
        and platform in {"panos", "paloaltopanos"}
    ):
        raise ValueError("PAN-OS HA existing peer catalog identity must be Palo Alto PAN-OS")
    serial = native.get("serial")
    if (
        serial is not None
        and (not isinstance(serial, str) or serial.strip())
        and serial != identity.get("serial")
    ):
        raise ValueError(
            "PAN-OS HA populated native peer serial differs from independent Palo identity"
        )
    observed = canonical_vm_uuid(system.get("vm-uuid"))
    expected = canonical_vm_uuid(
        expected_uuid if expected_uuid is not None else binding.get("expected_uuid")
    )
    if (
        binding.get("contract") != "panos-vm-identity-v1"
        or binding.get("system_command") != SYSTEM_INFO
        or binding.get("system_path") != "result/system"
        or source.get("command") != SYSTEM_INFO
        or source.get("path") != "result/system"
        or expected is None
        or observed != expected
        or canonical_vm_uuid(binding.get("observed_uuid")) != expected
        or canonical_vm_uuid(binding.get("expected_uuid")) != expected
        or binding.get("model") != identity.get("model")
        or identity.get("model") != native.get("model")
        or identity.get("model") != "PA-VM"
        or binding.get("family") != system.get("family")
        or system.get("family") != "vm"
        or not isinstance(system.get("vm-mode"), str)
        or not system["vm-mode"]
        or binding.get("vm_mode") != system["vm-mode"]
    ):
        raise ValueError(
            "PAN-OS HA explicit selected peer UUID does not match Palo system identity"
        )
    return observed


def _ha(discovery):
    observations = discovery.get("observations", {})
    ha = observations.get("ha", {}) if isinstance(observations, dict) else {}
    configuration = ha.get("configuration") if isinstance(ha, dict) else None
    runtime = ha.get("runtime") if isinstance(ha, dict) else None
    configured_source = _source(configuration, RUNNING_HA, "result/deviceconfig")
    runtime_source = _source(runtime, HA_STATE, "result")
    for fact, source, name, path, expected in (
        (configuration, configured_source, "enabled", _CONFIG + "enabled", True),
        (
            configuration,
            configured_source,
            "mode",
            _CONFIG + "group/mode/active-passive",
            "active-passive",
        ),
        (runtime, runtime_source, "enabled", "result/enabled", True),
        (runtime, runtime_source, "mode", "result/group/mode", "Active-Passive"),
    ):
        _field(source, name, path)
        if type(fact.get(name)) is not type(expected) or fact.get(name) != expected:
            raise ValueError(
                "Only explicit enabled active/passive PAN-OS HA has a reviewed writer contract"
            )
    _field(configured_source, "group_id", _CONFIG + "group/group-id")
    if type(configuration.get("group_id")) is not int or configuration["group_id"] <= 0:
        raise ValueError("PAN-OS HA requires an explicit positive configured group identity")
    for name, path, value, expected in (
        (
            "peer_connection_status",
            "result/group/peer-info/conn-status",
            runtime.get("peer_connection_status"),
            "up",
        ),
        (
            "synchronization.running_config_enabled",
            "result/group/running-sync-enabled",
            runtime.get("synchronization", {}).get("running_config_enabled"),
            True,
        ),
        (
            "synchronization.running_config_status",
            "result/group/running-sync",
            runtime.get("synchronization", {}).get("running_config_status"),
            "synchronized",
        ),
        (
            "synchronization.state_status",
            "result/group/local-info/state-sync",
            runtime.get("synchronization", {}).get("state_status"),
            "Complete",
        ),
    ):
        _field(runtime_source, name, path)
        if type(value) is not type(expected) or value != expected:
            raise ValueError(
                "PAN-OS HA peer connection and synchronization must be explicit and healthy"
            )
    for name, path in (
        ("running_config_enabled", "configuration-synchronization/enabled"),
        ("state_enabled", "state-synchronization/enabled"),
    ):
        _field(configured_source, "synchronization." + name, _CONFIG + "group/" + path)
        if configuration.get("synchronization", {}).get(name) is not True:
            raise ValueError(
                "PAN-OS HA configuration and state synchronization must both be enabled"
            )
    for side in ("local", "peer"):
        prefix = "result/group/" + side + "-info/"
        for name, path in (
            ("role", "state"),
            ("mode", "mode"),
            ("management_ip", "mgmt-ip"),
            ("platform", "platform-model"),
            ("software_version", "build-rel"),
            ("priority", "priority"),
        ):
            _field(runtime_source, side + "." + name, prefix + path)
        node = runtime.get(side, {})
        if node.get("mode") != "Active-Passive" or node.get("role") not in ("active", "passive"):
            raise ValueError("PAN-OS HA requires explicit stable active and passive roles")
        _host(node.get("management_ip"))
        if type(node.get("priority")) is not int or not 0 <= node["priority"] <= 255:
            raise ValueError("PAN-OS HA reported election priority is invalid")
    _field(
        configured_source,
        "election.device_priority",
        _CONFIG + "group/election-option/device-priority",
    )
    configured_priority = configuration.get("election", {}).get("device_priority")
    if type(configured_priority) is not int or configured_priority != runtime["local"]["priority"]:
        raise ValueError("PAN-OS HA applied and runtime local priorities disagree")
    for name in ("ha1", "ha2"):
        link = runtime.get("links", {}).get(name, {})
        _field(configured_source, name + ".port", _CONFIG + "interface/" + name + "/port")
        for field, path in (
            ("local_port", "result/group/local-info/" + name + "-port"),
            ("local_mac", "result/group/local-info/" + name + "-macaddr"),
            ("peer_mac", "result/group/peer-info/" + name + "-macaddr"),
            ("peer_status", "result/group/peer-info/conn-" + name + "/conn-status"),
        ):
            _field(runtime_source, name + "." + field, path)
        if link.get("peer_status") != "up" or link.get("local_port") != configuration.get(
            "interfaces", {}
        ).get(name, {}).get("port"):
            raise ValueError("PAN-OS HA applied port and healthy runtime link must match")
        for field in ("local_mac", "peer_mac"):
            if (
                not isinstance(link.get(field), str)
                or _MAC.fullmatch(link[field]) is None
                or link[field] == "00:00:00:00:00:00"
                or int(link[field].split(":")[0], 16) & 1
            ):
                raise ValueError("PAN-OS HA link lacks an explicit valid MAC identity")
    _field(configured_source, "peer_ip", _CONFIG + "group/peer-ip")
    for field, path in (
        ("ip_address", _CONFIG + "interface/ha1/ip-address"),
        ("netmask", _CONFIG + "interface/ha1/netmask"),
    ):
        _field(configured_source, "ha1." + field, path)
    for field, side in (("local_ip", "local"), ("peer_ip", "peer")):
        _field(runtime_source, "ha1." + field, "result/group/" + side + "-info/ha1-ipaddr")
    ha1 = configuration.get("interfaces", {}).get("ha1", {})
    local_host = _host(ha1.get("ip_address"))
    local_runtime = runtime["links"]["ha1"].get("local_ip")
    if not isinstance(local_runtime, str) or "/" not in local_runtime:
        raise ValueError("PAN-OS HA requires an explicit runtime HA1 link prefix")
    local_interface = ipaddress.ip_interface(local_runtime)
    if (
        local_interface.version != 4
        or str(local_interface.ip) != local_host
        or str(local_interface.network.netmask) != ha1.get("netmask")
    ):
        raise ValueError("PAN-OS HA applied and runtime HA1 addressing disagree")
    if _host(configuration.get("peer_ip")) != _host(runtime["links"]["ha1"].get("peer_ip")):
        raise ValueError("PAN-OS HA applied and runtime peer HA1 identity disagree")
    return configuration, runtime


def verify_panos_ha_pair(discovery, inventory):
    """Verify explicit native selections against independently collected Palo facts."""
    pair = discovery.get("ha_pair")
    policy = inventory.get("policy") if isinstance(inventory, dict) else None
    if (
        not isinstance(pair, dict)
        or pair.get("contract") != PAIR_CONTRACT
        or not isinstance(policy, dict)
        or policy.get("contract") != POLICY_CONTRACT
        or pair.get("policy") != policy
    ):
        raise ValueError("PAN-OS HA requires the explicit reviewed existing-peer selection")
    selected_id, peer_id = (
        str(policy.get("selected_device_id")),
        str(policy.get("peer_device", {}).get("id")),
    )
    if selected_id == peer_id:
        raise ValueError("PAN-OS HA selected and peer Device identities must differ")
    devices = inventory.get("devices", [])
    if not isinstance(devices, list) or any(not isinstance(row, dict) for row in devices):
        raise ValueError("PAN-OS HA native Device snapshot is invalid")
    selected = [row for row in devices if str(row.get("id")) == selected_id]
    peers = [row for row in devices if str(row.get("id")) == peer_id]
    if len(selected) != 1 or len(peers) != 1:
        raise ValueError("PAN-OS HA requires both explicitly selected existing Devices")
    peer_discovery = pair.get("peer_discovery")
    selected_uuid = _identity(discovery, selected[0])
    peer_uuid = _identity(peer_discovery, peers[0], policy.get("peer_vm_uuid"))
    if selected_uuid == peer_uuid:
        raise ValueError("PAN-OS HA peers must expose distinct explicit VM UUIDs")
    local_config, local_runtime = _ha(discovery)
    peer_config, peer_runtime = _ha(peer_discovery)
    if local_config["group_id"] != peer_config["group_id"]:
        raise ValueError("PAN-OS HA applied group identities are not reciprocal")
    for local, other in ((local_runtime, peer_runtime), (peer_runtime, local_runtime)):
        if (
            local["local"]["role"] != other["peer"]["role"]
            or local["peer"]["role"] != other["local"]["role"]
            or local["local"]["role"] == local["peer"]["role"]
        ):
            raise ValueError("PAN-OS HA active/passive peer roles are not reciprocal")
        for field in ("management_ip", "platform", "software_version", "priority", "serial"):
            observed, expected = local["peer"].get(field), other["local"].get(field)
            if field == "management_ip":
                observed, expected = _host(observed), _host(expected)
            if observed != expected:
                raise ValueError("PAN-OS HA peer runtime identity is not reciprocal")
        for name in ("ha1", "ha2"):
            if (
                local["links"][name]["peer_mac"] != other["links"][name]["local_mac"]
                or local["links"][name]["local_mac"] == local["links"][name]["peer_mac"]
            ):
                raise ValueError("PAN-OS HA link MAC identities are not reciprocal")
        if _host(local["links"]["ha1"]["peer_ip"]) != _host(other["links"]["ha1"]["local_ip"]):
            raise ValueError("PAN-OS HA1 peer addresses are not reciprocal")
    if _host(local_runtime["local"]["management_ip"]) == _host(
        peer_runtime["local"]["management_ip"]
    ):
        raise ValueError("PAN-OS HA management identities must remain distinct")
    if _host(local_runtime["links"]["ha1"]["local_ip"]) == _host(
        peer_runtime["links"]["ha1"]["local_ip"]
    ):
        raise ValueError("PAN-OS HA1 local identities must remain distinct")
    for observed, runtime in ((discovery, local_runtime), (peer_discovery, peer_runtime)):
        identity = observed["identity"]
        if runtime["local"]["platform"] != identity.get("model") or runtime["local"][
            "software_version"
        ] != identity.get("software_version"):
            raise ValueError("PAN-OS HA local runtime and independent system identity disagree")
        if (identity.get("serial") or None) != runtime["local"].get("serial"):
            raise ValueError("PAN-OS HA local serial and independent system identity disagree")
    return {
        "policy": deepcopy(policy),
        "selected_device": selected[0],
        "peer_device": peers[0],
        "selected_uuid": selected_uuid,
        "peer_uuid": peer_uuid,
        "configured_group_id": local_config["group_id"],
        "priorities": {
            selected_id: local_runtime["local"]["priority"],
            peer_id: peer_runtime["local"]["priority"],
        },
        "excluded_hosts": {
            _host(row["local"]["management_ip"]) for row in (local_runtime, peer_runtime)
        }
        | {_host(row["links"]["ha1"]["local_ip"]) for row in (local_runtime, peer_runtime)},
        "peer_discovery": peer_discovery,
    }


def _ipam_rows(discovery):
    # Lazy imports avoid a cycle with the PAN IPAM adapter's HA gate.
    from .adapters.panos_ipam import INTERFACE_PATHS, reviewed_interface_identity
    from .reconcile_panos_ipam import _catalog, _review_row

    raw = discovery.get("ipam")
    if (
        not isinstance(raw, dict)
        or raw.get("contract") != "panos-ipam-v1"
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
        or any(
            not isinstance(raw.get(name), list)
            for name in ("interfaces", "routers", "vsys", "sources", "unresolved", "excluded")
        )
        or len(raw["sources"]) != 2
        or {
            (source.get("command"), source.get("path"))
            for source in raw["sources"]
            if isinstance(source, dict) and source.get("contract") == "panos-ipam-v1"
        }
        != {(RUNNING_VPN, "result/network"), (RUNNING_VSYS, "result/vsys")}
    ):
        raise ValueError("PAN-OS HA shared addresses require complete applied IPAM sources")
    routers, owners = _catalog(raw)
    result = {}
    for row in raw["interfaces"]:
        _review_row(row, INTERFACE_PATHS)
        name = row["name"]
        if name in result:
            raise ValueError("PAN-OS HA applied interface names are ambiguous")
        if not reviewed_interface_identity(row):
            continue
        if row.get("virtual_router") != owners.get("interfaces", {}).get(name) or row.get(
            "vsys"
        ) != owners.get("imported_interfaces", {}).get(name):
            raise ValueError("PAN-OS HA shared interface routing membership provenance is invalid")
        router_vsys = routers.get(row.get("virtual_router"), {}).get("vsys")
        if router_vsys is not None and row.get("vsys") is not None and router_vsys != row["vsys"]:
            raise ValueError("PAN-OS HA shared interface and router vsys memberships disagree")
        result[name] = row
    return result


def _address_signature(row):
    addresses = []
    for version in (4, 6):
        dynamic = [
            value for key, value in row["addressing"].items() if key.startswith("ipv%d_" % version)
        ]
        blocked = any(
            value["enabled"] is True or value["present"] and value["enabled"] is None
            for value in dynamic
        )
        if version == 6 and row.get("ipv6_enabled") is not True:
            blocked = True
        for address in row["ipv%d" % version]:
            if (
                blocked
                or version == 6
                and (
                    address.get("enable_on_interface") is not True
                    or address.get("prefix") is True
                    or address.get("anycast") is True
                )
            ):
                continue
            addresses.append((version, address["host"], address["prefix_length"]))
    if len(set(addresses)) != len(addresses):
        raise ValueError("PAN-OS HA shared static address declarations are duplicated")
    return sorted(addresses)


def _sharing(discovery, existing, verified, plan):
    from .reconcile_panos_ipam import _targets

    sharing = {
        "contract": SHARING_CONTRACT,
        "selected_device_id": verified["policy"]["selected_device_id"],
        "peer_device_id": verified["policy"]["peer_device"]["id"],
        "redundancy_group_id": verified["policy"]["redundancy_group"]["id"],
        "addresses": [],
    }
    local_rows, peer_rows = _ipam_rows(discovery), _ipam_rows(verified["peer_discovery"])
    inventory = existing.get("ipam_inventory", {})
    if inventory.get("supported") is not True or inventory.get("policy") is None:
        return sharing
    targets = _targets(inventory["policy"], inventory)
    peer_interfaces = existing["ha_inventory"].get("peer_interfaces", [])
    if not isinstance(peer_interfaces, list) or any(
        not isinstance(row, dict) for row in peer_interfaces
    ):
        raise ValueError("PAN-OS HA native peer Interface snapshot is invalid")
    for name, row in local_rows.items():
        signatures = _address_signature(row)
        if not signatures:
            continue
        peer = peer_rows.get(name)
        matching = [
            item
            for item in peer_interfaces
            if item.get("name") == name and str(item.get("device_id")) == sharing["peer_device_id"]
        ]
        reason = None
        if (
            peer is None
            or any(
                peer.get(field) != row.get(field)
                for field in ("kind", "mode", "vsys", "virtual_router", "ipv6_enabled")
            )
            or peer["source"].get("parent_name") != row["source"].get("parent_name")
            or _address_signature(peer) != signatures
        ):
            reason = (
                "HA shared addresses require matching applied static configuration "
                "on both explicitly selected peers"
            )
        elif len(matching) != 1 or not matching[0].get("id"):
            reason = "HA shared addressing requires an exact existing peer Interface"
        target = targets.get((row.get("vsys"), row.get("virtual_router")))
        if reason is None and (
            target is None or row.get("vsys") is None or row.get("virtual_router") is None
        ):
            reason = "HA shared addressing requires explicit existing routing-domain targets"
        if (
            reason is None
            and matching[0].get("vrf_id") is not None
            and str(matching[0]["vrf_id"])
            != str(target["vrf"]["id"] if target["vrf"] is not None else None)
        ):
            reason = (
                "Preserved peer Interface VRF intent conflicts "
                "with the explicit shared routing domain"
            )
        if reason:
            plan["unresolved"].append(
                {"scope": "ha_shared_interface", "name": name, "reason": reason}
            )
            continue
        for version, host, mask_length in signatures:
            if host in verified["excluded_hosts"]:
                plan["unresolved"].append(
                    {
                        "scope": "ha_shared_address",
                        "name": host,
                        "interface": name,
                        "reason": (
                            "Management and HA-link addresses are never "
                            "treated as shared data-plane addresses"
                        ),
                    }
                )
                continue
            sharing["addresses"].append(
                {
                    "namespace_id": str(target["namespace"]["id"]),
                    "host": host,
                    "mask_length": mask_length,
                    "interface_name": name,
                    "peer_interface_id": str(matching[0]["id"]),
                    "peer_interface_name": name,
                    "peer_device_id": sharing["peer_device_id"],
                    "version": version,
                    "source": {
                        "selected": deepcopy(row["source"]),
                        "peer": deepcopy(peer["source"]),
                    },
                }
            )
    sharing["addresses"].sort(
        key=lambda row: (row["namespace_id"], row["host"], row["interface_name"])
    )
    return sharing


def plan_panos_ha(discovery, existing, *, identity_verified=False):
    plan = {
        "contract": CONTRACT,
        "policy": None,
        "group_updates": [],
        "device_updates": [],
        "sharing": None,
        "observed": None,
        "unresolved": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "summary": {
            "ha_groups_updated": 0,
            "ha_devices_updated": 0,
            "ha_shared_addresses_reviewed": 0,
            "unresolved_ha": 0,
        },
    }
    if discovery.get("adapter") != "panos" or discovery.get("ha_pair") is None:
        return plan
    inventory = existing.get("ha_inventory", {})
    if identity_verified is not True:
        plan["unresolved"].append(
            {
                "scope": "ha_pair",
                "reason": "Validated selected PAN-OS Device identity is required for HA ownership",
            }
        )
    elif not isinstance(inventory, dict) or inventory.get("supported") is not True:
        plan["unresolved"].append(
            {
                "scope": "ha_pair",
                "reason": (inventory.get("reason") if isinstance(inventory, dict) else None)
                or "Native DeviceRedundancyGroup capability is unavailable",
            }
        )
    else:
        try:
            verified = verify_panos_ha_pair(discovery, inventory)
            policy = verified["policy"]
            plan["policy"] = policy
            group = inventory.get("group")
            if (
                not isinstance(group, dict)
                or str(group.get("id")) != policy["redundancy_group"]["id"]
            ):
                raise ValueError("PAN-OS HA explicit existing redundancy group is unavailable")
            pair_ids = {policy["selected_device_id"], policy["peer_device"]["id"]}
            members = inventory.get("group_member_ids")
            if not isinstance(members, list) or any(str(item) not in pair_ids for item in members):
                raise ValueError(
                    "PAN-OS HA selected redundancy group has members outside the explicit pair"
                )
            strategy = group.get("failover_strategy")
            if strategy not in ("", "active-passive"):
                raise ValueError(
                    "PAN-OS HA selected native group has a conflicting failover strategy"
                )
            if strategy == "":
                plan["group_updates"].append(
                    {
                        "id": group["id"],
                        "changes": [
                            {"field": "failover_strategy", "before": "", "after": "active-passive"}
                        ],
                    }
                )
            ownership_conflict = False
            for device in (verified["selected_device"], verified["peer_device"]):
                changes = []
                before = device.get("device_redundancy_group_id")
                if before is None:
                    changes.append(
                        {
                            "field": "device_redundancy_group_id",
                            "before": None,
                            "after": group["id"],
                        }
                    )
                elif str(before) != str(group["id"]):
                    plan["conflicts"].append(
                        {
                            "scope": "ha_device",
                            "name": device.get("name"),
                            "field": "device_redundancy_group_id",
                            "before": before,
                            "observed": group["id"],
                        }
                    )
                    ownership_conflict = True
                priority = verified["priorities"][str(device["id"])]
                before_priority = device.get("device_redundancy_group_priority")
                if priority < 1:
                    plan["unresolved"].append(
                        {
                            "scope": "ha_priority",
                            "name": device.get("name"),
                            "reason": (
                                "Native redundancy priority cannot represent "
                                "the explicitly reported zero priority"
                            ),
                        }
                    )
                elif before_priority is None:
                    changes.append(
                        {
                            "field": "device_redundancy_group_priority",
                            "before": None,
                            "after": priority,
                        }
                    )
                elif type(before_priority) is not int or before_priority != priority:
                    plan["conflicts"].append(
                        {
                            "scope": "ha_device",
                            "name": device.get("name"),
                            "field": "device_redundancy_group_priority",
                            "before": before_priority,
                            "observed": priority,
                        }
                    )
                    ownership_conflict = True
                if changes:
                    plan["device_updates"].append(
                        {"id": device["id"], "name": device.get("name"), "changes": changes}
                    )
            plan["observed"] = {
                "configured_group_id": verified["configured_group_id"],
                "selected_uuid": verified["selected_uuid"],
                "peer_uuid": verified["peer_uuid"],
                "priorities": verified["priorities"],
            }
            if ownership_conflict:
                plan["group_updates"] = []
                plan["device_updates"] = []
                plan["unresolved"].append(
                    {
                        "scope": "ha_pair",
                        "reason": (
                            "Preserved native HA membership or priority intent "
                            "prevents shared-address ownership"
                        ),
                    }
                )
            else:
                plan["sharing"] = _sharing(discovery, existing, verified, plan)
        except (ValueError, TypeError, KeyError, AttributeError):
            plan["group_updates"] = []
            plan["device_updates"] = []
            plan["sharing"] = None
            plan["errors"].append(
                "PAN-OS HA pair source, reciprocal identity "
                "or native ownership provenance is invalid"
            )
    plan["summary"] = {
        "ha_groups_updated": len(plan["group_updates"]),
        "ha_devices_updated": len(plan["device_updates"]),
        "ha_shared_addresses_reviewed": len(plan["sharing"]["addresses"]) if plan["sharing"] else 0,
        "unresolved_ha": len(plan["unresolved"]),
    }
    return plan
