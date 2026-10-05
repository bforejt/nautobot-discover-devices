"""Pure, fill-only reconciliation. Building a plan never writes to Nautobot."""

import re
from collections import defaultdict

from .adapters import cisco_iosxe, panos
from .adapters.cisco_iosxe import canonical_interface_name, canonical_software_version
from .reconcile_components import plan_components
from .reconcile_console import plan_console_ports, reviewed_profile
from .reconcile_ipam import plan_ipam
from .reconcile_route_targets import plan_route_targets
from .reconcile_stack import plan_stack
from .reconcile_vlans import plan_vlans
from .transport_ssh import INTERFACES, RUNNING_INTERFACES, SYSTEM_INFO, VM_INTERFACES

INTERFACE_FIELDS = (
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
COPPER_DUPLEX_TYPES = {"100base-tx", "1000base-t", "2.5gbase-t", "5gbase-t", "10gbase-t"}
UNKNOWN_ETHERNET_TYPE_SOURCE = (
    "Observed IANA Ethernet interface; maximum physical capability unknown; "
    "Nautobot Other is an explicit unknown capability placeholder"
)
_PHYSICAL_ETHERNET_NAME = re.compile(
    r"(?:FastEthernet|GigabitEthernet|TwoGigabitEthernet|FiveGigabitEthernet|"
    r"TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|FiftyGigabitEthernet|"
    r"HundredGigE|TwoHundredGigE|FourHundredGigE)\d+/\d+(?:/\d+)?"
)


def _observed_physical_ethernet(fact, name):
    """Recognize explicit Ethernet evidence without inferring a cage capability.

    Interface names only reject logical/internal/breakout rows. Neither the
    prefix nor operational speed supplies the physical type. The adapter's
    structured IANA classification and known admin state remain mandatory.
    """
    source = fact.get("physical_ethernet_source")
    return (
        fact.get("physical_ethernet") is True
        and isinstance(source, dict)
        and source.get("module") == "Cisco-IOS-XE-interfaces-oper"
        and source.get("path") == "interfaces/interface/interface-type"
        and source.get("value") == "iana-iftype-ethernet-csmacd"
        and source.get("name") == name
        and source.get("oper_status") != "if-oper-state-not-present"
        and source.get("admin_status") in ("if-state-up", "if-state-down")
        and type(fact.get("enabled")) is bool
        and fact["enabled"] == (source["admin_status"] == "if-state-up")
        and _PHYSICAL_ETHERNET_NAME.fullmatch(name) is not None
    )


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _mac(value):
    if _blank(value):
        return None
    value = str(value).replace(":", "").replace("-", "").replace(".", "").lower()
    if value == "0" * 12:
        return None
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2))


def _equal(field, before, after, *, canonical_version=canonical_software_version):
    if field == "mac_address":
        return _mac(before) == _mac(after)
    if field == "software_version":
        before_version = canonical_version(before)
        after_version = canonical_version(after)
        if before_version is None or after_version is None:
            return before == after
        return before_version == after_version
    return before == after


def _panos_vm_interface_source(discovery, source, name):
    """Recheck complete KVM guest enumeration before it can prove a native port."""
    observations = discovery.get("observations")
    sources = discovery.get("sources")
    if not isinstance(observations, dict) or not isinstance(sources, dict):
        return False
    system, rows = observations.get("system"), observations.get("vm_interfaces")
    operational_rows = observations.get("interfaces")
    identity_source, vm_source = sources.get("identity"), sources.get("vm_interfaces")
    if (
        not isinstance(system, dict)
        or not isinstance(rows, list)
        or not isinstance(operational_rows, list)
        or not isinstance(identity_source, dict)
        or not isinstance(vm_source, dict)
        or discovery["identity"].get("model") != "PA-VM"
        or system.get("family") != "vm"
        or system.get("vm-mode") != "KVM"
        or identity_source.get("command") != SYSTEM_INFO
        or identity_source.get("path") != "result/system"
        or vm_source.get("command") != VM_INTERFACES
        or vm_source.get("path") != "result/entry"
        or source.get("enumeration_command") != VM_INTERFACES
        or source.get("enumeration_path") != "result/entry"
        or panos.canonical_vm_interface_name(source.get("raw_name")) != name
    ):
        return False
    identities = [panos.vm_interface_identity(row) for row in rows]
    if any(identity is None for identity in identities):
        return False
    for position in (0, 2, 3):
        if len({identity[position] for identity in identities}) != len(identities):
            return False
    observed = [
        row
        for row in operational_rows
        if isinstance(row, dict)
        and (panos.canonical_vm_interface_name(row.get("name")) or row.get("name")) == name
    ]
    if len(observed) != 1 or observed[0].get("hardware") != []:
        return False
    names = {identity[0] for identity in identities}
    if any(
        isinstance(row, dict)
        and row.get("hardware")
        and panos.canonical_vm_interface_name(row.get("name")) is not None
        and panos.canonical_vm_interface_name(row["name"]) not in names
        for row in operational_rows
    ):
        return False
    identity = panos.vm_interface_identity(source)
    return identity is not None and identities.count(identity) == 1


def _panos_native_values(discovery, fact, name, values, plan):
    """Require reviewed enumeration and applied evidence for configured PAN-OS fields."""
    source = fact.get("source")
    reviewed = isinstance(source, dict) and source.get("name") == name
    vm_contract = isinstance(source, dict) and source.get("contract") == "panos-vm-interface-v1"
    if reviewed:
        reviewed = (
            _panos_vm_interface_source(discovery, source, name)
            if vm_contract
            else source.get("contract") == "panos-interface-v1"
            and source.get("operational_command") == INTERFACES
            and source.get("hardware_path") == "result/hw/entry"
        )
        reviewed = (
            reviewed
            and source.get("applied_command") == RUNNING_INTERFACES
            and source.get("applied_path") == "result/interface/ethernet/entry"
        )
    if vm_contract and not reviewed:
        plan["errors"].append("%s: invalid PAN-OS VM enumeration provenance" % name)
    for field in ("enabled", "description", "mtu"):
        after = values[field]
        if _blank(after):
            continue
        valid = reviewed
        if field == "enabled":
            valid = valid and type(after) is bool
            if valid:
                state = source.get("link_state")
                valid = state in ("up", "down") and after is (state == "up")
        elif field == "description":
            valid = valid and isinstance(after, str) and source.get("comment") == after
        elif field == "mtu":
            raw = source.get("mtu") if reviewed else None
            valid = valid and type(after) is int and panos.configured_mtu(raw) == after
        if not valid:
            plan["errors"].append("%s: invalid PAN-OS applied %s provenance" % (name, field))
            values[field] = None


def _panos_vm_identity(discovery, device, plan):
    """Verify the selected VM's explicitly supplied identity without fabricating a serial."""
    binding = discovery.get("identity_binding")
    if binding is None:
        return False
    identity = discovery["identity"]
    observations = discovery.get("observations")
    system = observations.get("system") if isinstance(observations, dict) else None
    sources = discovery.get("sources")
    source = sources.get("identity") if isinstance(sources, dict) else None
    if (
        not isinstance(binding, dict)
        or not isinstance(system, dict)
        or not isinstance(source, dict)
    ):
        plan["errors"].append("PAN-OS VM identity binding has invalid structured provenance")
        return False
    expected = panos.canonical_vm_uuid(binding.get("expected_uuid"))
    observed = panos.canonical_vm_uuid(binding.get("observed_uuid"))
    system_uuid = panos.canonical_vm_uuid(system.get("vm-uuid"))
    reviewed = (
        binding.get("contract") == "panos-vm-identity-v1"
        and binding.get("system_command") == SYSTEM_INFO
        and binding.get("system_path") == "result/system"
        and source.get("command") == SYSTEM_INFO
        and source.get("path") == "result/system"
        and binding.get("model") == identity.get("model") == device.get("model") == "PA-VM"
        and binding.get("family") == system.get("family") == "vm"
        and binding.get("vm_mode") == system.get("vm-mode") == "KVM"
        and expected is not None
        and expected == observed == system_uuid
    )
    if not reviewed:
        plan["errors"].append(
            "PAN-OS VM identity binding does not match the reviewed UUID contract"
        )
        return False
    plan["identity_binding"] = dict(binding, expected_uuid=expected, observed_uuid=observed)
    return True


def _management_value(discovery, fact, row, effective_type, plan, conflict):
    """Allow the documented purpose correction only for the reviewed OOB port.

    Unlike most Boolean fields, mgmt_only starts False in Nautobot even when
    purpose has not been classified. This narrow correction never sets False
    and never infers purpose from an IP address or management VRF name.
    """
    value = fact.get("mgmt_only")
    if value is None:
        return None
    if type(value) is not bool:
        plan["errors"].append("Management-only discovery requires an actual Boolean value")
        return None
    if value is False:
        return None
    source = fact.get("mgmt_only_source")
    name = canonical_interface_name(fact["name"])
    if (
        not reviewed_profile(source, discovery["identity"].get("model"))
        or source.get("interface") != "GigabitEthernet0/0"
        or source.get("value") is not True
        or name != "GigabitEthernet0/0"
        or fact.get("type") != "1000base-t"
    ):
        plan["errors"].append("Management-only discovery has invalid reviewed hardware provenance")
        return None
    members = [
        canonical_interface_name(item.get("member"))
        for item in discovery.get("lag_memberships", [])
    ]
    components = discovery.get("components")
    component_items = components.get("items", []) if isinstance(components, dict) else []
    if not isinstance(component_items, list):
        component_items = []
    owned = [
        canonical_interface_name(interface)
        for item in component_items
        if isinstance(item, dict) and isinstance(item.get("interfaces", []), list)
        for interface in item.get("interfaces", [])
    ]
    unsafe = (
        effective_type != "1000base-t"
        or name in members
        or name in owned
        or (
            row
            and (
                row.get("module_id") is not None
                or row.get("lag_id") is not None
                or not _blank(row.get("lag"))
                or not _blank(row.get("mode"))
                or row.get("untagged_vlan_id") is not None
                or row.get("tagged_vlan_ids")
                or (not _blank(row.get("port_type")) and row.get("port_type") != "8p8c")
            )
        )
    )
    if unsafe:
        conflict(
            "interface",
            (row or fact)["name"],
            "mgmt_only",
            row.get("mgmt_only") if row else None,
            True,
        )
        plan["warnings"].append(
            "%s: preserved interface type, ownership, LAG or switching data prevents "
            "classifying the dedicated management port" % name
        )
        return None
    return True


def build_plan(discovery, existing):
    """Compare adapter facts with a serialized inventory snapshot.

    Empty means None or empty text; False, zero, and 'other' are populated.
    A conflicting serial/model or an ambiguous canonical name blocks apply.
    Explicit physical Ethernet observations can use Other to mean capability
    unknown. Unclassified interface types are reported and skipped, never guessed.
    """
    adapter_name = discovery.get("adapter")
    if (
        adapter_name not in ("cisco_iosxe", "panos")
        or discovery.get("schema_version") != 1
        or (adapter_name == "panos" and type(discovery.get("schema_version")) is not int)
    ):
        raise ValueError("Unsupported discovery adapter or schema version")
    adapter = panos if adapter_name == "panos" else cisco_iosxe
    canonical_interface_name = adapter.canonical_interface_name
    canonical_software_version = adapter.canonical_software_version

    def equal(field, before, after):
        return _equal(field, before, after, canonical_version=canonical_software_version)

    # PAN-OS schema v1 inventories identity and physical ports only. Keep all
    # Cisco-only domain planners on their established no-op paths.
    domain_discovery = discovery if adapter is cisco_iosxe else {"identity": discovery["identity"]}
    device = existing["device"]
    stack = plan_stack(domain_discovery, existing)
    identity = stack["identity"]
    plan = {
        "schema_version": 1,
        "adapter": discovery["adapter"],
        "target": {"id": str(device["id"]), "name": device.get("name")},
        "device_updates": [],
        "interface_creates": [],
        "interface_updates": [],
        "lag_assignments": [],
        "software_version": None,
        "stack": stack,
        "conflicts": list(stack["conflicts"]),
        "errors": list(stack["errors"]),
        "warnings": list(discovery.get("warnings", [])) + stack["warnings"],
        "missing_interfaces": [],
        "excluded_interfaces": list(discovery.get("excluded_interfaces", [])),
        "unknown_interface_capabilities": [],
    }

    if adapter is panos:
        manufacturer = str(device.get("manufacturer_name") or "").lower()
        manufacturer = manufacturer.replace(" ", "").replace("-", "")
        if manufacturer not in ("paloalto", "paloaltonetworks"):
            plan["errors"].append("The selected DeviceType manufacturer must be Palo Alto Networks")
        driver = str(device.get("platform_network_driver") or "").lower()
        platform_name = str(device.get("platform_name") or "").lower()
        platform_name = platform_name.replace("-", "").replace("_", "").replace(" ", "")
        if driver not in ("paloalto_panos", "panos") and not (
            not driver and platform_name in ("panos", "paloaltopanos")
        ):
            plan["errors"].append("The selected Device must have a PAN-OS platform")
        for field in ("stack", "components", "console_ports", "layer2", "ipam", "lag_memberships"):
            if discovery.get(field) is not None:
                plan["errors"].append("PAN-OS schema v1 does not support %s inventory" % field)

    def conflict(scope, name, field, before, after):
        plan["conflicts"].append(
            {"scope": scope, "name": name, "field": field, "before": before, "observed": after}
        )

    vm_identity = _panos_vm_identity(discovery, device, plan) if adapter is panos else False
    required_identity = ["serial", "model", "hostname", "software_version"]
    if vm_identity and _blank(device.get("serial")):
        required_identity.remove("serial")
    for field in required_identity:
        if _blank(identity.get(field)):
            plan["errors"].append("Discovery did not provide required identity field: %s" % field)
    for field in ("serial", "model"):
        before, after = device.get(field), identity.get(field)
        if not _blank(before) and not _blank(after) and str(before).strip() != str(after).strip():
            conflict("device", device.get("name"), field, before, after)
            plan["errors"].append("Selected Device %s differs from discovered chassis" % field)

    for field, source in (
        ("name", "hostname"),
        ("serial", "serial"),
        ("software_version", "software_version"),
    ):
        before, after = device.get(field), identity.get(source)
        if _blank(after):
            continue
        if _blank(before):
            plan["device_updates"].append({"field": field, "before": before, "after": after})
        elif not equal(field, before, after):
            conflict("device", device.get("name"), field, before, after)

    if any(change["field"] == "software_version" for change in plan["device_updates"]):
        if not device.get("platform_id"):
            plan["errors"].append(
                "Assign the Device's %s platform before loading software"
                % ("PAN-OS" if adapter is panos else "IOS XE")
            )
        version = canonical_software_version(identity["software_version"])
        if version is None:
            plan["errors"].append("Discovered software version is not a supported release token")
        versions = []
        for row in existing.get("software_versions", []):
            if equal("software_version", row["version"], version):
                versions.append(row)
        if len(versions) > 1:
            plan["errors"].append("Several SoftwareVersion records represent release %s" % version)
        plan["software_version"] = {
            "key": "%s:%s" % (device.get("platform_id"), version),
            "platform_id": device.get("platform_id"),
            "version": version,
            "existing_id": str(versions[0]["id"]) if len(versions) == 1 else None,
            "create": not versions,
        }

    by_name = defaultdict(list)
    for row in existing.get("interfaces", []):
        by_name[canonical_interface_name(row["name"])].append(row)
    templates = defaultdict(set)
    for row in existing.get("interface_templates", []):
        templates[canonical_interface_name(row["name"])].add(row["type"])
    for name, rows in by_name.items():
        if len(rows) > 1:
            plan["errors"].append("Several existing interfaces normalize to %s" % name)

    observed = set()
    for fact in sorted(discovery.get("interfaces", []), key=lambda item: item["name"]):
        name = canonical_interface_name(fact["name"])
        if not name:
            plan["errors"].append("Discovery returned an interface without a name")
            continue
        if name in observed:
            plan["errors"].append("Several discovered interfaces normalize to %s" % name)
            continue
        observed.add(name)
        values = {field: fact.get(field) for field in INTERFACE_FIELDS}
        if adapter is panos:
            for field in ("type", "mac_address", "speed", "duplex", "port_type", "mgmt_only"):
                if not _blank(values[field]):
                    plan["warnings"].append(
                        "%s: PAN-OS schema v1 retains %s as report-only evidence" % (name, field)
                    )
                values[field] = None
            _panos_native_values(discovery, fact, name, values, plan)
        for field in existing.get("unsupported_interface_fields", []):
            if not _blank(values.get(field)):
                plan["warnings"].append(
                    "%s: this Nautobot release does not support interface field %s" % (name, field)
                )
                values[field] = None
        values["mac_address"] = _mac(values["mac_address"])
        type_source = fact.get("type_source")
        if not values["type"] and len(templates[name]) == 1:
            values["type"] = next(iter(templates[name]))
            type_source = "existing DeviceType interface template"
        if len(by_name[name]) > 1:
            continue
        capability_unknown = not values["type"] and (
            panos.observed_physical_ethernet(fact, name)
            if adapter is panos
            else _observed_physical_ethernet(fact, name)
        )
        if capability_unknown:
            preserved_type = by_name[name][0].get("type") if by_name[name] else None
            plan["unknown_interface_capabilities"].append(
                {
                    "name": name,
                    "reason": "Maximum physical capability is not established by structured data",
                    "classification_source": fact["physical_ethernet_source"],
                    "preserved_type": preserved_type,
                }
            )
            if not by_name[name]:
                values["type"] = "other"
                type_source = (
                    "Reviewed PAN-OS physical Ethernet evidence; maximum physical capability "
                    "unknown; Nautobot Other is an explicit unknown capability placeholder"
                    if adapter is panos
                    else UNKNOWN_ETHERNET_TYPE_SOURCE
                )
            plan["warnings"].append(
                "%s: observed physical Ethernet, maximum capability unknown; %s"
                % (
                    name,
                    "preserved existing interface type"
                    if by_name[name]
                    else "using Nautobot type Other as an unknown capability placeholder",
                )
            )
        effective_type = (by_name[name][0].get("type") if by_name[name] else None) or values["type"]
        values["mgmt_only"] = (
            _management_value(
                discovery,
                fact,
                by_name[name][0] if by_name[name] else None,
                effective_type,
                plan,
                conflict,
            )
            if adapter is cisco_iosxe
            and "mgmt_only" not in existing.get("unsupported_interface_fields", [])
            else None
        )
        if effective_type in {"virtual", "bridge", "lag", "tunnel"} or str(
            effective_type
        ).startswith("ieee802.11"):
            if values["speed"] is not None:
                plan["warnings"].append(
                    "%s: operational speed is not supported by the preserved interface type" % name
                )
                values["speed"] = None
            if not _blank(values["port_type"]):
                plan["warnings"].append(
                    "%s: connector is not supported by the preserved interface type" % name
                )
                values["port_type"] = None
        if effective_type not in COPPER_DUPLEX_TYPES and not _blank(values["duplex"]):
            plan["warnings"].append(
                "%s: duplex is not supported by the preserved interface type" % name
            )
            values["duplex"] = None
        if not by_name[name]:
            if not values["type"] or values["enabled"] is None:
                reason = (
                    "unsupported physical type" if not values["type"] else "unknown admin state"
                )
                plan["warnings"].append("Skipped creating %s: %s" % (name, reason))
                plan["excluded_interfaces"].append({"name": name, "reason": reason})
                continue
            spec = {"name": name, **values, "type_source": type_source}
            if capability_unknown:
                spec["capability_unknown"] = True
            if values["mgmt_only"] is True:
                spec["mgmt_only_source"] = fact["mgmt_only_source"]
            plan["interface_creates"].append(spec)
            continue
        row = by_name[name][0]
        changes = []
        for field, after in values.items():
            before = row.get(field)
            if _blank(after):
                continue
            if field == "mgmt_only" and after is True:
                if before is False or _blank(before):
                    changes.append(
                        {
                            "field": field,
                            "before": before,
                            "after": True,
                            "source": fact["mgmt_only_source"],
                        }
                    )
                elif before is not True:
                    conflict("interface", row["name"], field, before, after)
                continue
            if _blank(before):
                changes.append({"field": field, "before": before, "after": after})
            elif not equal(field, before, after):
                conflict("interface", row["name"], field, before, after)
        if changes:
            plan["interface_updates"].append(
                {"id": str(row["id"]), "name": row["name"], "changes": changes}
            )

    _lag_assignments(domain_discovery, plan, by_name, observed, conflict)
    plan["layer2"] = plan_vlans(domain_discovery, existing, interface_plan=plan)
    for key in ("conflicts", "errors", "warnings"):
        plan[key].extend(plan["layer2"][key])
    plan["components"] = plan_components(
        domain_discovery, existing, interface_plan=plan, stack_plan=stack
    )
    for key in ("conflicts", "errors", "warnings"):
        plan[key].extend(plan["components"][key])
    plan["console_ports"] = plan_console_ports(domain_discovery, existing, stack_plan=stack)
    for key in ("conflicts", "errors", "warnings"):
        plan[key].extend(plan["console_ports"][key])
    plan["ipam"] = plan_ipam(domain_discovery, existing, interface_plan=plan)
    route_targets = plan_route_targets(domain_discovery, existing, plan["ipam"])
    for key in ("route_targets", "vrf_route_targets"):
        plan["ipam"][key] = route_targets[key]
    for key in ("unresolved", "conflicts", "errors", "warnings"):
        plan["ipam"][key].extend(route_targets[key])
    plan["ipam"]["summary"].update(route_targets["summary"])
    plan["ipam"]["summary"]["unresolved_ipam"] = len(plan["ipam"]["unresolved"])
    for key in ("conflicts", "errors", "warnings"):
        plan[key].extend(plan["ipam"][key])
    changed_interfaces = {row["id"] for row in plan["interface_updates"]}
    changed_interfaces.update(
        row["member_id"] for row in plan["lag_assignments"] if row["member_id"] is not None
    )
    changed_interfaces.update(
        row["id"] for row in plan["components"]["interface_assignments"] if row["id"] is not None
    )
    changed_interfaces.update(
        row["id"] for row in plan["layer2"]["assignments"] if row["id"] is not None
    )
    changed_interfaces.update(
        row["id"] for row in plan["ipam"]["interface_vrfs"] if row["id"] is not None
    )
    plan["missing_interfaces"] = [
        {"id": str(row["id"]), "name": row["name"]}
        for name, rows in sorted(by_name.items())
        if name not in observed
        for row in rows
    ]
    plan["summary"] = {
        "device_fields_updated": len(plan["device_updates"]),
        "interfaces_created": len(plan["interface_creates"]),
        "interfaces_updated": len(changed_interfaces),
        "lag_memberships_updated": len(plan["lag_assignments"]),
        "management_interfaces_updated": sum(
            any(change["field"] == "mgmt_only" for change in row["changes"])
            for row in plan["interface_updates"]
        ),
        "conflicts": len(plan["conflicts"]),
        "missing_interfaces": len(plan["missing_interfaces"]),
        "excluded_interfaces": len(plan["excluded_interfaces"]),
        "unknown_interface_capabilities": len(plan["unknown_interface_capabilities"]),
        "blocked": bool(plan["errors"]),
        **plan["components"]["summary"],
        **plan["layer2"]["summary"],
        **plan["console_ports"]["summary"],
        **plan["ipam"]["summary"],
        **stack["summary"],
    }
    return plan


def _lag_assignments(discovery, plan, by_name, observed, conflict):
    """Plan explicit, fill-only member-to-LAG relationships after interface planning."""
    creates = {row["name"]: row for row in plan["interface_creates"]}
    updates = {
        row["id"]: {change["field"]: change["after"] for change in row["changes"]}
        for row in plan["interface_updates"]
    }
    targets = defaultdict(set)
    sources = {}
    for fact in discovery.get("lag_memberships", []):
        member = canonical_interface_name(fact.get("member"))
        lag = canonical_interface_name(fact.get("lag"))
        if not member or not lag:
            plan["errors"].append("Discovery returned a LAG membership without both endpoint names")
            continue
        targets[member].add(lag)
        sources[(member, lag)] = fact.get("source")

    def endpoint(name):
        if name not in observed or len(by_name[name]) > 1:
            return None
        if by_name[name]:
            row = by_name[name][0]
            return {**row, **updates.get(str(row["id"]), {})}
        return creates.get(name)

    for member_name, lag_names in sorted(targets.items()):
        if len(lag_names) != 1:
            plan["errors"].append("Discovered member %s belongs to several LAGs" % member_name)
            continue
        lag_name = next(iter(lag_names))
        if member_name == lag_name:
            plan["errors"].append("Discovered LAG %s cannot be its own member" % member_name)
            continue
        member, lag = endpoint(member_name), endpoint(lag_name)
        if member is None or lag is None:
            plan["warnings"].append(
                "Skipped LAG membership %s -> %s: an endpoint is unavailable in the interface plan"
                % (member_name, lag_name)
            )
            continue
        if lag.get("type") != "lag":
            plan["warnings"].append(
                "Skipped LAG membership %s -> %s: target interface type is %r, not lag"
                % (member_name, lag_name, lag.get("type"))
            )
            continue
        if member.get("type") in ("virtual", "bridge", "lag", "tunnel") or not member.get("type"):
            plan["warnings"].append(
                "Skipped LAG membership %s -> %s: member must be a physical interface"
                % (member_name, lag_name)
            )
            continue
        before_id, before_name = member.get("lag_id"), member.get("lag")
        if not _blank(before_id) or not _blank(before_name):
            matches = (
                str(before_id) == str(lag.get("id"))
                if not _blank(before_id)
                else canonical_interface_name(before_name) == lag_name
            )
            if not matches:
                conflict("interface", member["name"], "lag", before_name or before_id, lag["name"])
            continue
        plan["lag_assignments"].append(
            {
                "member": member["name"],
                "member_id": str(member["id"]) if member.get("id") is not None else None,
                "lag": lag["name"],
                "lag_id": str(lag["id"]) if lag.get("id") is not None else None,
                "source": sources[(member_name, lag_name)],
            }
        )
