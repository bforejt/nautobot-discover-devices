"""Nautobot boundary: snapshots, validation, and atomic application of plans."""

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from nautobot.dcim.models import (
    Device,
    Interface,
    InterfaceTemplate,
    Manufacturer,
    Platform,
    SoftwareVersion,
)
from nautobot.extras.models import Status
from nautobot.ipam.models import Namespace

from .adapters import cisco_iosxe, esxi, panos, proxmox
from .exceptions import InventoryError
from .nautobot_capacity import (
    clean_capacity_device,
    save_capacity_device,
    snapshot_capacity,
    stage_capacity,
)
from .nautobot_components import (
    component_objects,
    save_components,
    snapshot_components,
    validate_components,
)
from .nautobot_console import (
    console_objects,
    save_console_ports,
    snapshot_console_ports,
    validate_console_ports,
)
from .nautobot_esxi_guests import (
    lock_esxi_guests,
    save_esxi_guests,
    snapshot_esxi_guests,
    stage_esxi_guests,
    validate_esxi_guests,
)
from .nautobot_ipam import (
    _namespace_ids as ipam_namespace_ids,
)
from .nautobot_ipam import (
    ipam_objects,
    save_ipam_assignments,
    save_ipam_catalog,
    snapshot_ipam,
    validate_ipam_objects,
)
from .nautobot_panos_ha import (
    save_panos_ha_objects,
    snapshot_panos_ha,
    stage_panos_ha,
    validate_panos_ha_objects,
)
from .nautobot_panos_interfaces import (
    panos_interface_objects,
    save_panos_interfaces,
    snapshot_panos_interfaces,
    validate_panos_interfaces,
)
from .nautobot_panos_vpn import (
    panos_vpn_objects,
    save_panos_vpn_assignments,
    save_panos_vpn_catalog,
    snapshot_panos_vpn,
    validate_panos_vpn_objects,
)
from .nautobot_proxmox_guests import (
    lock_proxmox_guests,
    save_proxmox_guests,
    snapshot_proxmox_guests,
    stage_proxmox_guests,
    validate_proxmox_guests,
)
from .nautobot_stack import save_stack, snapshot_stack, stack_objects, validate_stack
from .nautobot_vlans import (
    save_vlan_assignments,
    save_vlan_catalog,
    snapshot_vlans,
    validate_vlan_objects,
    vlan_objects,
)
from .reconcile import INTERFACE_FIELDS, build_plan


def snapshot_inventory(device, *, lock=False, discovery=None, vlan_group=None, ipam_policy=None):
    """Serialize only the fields this job may reconcile."""
    interfaces = device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
    if lock:
        interfaces = interfaces.select_for_update(of=("self",))
    interfaces = interfaces.select_related("lag").prefetch_related("tagged_vlans")
    rows = [
        {
            "id": str(interface.pk),
            "name": interface.name,
            "device_id": str(interface.device_id) if interface.device_id else None,
            "lag_id": str(interface.lag_id) if interface.lag_id else None,
            "lag": interface.lag.name if interface.lag_id else None,
            "parent_interface_id": str(getattr(interface, "parent_interface_id", None))
            if getattr(interface, "parent_interface_id", None)
            else None,
            "module_id": str(interface.module_id) if interface.module_id else None,
            "vrf_id": str(interface.vrf_id) if interface.vrf_id else None,
            "mode": interface.mode,
            "untagged_vlan_id": str(interface.untagged_vlan_id)
            if interface.untagged_vlan_id
            else None,
            "tagged_vlan_ids": sorted(str(vlan.pk) for vlan in interface.tagged_vlans.all()),
            **{
                field: str(getattr(interface, field))
                if field == "mac_address" and getattr(interface, field) is not None
                else getattr(interface, field, None)
                for field in INTERFACE_FIELDS
            },
        }
        for interface in interfaces.order_by("pk")
    ]
    versions = SoftwareVersion.objects.filter(platform_id=device.platform_id)
    return {
        "device": {
            "id": str(device.pk),
            "name": device.name,
            "serial": device.serial,
            "model": device.device_type.model,
            "manufacturer_name": device.device_type.manufacturer.name,
            "platform_name": device.platform.name if device.platform_id else None,
            "platform_network_driver": getattr(device.platform, "network_driver", None)
            if device.platform_id
            else None,
            "platform_id": str(device.platform_id) if device.platform_id else None,
            "primary_ip4_id": str(device.primary_ip4_id) if device.primary_ip4_id else None,
            "primary_ip6_id": str(device.primary_ip6_id) if device.primary_ip6_id else None,
            "software_version": device.software_version.version
            if device.software_version_id
            else None,
        },
        "interfaces": rows,
        "unsupported_interface_fields": [
            field
            for field in INTERFACE_FIELDS
            if field not in {model_field.name for model_field in Interface._meta.fields}
        ],
        "software_versions": [{"id": str(v.pk), "version": v.version} for v in versions],
        "interface_templates": list(
            InterfaceTemplate.objects.filter(device_type_id=device.device_type_id).values(
                "name", "type"
            )
        ),
        "components": snapshot_components(device, lock=lock, discovery=discovery),
        "vlan_inventory": snapshot_vlans(device, vlan_group, lock=lock),
        "console_inventory": snapshot_console_ports(device, lock=lock, discovery=discovery),
        "stack": snapshot_stack(device, lock=lock, discovery=discovery),
        "ipam_inventory": snapshot_ipam(device, ipam_policy, lock=lock, discovery=discovery),
        "capacity_inventory": snapshot_capacity(device, lock=lock, discovery=discovery),
        "esxi_guest_inventory": snapshot_esxi_guests(device, lock=lock, discovery=discovery),
        "proxmox_guest_inventory": snapshot_proxmox_guests(device, lock=lock, discovery=discovery),
        "panos_interface_inventory": snapshot_panos_interfaces(
            device, lock=lock, discovery=discovery
        ),
        "ha_inventory": snapshot_panos_ha(device, lock=lock, discovery=discovery),
        "panos_vpn_inventory": snapshot_panos_vpn(
            device, (discovery or {}).get("vpn_policy"), lock=lock, discovery=discovery
        ),
    }


def _status(model, selected):
    content_type = ContentType.objects.get_for_model(model)
    statuses = Status.objects.filter(content_types=content_type)
    if selected is not None:
        status = statuses.filter(pk=selected.pk).first()
    else:
        status = statuses.filter(name="Active").first()
    if status is None:
        raise InventoryError(
            "Select an applicable status for new %s records" % model._meta.verbose_name
        )
    return status


def _objects(
    plan,
    device,
    interface_status,
    software_version_status,
    module_status,
    vlan_status,
    ipam_prefix_status=None,
    ipam_ip_address_status=None,
    stack=None,
):
    if plan["errors"]:
        raise InventoryError("; ".join(plan["errors"]))
    version = None
    version_spec = plan["software_version"]
    if version_spec is not None:
        key = version_spec.get("key") or "%s:%s" % (device.platform_id, version_spec["version"])
        cached_versions = stack["software_versions"] if stack is not None else {}
        if key in cached_versions:
            version = cached_versions[key]
        elif version_spec["create"]:
            version = SoftwareVersion(
                platform=device.platform,
                version=version_spec["version"],
                status=_status(SoftwareVersion, software_version_status),
            )
        else:
            version = SoftwareVersion.objects.get(pk=version_spec["existing_id"])
        if stack is not None:
            cached_versions[key] = version
    status = _status(Interface, interface_status) if plan["interface_creates"] else None
    creates = []
    for row in plan["interface_creates"]:
        attributes = {field: row[field] for field in INTERFACE_FIELDS if row[field] is not None}
        creates.append(Interface(device=device, name=row["name"], status=status, **attributes))
    updates = []
    for row in plan["interface_updates"]:
        interfaces = (
            device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
        )
        interface = interfaces.get(pk=row["id"])
        for change in row["changes"]:
            setattr(interface, change["field"], change["after"])
        updates.append(interface)
    for change in plan["device_updates"]:
        if change["field"] != "software_version":
            setattr(device, change["field"], change["after"])
    stage_capacity(plan, device)
    for change in plan.get("management", {}).get("primary_updates", []):
        if (
            change["field"] not in ("primary_ip4", "primary_ip6")
            or getattr(device, change["field"] + "_id") is not None
        ):
            raise InventoryError("Populated primary IPs must be preserved")
        from nautobot.ipam.models import IPAddress

        setattr(device, change["field"], IPAddress.objects.get(pk=change["after"]))
    ha_objects = stage_panos_ha(plan, device)
    memberships, ownerships = [], []
    component_plan = plan["components"]
    devices_by_serial = {}
    selected_serial = plan.get("stack", {}).get("identity", {}).get("serial")
    if selected_serial:
        devices_by_serial[selected_serial] = device
    if stack is not None:
        devices_by_serial.update(
            {member.serial.strip(): member for member in stack["members"].values() if member.serial}
        )
    components = (
        component_objects(
            component_plan,
            device,
            module_status=module_status,
            status_resolver=_status,
            devices_by_serial=devices_by_serial,
        )
        if component_plan["modules"]
        or component_plan["module_types"]
        or component_plan["bays"]
        or component_plan.get("power_ports")
        else None
    )
    vlan_plan = plan["layer2"]
    vlans = None
    vlan_work = bool(vlan_plan["assignments"]) or any(
        spec["create"] or spec["changes"] for spec in vlan_plan["catalog"]
    )
    ipam_plan = plan.get("ipam")
    ipam_work = bool(ipam_plan and ipam_plan.get("policy"))
    objects = {}
    if (
        plan["lag_assignments"]
        or component_plan["interface_assignments"]
        or vlan_work
        or ipam_work
        or plan["adapter"] == "panos"
    ):
        interfaces = (
            device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
        )
        canonical_interface_name = {
            "panos": panos,
            "esxi": esxi,
            "proxmox": proxmox,
            "cisco_iosxe": cisco_iosxe,
        }[plan["adapter"]].canonical_interface_name
        objects = {canonical_interface_name(row.name): row for row in interfaces}
        objects.update({canonical_interface_name(row.name): row for row in creates + updates})
        for assignment in plan["lag_assignments"]:
            member = objects[canonical_interface_name(assignment["member"])]
            lag = objects[canonical_interface_name(assignment["lag"])]
            memberships.append((member, lag))
        for assignment in component_plan["interface_assignments"]:
            interface = objects[canonical_interface_name(assignment["name"])]
            ownerships.append((interface, components["modules"][assignment["module_key"]]))
        if vlan_work:
            vlans = vlan_objects(
                vlan_plan, objects, vlan_status=vlan_status, status_resolver=_status
            )
    ipam = (
        ipam_objects(
            ipam_plan,
            objects,
            device,
            prefix_status=ipam_prefix_status,
            ip_address_status=ipam_ip_address_status,
            status_resolver=_status,
        )
        if ipam_work
        else None
    )
    console_plan = plan["console_ports"]
    consoles = (
        console_objects(console_plan, device, devices_by_serial=devices_by_serial)
        if console_plan["creates"] or console_plan["updates"]
        else []
    )
    pan_interfaces = (
        panos_interface_objects(plan["panos_interfaces"], objects, device)
        if plan.get("panos_interfaces", {}).get("contract")
        else []
    )
    vpn_objects = panos_vpn_objects(plan.get("vpn", {}), device, objects, ipam)
    domains = {
        "ha": ha_objects,
        "interfaces": pan_interfaces,
        "vpn": vpn_objects,
        "esxi_guests": stage_esxi_guests(plan, device),
        "proxmox_guests": stage_proxmox_guests(plan, device),
    }
    return (
        version,
        creates,
        updates,
        memberships,
        components,
        ownerships,
        vlans,
        consoles,
        ipam,
        domains,
    )


def _validate_interface(interface, *, preserve_custom_fields=False):
    """UUID parents may exist only as cached objects during a preview."""
    if interface.mode != "tagged" and interface.tagged_vlans.exists():
        raise InventoryError("Saving this interface would clear populated tagged VLAN membership")
    excluded = []
    for field in ("module", "lag", "untagged_vlan", "parent_interface"):
        related = getattr(interface, field, None)
        if related is not None and related._state.adding:
            excluded.append(field)
    if preserve_custom_fields:
        clean_capacity_device(interface, exclude=excluded)
    else:
        interface.full_clean(exclude=excluded)


def _validate_membership(member, lag, device):
    """Enforce our physical-member and same-Device rules beyond model validation."""
    if lag.type != "lag":
        raise InventoryError("LAG target %s must have interface type lag" % lag.name)
    if not member.type or member.is_virtual or member.pk == lag.pk:
        raise InventoryError("LAG member %s must be a distinct physical interface" % member.name)
    if (
        member.parent is None
        or lag.parent is None
        or member.parent.pk != device.pk
        or lag.parent.pk != device.pk
    ):
        raise InventoryError("LAG member and target must belong to the selected Device")
    if member.lag_id is not None and member.lag_id != lag.pk:
        raise InventoryError("LAG member %s already has a different assignment" % member.name)


def _validate_ownership(interface, module, device):
    if interface.device_id != device.pk or module.device is None or module.device.pk != device.pk:
        raise InventoryError("Interface and owning Module must belong to the selected Device")
    if interface.module_id is not None and interface.module_id != module.pk:
        raise InventoryError("Interface %s already belongs to another Module" % interface.name)
    if interface.is_virtual:
        raise InventoryError(
            "Discovered Module-owned interface %s must be physical" % interface.name
        )


def validate_plan(
    plan,
    device,
    *,
    interface_status=None,
    software_version_status=None,
    module_status=None,
    vlan_status=None,
    ipam_prefix_status=None,
    ipam_ip_address_status=None,
):
    """Validate without saving. Re-fetch the Device to avoid mutating inputs."""
    device = Device.objects.get(pk=device.pk)
    stack = stack_objects(
        plan.get("stack"),
        device,
        software_version_status=software_version_status,
        status_resolver=_status,
    )
    validate_stack(stack)
    (
        version,
        creates,
        updates,
        memberships,
        components,
        ownerships,
        vlans,
        consoles,
        ipam,
        domains,
    ) = _objects(
        plan,
        device,
        interface_status,
        software_version_status,
        module_status,
        vlan_status,
        ipam_prefix_status,
        ipam_ip_address_status,
        stack=stack,
    )
    if version is not None:
        version.full_clean()
    if _device_work(plan, domains):
        if version is not None and not plan["software_version"]["create"]:
            device.software_version = version
        # A planned new software row has no DB record for foreign-key validation yet.
        excluded = (
            ["software_version"]
            if version is not None and plan["software_version"]["create"]
            else []
        )
        if device.virtual_chassis is not None and device.virtual_chassis._state.adding:
            excluded.append("virtual_chassis")
        if (
            plan["adapter"] in ("panos", "esxi", "proxmox")
            or plan.get("capacity", {}).get("preserve_custom_fields")
            or plan.get("capacity", {}).get("updates")
        ):
            clean_capacity_device(device, exclude=excluded)
        else:
            device.full_clean(exclude=excluded)
    validate_panos_ha_objects(domains["ha"], validate_selected=False)
    if components is not None:
        validate_components(components)
    if vlans is not None:
        validate_vlan_objects(vlans, device)
    validate_console_ports(consoles, device)
    for interface in creates + updates:
        _validate_interface(
            interface,
            preserve_custom_fields=plan["adapter"] in ("esxi", "proxmox")
            and not interface._state.adding,
        )
    for interface, module in ownerships:
        _validate_ownership(interface, module, device)
        interface.module = module
        _validate_interface(interface)
    for member, lag in memberships:
        _validate_membership(member, lag, device)
        member.lag = lag
        # UUIDs are assigned before INSERT. A newly planned parent cannot yet
        # pass the FK existence query, but model clean() still checks the
        # cached object's relationship semantics when this field is excluded.
        _validate_interface(member)
    if vlans is not None:
        for interface, _spec in vlans["assignments"]:
            _validate_interface(interface)
    if ipam is not None:
        validate_ipam_objects(ipam, device)
    validate_panos_interfaces(domains["interfaces"], device)
    validate_panos_vpn_objects(domains["vpn"], device)
    validate_esxi_guests(domains["esxi_guests"])
    validate_proxmox_guests(domains["proxmox_guests"])


def _device_work(plan, domains):
    return bool(
        plan["device_updates"]
        or plan.get("capacity", {}).get("updates")
        or plan.get("management", {}).get("primary_updates")
        or domains["ha"]["selected_device_changed"]
    )


def apply_discovery(
    discovery,
    device,
    *,
    interface_status=None,
    software_version_status=None,
    module_status=None,
    vlan_group=None,
    vlan_status=None,
    ipam_policy=None,
    ipam_prefix_status=None,
    ipam_ip_address_status=None,
):
    """Re-read under lock and apply the complete valid change set in one transaction."""
    with transaction.atomic():
        namespace_ids = set(ipam_namespace_ids(ipam_policy)) if ipam_policy is not None else set()
        namespace_ids.update(
            str(row[key]["id"])
            for row in (discovery.get("vpn_policy") or {}).get("tunnels", [])
            for key in (
                "local_namespace",
                "remote_namespace",
                "local_protected_namespace",
                "remote_protected_namespace",
            )
            if row.get(key)
        )
        if namespace_ids:
            namespace_ids = sorted(namespace_ids)
            # Serialize shared Namespace catalogs before the per-Device locks.
            locked = list(
                Namespace.objects.filter(pk__in=namespace_ids).order_by("pk").select_for_update()
            )
            if len(locked) != len(namespace_ids):
                raise InventoryError("A selected IPAM Namespace no longer exists")
        lock_esxi_guests(discovery)
        lock_proxmox_guests(discovery)
        context = Device.objects.values("platform_id", "device_type__manufacturer_id").get(
            pk=device.pk
        )
        # Stack jobs can target different members while touching the same asset
        # graph. Acquire shared catalog locks before any member Device lock.
        Manufacturer.objects.select_for_update().get(pk=context["device_type__manufacturer_id"])
        if context["platform_id"]:
            Platform.objects.select_for_update().get(pk=context["platform_id"])
        pair_policy = (discovery.get("ha_pair") or {}).get("policy")
        device_ids = {str(device.pk)}
        if discovery.get("adapter") in ("esxi", "proxmox") and discovery.get("guest_policy"):
            device_ids.update(row["device"]["id"] for row in discovery["guest_policy"]["mappings"])
        if pair_policy:
            from nautobot.dcim import models as dcim_models

            group_model = getattr(dcim_models, "DeviceRedundancyGroup", None)
            if group_model is not None:
                group_model.objects.select_for_update().get(
                    pk=pair_policy["redundancy_group"]["id"]
                )
            device_ids.add(pair_policy["peer_device"]["id"])
        locked_devices = list(
            Device.objects.filter(pk__in=device_ids).order_by("pk").select_for_update()
        )
        if len(locked_devices) != len(device_ids):
            raise InventoryError("An explicitly selected Device no longer exists")
        device = next(row for row in locked_devices if row.pk == device.pk)
        if (
            device.platform_id != context["platform_id"]
            or device.device_type.manufacturer_id != context["device_type__manufacturer_id"]
        ):
            raise InventoryError("Selected Device catalog context changed; retry discovery")
        plan = build_plan(
            discovery,
            snapshot_inventory(
                device,
                lock=True,
                discovery=discovery,
                vlan_group=vlan_group,
                ipam_policy=ipam_policy,
            ),
        )
        validate_plan(
            plan,
            device,
            interface_status=interface_status,
            software_version_status=software_version_status,
            module_status=module_status,
            vlan_status=vlan_status,
            ipam_prefix_status=ipam_prefix_status,
            ipam_ip_address_status=ipam_ip_address_status,
        )
        stack = stack_objects(
            plan.get("stack"),
            device,
            software_version_status=software_version_status,
            status_resolver=_status,
        )
        (
            version,
            creates,
            updates,
            memberships,
            components,
            ownerships,
            vlans,
            consoles,
            ipam,
            domains,
        ) = _objects(
            plan,
            device,
            interface_status,
            software_version_status,
            module_status,
            vlan_status,
            ipam_prefix_status,
            ipam_ip_address_status,
            stack=stack,
        )
        save_stack(stack)
        save_panos_ha_objects(domains["ha"])
        if version is not None:
            if version._state.adding:
                version.validated_save()
            device.software_version = version
        if _device_work(plan, domains):
            if (
                plan["adapter"] in ("panos", "esxi", "proxmox")
                or plan.get("capacity", {}).get("preserve_custom_fields")
                or plan.get("capacity", {}).get("updates")
            ):
                save_capacity_device(device)
            else:
                device.validated_save()
        if components is not None:
            save_components(components)
        if vlans is not None:
            save_vlan_catalog(vlans)
            validate_vlan_objects(vlans, device)
        for interface in creates + updates:
            if plan["adapter"] in ("esxi", "proxmox") and not interface._state.adding:
                save_capacity_device(interface)
            else:
                interface.validated_save()
        save_panos_interfaces(domains["interfaces"], device)
        for interface, module in ownerships:
            _validate_ownership(interface, module, device)
            interface.module = module
            interface.validated_save()
        for member, lag in memberships:
            _validate_membership(member, lag, device)
            member.lag = lag
            member.validated_save()
        if vlans is not None:
            save_vlan_assignments(vlans, device)
        if ipam is not None:
            save_ipam_catalog(ipam, device)
            save_ipam_assignments(ipam, device)
        save_panos_vpn_catalog(domains["vpn"])
        save_panos_vpn_assignments(domains["vpn"])
        save_esxi_guests(domains["esxi_guests"])
        save_proxmox_guests(domains["proxmox_guests"])
        save_console_ports(consoles)
        return plan
