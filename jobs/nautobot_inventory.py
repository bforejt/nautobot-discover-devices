"""Nautobot boundary: snapshots, validation, and atomic application of plans."""

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from nautobot.dcim.models import Device, Interface, InterfaceTemplate, Platform, SoftwareVersion
from nautobot.extras.models import Status

from .adapters.cisco_iosxe import canonical_interface_name
from .exceptions import InventoryError
from .nautobot_components import (
    component_objects,
    save_components,
    snapshot_components,
    validate_components,
)
from .nautobot_vlans import (
    save_vlan_assignments,
    save_vlan_catalog,
    snapshot_vlans,
    validate_vlan_objects,
    vlan_objects,
)
from .reconcile import INTERFACE_FIELDS, build_plan


def snapshot_inventory(device, *, lock=False, discovery=None, vlan_group=None):
    """Serialize only the fields this job may reconcile."""
    interfaces = device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
    if lock:
        interfaces = interfaces.select_for_update(of=("self",))
    interfaces = interfaces.select_related("lag").prefetch_related("tagged_vlans")
    rows = [
        {
            "id": str(interface.pk),
            "name": interface.name,
            "lag_id": str(interface.lag_id) if interface.lag_id else None,
            "lag": interface.lag.name if interface.lag_id else None,
            "module_id": str(interface.module_id) if interface.module_id else None,
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
            "platform_id": str(device.platform_id) if device.platform_id else None,
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


def _objects(plan, device, interface_status, software_version_status, module_status, vlan_status):
    if plan["errors"]:
        raise InventoryError("; ".join(plan["errors"]))
    version = None
    version_spec = plan["software_version"]
    if version_spec is not None:
        if version_spec["create"]:
            version = SoftwareVersion(
                platform=device.platform,
                version=version_spec["version"],
                status=_status(SoftwareVersion, software_version_status),
            )
        else:
            version = SoftwareVersion.objects.get(pk=version_spec["existing_id"])
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
    memberships, ownerships = [], []
    component_plan = plan["components"]
    components = (
        component_objects(
            component_plan, device, module_status=module_status, status_resolver=_status
        )
        if component_plan["modules"] or component_plan["module_types"]
        else None
    )
    vlan_plan = plan["layer2"]
    vlans = None
    vlan_work = bool(vlan_plan["assignments"]) or any(
        spec["create"] or spec["changes"] for spec in vlan_plan["catalog"]
    )
    if plan["lag_assignments"] or component_plan["interface_assignments"] or vlan_work:
        interfaces = (
            device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
        )
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
    return version, creates, updates, memberships, components, ownerships, vlans


def _validate_interface(interface):
    """UUID parents may exist only as cached objects during a preview."""
    if interface.mode != "tagged" and interface.tagged_vlans.exists():
        raise InventoryError("Saving this interface would clear populated tagged VLAN membership")
    excluded = []
    for field in ("module", "lag", "untagged_vlan"):
        related = getattr(interface, field)
        if related is not None and related._state.adding:
            excluded.append(field)
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
):
    """Validate without saving. Re-fetch the Device to avoid mutating inputs."""
    device = Device.objects.get(pk=device.pk)
    version, creates, updates, memberships, components, ownerships, vlans = _objects(
        plan, device, interface_status, software_version_status, module_status, vlan_status
    )
    if version is not None:
        version.full_clean()
    if plan["device_updates"]:
        if version is not None and not plan["software_version"]["create"]:
            device.software_version = version
        # A planned new software row has no DB record for foreign-key validation yet.
        excluded = (
            ["software_version"]
            if version is not None and plan["software_version"]["create"]
            else []
        )
        device.full_clean(exclude=excluded)
    if components is not None:
        validate_components(components)
    if vlans is not None:
        validate_vlan_objects(vlans, device)
    for interface in creates + updates:
        _validate_interface(interface)
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


def apply_discovery(
    discovery,
    device,
    *,
    interface_status=None,
    software_version_status=None,
    module_status=None,
    vlan_group=None,
    vlan_status=None,
):
    """Re-read under lock and apply the complete valid change set in one transaction."""
    with transaction.atomic():
        device = Device.objects.select_for_update().get(pk=device.pk)
        # Serialize catalog creation across participating jobs for this platform.
        if device.platform_id:
            Platform.objects.select_for_update().get(pk=device.platform_id)
        plan = build_plan(
            discovery,
            snapshot_inventory(device, lock=True, discovery=discovery, vlan_group=vlan_group),
        )
        validate_plan(
            plan,
            device,
            interface_status=interface_status,
            software_version_status=software_version_status,
            module_status=module_status,
            vlan_status=vlan_status,
        )
        version, creates, updates, memberships, components, ownerships, vlans = _objects(
            plan, device, interface_status, software_version_status, module_status, vlan_status
        )
        if version is not None:
            if plan["software_version"]["create"]:
                version.validated_save()
            device.software_version = version
        if plan["device_updates"]:
            device.validated_save()
        if components is not None:
            save_components(components)
        if vlans is not None:
            save_vlan_catalog(vlans)
            validate_vlan_objects(vlans, device)
        for interface in creates + updates:
            interface.validated_save()
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
        return plan
