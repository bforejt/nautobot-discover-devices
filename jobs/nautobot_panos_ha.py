"""Feature-detected native DeviceRedundancyGroup boundary for PAN-OS HA."""

from copy import deepcopy

from nautobot.dcim import models as dcim_models

from .exceptions import InventoryError
from .panos_ha_policy import CONTRACT as POLICY_CONTRACT
from .reconcile_panos_ha import CONTRACT, PAIR_CONTRACT


def _capability():
    device = getattr(dcim_models, "Device", None)
    group = getattr(dcim_models, "DeviceRedundancyGroup", None)
    if device is None or group is None:
        return None
    device_fields = {field.name: field for field in device._meta.fields}
    group_fields = {field.name: field for field in group._meta.fields}
    membership = device_fields.get("device_redundancy_group")
    priority = device_fields.get("device_redundancy_group_priority")
    strategy = group_fields.get("failover_strategy")
    if (
        membership is None
        or getattr(membership, "related_model", None) is not group
        or priority is None
        or priority.get_internal_type() != "PositiveIntegerField"
        or strategy is None
        or "active-passive" not in {value for value, label in strategy.flatchoices}
        or not {"name", "status"}.issubset(group_fields)
    ):
        return None
    return device, group


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def _device_row(device):
    return {
        "id": str(device.pk),
        "name": device.name,
        "model": device.device_type.model,
        "serial": device.serial,
        "manufacturer_name": device.device_type.manufacturer.name,
        "platform_name": device.platform.name if device.platform else None,
        "platform_network_driver": device.platform.network_driver if device.platform else None,
        "device_redundancy_group_id": str(device.device_redundancy_group_id)
        if device.device_redundancy_group_id
        else None,
        "device_redundancy_group_priority": device.device_redundancy_group_priority,
    }


def snapshot_panos_ha(device, *, lock=False, discovery=None):
    """Read only the explicitly supplied peer, existing group and peer interfaces.

    The enclosing apply locks selected and peer Devices together, in UUID order,
    before this snapshot. Existing group and peer interface rows can also be
    locked here; no object lookup is based on a reported address or hostname.
    """
    result = {
        "supported": False,
        "reason": None,
        "policy": None,
        "group": None,
        "group_member_ids": [],
        "devices": [],
        "peer_interfaces": [],
    }
    pair = discovery.get("ha_pair") if isinstance(discovery, dict) else None
    if not isinstance(pair, dict) or pair.get("contract") != PAIR_CONTRACT:
        result["reason"] = "No explicit PAN-OS HA peer selection was supplied"
        return result
    policy = pair.get("policy")
    if (
        not isinstance(policy, dict)
        or policy.get("contract") != POLICY_CONTRACT
        or str(policy.get("selected_device_id")) != str(device.pk)
    ):
        raise InventoryError("PAN-OS HA policy does not match the selected Device")
    result["policy"] = deepcopy(policy)
    capability = _capability()
    if capability is None:
        result["reason"] = "Installed native DeviceRedundancyGroup capability is unavailable"
        return result
    Device, Group = capability
    peer_id, group_id = policy["peer_device"]["id"], policy["redundancy_group"]["id"]
    if str(peer_id) == str(device.pk):
        raise InventoryError("PAN-OS HA peer must be a different existing Device")
    try:
        peer = Device.objects.select_related("device_type").get(pk=peer_id)
        group = _locked(Group.objects.all(), lock).get(pk=group_id)
    except (Device.DoesNotExist, Group.DoesNotExist, ValueError):
        raise InventoryError(
            "An explicitly selected existing HA Device or group no longer exists"
        ) from None
    if (
        peer.device_type.model != policy["peer_device"].get("model")
        or peer.device_type.model != "PA-VM"
    ):
        raise InventoryError("PAN-OS HA selected peer DeviceType changed; retry discovery")
    result.update(
        {
            "supported": True,
            "group": {
                "id": str(group.pk),
                "name": group.name,
                "failover_strategy": group.failover_strategy,
            },
            "group_member_ids": [
                str(value)
                for value in Device.objects.filter(device_redundancy_group=group)
                .order_by("pk")
                .values_list("pk", flat=True)
            ],
            "devices": [_device_row(device), _device_row(peer)],
            "peer_interfaces": [
                {
                    "id": str(interface.pk),
                    "name": interface.name,
                    "device_id": str(peer.pk),
                    "vrf_id": str(interface.vrf_id) if interface.vrf_id else None,
                }
                for interface in _locked(peer.interfaces.all().order_by("pk"), lock)
            ],
        }
    )
    return result


def _plan(plan):
    result = plan.get("ha", plan)
    if not isinstance(result, dict) or result.get("contract") != CONTRACT:
        raise InventoryError("Unsupported native PAN-OS HA plan")
    return result


def _changes(obj, changes, allowed):
    seen = set()
    for change in changes:
        field = change.get("field") if isinstance(change, dict) else None
        if field not in allowed or field in seen:
            raise InventoryError("Invalid native PAN-OS HA enrichment")
        seen.add(field)
        before = getattr(obj, field)
        expected = change.get("before")
        if type(before) is not type(expected) or before != expected:
            raise InventoryError(
                "Native PAN-OS HA intent changed during validation; retry discovery"
            )
        if before not in (None, ""):
            raise InventoryError("Populated native PAN-OS HA intent must be preserved")
        after = change.get("after")
        if field == "failover_strategy" and after != "active-passive":
            raise InventoryError("Unsupported PAN-OS HA native failover strategy")
        if field == "device_redundancy_group_priority" and (
            type(after) is not int or not 1 <= after <= 255
        ):
            raise InventoryError("PAN-OS HA native priority must be an explicit positive integer")
        setattr(obj, field, after)


def stage_panos_ha(plan, device):
    """Stage fill-only existing group/Device updates without inventory writes."""
    ha = _plan(plan)
    objects = {
        "plan": ha,
        "group": None,
        "group_changed": False,
        "devices": {},
        "selected_device_id": str(device.pk),
        "selected_device_changed": False,
    }
    if not ha.get("group_updates") and not ha.get("device_updates"):
        return objects
    capability = _capability()
    if capability is None:
        raise InventoryError("Native PAN-OS HA capability changed; retry discovery")
    Device, Group = capability
    policy = ha.get("policy")
    if (
        not isinstance(policy, dict)
        or policy.get("contract") != POLICY_CONTRACT
        or policy.get("selected_device_id") != str(device.pk)
    ):
        raise InventoryError("Native PAN-OS HA plan lacks explicit selected Device ownership")
    group_id = policy["redundancy_group"]["id"]
    try:
        group = Group.objects.get(pk=group_id)
    except Group.DoesNotExist:
        raise InventoryError("Selected existing PAN-OS HA group no longer exists") from None
    objects["group"] = group
    updates = ha.get("group_updates", [])
    if len(updates) > 1 or any(str(row.get("id")) != str(group.pk) for row in updates):
        raise InventoryError("Native PAN-OS HA plan attempts to update another group")
    for row in updates:
        _changes(group, row["changes"], {"failover_strategy"})
        objects["group_changed"] = True
    pair_ids = {str(device.pk), policy["peer_device"]["id"]}
    seen = set()
    for row in ha.get("device_updates", []):
        device_id = str(row.get("id"))
        if device_id not in pair_ids or device_id in seen:
            raise InventoryError("Native PAN-OS HA plan attempts to update another Device")
        seen.add(device_id)
        try:
            target = device if device_id == str(device.pk) else Device.objects.get(pk=device_id)
        except Device.DoesNotExist:
            raise InventoryError("Selected existing PAN-OS HA peer no longer exists") from None
        for change in row["changes"]:
            if (
                change.get("field") == "device_redundancy_group_id"
                and str(change.get("after")) != group_id
            ):
                raise InventoryError(
                    "Native PAN-OS HA Device target group is outside the explicit selection"
                )
            if change.get("field") == "device_redundancy_group_priority" and change.get(
                "after"
            ) != ha.get("observed", {}).get("priorities", {}).get(device_id):
                raise InventoryError(
                    "Native PAN-OS HA Device priority differs from reviewed applied evidence"
                )
        _changes(
            target,
            row["changes"],
            {"device_redundancy_group_id", "device_redundancy_group_priority"},
        )
        objects["devices"][device_id] = target
        if device_id == str(device.pk):
            objects["selected_device_changed"] = True
    return objects


def _clean(obj, **kwargs):
    intended = deepcopy(getattr(obj, "_custom_field_data", None))
    obj.full_clean(**kwargs)
    if isinstance(intended, dict):
        obj._custom_field_data = intended


def validate_panos_ha_objects(objects, *, validate_selected=True):
    """Validate the existing objects in memory; the enclosing preview performs no DML.

    The enclosing inventory boundary may validate the selected Device with its
    other staged fields and then pass ``validate_selected=False`` here.
    """
    if objects["group_changed"]:
        _clean(objects["group"])
    for device_id, device in objects["devices"].items():
        if validate_selected or device_id != objects["selected_device_id"]:
            _clean(device)


def save_panos_ha_objects(objects, *, save_selected=False):
    """Save actual HA changes once inside the enclosing atomic apply.

    The selected Device normally has one enclosing save for all discovery fields.
    Existing peer custom fields and unrelated intent retain their exact values.
    """
    if objects["group_changed"]:
        _clean(objects["group"])
        objects["group"].save()
    for device_id, device in objects["devices"].items():
        if save_selected or device_id != objects["selected_device_id"]:
            _clean(device)
            device.save()
