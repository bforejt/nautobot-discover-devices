"""Existing Device capacity custom fields at the native Nautobot boundary."""

from copy import deepcopy

from nautobot.dcim.models import Device
from nautobot.extras.models import CustomField

from .exceptions import InventoryError
from .reconcile_capacity import CAPACITY_FIELDS, blank_capacity, capacity_field_reason


def snapshot_capacity(device, *, lock=False, discovery=None):
    """Read only the approved definitions and raw values; never create schema."""
    result = {"supported": False, "reason": None, "fields": {}, "values": {}}
    if (
        not isinstance(discovery, dict)
        or discovery.get("adapter") != "panos"
        or "capacity" not in discovery
    ):
        return result
    model_fields = {field.name: field for field in Device._meta.fields}
    custom_fields = {field.name: field for field in CustomField._meta.get_fields()}
    storage = model_fields.get("_custom_field_data")
    scope = custom_fields.get("content_types")
    if (
        storage is None
        or storage.get_internal_type() != "JSONField"
        or not isinstance(getattr(device, "_custom_field_data", None), dict)
        or not {"key", "type"}.issubset(custom_fields)
        or scope is None
        or not scope.many_to_many
    ):
        result["reason"] = (
            "Native Device custom-field storage or definition capability is unavailable"
        )
        return result
    result["supported"] = True
    result["values"] = {
        key: deepcopy(device._custom_field_data.get(key)) for key in CAPACITY_FIELDS
    }
    definitions = CustomField.objects.filter(key__in=CAPACITY_FIELDS).order_by("key")
    if lock:
        definitions = definitions.select_for_update()
    for definition in definitions.prefetch_related("content_types"):
        result["fields"][definition.key] = {
            "id": str(definition.pk),
            "type": definition.type,
            "device_scope": any(
                content_type.app_label == "dcim" and content_type.model == "device"
                for content_type in definition.content_types.all()
            ),
            "supported": callable(getattr(definition, "validate", None)),
            "scope_filter": deepcopy(getattr(definition, "scope_filter", None)),
            "validation_minimum": getattr(definition, "validation_minimum", None),
            "validation_maximum": getattr(definition, "validation_maximum", None),
        }
    return result


def stage_capacity(plan, device):
    """Recheck definitions and raw blanks before staging all values in memory."""
    updates = plan.get("capacity", {}).get("updates", [])
    if not updates:
        return
    inventory = snapshot_capacity(device, discovery={"adapter": "panos", "capacity": {}})
    if inventory["supported"] is not True:
        raise InventoryError("Native Device capacity capability changed; retry discovery")
    values = deepcopy(device._custom_field_data)
    seen = set()
    for update in updates:
        key, after = update["field"], update["after"]
        if key not in CAPACITY_FIELDS or key in seen or type(after) is not int or after <= 0:
            raise InventoryError("Invalid Device capacity field update")
        seen.add(key)
        definition = inventory["fields"].get(key)
        reason = capacity_field_reason(definition, after)
        if reason or definition["id"] != update.get("definition_id"):
            raise InventoryError("Device capacity definition changed; retry discovery")
        before = values.get(key)
        if (
            not blank_capacity(before)
            or type(before) is not type(update["before"])
            or before != update["before"]
        ):
            raise InventoryError("Device capacity intent changed; retry discovery")
        # Native value validation is mandatory in addition to the pure range check.
        cleaned = CustomField.objects.get(pk=definition["id"]).validate(after)
        if type(cleaned) is not int or cleaned != after:
            raise InventoryError("Native capacity validation altered the reported capacity")
        values[key] = after
    device._custom_field_data = values


def clean_capacity_device(device, **kwargs):
    """Run complete model clean while preserving exact unrelated and populated CFs.

    Nautobot clean() can normalize existing custom-field values and add defaults.
    Neither operation is part of capacity discovery. Proposed values already
    passed their own native field validator and still pass full model validation.
    """
    intended = deepcopy(device._custom_field_data)
    device.full_clean(**kwargs)
    device._custom_field_data = intended


def save_capacity_device(device):
    """Use the native full_clean/save sequence once for the selected Device."""
    clean_capacity_device(device)
    device.save()
