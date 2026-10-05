"""Fill-only planning for the three existing VM sizing custom fields.

These fields describe deployment intent. Discovery may seed empty intent from
reviewed capacity evidence, but it never converges populated intent to the
observed VM. Custom-field definitions are inventory, not objects to create.
"""

from copy import deepcopy

CAPACITY_CONTRACT = "panos-capacity-v1"
CAPACITY_FIELDS = ("vcpus", "memory_mb", "disk_gb")


def blank_capacity(value):
    """False and zero are populated, even when their type is unexpected."""
    return value is None or (isinstance(value, str) and not value.strip())


def capacity_field_reason(field, value):
    """Validate serialized native capability without importing Nautobot models."""
    if not isinstance(field, dict):
        return "Existing Device custom-field definition is missing"
    if not isinstance(field.get("id"), str) or not field["id"]:
        return "Existing custom-field identity is unavailable"
    if field.get("type") != "integer":
        return "Existing custom field must have Integer type"
    if field.get("device_scope") is not True:
        return "Existing custom field is not attached to Devices"
    if field.get("supported") is not True:
        return "Native custom-field validation capability is unavailable"
    scope_filter = field.get("scope_filter")
    if scope_filter is not None and not isinstance(scope_filter, dict):
        return "Custom-field scope metadata is incompatible"
    if scope_filter:
        return "Scoped custom-field definitions require a reviewed applicability policy"
    for name, test, label in (
        ("validation_minimum", lambda a, b: a < b, "below"),
        ("validation_maximum", lambda a, b: a > b, "above"),
    ):
        bound = field.get(name)
        if bound is None:
            continue
        if type(bound) is not int:
            return "Custom-field numeric validation metadata is incompatible"
        if test(value, bound):
            return "Reported capacity is %s the existing custom-field %s" % (label, name)
    return None


def plan_capacity(discovery, existing, *, identity_verified=False):
    """Propose exact fields after source and shared selected-Device identity checks."""
    plan = {
        "contract": CAPACITY_CONTRACT,
        "updates": [],
        "observed": {},
        "unresolved": [],
        "conflicts": [],
        "errors": [],
        "warnings": [],
        "preserve_custom_fields": False,
        "summary": {"capacity_fields_updated": 0, "unresolved_capacity": 0},
    }
    if discovery.get("adapter") != "panos" or "capacity" not in discovery:
        return plan

    from .adapters.panos_capacity import validate_capacity

    capacity = discovery["capacity"]
    if not validate_capacity(discovery, capacity):
        plan["errors"].append("PAN-OS capacity source provenance is invalid")
        return plan
    plan["preserve_custom_fields"] = True
    plan["observed"] = deepcopy(capacity["fields"])
    plan["unresolved"] = deepcopy(capacity["unresolved"])
    inventory = existing.get("capacity_inventory")
    device = existing.get("device", {})
    for key in CAPACITY_FIELDS:
        fact = capacity["fields"].get(key)
        if fact is None:
            continue
        after = fact["value"]
        reason = None
        if identity_verified is not True:
            reason = "Validated selected PAN-OS Device identity is required for capacity writes"
        elif not isinstance(inventory, dict) or inventory.get("supported") is not True:
            reason = (
                inventory.get("reason") if isinstance(inventory, dict) else None
            ) or "Native Device custom-field storage capability is unavailable"
        elif type(after) is not int or after <= 0:
            reason = "Observed capacity requires an explicit positive Integer capacity"
        else:
            reason = capacity_field_reason(inventory.get("fields", {}).get(key), after)
        if reason:
            plan["unresolved"].append(
                {
                    "field": key,
                    "reason": reason,
                    "observed": after,
                    "source": deepcopy(fact["source"]),
                }
            )
            continue
        before = inventory.get("values", {}).get(key)
        if blank_capacity(before):
            plan["updates"].append(
                {
                    "field": key,
                    "before": deepcopy(before),
                    "after": after,
                    "definition_id": inventory["fields"][key]["id"],
                    "source": deepcopy(fact["source"]),
                }
            )
        elif type(before) is not type(after) or before != after:
            plan["conflicts"].append(
                {
                    "scope": "device_capacity",
                    "name": device.get("name"),
                    "field": key,
                    "before": deepcopy(before),
                    "observed": after,
                    "source": deepcopy(fact["source"]),
                }
            )
    plan["summary"]["capacity_fields_updated"] = len(plan["updates"])
    plan["summary"]["unresolved_capacity"] = len(plan["unresolved"])
    return plan
