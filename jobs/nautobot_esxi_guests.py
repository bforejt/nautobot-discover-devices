"""Native existing-schema Hosted On boundary; no guest or schema creation."""

from copy import deepcopy

from django.contrib.contenttypes.models import ContentType
from nautobot.dcim.models import Device
from nautobot.extras import models as extras_models

from .exceptions import InventoryError
from .reconcile_esxi_guests import CONTRACT, relationship_matches, validated_policy


def _capability():
    relationship = getattr(extras_models, "Relationship", None)
    association = getattr(extras_models, "RelationshipAssociation", None)
    if relationship is None or association is None:
        return None
    relation_fields = {field.name: field for field in relationship._meta.fields}
    association_fields = {field.name: field for field in association._meta.fields}
    if not {
        "id",
        "key",
        "type",
        "source_type",
        "destination_type",
        "source_filter",
        "destination_filter",
    }.issubset(relation_fields) or not {
        "id",
        "relationship",
        "source_type",
        "source_id",
        "destination_type",
        "destination_id",
    }.issubset(association_fields):
        return None
    if (
        getattr(association_fields["relationship"], "related_model", None) is not relationship
        or any(
            getattr(association_fields[field], "related_model", None) is not ContentType
            for field in ("source_type", "destination_type")
        )
        or any(
            getattr(relation_fields[field], "related_model", None) is not ContentType
            for field in ("source_type", "destination_type")
        )
        or any(
            association_fields[field].get_internal_type() != "UUIDField"
            for field in ("id", "source_id", "destination_id")
        )
        or "one-to-many" not in {value for value, label in relation_fields["type"].flatchoices}
        or not callable(getattr(association, "full_clean", None))
        or not callable(getattr(association, "validated_save", None))
    ):
        return None
    return relationship, association


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def _type(content_type):
    return "%s.%s" % (content_type.app_label, content_type.model)


def _relationship(relationship):
    return {
        "id": str(relationship.pk),
        "key": relationship.key,
        "type": relationship.type,
        "source_type": _type(relationship.source_type),
        "destination_type": _type(relationship.destination_type),
        "source_filter": deepcopy(relationship.source_filter),
        "destination_filter": deepcopy(relationship.destination_filter),
    }


def _policy(discovery, device=None):
    if not isinstance(discovery, dict) or discovery.get("adapter") != "esxi":
        return None
    policy = discovery.get("guest_policy")
    if policy is None:
        return None
    if not isinstance(policy, dict):
        raise InventoryError("ESXi Hosted On policy has an invalid contract")
    host_id = str(device.pk) if device is not None else policy.get("host_device_id")
    if not validated_policy(policy, host_id):
        raise InventoryError("ESXi Hosted On policy does not match the selected existing Devices")
    return policy


def lock_esxi_guests(discovery):
    """Lock the shared relationship before ordered host/guest Device locks.

    Call only inside the surrounding apply transaction. Serializing on the
    existing definition prevents two discovery applies from adding competing
    one-to-many ownership for a guest with no association row to lock yet.
    """
    policy = _policy(discovery)
    if policy is None:
        return
    capability = _capability()
    if capability is None:
        raise InventoryError("Native Hosted On capability is unavailable")
    Relationship, _ = capability
    try:
        relationship = Relationship.objects.select_for_update(of=("self",)).get(
            pk=policy["relationship"]["id"]
        )
    except Relationship.DoesNotExist:
        raise InventoryError(
            "The selected existing Hosted On relationship no longer exists"
        ) from None
    if not relationship_matches(_relationship(relationship), policy):
        raise InventoryError("The selected Hosted On relationship changed identity or scope")


def snapshot_esxi_guests(device, *, lock=False, discovery=None):
    """Read selected guests and every existing ownership record in their UUID scope."""
    result = {
        "supported": False,
        "reason": None,
        "relationship": None,
        "devices": [],
        "associations": [],
    }
    if not isinstance(discovery, dict) or discovery.get("adapter") != "esxi":
        return result
    policy = _policy(discovery, device)
    if policy is None:
        result["reason"] = "No explicit ESXi guest Device mappings were supplied"
        return result
    capability = _capability()
    if capability is None:
        result["reason"] = "Installed native Hosted On capability is unavailable"
        return result
    Relationship, Association = capability
    try:
        relationship = _locked(Relationship.objects.all(), lock).get(
            pk=policy["relationship"]["id"]
        )
    except Relationship.DoesNotExist:
        result["reason"] = "The selected existing Hosted On relationship no longer exists"
        return result
    guest_ids = sorted(row["device"]["id"] for row in policy["mappings"])
    result.update(
        {
            "supported": True,
            "relationship": _relationship(relationship),
            "devices": [
                {"id": str(row.pk), "name": row.name}
                for row in _locked(Device.objects.filter(pk__in=guest_ids).order_by("pk"), lock)
            ],
            "associations": [
                {
                    "id": str(row.pk),
                    "relationship_id": str(row.relationship_id),
                    "source_type": _type(row.source_type),
                    "source_id": str(row.source_id),
                    "destination_type": _type(row.destination_type),
                    "destination_id": str(row.destination_id),
                }
                for row in _locked(
                    Association.objects.filter(
                        relationship=relationship,
                        destination_id__in=guest_ids,
                    )
                    .select_related("source_type", "destination_type")
                    .order_by("pk"),
                    lock,
                )
            ],
        }
    )
    return result


def stage_esxi_guests(plan, device):
    """Stage only native associations after checking current ownership and definition."""
    domain = plan.get("esxi_guests", plan)
    if not isinstance(domain, dict) or domain.get("contract") != CONTRACT:
        if plan.get("adapter") == "esxi":
            raise InventoryError("Unsupported native ESXi Hosted On plan")
        return []
    if domain.get("errors"):
        raise InventoryError("; ".join(domain["errors"]))
    if not domain.get("creates"):
        return []
    policy = domain.get("policy")
    if not validated_policy(policy, str(device.pk)):
        raise InventoryError("Native Hosted On plan lacks explicit selected Device ownership")
    capability = _capability()
    if capability is None:
        raise InventoryError("Native Hosted On capability changed; retry discovery")
    Relationship, Association = capability
    try:
        relationship = Relationship.objects.get(pk=policy["relationship"]["id"])
    except Relationship.DoesNotExist:
        raise InventoryError(
            "The selected existing Hosted On relationship no longer exists"
        ) from None
    definition = _relationship(relationship)
    if not relationship_matches(definition, policy) or definition != domain.get("relationship"):
        raise InventoryError("Native Hosted On definition changed; retry discovery")
    targets = {row["device"]["id"]: row["vm_uuid"] for row in policy["mappings"]}
    objects, seen = [], set()
    for row in domain["creates"]:
        guest_id = row.get("destination_id")
        if (
            guest_id not in targets
            or guest_id in seen
            or row.get("vm_uuid") != targets[guest_id]
            or row.get("relationship_id") != str(relationship.pk)
            or row.get("source_id") != str(device.pk)
            or row.get("source_type") != "dcim.device"
            or row.get("destination_type") != "dcim.device"
        ):
            raise InventoryError("Invalid native Hosted On association plan")
        seen.add(guest_id)
        if not Device.objects.filter(pk=guest_id).exists():
            raise InventoryError("An explicitly selected ESXi guest Device no longer exists")
        if Association.objects.filter(relationship=relationship, destination_id=guest_id).exists():
            raise InventoryError("Native Hosted On ownership changed; retry discovery")
        objects.append(
            Association(
                relationship=relationship,
                source_type=relationship.source_type,
                source_id=device.pk,
                destination_type=relationship.destination_type,
                destination_id=guest_id,
            )
        )
    return objects


def validate_esxi_guests(objects):
    """Run complete native filter, scope and cardinality validation without saving."""
    for association in objects:
        association.full_clean()


def save_esxi_guests(objects):
    """Save additions through native validation; never replace an association."""
    for association in objects:
        association.validated_save()
