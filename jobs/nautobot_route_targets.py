"""Native RouteTarget snapshots and write-free VRF target relationship staging."""

from nautobot.ipam.models import VRF, RouteTarget, VRFDeviceAssignment

from .exceptions import InventoryError
from .reconcile_route_targets import canonical_route_target


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def snapshot_route_targets(vrfs, *, lock=False):
    """Lock native catalogs and both through tables inside the inventory transaction."""
    catalog = list(_locked(RouteTarget.objects.order_by("pk"), lock))
    relationships = {
        str(vrf.pk): {"import_target_ids": [], "export_target_ids": []} for vrf in vrfs
    }
    ids = [vrf.pk for vrf in vrfs]
    for direction in ("import", "export"):
        through = VRF._meta.get_field("%s_targets" % direction).remote_field.through
        rows = _locked(through.objects.filter(vrf_id__in=ids).order_by("pk"), lock)
        for row in rows:
            relationships[str(row.vrf_id)]["%s_target_ids" % direction].append(
                str(row.routetarget_id)
            )
    for row in relationships.values():
        for ids in row.values():
            ids.sort()
    return {
        "route_targets": [{"id": str(row.pk), "name": row.name} for row in catalog],
        "relationships": relationships,
    }


def route_target_objects(plan, vrfs, device):
    """Build cached UUID parents and native automatic through rows without DML."""
    objects = {"plan": plan, "targets": {}, "bindings": []}
    for spec in plan.get("route_targets", []):
        target = (
            RouteTarget(name=spec["name"])
            if spec["create"]
            else RouteTarget.objects.get(pk=spec["id"])
        )
        objects["targets"][spec["key"]] = target
    for spec in plan.get("vrf_route_targets", []):
        vrf = vrfs.get(spec["vrf_key"])
        if vrf is None or spec["direction"] not in ("import", "export"):
            raise InventoryError("Route target binding has no validated VRF or direction")
        through = VRF._meta.get_field("%s_targets" % spec["direction"]).remote_field.through
        rows = [
            through(vrf=vrf, routetarget=objects["targets"][key]) for key in spec["add_target_keys"]
        ]
        objects["bindings"].append((vrf, spec, rows))
    return objects


def _validate_binding_scope(vrf, spec, device, plan):
    if str(vrf.namespace_id) != spec["namespace_id"] or (
        spec["vrf_id"] is not None and str(vrf.pk) != spec["vrf_id"]
    ):
        raise InventoryError("Route target VRF identity or Namespace changed during validation")
    assignments = [
        row
        for row in plan.get("vrf_device_assignments", [])
        if row["vrf_key"] == spec["vrf_key"]
        and row["name"] == spec["local_name"]
        and str(row["device_id"]) == str(device.pk)
    ]
    if len(assignments) != 1 or spec["local_name"] == "Mgmt-vrf":
        raise InventoryError("Route target binding is not a resolved non-management Device VRF")
    if (
        not vrf._state.adding
        and VRFDeviceAssignment.objects.filter(vrf=vrf).exclude(device=device).exists()
    ):
        raise InventoryError("A shared VRF target direction cannot be established by one Device")
    before = (
        []
        if vrf._state.adding
        else sorted(
            str(pk)
            for pk in getattr(vrf, "%s_targets" % spec["direction"]).values_list("pk", flat=True)
        )
    )
    if before != sorted(spec["before_target_ids"]) or before:
        raise InventoryError(
            "An existing VRF target direction changed or is populated; retry discovery"
        )


def validate_route_target_objects(objects, device):
    """Validate the complete unsaved graph before any inventory write."""
    plan = objects["plan"]
    for spec in plan.get("route_targets", []):
        target = objects["targets"][spec["key"]]
        if target.name != spec["name"] or canonical_route_target(target.name) != spec["literal"]:
            raise InventoryError("Native route target literal identity changed during validation")
        target.full_clean()
    for vrf, spec, rows in objects["bindings"]:
        _validate_binding_scope(vrf, spec, device, plan)
        if spec.get("source", {}).get("complete") is not True:
            raise InventoryError("Incomplete route target source evidence cannot populate a VRF")
        for row in rows:
            if row.vrf_id != vrf.pk or row.routetarget_id not in {
                target.pk for target in objects["targets"].values()
            }:
                raise InventoryError("Invalid native VRF route target assignment")
            row.full_clean(
                exclude=[
                    field for field in ("vrf", "routetarget") if getattr(row, field)._state.adding
                ]
            )


def save_route_target_catalog(objects):
    """Save literal catalogs before VRF target through rows."""
    for spec in objects["plan"].get("route_targets", []):
        if spec["create"]:
            objects["targets"][spec["key"]].validated_save()


def save_route_target_assignments(objects, device):
    """Add native through rows after parent catalogs; never replace or remove rows."""
    for vrf, spec, rows in objects["bindings"]:
        _validate_binding_scope(vrf, spec, device, objects["plan"])
        for row in rows:
            row.full_clean()
        getattr(vrf, "%s_targets" % spec["direction"]).add(*(row.routetarget for row in rows))
