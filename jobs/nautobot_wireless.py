"""Native AP graphs: read-only staging and independently atomic reconciliation."""

from copy import deepcopy
from uuid import UUID

from .exceptions import InventoryError


class SharedSourceError(InventoryError):
    """The controller scope or declared native policy changed during the batch."""


def _cancellation_errors():
    try:
        from billiard.exceptions import SoftTimeLimitExceeded
    except ImportError:
        return ()
    return (SoftTimeLimitExceeded,)


def _models():
    from nautobot.dcim import models

    required = (
        "Controller",
        "ControllerManagedDeviceGroup",
        "Device",
        "DeviceType",
        "Interface",
        "Location",
        "Manufacturer",
        "Platform",
        "SoftwareVersion",
    )
    if any(not hasattr(models, name) for name in required):
        raise InventoryError("Installed Nautobot lacks reviewed native wireless capabilities")
    return {name: getattr(models, name) for name in required}


def _id(value):
    return str(value) if value is not None else None


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def _device_row(device):
    interfaces = [
        {
            "id": str(interface.pk),
            "name": interface.name,
            "type": interface.type,
            "enabled": interface.enabled,
            "mac_address": str(interface.mac_address) if interface.mac_address else None,
            "speed": interface.speed,
            "description": interface.description,
        }
        for interface in device.interfaces.all().order_by("pk")
    ]
    return {
        "id": str(device.pk),
        "name": device.name,
        "serial": device.serial,
        "model": device.device_type.model,
        "device_type_id": str(device.device_type_id),
        "manufacturer_id": str(device.device_type.manufacturer_id),
        "manufacturer_name": device.device_type.manufacturer.name,
        "platform_id": _id(device.platform_id),
        "location_id": _id(device.location_id),
        "role_id": _id(device.role_id),
        "status_id": _id(device.status_id),
        "software_version_id": _id(device.software_version_id),
        "software_version": device.software_version.version if device.software_version_id else None,
        "controller_managed_device_group_id": _id(device.controller_managed_device_group_id),
        "rack_id": _id(device.rack_id),
        "rack_location_id": _id(device.rack.location_id) if device.rack_id else None,
        "interfaces": interfaces,
        "mac_addresses": [row["mac_address"] for row in interfaces if row["mac_address"]],
    }


def resolve_wireless_target(kind, identifier):
    """Resolve only existing explicitly selected native UUID targets."""
    from django.contrib.contenttypes.models import ContentType
    from nautobot.extras.models import Role, Status

    models = _models()
    names = {
        "manufacturer": "Manufacturer",
        "platform": "Platform",
        "location": "Location",
        "managed_group": "ControllerManagedDeviceGroup",
        "device": "Device",
    }
    model = {"role": Role, "status": Status}.get(kind)
    if model is None:
        model = models.get(names.get(kind))
    if model is None:
        raise InventoryError("Unsupported wireless policy target")
    try:
        obj = model.objects.get(pk=str(UUID(str(identifier))))
    except (model.DoesNotExist, ValueError, TypeError):
        raise InventoryError(
            "Explicit wireless %s UUID does not identify an existing object" % kind
        ) from None
    if kind == "device":
        return _device_row(obj)
    result = {"id": str(obj.pk), "name": obj.name}
    content_type = ContentType.objects.get_for_model(models["Device"])
    if kind in {"role", "status"} and not obj.content_types.filter(pk=content_type.pk).exists():
        raise InventoryError("Selected wireless %s is not applicable to native Device" % kind)
    if kind == "location":
        if not obj.location_type.content_types.filter(pk=content_type.pk).exists():
            raise InventoryError("Selected Location Type does not permit native Devices")
        result["location_type_id"] = str(obj.location_type_id)
    if kind == "managed_group":
        result["controller_id"] = str(obj.controller_id)
    if kind == "platform":
        result["manufacturer_id"] = _id(obj.manufacturer_id)
    return result


def _policy_targets(policy, *, lock=False):
    """Recheck declared native target facts; UUIDs alone do not preserve scope."""
    models = _models()
    from nautobot.extras.models import Role, Status

    classes = {
        "manufacturer": models["Manufacturer"],
        "platform": models["Platform"],
        "role": Role,
        "status": Status,
        "managed_group": models["ControllerManagedDeviceGroup"],
        "location": models["Location"],
        "device": models["Device"],
    }
    targets = [(kind, policy[kind]) for kind in classes if kind in policy]
    targets.extend(("location", row["location"]) for row in policy.get("locations", []))
    targets.extend(("device", row["device"]) for row in policy.get("identity_bindings", []))
    for kind, expected in sorted(targets, key=lambda row: (row[0], row[1]["id"])):
        model = classes[kind]
        if lock and kind != "device":
            try:
                _locked(model.objects.all(), True).get(pk=expected["id"])
            except model.DoesNotExist:
                raise InventoryError("Selected wireless policy target no longer exists") from None
        actual = resolve_wireless_target(kind, expected["id"])
        # Device facts legitimately change as APs are reconciled; its identity
        # remains planner input and is checked under ordered Device locks.
        keys = {"id", "controller_id", "manufacturer_id", "location_type_id"} & expected.keys()
        if any(actual.get(key) != expected.get(key) for key in keys):
            raise InventoryError("Selected wireless policy target changed scope; retry discovery")


def _source(discovery, policy, *, lock=False):
    try:
        return _source_impl(discovery, policy, lock=lock)
    except InventoryError as exc:
        raise SharedSourceError(str(exc)) from None


def _source_impl(discovery, policy, *, lock=False):
    from .controller_sources import controller_snapshot

    models = _models()
    controller_id = discovery.get("controller_id") or policy.get("controller_id")
    if str(controller_id) != str(policy.get("controller_id")):
        raise InventoryError("Wireless discovery and admission policy select different Controllers")
    try:
        controller = _locked(models["Controller"].objects.all(), lock).get(pk=controller_id)
    except models["Controller"].DoesNotExist:
        raise InventoryError("Wireless source Controller no longer exists") from None
    expected = discovery.get("source_binding")
    if not isinstance(expected, dict) or expected.get("id") != str(controller.pk):
        raise InventoryError(
            "Wireless discovery requires a verified native controller source binding"
        )
    if lock:
        integration = controller.external_integration
        if integration is not None:
            controller.external_integration = _locked(type(integration).objects.all(), True).get(
                pk=integration.pk
            )
        if expected.get("seed_kind") == "ap" or expected.get("seed_is_ap") is True:
            group_id = expected.get("seed_group_id")
            if group_id is not None:
                try:
                    _locked(models["ControllerManagedDeviceGroup"].objects.all(), True).get(
                        pk=group_id
                    )
                except models["ControllerManagedDeviceGroup"].DoesNotExist:
                    raise InventoryError("Seed AP managed group no longer exists") from None
        endpoint = controller.controller_device
        if endpoint is not None:
            from nautobot.ipam.models import IPAddress

            list(
                _locked(
                    IPAddress.objects.filter(
                        pk__in={
                            identifier
                            for identifier in (endpoint.primary_ip4_id, endpoint.primary_ip6_id)
                            if identifier is not None
                        }
                    ).order_by("pk"),
                    True,
                )
            )
    if expected is not None:
        current = controller_snapshot(controller, controller.controller_device)
        if not set(current).issubset(expected):
            raise InventoryError("Wireless controller binding lacks required native source facts")
        if any(current.get(key) != value for key, value in expected.items() if key in current):
            raise InventoryError("Native controller endpoint binding changed; retry discovery")
        seed_id = expected.get("seed_device_id")
        if seed_id is not None and (
            expected.get("seed_kind") == "ap" or expected.get("seed_is_ap") is True
        ):
            try:
                seed = models["Device"].objects.get(pk=seed_id)
            except models["Device"].DoesNotExist:
                raise InventoryError("Controller seed Device no longer exists") from None
            if _id(seed.controller_managed_device_group_id) != expected.get("seed_group_id"):
                raise InventoryError("Seed AP configured group changed; retry discovery")
            if seed.controller_managed_device_group_id and str(
                seed.controller_managed_device_group.controller_id
            ) != str(controller.pk):
                raise InventoryError("Seed AP configured Controller changed; retry discovery")
    _policy_targets(policy, lock=lock)
    return controller


def snapshot_wireless_inventory(discovery, policy, *, lock=False):
    """Include exact serial identities, naming collisions and selected bindings."""
    from django.db.models import Q
    from django.db.models.functions import Trim

    models = _models()
    _source(discovery, policy, lock=lock)
    aps = discovery.get("aps", [])
    serials = {row.get("serial") for row in aps if isinstance(row, dict) and row.get("serial")}
    names = {row.get("name") for row in aps if isinstance(row, dict) and row.get("name")}
    bindings = {row["device"]["id"] for row in policy.get("identity_bindings", [])}
    source_device_ids = {
        value
        for key, value in discovery.get("source_binding", {}).items()
        if key in {"controller_device_id", "seed_device_id"} and value is not None
    }
    query = (
        models["Device"]
        .objects.annotate(_wireless_serial=Trim("serial"))
        .filter(
            Q(_wireless_serial__in=serials)
            | Q(pk__in=bindings)
            | Q(name__in=names)
            | Q(pk__in=source_device_ids)
        )
        .select_related("device_type__manufacturer", "software_version", "platform", "rack")
        .order_by("pk")
    )
    # Platforms serialize software catalog creation; Manufacturer serializes
    # missing-AP admission across controller scopes before ordered Device locks.
    manufacturer_ids = {policy["manufacturer"]["id"]} if "manufacturer" in policy else set()
    manufacturer_ids.update(query.values_list("device_type__manufacturer_id", flat=True))
    if lock:
        list(
            _locked(
                models["Manufacturer"].objects.filter(pk__in=manufacturer_ids).order_by("pk"), True
            )
        )
    platform_ids = set(query.exclude(platform=None).values_list("platform_id", flat=True))
    if "platform" in policy:
        platform_ids.add(policy["platform"]["id"])
    if lock:
        list(_locked(models["Platform"].objects.filter(pk__in=platform_ids).order_by("pk"), True))
    types = list(
        _locked(
            models["DeviceType"]
            .objects.filter(
                manufacturer_id__in=manufacturer_ids,
                model__in={row.get("model") for row in aps if isinstance(row, dict)},
            )
            .order_by("pk"),
            lock,
        )
    )
    versions = list(
        _locked(
            models["SoftwareVersion"]
            .objects.filter(
                platform_id__in=platform_ids,
                version__in={row.get("software_version") for row in aps if isinstance(row, dict)},
            )
            .order_by("pk"),
            lock,
        )
    )
    devices = list(_locked(query, lock))
    if lock:
        list(_locked(models["Interface"].objects.filter(device__in=devices).order_by("pk"), True))
        _source(discovery, policy)
    return {
        "supported": True,
        "locations": list(
            {row["location"]["id"]: row["location"] for row in policy.get("locations", [])}.values()
        ),
        "devices": [_device_row(row) for row in devices],
        "device_types": [
            {"id": str(row.pk), "model": row.model, "manufacturer_id": str(row.manufacturer_id)}
            for row in types
        ],
        "software_versions": [
            {"id": str(row.pk), "version": row.version, "platform_id": str(row.platform_id)}
            for row in versions
        ],
    }


def _status(model, selected):
    from nautobot.extras.models import Status

    queryset = Status.objects.get_for_model(model)
    try:
        return (
            queryset.get(pk=getattr(selected, "pk", selected))
            if selected is not None
            else queryset.get(name="Active")
        )
    except (Status.DoesNotExist, Status.MultipleObjectsReturned, ValueError):
        raise InventoryError(
            "Select an applicable status for new %s records" % model.__name__
        ) from None


def _stage(ap, *, interface_status=None, software_version_status=None):
    """Construct one validated graph without any save or other inventory DML."""
    models = _models()
    software = None
    spec = ap.get("software")
    if spec:
        if spec["create"]:
            software = models["SoftwareVersion"](
                platform_id=spec["platform_id"],
                version=spec["version"],
                status=_status(models["SoftwareVersion"], software_version_status),
            )
        else:
            software = models["SoftwareVersion"].objects.get(pk=spec["existing_id"])
        if (
            str(software.platform_id) != str(spec["platform_id"])
            or software.version != spec["version"]
        ):
            raise InventoryError("AP software catalog identity changed; retry discovery")
        software.full_clean()
    if ap["create"]:
        attrs = {key: value for key, value in ap["device"].items() if key != "manufacturer_id"}
        device = models["Device"](**attrs)
    else:
        device = models["Device"].objects.get(pk=ap["device_id"])
    allowed = {"location_id", "software_version_id", "serial", "name"}
    for change in ap.get("updates", []):
        field = change["field"]
        if field not in allowed:
            raise InventoryError("Unsupported AP replacement domain")
        before = getattr(device, field)
        if (_id(before) if field.endswith("_id") else before) != change["before"]:
            raise InventoryError("AP changed after planning; retry discovery")
        if field in {"serial", "name"} and before not in {None, ""}:
            raise InventoryError("AP verified identity fills cannot replace populated identity")
        if field == "software_version_id":
            if software is None:
                raise InventoryError("AP software update lacks a validated catalog proposal")
            device.software_version = software
        else:
            setattr(device, field, change["after"])
    if ap["create"] and software is not None:
        device.software_version = software
    if software is not None and str(device.platform_id) != str(software.platform_id):
        raise InventoryError("AP running software must use the AP's own Platform")
    excludes = ["software_version"] if software is not None and software._state.adding else []
    device.full_clean(exclude=excludes)
    if ap["create"]:
        from .nautobot_stack import _suppression_context

        _suppression_context(device.device_type)
    interfaces = []
    for spec in ap.get("interface_creates", []):
        if type(spec.get("enabled")) is not bool or spec.get("type") != "other":
            raise InventoryError(
                "AP Ethernet creation requires reviewed type and explicit administration"
            )
        obj = models["Interface"](
            device=device,
            status=_status(models["Interface"], interface_status),
            **{key: value for key, value in spec.items() if key != "source"},
        )
        obj.full_clean(exclude=["device"] if device._state.adding else [])
        interfaces.append(obj)
    for spec in ap.get("interface_updates", []):
        obj = models["Interface"].objects.get(pk=spec["id"], device_id=device.pk)
        for change in spec["changes"]:
            field = change["field"]
            before = getattr(obj, field, None)
            if field not in {"mac_address", "speed", "description"} or before not in {None, ""}:
                raise InventoryError("AP Ethernet updates can only fill reviewed blank facts")
            if before != change["before"]:
                raise InventoryError("AP Ethernet changed after planning; retry discovery")
            setattr(obj, change["field"], change["after"])
        obj.full_clean()
        interfaces.append(obj)
    return {"device": device, "software": software, "interfaces": interfaces, "ap": ap}


def validate_wireless_plan(plan, *, interface_status=None, software_version_status=None):
    """Annotate independent native failures while retaining eligible AP graphs."""
    if not isinstance(plan, dict) or plan.get("contract") != "wireless-plan-v1":
        raise InventoryError("Unsupported native wireless plan contract")
    if plan.get("errors"):
        raise InventoryError("; ".join(plan["errors"]))
    for ap in plan.get("aps", []):
        if ap.get("errors") or ap.get("outcome") in {"unresolved", "unchanged"}:
            continue
        try:
            _stage(
                ap,
                interface_status=interface_status,
                software_version_status=software_version_status,
            )
        except _cancellation_errors():
            raise
        except Exception as exc:
            ap.setdefault("errors", []).append("Native AP validation failed: %s" % exc)
            ap["outcome"] = "unresolved"
    _summary(plan)
    return plan


def _summary(plan, *, applied=False):
    """Count only graphs that remain actionable or were actually committed."""
    rows = plan["aps"]
    active = [
        row
        for row in rows
        if row["outcome"] in ({"created", "updated"} if applied else {"eligible"})
    ]
    summary = {key: 0 for key in plan.get("summary", {})}
    summary["observed"] = len(rows)
    for outcome in ("eligible", "unchanged", "unresolved", "failed"):
        summary[outcome] = sum(row["outcome"] == outcome for row in rows)
    for outcome in ("created", "updated"):
        summary[outcome] = (
            sum(row["outcome"] == outcome for row in rows)
            if applied
            else sum(row["create"] == (outcome == "created") for row in active)
        )
    summary["location_updates"] = sum(
        change["field"] == "location_id" for row in active for change in row["updates"]
    )
    summary["software_updates"] = sum(
        change["field"] == "software_version_id" for row in active for change in row["updates"]
    )
    for key in ("interface_creates", "interface_updates"):
        summary[key] = sum(len(row[key]) for row in active)
    plan["summary"] = summary


def _save(graph):
    from .nautobot_stack import _suppression_context

    device, software, ap = graph["device"], graph["software"], graph["ap"]
    if software is not None and software._state.adding:
        software.validated_save()
    if ap["create"]:
        with _suppression_context(device.device_type):
            device.validated_save()
    elif ap.get("updates"):
        device.validated_save()
    for interface in graph["interfaces"]:
        interface.validated_save()


def apply_wireless_discovery(
    discovery,
    policy,
    *,
    interface_status=None,
    software_version_status=None,
    progress_callback=None,
):
    """Validate the full index once, then replan and commit independent AP graphs.

    The optional callback receives current actual outcomes after each graph's
    transaction exits, and before cancellation propagates. Pending rows never
    appear as committed updates in the published report.
    """
    from django.db import transaction

    from .reconcile_wireless import build_wireless_plan

    initial = build_wireless_plan(discovery, snapshot_wireless_inventory(discovery, policy), policy)
    if initial.get("errors"):
        raise InventoryError("; ".join(initial["errors"]))
    _source(discovery, policy)
    result = deepcopy(initial)
    for row in result["aps"]:
        row["outcome"] = "pending"
    _summary(result, applied=True)
    result["partial"] = False
    result["incomplete"] = False
    observations = {row.get("serial"): row for row in discovery["aps"]}

    def publish(index, ap):
        result["aps"][index] = ap
        outcome = ap["outcome"]
        if outcome in result["summary"]:
            result["summary"][outcome] += 1
        if outcome in {"created", "updated"}:
            result["summary"]["location_updates"] += sum(
                change["field"] == "location_id" for change in ap["updates"]
            )
            result["summary"]["software_updates"] += sum(
                change["field"] == "software_version_id" for change in ap["updates"]
            )
            for key in ("interface_creates", "interface_updates"):
                result["summary"][key] += len(ap[key])
        result["partial"] = result["partial"] or outcome in {"failed", "unresolved"}
        if progress_callback is not None:
            progress_callback(result)

    for index, original in enumerate(initial["aps"]):
        try:
            if original.get("errors") or original.get("outcome") == "unresolved":
                publish(index, deepcopy(original))
                continue
            # Duplicate identities and labels were rejected in the complete
            # index above. Retain that proof while querying only this AP's
            # relevant native collisions and exact software/model catalogs.
            scoped_discovery = {**discovery, "aps": [observations[original["key"]]]}
            scoped_policy = {
                **policy,
                "identity_bindings": [
                    row
                    for row in policy.get("identity_bindings", [])
                    if row["serial"] == original["key"]
                ],
            }
            with transaction.atomic():
                current = build_wireless_plan(
                    scoped_discovery,
                    snapshot_wireless_inventory(scoped_discovery, scoped_policy, lock=True),
                    scoped_policy,
                )
                if current.get("errors"):
                    raise InventoryError("; ".join(current["errors"]))
                if len(current["aps"]) != 1 or current["aps"][0]["key"] != original["key"]:
                    raise InventoryError("AP identity index changed during reconciliation")
                ap = current["aps"][0]
                if not ap.get("errors") and ap.get("outcome") == "eligible":
                    graph = _stage(
                        ap,
                        interface_status=interface_status,
                        software_version_status=software_version_status,
                    )
                    _save(graph)
                    ap["device_id"] = str(graph["device"].pk)
                    if graph["software"] is not None:
                        software_id = str(graph["software"].pk)
                        ap["software"]["result_id"] = software_id
                        for change in ap["updates"]:
                            if change["field"] == "software_version_id":
                                change["after"] = software_id
                    for spec in ap["interface_creates"]:
                        spec["result_id"] = next(
                            str(obj.pk) for obj in graph["interfaces"] if obj.name == spec["name"]
                        )
                    ap["outcome"] = "created" if ap["create"] else "updated"
            publish(index, ap)
        except _cancellation_errors():
            result["incomplete"] = True
            result["partial"] = True
            if progress_callback is not None:
                progress_callback(result)
            raise
        except SharedSourceError as exc:
            result.setdefault("errors", []).append(
                "Controller scope changed during batch: %s" % exc
            )
            for pending_index, pending in enumerate(initial["aps"][index:], start=index):
                failed = deepcopy(pending)
                failed.setdefault("errors", []).append(
                    "Shared controller source changed; graph not applied"
                )
                failed["outcome"] = "failed"
                publish(pending_index, failed)
            break
        except Exception as exc:
            failed = deepcopy(original)
            failed.setdefault("errors", []).append("AP graph rolled back: %s" % exc)
            failed["outcome"] = "failed"
            publish(index, failed)
    _summary(result, applied=True)
    return result
