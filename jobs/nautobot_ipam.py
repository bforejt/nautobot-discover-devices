"""Namespace-scoped IPAM snapshots and a write-free staged routing graph."""

import copy
import ipaddress

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from nautobot.dcim.models import Location
from nautobot.ipam.models import (
    VRF,
    IPAddress,
    IPAddressRange,
    IPAddressToInterface,
    Namespace,
    Prefix,
    PrefixLocationAssignment,
    VRFDeviceAssignment,
    VRFPrefixAssignment,
)

from .adapters.cisco_iosxe import canonical_interface_name
from .exceptions import InventoryError
from .nautobot_route_targets import (
    route_target_objects,
    save_route_target_assignments,
    save_route_target_catalog,
    snapshot_route_targets,
    validate_route_target_objects,
)


def _id(value):
    return str(value) if value is not None else None


def _locked(queryset, lock):
    return queryset.select_for_update(of=("self",)) if lock else queryset


def _namespace_ids(policy):
    return sorted(
        {
            str(scope["id"])
            for scope in (policy.get("default_namespace"), policy.get("override_namespace"))
            if scope is not None
        }
    )


def snapshot_ipam(device, policy, *, lock=False, discovery=None):
    """Include complete scoped hierarchy and cross-scope device references for safety."""
    if policy is None:
        return {"supported": True, "policy": None}
    namespace_ids = _namespace_ids(policy)
    namespaces = list(_locked(Namespace.objects.filter(pk__in=namespace_ids).order_by("pk"), lock))
    if len(namespaces) != len(namespace_ids):
        raise InventoryError("A selected IPAM Namespace no longer exists")
    interfaces = device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
    interface_ids = list(interfaces.values_list("pk", flat=True))
    assigned_vrf_ids = VRFDeviceAssignment.objects.filter(device=device).values_list(
        "vrf_id", flat=True
    )
    interface_vrf_ids = interfaces.exclude(vrf=None).values_list("vrf_id", flat=True)
    vrfs = list(
        _locked(
            VRF.objects.filter(
                Q(namespace_id__in=namespace_ids)
                | Q(pk__in=assigned_vrf_ids)
                | Q(pk__in=interface_vrf_ids)
            ).order_by("pk"),
            lock,
        )
    )
    assignments = _locked(
        VRFDeviceAssignment.objects.filter(
            Q(vrf_id__in=[vrf.pk for vrf in vrfs]) | Q(device=device)
        )
        .select_related("vrf")
        .order_by("pk"),
        lock,
    )
    prefixes = _locked(
        Prefix.objects.filter(namespace_id__in=namespace_ids)
        .prefetch_related("locations", "vrfs")
        .order_by("pk"),
        lock,
    )
    on_device = IPAddressToInterface.objects.filter(interface_id__in=interface_ids).values_list(
        "ip_address_id", flat=True
    )
    addresses = list(
        _locked(
            IPAddress.objects.filter(
                Q(parent__namespace_id__in=namespace_ids) | Q(pk__in=on_device)
            )
            .select_related("parent")
            .order_by("pk"),
            lock,
        )
    )
    ip_assignments = _locked(
        IPAddressToInterface.objects.filter(
            Q(ip_address_id__in=[address.pk for address in addresses])
            | Q(interface_id__in=interface_ids)
        )
        .select_related("interface", "vm_interface")
        .order_by("pk"),
        lock,
    )
    ranges = _locked(
        IPAddressRange.objects.filter(parent__namespace_id__in=namespace_ids)
        .select_related("parent")
        .order_by("pk"),
        lock,
    )
    route_targets = snapshot_route_targets(vrfs, lock=lock)
    return {
        "supported": True,
        "policy": copy.deepcopy(policy),
        "device": {
            "id": str(device.pk),
            "name": device.name,
            "location_id": _id(device.location_id),
        },
        "namespaces": [{"id": str(row.pk), "name": row.name} for row in namespaces],
        "vrfs": [
            {
                "id": str(row.pk),
                "name": row.name,
                "namespace_id": str(row.namespace_id),
                "rd": row.rd,
                **route_targets["relationships"][str(row.pk)],
            }
            for row in vrfs
        ],
        "route_targets": route_targets["route_targets"],
        "vrf_device_assignments": [
            {
                "id": str(row.pk),
                "vrf_id": str(row.vrf_id),
                "device_id": _id(row.device_id),
                "virtual_machine_id": _id(row.virtual_machine_id),
                "virtual_device_context_id": _id(row.virtual_device_context_id),
                "name": row.name,
                "rd": row.rd,
                "effective_name": row.name or row.vrf.name,
                "effective_rd": row.rd or row.vrf.rd,
            }
            for row in assignments
        ],
        "prefixes": [
            {
                "id": str(row.pk),
                "prefix": str(row.prefix),
                "namespace_id": str(row.namespace_id),
                "type": row.type,
                "location_ids": sorted(str(location.pk) for location in row.locations.all()),
                "vrf_ids": sorted(str(vrf.pk) for vrf in row.vrfs.all()),
                "parent_id": _id(row.parent_id),
            }
            for row in prefixes
        ],
        "ip_addresses": [
            {
                "id": str(row.pk),
                "host": str(row.host),
                "mask_length": row.mask_length,
                "type": row.type,
                "parent_id": str(row.parent_id),
                "namespace_id": str(row.parent.namespace_id),
            }
            for row in addresses
        ],
        "ip_assignments": [
            {
                "id": str(row.pk),
                "ip_address_id": str(row.ip_address_id),
                "interface_id": _id(row.interface_id),
                "interface_device_id": (
                    _id(row.interface.device_id) if row.interface is not None else None
                ),
                "vm_interface_id": _id(row.vm_interface_id),
                "is_secondary": row.is_secondary,
                "is_primary": row.is_primary,
            }
            for row in ip_assignments
        ],
        "ip_ranges": [
            {
                "id": str(row.pk),
                "start_address": str(row.start_host),
                "end_address": str(row.end_host),
                "parent_id": str(row.parent_id),
                "namespace_id": str(row.parent.namespace_id),
                "is_exclusive": row.is_exclusive,
            }
            for row in ranges
        ],
    }


def _change_fields(obj, changes):
    for change in changes:
        if change["field"] not in {"name", "rd"}:
            raise InventoryError("Unsupported planned IPAM enrichment")
        before = getattr(obj, change["field"])
        if before != change["before"]:
            raise InventoryError("IPAM value changed during validation; retry discovery")
        if before not in (None, "") and before != change["after"]:
            raise InventoryError("Populated IPAM fields must be preserved")
        setattr(obj, change["field"], change["after"])


def ipam_objects(plan, interfaces, device, *, prefix_status, ip_address_status, status_resolver):
    """Construct cached UUID parents; no preview step persists graph nodes."""
    objects = {
        "plan": plan,
        "vrfs": {},
        "vrf_device_assignments": {},
        "prefixes": {},
        "ip_addresses": {},
        "interface_vrfs": [],
        "ip_assignments": {},
        "prefix_vrfs": [],
        "prefix_locations": [],
    }
    for spec in plan["vrfs"]:
        vrf = (
            VRF(name=spec["name"], namespace_id=spec["namespace_id"], rd=spec.get("rd"))
            if spec["create"]
            else VRF.objects.select_related("namespace").get(pk=spec["id"])
        )
        _change_fields(vrf, spec.get("changes", []))
        objects["vrfs"][spec["key"]] = vrf
    for spec in plan["vrf_device_assignments"]:
        assignment = (
            VRFDeviceAssignment(
                vrf=objects["vrfs"][spec["vrf_key"]],
                device=device,
                name=spec["name"],
                rd=spec.get("rd"),
            )
            if spec["create"]
            else VRFDeviceAssignment.objects.select_related("vrf", "device").get(pk=spec["id"])
        )
        _change_fields(assignment, spec.get("changes", []))
        objects["vrf_device_assignments"][spec["key"]] = assignment
    status = (
        status_resolver(Prefix, prefix_status)
        if any(spec["create"] for spec in plan["prefixes"])
        else None
    )
    for spec in plan["prefixes"]:
        prefix = (
            Prefix(
                prefix=spec["prefix"],
                namespace_id=spec["namespace_id"],
                type="network",
                status=status,
            )
            if spec["create"]
            else Prefix.objects.select_related("namespace", "parent").get(pk=spec["id"])
        )
        objects["prefixes"][spec["key"]] = prefix
        if spec["create"] and spec.get("location_id"):
            objects["prefix_locations"].append(
                PrefixLocationAssignment(
                    prefix=prefix, location=Location.objects.get(pk=spec["location_id"])
                )
            )
        for vrf_key in spec.get("add_vrf_keys", []):
            objects["prefix_vrfs"].append(
                VRFPrefixAssignment(prefix=prefix, vrf=objects["vrfs"][vrf_key])
            )
    status = (
        status_resolver(IPAddress, ip_address_status)
        if any(spec["create"] for spec in plan["ip_addresses"])
        else None
    )
    for spec in plan["ip_addresses"]:
        parent = objects["prefixes"][spec["parent_key"]]
        address = (
            IPAddress(address=spec["address"], parent=parent, status=status, type="host")
            if spec["create"]
            else IPAddress.objects.select_related("parent__namespace").get(pk=spec["id"])
        )
        objects["ip_addresses"][spec["key"]] = address
    for spec in plan["interface_vrfs"]:
        interface = interfaces[canonical_interface_name(spec["name"])]
        objects["interface_vrfs"].append((interface, spec))
    for spec in plan["ip_assignments"]:
        interface = interfaces[canonical_interface_name(spec["name"])]
        assignment = (
            IPAddressToInterface(
                ip_address=objects["ip_addresses"][spec["ip_key"]],
                interface=interface,
                is_secondary=spec.get("is_secondary", False),
            )
            if spec["create"]
            else IPAddressToInterface.objects.select_related("ip_address", "interface").get(
                pk=spec["id"]
            )
        )
        objects["ip_assignments"][spec["key"]] = assignment
    objects["route_targets"] = route_target_objects(plan, objects["vrfs"], device)
    return objects


def _exclude_new_relations(obj, fields):
    return [
        field
        for field in fields
        if getattr(obj, field) is not None and getattr(obj, field)._state.adding
    ]


def _prefix_graph(objects):
    namespace_ids = {prefix.namespace_id for prefix in objects["prefixes"].values()} | {
        vrf.namespace_id for vrf in objects["vrfs"].values()
    }
    graph = {
        prefix.pk: {
            "object": prefix,
            "network": ipaddress.ip_network(str(prefix.prefix)),
            "vrfs": {vrf.pk for vrf in prefix.vrfs.all()},
        }
        for prefix in Prefix.objects.filter(namespace_id__in=namespace_ids).prefetch_related("vrfs")
    }
    for prefix in objects["prefixes"].values():
        graph.setdefault(
            prefix.pk,
            {"object": prefix, "network": ipaddress.ip_network(str(prefix.prefix)), "vrfs": set()},
        )
    for assignment in objects["prefix_vrfs"]:
        graph[assignment.prefix_id]["vrfs"].add(assignment.vrf_id)
    return graph


def _closest(graph, namespace_id, start, end=None):
    host = ipaddress.ip_address(str(start))
    last = ipaddress.ip_address(str(end)) if end is not None else host
    candidates = [
        row
        for row in graph.values()
        if row["object"].namespace_id == namespace_id
        and row["network"].version == host.version == last.version
        and host in row["network"]
        and last in row["network"]
    ]
    if not candidates:
        raise InventoryError("A discovered IP address has no validated containing Prefix")
    return max(candidates, key=lambda row: row["network"].prefixlen)


def _validate_hierarchy(objects, graph):
    """Prefix.save reparents children; reject any implicit routing-domain change."""
    namespace_ids = {row["object"].namespace_id for row in graph.values()}
    for model, start_field, end_field in (
        (IPAddress, "host", None),
        (IPAddressRange, "start_host", "end_host"),
    ):
        rows = model.objects.filter(parent__namespace_id__in=namespace_ids).select_related("parent")
        for row in rows:
            candidate = _closest(
                graph,
                row.parent.namespace_id,
                getattr(row, start_field),
                getattr(row, end_field) if end_field else None,
            )
            before = set(row.parent.vrfs.values_list("pk", flat=True))
            if candidate["vrfs"] != before:
                raise InventoryError(
                    "A planned Prefix would change existing IP or range VRF associations"
                )
    exclusive = list(
        IPAddressRange.objects.filter(
            parent__namespace_id__in=namespace_ids, is_exclusive=True
        ).select_related("parent")
    )
    for spec in objects["plan"]["prefixes"]:
        if not spec["create"]:
            continue
        prefix = objects["prefixes"][spec["key"]]
        network = ipaddress.ip_network(str(prefix.prefix))
        for row in exclusive:
            start, end = (
                ipaddress.ip_address(str(row.start_host)),
                ipaddress.ip_address(str(row.end_host)),
            )
            if (
                row.parent.namespace_id == prefix.namespace_id
                and start.version == network.version
                and int(start) <= int(network.broadcast_address)
                and int(end) >= int(network.network_address)
            ):
                raise InventoryError("A planned Prefix overlaps an exclusive IP Address Range")


def _validate_interface_vrf(interface, vrf, objects, device, graph=None):
    if interface.device_id != device.pk:
        raise InventoryError("Discovered IPAM assignments must belong to the selected Device")
    if interface.vrf_id not in (None, vrf.pk):
        raise InventoryError("An existing Interface VRF must be preserved")
    if (
        not any(
            assignment.device_id == device.pk and assignment.vrf_id == vrf.pk
            for assignment in objects["vrf_device_assignments"].values()
        )
        and not VRFDeviceAssignment.objects.filter(device=device, vrf_id=vrf.pk).exists()
    ):
        raise InventoryError("Interface VRF is not assigned to the selected Device")
    graph = _prefix_graph(objects) if graph is None else graph
    assigned_ips = IPAddress.objects.filter(interface_assignments__interface_id=interface.pk)
    for address in assigned_ips.select_related("parent__namespace"):
        projected = _closest(graph, address.parent.namespace_id, address.host)
        if address.parent.namespace_id != vrf.namespace_id or vrf.pk not in projected["vrfs"]:
            raise InventoryError("Existing Interface IP addresses conflict with the discovered VRF")
    # Native Interface.clean checks the persisted Device's VRFs. Validate all
    # other fields on a copy, and validate that relation against our staged
    # DeviceAssignment graph until both sides have actually been saved.
    staged = copy.copy(interface)
    staged._state = copy.copy(interface._state)
    staged._state.fields_cache = interface._state.fields_cache.copy()
    staged.vrf = None
    exclusions = ["vrf", *_exclude_new_relations(staged, ("module", "lag", "untagged_vlan"))]
    staged.full_clean(exclude=exclusions)


def validate_ipam_objects(objects, device):
    """Native field validation plus explicit checks for unsaved relation parents."""
    plan = objects["plan"]
    for spec in plan["vrfs"]:
        vrf = objects["vrfs"][spec["key"]]
        if str(vrf.namespace_id) != str(spec["namespace_id"]):
            raise InventoryError("VRF Namespace changed during validation")
        vrf.full_clean()
    for spec in plan["vrf_device_assignments"]:
        assignment = objects["vrf_device_assignments"][spec["key"]]
        if (
            assignment.device_id != device.pk
            or assignment.vrf_id != objects["vrfs"][spec["vrf_key"]].pk
        ):
            raise InventoryError("Invalid discovered VRF Device Assignment")
        assignment.full_clean(exclude=_exclude_new_relations(assignment, ("vrf",)))
    for spec in plan["prefixes"]:
        prefix = objects["prefixes"][spec["key"]]
        if (
            ipaddress.ip_network(str(prefix.prefix)) != ipaddress.ip_network(spec["prefix"])
            or str(prefix.namespace_id) != str(spec["namespace_id"])
            or prefix.type != spec["type"]
            or spec["create"]
            and prefix.type != "network"
        ):
            raise InventoryError("Connected Prefix identity or type changed during validation")
        prefix.full_clean()
    graph = _prefix_graph(objects)
    _validate_hierarchy(objects, graph)
    content_type = ContentType.objects.get_for_model(Prefix)
    for assignment in objects["prefix_locations"]:
        if not assignment.location.location_type.content_types.filter(pk=content_type.pk).exists():
            raise InventoryError("Selected Location Type does not permit Prefix records")
        assignment.full_clean(exclude=_exclude_new_relations(assignment, ("prefix",)))
    for assignment in objects["prefix_vrfs"]:
        assignment.full_clean(exclude=_exclude_new_relations(assignment, ("prefix", "vrf")))
    for spec in plan["ip_addresses"]:
        address = objects["ip_addresses"][spec["key"]]
        parent = objects["prefixes"][spec["parent_key"]]
        if (
            ipaddress.ip_address(str(address.host)) != ipaddress.ip_address(spec["host"])
            or address.mask_length != spec["mask_length"]
        ):
            raise InventoryError("An existing IP Address host or mask must be preserved")
        closest = _closest(graph, parent.namespace_id, address.host)["object"]
        if closest.pk != parent.pk:
            raise InventoryError("Planned IP parent is not the closest containing Prefix")
        if not spec["create"] and address.parent.namespace_id != parent.namespace_id:
            raise InventoryError("An existing IP Address Namespace must be preserved")
        address.parent = parent
        # The closest parent is a validated object, possibly not in the database
        # yet. This per-instance core cache lets native clean validate that graph
        # while still checking exclusive ranges and duplicate hosts without DML.
        address._closest_parent_cache[(parent.namespace_id, address.host)] = parent
        address.full_clean(exclude=_exclude_new_relations(address, ("parent",)))
    for interface, spec in objects["interface_vrfs"]:
        vrf = objects["vrfs"][spec["vrf_key"]]
        _validate_interface_vrf(interface, vrf, objects, device, graph=graph)
    desired_vrfs = {
        interface.pk: objects["vrfs"][spec["vrf_key"]]
        for interface, spec in objects["interface_vrfs"]
    }
    for spec in plan["ip_assignments"]:
        assignment = objects["ip_assignments"][spec["key"]]
        if (
            assignment.interface is None
            or assignment.interface.device_id != device.pk
            or spec.get("interface_id") is not None
            and str(assignment.interface_id) != str(spec["interface_id"])
            or canonical_interface_name(assignment.interface.name)
            != canonical_interface_name(spec["name"])
            or assignment.ip_address_id != objects["ip_addresses"][spec["ip_key"]].pk
        ):
            raise InventoryError("Invalid discovered IP Address Assignment")
        address = assignment.ip_address
        vrf = desired_vrfs.get(assignment.interface_id, assignment.interface.vrf)
        projected = _closest(graph, address.parent.namespace_id, address.host)
        if (
            vrf is not None
            and (vrf.namespace_id != address.parent.namespace_id or vrf.pk not in projected["vrfs"])
            or vrf is None
            and projected["vrfs"]
        ):
            raise InventoryError("IP parent routing domain conflicts with the discovered Interface")
        assignment.full_clean(
            exclude=_exclude_new_relations(assignment, ("ip_address", "interface"))
        )
    validate_route_target_objects(objects["route_targets"], device)


def save_ipam_catalog(objects, device):
    """Persist routing parents before interfaces inside the caller's transaction."""
    validate_ipam_objects(objects, device)
    save_route_target_catalog(objects["route_targets"])
    for spec in objects["plan"]["vrfs"]:
        if spec["create"] or spec.get("changes"):
            objects["vrfs"][spec["key"]].validated_save()
    for spec in objects["plan"]["vrf_device_assignments"]:
        if spec["create"] or spec.get("changes"):
            objects["vrf_device_assignments"][spec["key"]].validated_save()
    for spec in sorted(
        objects["plan"]["prefixes"], key=lambda row: ipaddress.ip_network(row["prefix"]).prefixlen
    ):
        if spec["create"]:
            objects["prefixes"][spec["key"]].validated_save()
    for assignment in objects["prefix_locations"]:
        assignment.validated_save()
    for assignment in objects["prefix_vrfs"]:
        assignment.validated_save()
    for spec in objects["plan"]["ip_addresses"]:
        if spec["create"]:
            address = objects["ip_addresses"][spec["key"]]
            address._closest_parent_cache.clear()
            address.validated_save()
        else:
            objects["ip_addresses"][spec["key"]].refresh_from_db()
    save_route_target_assignments(objects["route_targets"], device)


def save_ipam_assignments(objects, device):
    """Fill Interface VRFs and add explicit host assignments after interfaces save."""
    graph = _prefix_graph(objects)
    for interface, spec in objects["interface_vrfs"]:
        vrf = objects["vrfs"][spec["vrf_key"]]
        _validate_interface_vrf(interface, vrf, objects, device, graph=graph)
        if spec.get("changes"):
            interface.vrf = vrf
            interface.validated_save()
    for spec in objects["plan"]["ip_assignments"]:
        if spec["create"]:
            assignment = objects["ip_assignments"][spec["key"]]
            if assignment.interface.device_id != device.pk:
                raise InventoryError("IP Address Assignment belongs to another Device")
            assignment.validated_save()
