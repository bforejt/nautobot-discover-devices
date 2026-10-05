"""Capability-detected native VPN staging without importing optional VPN models."""

from copy import deepcopy
from ipaddress import ip_interface, ip_network

from .exceptions import InventoryError
from .reconcile_panos_vpn import MODELS, _source, crypto_policy_name

FIELDS = {
    "VPN": ("name", "vpn_profile", "service_type", "status"),
    "VPNProfile": ("name", "keepalive_enabled", "nat_traversal"),
    "VPNPhase1Policy": (
        "name",
        "ike_version",
        "aggressive_mode",
        "encryption_algorithm",
        "integrity_algorithm",
        "dh_group",
        "lifetime_seconds",
    ),
    "VPNPhase2Policy": (
        "name",
        "encryption_algorithm",
        "integrity_algorithm",
        "pfs_group",
        "lifetime",
    ),
    "VPNTunnel": (
        "name",
        "vpn",
        "vpn_profile",
        "status",
        "encapsulation",
        "endpoint_a",
        "endpoint_z",
    ),
    "VPNTunnelEndpoint": (
        "name",
        "device",
        "source_interface",
        "source_ipaddress",
        "source_fqdn",
        "tunnel_interface",
        "vpn_profile",
        "protected_prefixes",
    ),
    "VPNProfilePhase1PolicyAssignment": ("vpn_profile", "vpn_phase1_policy", "weight"),
    "VPNProfilePhase2PolicyAssignment": ("vpn_profile", "vpn_phase2_policy", "weight"),
}
OPTIONAL = {"VPN": {"service_type", "status"}}


def _models():
    from django.apps import apps

    result = {}
    for name in MODELS:
        try:
            result[name] = apps.get_model("vpn", name)
        except LookupError:
            return None
    return result


def _capabilities(models):
    if models is None:
        return None
    result = {}
    for name, model in models.items():
        fields = {field.name: field for field in model._meta.get_fields()}
        required = set(FIELDS[name]) - OPTIONAL.get(name, set())
        if not required <= fields.keys():
            return None
        if name == "VPNTunnelEndpoint":
            prefixes = fields["protected_prefixes"]
            remote = getattr(prefixes, "remote_field", None)
            target = getattr(getattr(remote, "model", None), "_meta", None)
            if (
                getattr(prefixes, "is_relation", False) is not True
                or getattr(prefixes, "many_to_many", False) is not True
                or getattr(prefixes, "auto_created", True) is not False
                or getattr(target, "label_lower", None) != "ipam.prefix"
            ):
                return None
        result[name] = {"fields": list(fields), "choices": {}, "collections": []}
        for field in fields.values():
            base = getattr(field, "base_field", field)
            if hasattr(field, "base_field"):
                result[name]["collections"].append(field.name)
            if getattr(base, "choices", None):
                result[name]["choices"][field.name] = [value for value, _ in base.flatchoices]
    return result


def _serialize(model, row):
    fields = {field.name: field for field in model._meta.fields}
    values = {"id": str(row.pk)}
    for name in FIELDS[model.__name__]:
        if name not in fields:
            continue
        field = fields[name]
        value = getattr(row, field.attname)
        values[field.attname] = (
            str(value) if field.is_relation and value is not None else deepcopy(value)
        )
    if model.__name__ == "VPNTunnelEndpoint":
        values["protected_prefix_ids"] = sorted(
            str(prefix.pk) for prefix in row.protected_prefixes.all()
        )
    return values


def snapshot_panos_vpn(device, policy, *, lock=False, discovery=None):
    """Read selected scopes and catalogs; absent optional models remain report-only."""
    models = _models()
    capabilities = _capabilities(models)
    result = {
        "supported": capabilities is not None,
        "reason": None
        if capabilities is not None
        else "Installed Nautobot lacks compatible native VPN models",
        "policy": deepcopy(policy),
        "capabilities": capabilities or {},
        "catalog": {},
        "interfaces": [],
        "ip_addresses": [],
        "ip_assignments": [],
        "prefixes": [],
        "namespaces": [],
    }
    if policy is None or capabilities is None:
        return result
    from django.db.models import Q
    from nautobot.ipam.models import IPAddress, IPAddressToInterface, Namespace, Prefix

    configuration = _source(discovery)
    configured = {row["name"]: row for row in configuration["ipsec_tunnels"]}
    gateways = {row["name"]: row for row in configuration["ike_gateways"]}
    selected_gateways, phase1_names, phase2_names, hosts, networks = [], set(), set(), set(), set()
    for row in policy["tunnels"]:
        tunnel = configured.get(row["tunnel"], {})
        auto = tunnel.get("auto_key") or {}
        phase2_name = auto.get("crypto_profile")
        if phase2_name:
            phase2_names.add(crypto_policy_name(str(device.pk), "IPsec", phase2_name))
        for gateway_name in auto.get("ike_gateways") or []:
            gateway = gateways.get(gateway_name)
            if gateway is None:
                continue
            selected_gateways.append(gateway)
            protocol = gateway.get("protocol") or {}
            version = protocol.get("version")
            if version in ("ikev1", "ikev2") and protocol.get(version + "_profile"):
                phase1_names.add(
                    crypto_policy_name(
                        str(device.pk), "IKE", protocol[version + "_profile"], version
                    )
                )
            for value in (
                gateway.get("local_address", {}).get("ip"),
                gateway.get("peer_address", {}).get("ip"),
            ):
                if value:
                    hosts.add(str(ip_interface(value).ip))
        for selector in (auto.get("selectors_ipv4") or []) + (auto.get("selectors_ipv6") or []):
            for side in ("local", "remote"):
                if selector.get(side):
                    networks.add(ip_network(selector[side], strict=False))

    namespace_ids = {
        str(row[key]["id"])
        for row in policy["tunnels"]
        for key in (
            "local_namespace",
            "remote_namespace",
            "local_protected_namespace",
            "remote_protected_namespace",
        )
        if row.get(key) is not None
    }
    namespaces = Namespace.objects.filter(pk__in=namespace_ids).order_by("pk")
    if lock:
        namespaces = namespaces.select_for_update()
    result["namespaces"] = [{"id": str(row.pk), "name": row.name} for row in namespaces]
    if len(result["namespaces"]) != len(namespace_ids):
        raise InventoryError("A selected VPN Namespace no longer exists")
    interfaces = device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
    result["interfaces"] = [
        {"id": str(row.pk), "name": row.name, "device_id": str(row.device_id)} for row in interfaces
    ]
    interface_ids = [row["id"] for row in result["interfaces"]]
    names = {
        "VPN": {row["vpn_name"] for row in policy["tunnels"]},
        "VPNTunnel": {row["tunnel_name"] for row in policy["tunnels"]},
        "VPNProfile": {row["profile_name"] for row in policy["tunnels"]},
        "VPNPhase1Policy": phase1_names,
        "VPNPhase2Policy": phase2_names,
    }
    remote_fqdns = {gateway.get("peer_address", {}).get("fqdn") for gateway in selected_gateways}
    for name, model in models.items():
        if name in names:
            queryset = model.objects.filter(name__in=names[name])
        elif name.startswith("VPNProfilePhase"):
            queryset = model.objects.filter(vpn_profile__name__in=names["VPNProfile"])
        else:
            matches = model.objects.filter(
                Q(device=device)
                | Q(source_interface_id__in=interface_ids)
                | Q(tunnel_interface_id__in=interface_ids)
                | Q(source_fqdn__in=remote_fqdns - {None})
                | Q(
                    source_ipaddress__host__in=hosts,
                    source_ipaddress__parent__namespace_id__in=namespace_ids,
                )
                | Q(endpoint_a_vpn_tunnels__name__in=names["VPNTunnel"])
                | Q(endpoint_z_vpn_tunnels__name__in=names["VPNTunnel"])
            )
            queryset = model.objects.filter(pk__in=matches.values("pk"))
        queryset = queryset.order_by("pk")
        if lock:
            queryset = queryset.select_for_update(of=("self",))
        if name == "VPNTunnelEndpoint":
            queryset = queryset.prefetch_related("protected_prefixes")
        result["catalog"][name] = [_serialize(model, row) for row in queryset]
    addresses = IPAddress.objects.filter(
        parent__namespace_id__in=namespace_ids, host__in=hosts
    ).select_related("parent")
    result["ip_addresses"] = [
        {
            "id": str(row.pk),
            "host": str(row.host),
            "mask_length": row.mask_length,
            "namespace_id": str(row.parent.namespace_id),
        }
        for row in addresses
    ]
    result["ip_assignments"] = [
        {"ip_address_id": str(row.ip_address_id), "interface_id": str(row.interface_id)}
        for row in IPAddressToInterface.objects.filter(
            interface_id__in=[row["id"] for row in result["interfaces"]]
        )
    ]
    result["prefixes"] = [
        {"id": str(row.pk), "prefix": str(row.prefix), "namespace_id": str(row.namespace_id)}
        for row in Prefix.objects.filter(
            namespace_id__in=namespace_ids,
            network__in=[str(network.network_address) for network in networks],
            prefix_length__in=[network.prefixlen for network in networks],
        )
    ]
    return result


def panos_vpn_objects(plan, device, interfaces=None, ipam_objects=None, *, status_resolver=None):
    """Stage cached native records with exact relation references and no writes."""
    if plan.get("errors"):
        raise InventoryError("; ".join(plan["errors"]))
    models = _models()
    if not plan.get("catalog"):
        return {"plan": plan, "catalog": {}, "assignments": [], "prefix_assignments": []}
    if _capabilities(models) is None:
        raise InventoryError("Native VPN capability changed; retry discovery")
    from nautobot.dcim.models import Interface
    from nautobot.extras.models import Status
    from nautobot.ipam.models import IPAddress, Prefix

    objects = {"plan": plan, "catalog": {}, "assignments": [], "prefix_assignments": []}
    related = {
        "source_interface": Interface,
        "tunnel_interface": Interface,
        "source_ipaddress": IPAddress,
        "device": type(device),
        "status": Status,
    }
    for spec in plan["catalog"]:
        model = models[spec["model"]]
        obj = model() if spec["create"] else model.objects.get(pk=spec["id"])
        if spec["create"]:
            for field, value in spec["values"].items():
                setattr(obj, field, deepcopy(value))
        else:
            for change in spec["changes"]:
                if getattr(obj, change["field"]) != change["before"]:
                    raise InventoryError("Native VPN value changed; retry discovery")
                if getattr(obj, change["field"]) not in (None, ""):
                    raise InventoryError("Populated native VPN fields must be preserved")
                setattr(obj, change["field"], deepcopy(change["after"]))
        for field, reference in spec.get("relations", {}).items():
            if not spec["create"] and getattr(obj, field + "_id") is not None:
                continue
            parent = objects["catalog"].get(reference.get("key"))
            if parent is None:
                parent = related[field].objects.get(pk=reference["id"])
            if field == "status":
                from django.contrib.contenttypes.models import ContentType

                if not parent.content_types.filter(
                    pk=ContentType.objects.get_for_model(model).pk
                ).exists():
                    raise InventoryError(
                        "Selected native VPN Status is not applicable to this model"
                    )
            setattr(obj, field, parent)
        if spec["model"] == "VPNTunnelEndpoint":
            # The model generates this readonly field at save. Never invent a
            # Device or FQDN merely to make the generated name nonblank.
            obj.name = obj._name()
            if spec.get("source_binding"):
                obj._panos_source_binding = deepcopy(spec["source_binding"])
        objects["catalog"][spec["key"]] = obj
    for spec in plan["assignments"]:
        model = models[spec["model"]]
        obj = model(weight=spec["weight"])
        obj.vpn_profile = objects["catalog"][spec["profile_key"]]
        setattr(obj, spec["policy_field"], objects["catalog"][spec["policy_key"]])
        objects["assignments"].append(obj)
    for spec in plan["prefix_assignments"]:
        objects["prefix_assignments"].append(
            (objects["catalog"][spec["endpoint_key"]], Prefix.objects.get(pk=spec["prefix_id"]))
        )
    return objects


def validate_panos_vpn_objects(objects, device=None):
    """Run native model clean, excluding only unsaved FKs and generated names."""
    for obj in list(objects["catalog"].values()) + objects["assignments"]:
        binding = getattr(obj, "_panos_source_binding", None)
        if binding is not None:
            from nautobot.dcim.models import Interface
            from nautobot.ipam.models import IPAddressToInterface

            source = Interface.objects.get(pk=binding["source_interface_id"])
            tunnel = obj.tunnel_interface
            address = obj.source_ipaddress
            expected = ip_interface(binding["source_address"])
            if (
                str(obj.device_id) != binding["device_id"]
                or str(source.device_id) != binding["device_id"]
                or tunnel is None
                or str(tunnel.pk) != binding["tunnel_interface_id"]
                or str(tunnel.device_id) != binding["device_id"]
                or address is None
                or str(address.pk) != binding["source_ipaddress_id"]
                or str(address.parent.namespace_id) != binding["namespace_id"]
                or str(address.host) != str(expected.ip)
                or (
                    "/" in binding["source_address"]
                    and address.mask_length != expected.network.prefixlen
                )
                or (
                    obj.source_interface_id is not None
                    and str(obj.source_interface_id) != str(source.pk)
                )
                or not IPAddressToInterface.objects.filter(
                    interface=source, ip_address=address
                ).exists()
            ):
                raise InventoryError(
                    "Observed native VPN source/interface/IP ownership changed; retry discovery"
                )
        excluded = []
        for field in obj._meta.fields:
            if field.is_relation:
                related = getattr(obj, field.name, None)
                if related is not None and related._state.adding:
                    excluded.append(field.name)
        if obj._meta.model_name == "vpntunnelendpoint" and not obj._meta.get_field("name").editable:
            excluded.append("name")
        obj.full_clean(exclude=excluded)


def save_panos_vpn_catalog(objects):
    """Save changed catalogs in dependency order; unchanged inventory produces no DML."""
    specs = {spec["key"]: spec for spec in objects["plan"]["catalog"]}
    for key, obj in objects["catalog"].items():
        spec = specs[key]
        if spec["create"] or spec["changes"] or spec.get("relation_changes"):
            validate_panos_vpn_objects({"catalog": {key: obj}, "assignments": []})
            obj.save()


def save_panos_vpn_assignments(objects):
    """Save only planned policy and protected-prefix associations."""
    for assignment in objects["assignments"]:
        assignment.validated_save()
    for endpoint, prefix in objects["prefix_assignments"]:
        endpoint.protected_prefixes.add(prefix)
