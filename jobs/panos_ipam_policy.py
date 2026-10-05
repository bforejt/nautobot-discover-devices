"""Explicit PAN-OS routing-domain intent, independent of models and transport."""

import json


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("PAN-OS routing mappings contain duplicate JSON fields")
        value[key] = item
    return value


def _name(value):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("PAN-OS routing mappings require exact nonblank identifiers")
    return value


def normalize_panos_ipam_policy(
    text, resolve, *, create_missing_prefixes=True, location=None, location_reason=None
):
    """Resolve operator-selected existing targets; no source name selects a VRF.

    ``resolve(kind, identifier, namespace_id)`` returns a safe serialized existing
    object. Namespace/VRF labels or UUIDs are deliberate selections. An explicit
    null VRF selects global routing in that Namespace. Blank mappings are report-only.
    """
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("PAN-OS routing mappings must be bounded JSON text")
    if type(create_missing_prefixes) is not bool:
        raise ValueError("Create missing networks must be true or false")
    if not text.strip():
        return None
    try:
        rows = json.loads(text, object_pairs_hook=_object)
    except json.JSONDecodeError:
        raise ValueError("PAN-OS routing mappings must be a JSON list") from None
    if not isinstance(rows, list) or not rows or len(rows) > 65535:
        raise ValueError("PAN-OS routing mappings require a nonempty list of explicit domains")
    domains, scopes = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"vsys", "virtual_router", "namespace", "vrf"}:
            raise ValueError("Each PAN-OS mapping requires vsys, virtual_router, namespace and vrf")
        scope = (_name(row["vsys"]), _name(row["virtual_router"]))
        if scope in scopes:
            raise ValueError("PAN-OS routing mappings repeat a source routing domain")
        scopes.add(scope)
        namespace = resolve("namespace", _name(row["namespace"]), None)
        if not isinstance(namespace, dict) or not namespace.get("id") or not namespace.get("name"):
            raise ValueError("PAN-OS mappings require an existing Namespace")
        namespace = {"id": str(namespace["id"]), "name": _name(namespace["name"])}
        vrf = None
        if row["vrf"] is not None:
            vrf = resolve("vrf", _name(row["vrf"]), namespace["id"])
            if (
                not isinstance(vrf, dict)
                or not vrf.get("id")
                or str(vrf.get("namespace_id")) != namespace["id"]
            ):
                raise ValueError(
                    "PAN-OS mappings require an existing VRF in the selected Namespace"
                )
            vrf = {
                "id": str(vrf["id"]),
                "name": _name(vrf.get("name")),
                "namespace_id": namespace["id"],
            }
        domains.append(
            {"vsys": scope[0], "virtual_router": scope[1], "namespace": namespace, "vrf": vrf}
        )
    domains.sort(key=lambda row: (row["vsys"], row["virtual_router"]))
    return {
        "contract": "panos-ipam-policy-v1",
        "panos_routing_domains": domains,
        # Shared staging expects this field; PAN routing always uses its exact
        # domain binding, never this value as a classification fallback.
        "default_namespace": domains[0]["namespace"],
        "override_namespace": None,
        "override_rfc1918": False,
        "override_networks": [],
        "group_user_vrfs": False,
        "local_vrf_names": [],
        "create_missing_prefixes": create_missing_prefixes,
        "location": location,
        "location_reason": location_reason,
    }
