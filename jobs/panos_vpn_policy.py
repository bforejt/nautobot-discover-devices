"""Explicit existing Namespace and native-name intent for PAN-OS VPN processing."""

import json

from .panos_ipam_policy import _name, _object


def normalize_panos_vpn_policy(text, resolve):
    """Resolve deliberate selections without deriving native domains from tunnel names."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("PAN-OS VPN mappings must be bounded JSON text")
    if not text.strip():
        return None
    try:
        rows = json.loads(text, object_pairs_hook=_object)
    except json.JSONDecodeError:
        raise ValueError("PAN-OS VPN mappings must be a JSON list") from None
    if not isinstance(rows, list) or not rows or len(rows) > 65535:
        raise ValueError("PAN-OS VPN mappings require a nonempty list")
    required = {"tunnel", "vpn_name", "tunnel_name", "profile_name"}
    scopes = {
        "local_namespace",
        "remote_namespace",
        "local_protected_namespace",
        "remote_protected_namespace",
    }
    normalized, seen, native_names = (
        [],
        set(),
        {key: set() for key in ("vpn_name", "tunnel_name", "profile_name")},
    )
    for row in rows:
        if (
            not isinstance(row, dict)
            or not required <= row.keys()
            or row.keys() - required - scopes - {"status"}
        ):
            raise ValueError("PAN-OS VPN mapping has missing or unsupported fields")
        values = {key: _name(row[key]) for key in required}
        if values["tunnel"] in seen:
            raise ValueError("PAN-OS VPN mappings repeat a source tunnel")
        seen.add(values["tunnel"])
        for key in native_names:
            if values[key] in native_names[key]:
                raise ValueError(
                    "Each mapped tunnel requires distinct explicit native object names"
                )
            native_names[key].add(values[key])
        for key in scopes:
            values[key] = (
                resolve("namespace", _name(row[key])) if row.get(key) is not None else None
            )
        values["status"] = (
            resolve("status", _name(row["status"])) if row.get("status") is not None else None
        )
        normalized.append(values)
    return {"contract": "panos-vpn-policy-v1", "tunnels": normalized}
