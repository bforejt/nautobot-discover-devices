"""Allowlisted PAN-OS VPN runtime observations, without configuration or native writes.

The reviewed SSH/XML shapes come from PA-VM 11.2.8: unfiltered IKE rows at
result/entry, IPsec SAs at result/entries/entry, and flows at result/IPSec/entry.
Filtered IKE has a different shape and is deliberately not treated as this
inventory. Unknown structural sections fail closed; unknown enum values remain
literal observations. A flow name includes its selector identity and is never
split into a guessed configuration name.
"""

import re
from ipaddress import ip_address

from .panos import DiscoveryError, _one, _result
from .panos import _container as _xml_container

CONTRACT = "panos-vpn-runtime-v1"
IKE_SAS = "show vpn ike-sa"
IPSEC_SAS = "show vpn ipsec-sa"
VPN_FLOWS = "show vpn flow"
_DETAIL_ID = re.compile(r"show vpn flow tunnel-id ([1-9][0-9]{0,4})")
_ERROR_TAGS = {"error", "errors", "errmsg", "error-message", "msg"}
_UINT64_MAX = (1 << 64) - 1
_COUNTERS = (
    "pkt-encap",
    "pkt-decap",
    "byte-encap",
    "byte-decap",
    "pkt-encap-v4",
    "pkt-decap-v4",
    "byte-encap-v4",
    "byte-decap-v4",
    "pkt-encap-v6",
    "pkt-decap-v6",
    "byte-encap-v6",
    "byte-decap-v6",
    "auth-err",
    "dec-err",
    "inner-warn",
    "pkt-replay",
    "pkt-lifetime",
    "pkt-lifesize",
    "seq-send",
    "seq-recv",
    "acquire",
)


def _container(element):
    if element.attrib:
        raise DiscoveryError("VPN operational container has unreviewed scope attributes")
    _xml_container(element)


def _response(output, command):
    if isinstance(output, str) and "<![CDATA[" in output:
        raise DiscoveryError("VPN operational response contains unsupported CDATA")
    result = _result(output, command)
    if any(
        node.tag.casefold() in _ERROR_TAGS or node.get("status", "").casefold() == "error"
        for node in result.iter()
    ):
        raise DiscoveryError("VPN operational response contains an embedded error")
    return result


def _text(element, field, *, required=False):
    node = _one(element, field, required=required)
    if node is None:
        return None
    if node.attrib or len(node):
        raise DiscoveryError("VPN operational scalar has an unsupported structure")
    value = (node.text or "").strip()
    if len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise DiscoveryError("VPN operational scalar contains unsupported text")
    if required and not value:
        raise DiscoveryError("VPN operational identity is missing")
    return value or None


def _uint(element, field, *, maximum=_UINT64_MAX, minimum=0, required=False):
    value = _text(element, field, required=required)
    if value is None:
        if _one(element, field) is not None:
            raise DiscoveryError("VPN operational numeric field is present but blank")
        return None
    if len(value) > 20 or re.fullmatch(r"[0-9]+", value) is None:
        raise DiscoveryError("VPN operational numeric field is invalid")
    number = int(value)
    if not minimum <= number <= maximum:
        raise DiscoveryError("VPN operational numeric field is outside its reviewed range")
    return number


def _hex_spi(element, field):
    value = _text(element, field)
    if value is None:
        if _one(element, field) is not None:
            raise DiscoveryError("VPN flow SPI is present but blank")
        return None
    if re.fullmatch(r"[0-9a-fA-F]{1,8}", value) is None:
        raise DiscoveryError("VPN flow SPI is not an unsigned 32-bit hexadecimal value")
    return int(value, 16)


def _address(element, field, *, required=False):
    value = _text(element, field, required=required)
    if value is not None:
        try:
            ip_address(value)
        except ValueError:
            raise DiscoveryError("VPN operational address is invalid") from None
    return value


def _row(entry):
    if entry.tag != "entry" or entry.attrib:
        raise DiscoveryError("VPN operational inventory has an unsupported row structure")
    _container(entry)
    if len({child.tag for child in entry}) != len(entry):
        raise DiscoveryError("VPN operational row contains duplicate fields")


def _structure(result, allowed):
    _container(result)
    if any(child.tag not in allowed for child in result):
        raise DiscoveryError("VPN operational inventory has an unsupported result structure")
    for tag in allowed - {"entry"}:
        _one(result, tag)


def _source(command, path, index):
    return {"contract": CONTRACT, "command": command, "path": path, "index": index}


def parse_ike_sas(output, command):
    """Retain each observed IKE SA, including legitimate multiple roles per gateway."""
    if command != IKE_SAS:
        raise DiscoveryError("IKE inventory requires the reviewed unfiltered command")
    result = _response(output, command)
    _structure(result, {"entry"})
    rows, identities = [], set()
    for index, entry in enumerate(result, 1):
        _row(entry)
        row = {
            "gateway_id": _uint(entry, "gwid", required=True),
            "gateway_name": _text(entry, "name", required=True),
            "role": _text(entry, "role"),
            "mode": _text(entry, "mode"),
            "algorithm": _text(entry, "algo"),
            "created": _text(entry, "created"),
            "expires": _text(entry, "expires"),
        }
        identity = tuple(row.values())
        if identity in identities:
            raise DiscoveryError("IKE inventory contains indistinguishable SA rows")
        identities.add(identity)
        row["source"] = _source(command, "result/entry", index)
        rows.append(row)
    return rows


def parse_ipsec_sas(output, command):
    """Retain complete SA names and SPIs; multiple rekey SAs are not collapsed."""
    if command != IPSEC_SAS:
        raise DiscoveryError("IPsec inventory requires the reviewed unfiltered command")
    result = _response(output, command)
    _structure(result, {"entries", "ntun"})
    entries = _one(result, "entries", required=True)
    _container(entries)
    declared_count = _uint(result, "ntun")
    rows, identities = [], set()
    for index, entry in enumerate(entries, 1):
        _row(entry)
        row = {
            "gateway_id": _uint(entry, "gwid", required=True),
            "gateway_name": _text(entry, "gateway", required=True),
            "tunnel_id": _uint(entry, "tid", minimum=1, maximum=65535, required=True),
            "name": _text(entry, "name", required=True),
            "peer_address": _address(entry, "remote"),
            "protocol": _text(entry, "proto"),
            "encryption": _text(entry, "enc"),
            "authentication": _text(entry, "hash"),
            "inbound_spi": _uint(entry, "i_spi", maximum=(1 << 32) - 1),
            "outbound_spi": _uint(entry, "o_spi", maximum=(1 << 32) - 1),
            "dh_group": _text(entry, "dh"),
            "lifetime_seconds": _uint(entry, "life"),
            "remaining_seconds": _uint(entry, "remain"),
            "lifetime_kb_raw": _text(entry, "kb"),
        }
        identity = tuple(
            row[field]
            for field in ("gateway_id", "tunnel_id", "name", "inbound_spi", "outbound_spi")
        )
        if identity in identities:
            raise DiscoveryError("IPsec inventory contains indistinguishable SA rows")
        identities.add(identity)
        row["source"] = _source(command, "result/entries/entry", index)
        rows.append(row)
    tunnel_ids = {row["tunnel_id"] for row in rows}
    if declared_count is not None and (declared_count != len(rows) or len(tunnel_ids) != len(rows)):
        # The live shape has one row per reported tunnel. No captured rekey
        # response establishes whether ntun counts SAs or distinct tunnels.
        # Do not infer either meaning for incomplete or repeated-ID coverage.
        raise DiscoveryError(
            "IPsec declared count and SA coverage have an unsupported relationship"
        )
    for row in rows:
        row["source"]["coverage"] = {
            "declared_ntun": declared_count,
            "observed_sa_rows": len(rows),
            "observed_distinct_tunnel_ids": len(tunnel_ids),
        }
    return rows


def _traffic_selector(element):
    _container(element)
    start = _address(element, "sip", required=True)
    end = _address(element, "eip", required=True)
    start_port = _uint(element, "sport", maximum=65535, required=True)
    end_port = _uint(element, "eport", maximum=65535, required=True)
    first, last = ip_address(start), ip_address(end)
    if first.version != last.version or int(first) > int(last) or start_port > end_port:
        raise DiscoveryError("VPN negotiated selector range is invalid")
    return {
        "start_address": start,
        "end_address": end,
        "protocol": _uint(element, "proto", maximum=255, required=True),
        "start_port": start_port,
        "end_port": end_port,
    }


def _selectors(entry):
    ts = _one(entry, "ts")
    if ts is None:
        return None
    _container(ts)
    _structure(ts, {"local", "remote"})
    return {side: _traffic_selector(_one(ts, side, required=True)) for side in ("local", "remote")}


def _proxy_id(entry):
    """An unnegotiated proxy ID is distinct from an established traffic selector."""
    proxy = _one(entry, "proxy-id")
    if proxy is None:
        return None
    _container(proxy)
    local = _address(proxy, "lip", required=True)
    remote = _address(proxy, "rip", required=True)
    return {
        "local_address": local,
        "local_prefix": _uint(
            proxy, "lprefix", maximum=ip_address(local).max_prefixlen, required=True
        ),
        "remote_address": remote,
        "remote_prefix": _uint(
            proxy, "rprefix", maximum=ip_address(remote).max_prefixlen, required=True
        ),
        "protocol": _uint(proxy, "proto", maximum=255, required=True),
        "local_port": _uint(proxy, "lport", maximum=65535, required=True),
        "remote_port": _uint(proxy, "rport", maximum=65535, required=True),
    }


def _monitor(entry):
    monitor = _one(entry, "monitor")
    if monitor is None:
        return None
    _container(monitor)
    return {
        "enabled_raw": _text(monitor, "on"),
        "status_raw": _text(monitor, "status"),
        **{
            field.replace("-", "_"): _uint(monitor, field)
            for field in (
                "ka-status",
                "interval",
                "threshold",
                "pkt-sent",
                "pkt-recv",
                "pkt-seen",
                "pkt-reply",
            )
        },
    }


def parse_vpn_flows(output, command, detail=False):
    """Parse independent flow observations; counters are strict unsigned 64-bit values."""
    matched_id = _DETAIL_ID.fullmatch(command) if isinstance(command, str) else None
    if detail:
        if not (matched_id and int(matched_id.group(1)) <= 65535):
            raise DiscoveryError("VPN detail requires the reviewed numeric tunnel-ID command")
    elif command != VPN_FLOWS:
        raise DiscoveryError("VPN flow inventory requires the reviewed unfiltered command")
    result = _response(output, command)
    _structure(result, {"IPSec", "dp", "num_ipsec", "num_sslvpn", "total"})
    entries = _one(result, "IPSec", required=True)
    _container(entries)
    dataplane = _text(result, "dp", required=bool(len(entries)))
    counts = {count: _uint(result, count) for count in ("num_ipsec", "num_sslvpn", "total")}
    rows, ids = [], set()
    for index, entry in enumerate(entries, 1):
        _row(entry)
        row = {
            "tunnel_id": _uint(entry, "id", minimum=1, maximum=65535, required=True),
            "gateway_id": _uint(entry, "gwid", required=True),
            "name": _text(entry, "name", required=True),
            "tunnel_interface": _text(entry, "inner-if"),
            "outer_interface": _text(entry, "outer-if"),
            "mode": _text(entry, "ipsec-mode"),
            "local_address": _address(entry, "localip"),
            "peer_address": _address(entry, "peerip"),
            "state": _text(entry, "state"),
            "monitor_status": _text(entry, "mon"),
            "dataplane": dataplane,
            "source": _source(command, "result/IPSec/entry", index),
        }
        if row["tunnel_id"] in ids:
            raise DiscoveryError("VPN flow inventory contains duplicate tunnel IDs")
        if matched_id and row["tunnel_id"] != int(matched_id.group(1)):
            raise DiscoveryError("VPN flow detail does not match its requested tunnel ID")
        row["source"]["dataplane"] = dataplane
        ids.add(row["tunnel_id"])
        if detail:
            row.update(
                {
                    "local_spi": _hex_spi(entry, "local-spi"),
                    "remote_spi": _hex_spi(entry, "remote-spi"),
                    "protocol": _text(entry, "proto"),
                    "encryption": _text(entry, "enc"),
                    "authentication": _text(entry, "auth"),
                    "mtu": _uint(entry, "mtu", minimum=1, maximum=65536),
                    "lifetime_seconds": _uint(entry, "hardtime"),
                    "soft_lifetime_seconds": _uint(entry, "softtime"),
                    "remaining_seconds": _uint(entry, "remaintime"),
                    "last_rekey": _uint(entry, "last-rekey"),
                    "selectors": _selectors(entry),
                    "configured_proxy_id": _proxy_id(entry),
                    "monitor": _monitor(entry),
                    "counters": {
                        field.replace("-", "_"): _uint(entry, field) for field in _COUNTERS
                    },
                }
            )
        rows.append(row)
    if counts["num_ipsec"] is not None and counts["num_ipsec"] != len(rows):
        raise DiscoveryError(
            "VPN declared IPsec count does not match the single-dataplane coverage"
        )
    if counts["total"] is not None and (
        counts["total"] < len(rows) or (counts["num_sslvpn"] == 0 and counts["total"] != len(rows))
    ):
        raise DiscoveryError(
            "VPN declared total and flow coverage have an unsupported relationship"
        )
    for row in rows:
        row["source"]["coverage"] = {
            "declared_counts": dict(counts),
            "observed_ipsec_rows": len(rows),
        }
    if detail and len(rows) > 1:
        raise DiscoveryError("VPN numeric flow detail contains ambiguous rows")
    return rows
