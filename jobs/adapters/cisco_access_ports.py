"""Reviewed C9300 console connectors and management-port observations.

Physical connector inventory comes from the observed chassis PID and Cisco's
hardware specifications. Terminal configuration remains separate. Routing data
is report-only until an operator selects its Nautobot Namespace/VRF mapping.
"""

import ipaddress
from copy import deepcopy

from ..transport_restconf import RestconfError

PROFILE = "c9300-48uxm-access-ports-v1"
MODEL = "C9300-48UXM"
MANAGEMENT_INTERFACE = "GigabitEthernet0/0"
HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
NATIVE_MODULE = "Cisco-IOS-XE-native"
OPER_MODULE = "Cisco-IOS-XE-interfaces-oper"
MANAGEMENT_PATH = "/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet=0%2F0"
MANAGEMENT_FIELDS = "name;description;shutdown;vrf;ip(address);ipv6(address)"
MANAGEMENT_OPER_PATH = (
    "/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface=GigabitEthernet0%2F0"
)
MANAGEMENT_OPER_FIELDS = "name;vrf;ipv4;ipv4-subnet-mask;ipv6-addrs"
CONSOLE_PATH = "/data/Cisco-IOS-XE-native:native/line/console=0"
CONSOLE_FIELDS = "first;speed;rxspeed;txspeed;databits;parity;stopbits;media-type"
VRF_PATH = "/data/Cisco-IOS-XE-native:native/vrf"
VRF_FIELDS = "definition(name;rd;address-family)"
HARDWARE_DOCUMENTS = [
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "hardware/install/b_c9300_hig/Product-overview.html",
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "hardware/install/b_c9300_hig/connector-cable-specs.html",
]
MANAGEMENT_DOCUMENT = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
    "software/release/17-12/configuration_guide/int_hw/"
    "b_1712_int_and_hw_9300_cg/configuring_ethernet_management_port.html"
)


class _ScopedDataError(ValueError):
    """An optional source has ambiguous or malformed structured evidence."""


def _value(mapping, name, module=NATIVE_MODULE):
    if not isinstance(mapping, dict):
        raise _ScopedDataError("Expected a structured object")
    matches = [(key, value) for key, value in mapping.items() if key.split(":")[-1] == name]
    if len(matches) > 1:
        raise _ScopedDataError("Duplicate namespace-qualified fields")
    if not matches:
        return None
    key, value = matches[0]
    if key not in (name, module + ":" + name):
        raise _ScopedDataError("Unexpected YANG field namespace")
    if value is None:
        raise _ScopedDataError("A present structured field cannot be null")
    return value


def _has(mapping, name):
    return any(key.split(":")[-1] == name for key in mapping)


def _object(value):
    if not isinstance(value, dict):
        raise _ScopedDataError("Expected a structured container")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise _ScopedDataError("Expected a nonempty structured string")
    return value.strip()


def _rows(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise _ScopedDataError("Expected a structured list of objects")
    return value


def _row(payload, container, key, wanted, module=NATIVE_MODULE):
    rows = _rows(_value(_object(payload), container, module))
    if len(rows) != 1 or str(_value(rows[0], key, module)) != wanted:
        raise _ScopedDataError("Targeted response lacks one matching source identity")
    return rows[0]


def _source(module, path, fields):
    return {
        "module": module,
        "path": path,
        "requested_fields": fields,
        "request": path + "?fields=" + fields,
        "complete": True,
    }


def _read(client, path, fields, label, unresolved):
    try:
        payload = client.get(path + "?fields=" + fields)
        if payload is None:
            unresolved.append(
                {"source": label, "path": path, "reason": "Optional structured source is empty"}
            )
        return payload
    except RestconfError as exc:
        # Never retry without fields: terminal configuration can contain secrets.
        unresolved.append(
            {
                "source": label,
                "path": path,
                "reason": "Optional structured source unavailable",
                "http_status": exc.status_code,
            }
        )
        return None


def _optional(parse, payload, label, path, unresolved):
    if payload is None:
        return None
    try:
        return parse(payload)
    except (_ScopedDataError, ValueError):
        unresolved.append(
            {
                "source": label,
                "path": path,
                "reason": "Optional structured source is malformed, incomplete, or ambiguous",
            }
        )
        return None


def _hardware_source(model, member):
    return {
        "method": "reviewed-hardware-profile",
        "profile": PROFILE,
        "model": model,
        "member": member,
        "module": "Cisco-IOS-XE-device-hardware-oper",
        "path": HARDWARE_PATH,
        "field": "device-hardware/device-inventory[hw-type=hw-type-chassis]/part-number",
        "documents": list(HARDWARE_DOCUMENTS),
    }


def _ipv4(row):
    ip = _value(row, "ip")
    if ip is None:
        return [], "not-configured"
    address = _value(_object(ip), "address")
    if address is None:
        return [], "not-configured"
    address = _object(address)
    modes = [name for name in ("primary", "secondary", "dhcp", "negotiated") if _has(address, name)]
    if any(name in modes for name in ("dhcp", "negotiated")):
        if len(modes) != 1:
            raise _ScopedDataError("Conflicting IPv4 assignment methods")
        name = modes[0]
        if name == "dhcp":
            _object(_value(address, name))
        elif _value(address, name) != [None]:
            raise _ScopedDataError("Malformed IPv4 negotiated flag")
        return [], name
    addresses = []
    primary = _value(address, "primary")
    configured = [(primary, False)] if primary is not None else []
    secondary = _value(address, "secondary")
    if secondary is not None:
        configured.extend((value, True) for value in _rows(secondary))
    for value, is_secondary in configured:
        value = _object(value)
        host = ipaddress.IPv4Address(_text(_value(value, "address")))
        mask = _text(_value(value, "mask"))
        network = ipaddress.IPv4Network("%s/%s" % (host, mask), strict=False)
        if host.is_unspecified or str(network.netmask) != mask:
            raise _ScopedDataError("IPv4 address or mask is unavailable or invalid")
        if is_secondary and _value(value, "secondary") != [None]:
            raise _ScopedDataError("Secondary IPv4 address lacks its configured flag")
        addresses.append(
            {
                "address": str(host),
                "mask": mask,
                "prefix_length": network.prefixlen,
                "secondary": is_secondary,
                "method": "configured-static",
            }
        )
    if len({item["address"] for item in addresses}) != len(addresses):
        raise _ScopedDataError("Duplicate configured IPv4 addresses")
    return addresses, "static" if addresses else "not-configured"


def _ipv6(row):
    ipv6 = _value(row, "ipv6")
    if ipv6 is None:
        return [], {"dhcp": False, "autoconfig": False}
    address = _value(_object(ipv6), "address")
    if address is None:
        return [], {"dhcp": False, "autoconfig": False}
    address = _object(address)
    configuration = {}
    for method in ("dhcp", "autoconfig"):
        value = _value(address, method)
        if value is not None:
            _object(value)
        configuration[method] = value is not None
    result = []
    prefixes = _value(address, "prefix-list")
    seen_prefixes = set()
    for entry in _rows(prefixes) if prefixes is not None else []:
        configured_prefix = _text(_value(entry, "prefix"))
        if "/" not in configured_prefix:
            raise _ScopedDataError("Configured IPv6 prefix length is missing")
        prefix = ipaddress.IPv6Interface(configured_prefix)
        if prefix.ip.is_unspecified or prefix.ip.is_multicast or prefix.scope_id is not None:
            raise _ScopedDataError("IPv6 prefix lacks an unambiguous unicast address")
        if str(prefix) in seen_prefixes:
            raise _ScopedDataError("Duplicate configured IPv6 prefixes")
        seen_prefixes.add(str(prefix))
        flags = {}
        for flag in ("eui-64", "anycast"):
            if _has(entry, flag) and _value(entry, flag) != [None]:
                raise _ScopedDataError("Malformed IPv6 address flag")
            flags[flag.replace("-", "_")] = _has(entry, flag)
        result.append({"configured_prefix": str(prefix), "method": "configured", **flags})
    link_local = _value(address, "link-local-address")
    link_local_rows = _rows(link_local) if link_local is not None else []
    link_local_container = _value(address, "link-local-address-container")
    if link_local_container is not None:
        link_local_rows = link_local_rows + [_object(link_local_container)]
    seen_link_local = set()
    for entry in link_local_rows:
        host = ipaddress.IPv6Address(_text(_value(entry, "address")))
        if (
            not host.is_link_local
            or host.scope_id is not None
            or _value(entry, "link-local") != [None]
            or str(host) in seen_link_local
        ):
            raise _ScopedDataError("Malformed configured IPv6 link-local address")
        seen_link_local.add(str(host))
        result.append({"address": str(host), "method": "configured-link-local"})
    named_prefixes = _value(address, "prefix-name")
    seen_names = set()
    for entry in _rows(named_prefixes) if named_prefixes is not None else []:
        name = _text(_value(entry, "name"))
        if name in seen_names:
            raise _ScopedDataError("Duplicate named IPv6 prefix references")
        seen_names.add(name)
        # General-prefix sub-bits cannot establish a complete configured host
        # without separately resolving the named prefix. Preserve this scoped
        # observation without discarding independent literal IPv6 or IPv4 data.
        result.append(
            {
                "method": "configured-named-prefix",
                "prefix_name": name,
                "configuration": deepcopy(entry),
            }
        )
    return result, configuration


def _management_config(payload):
    row = _row(payload, "GigabitEthernet", "name", "0/0")
    vrf = _value(row, "vrf")
    vrf_name = None
    if vrf is not None:
        forwarding = _value(_object(vrf), "forwarding")
        vrf_name = _text(forwarding) if forwarding is not None else None
    ipv4, method4 = _ipv4(row)
    ipv6, methods6 = _ipv6(row)
    return {
        "name": MANAGEMENT_INTERFACE,
        "vrf": vrf_name,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "addressing": {"ipv4_method": method4, "ipv6_methods": methods6},
        "source": _source(NATIVE_MODULE, MANAGEMENT_PATH, MANAGEMENT_FIELDS),
    }


def _management_oper(payload):
    row = _row(payload, "interface", "name", MANAGEMENT_INTERFACE, OPER_MODULE)
    result = {"name": MANAGEMENT_INTERFACE}
    for field in ("vrf", "ipv4", "ipv4-subnet-mask"):
        value = _value(row, field, OPER_MODULE)
        result[field] = _text(value) if value is not None else None
    addresses = _value(row, "ipv6-addrs", OPER_MODULE)
    if addresses is not None and (
        not isinstance(addresses, list) or any(not isinstance(value, str) for value in addresses)
    ):
        raise _ScopedDataError("Malformed operational IPv6 address list")
    result["ipv6-addrs"] = addresses
    result["source"] = _source(OPER_MODULE, MANAGEMENT_OPER_PATH, MANAGEMENT_OPER_FIELDS)
    result["meaning"] = (
        "Operational observations only; zero IPv4 values are unavailable sentinels, "
        "and IPv6 addresses have no reported prefix length"
    )
    return result


def _console_line(payload):
    row = _row(payload, "console", "first", "0")
    result = {"first": "0", "baudrate": None}
    for field in ("speed", "rxspeed", "txspeed"):
        value = _value(row, field)
        if value is not None and (type(value) is not int or not 0 <= value <= 4_294_967_295):
            raise _ScopedDataError("Malformed console speed")
        result[field] = value
    if result["speed"] and all(
        result[field] is None or result[field] == result["speed"]
        for field in ("rxspeed", "txspeed")
    ):
        result["baudrate"] = result["speed"]
    stopbits = _value(row, "stopbits")
    if stopbits is not None and stopbits not in ("1", "1.5", "2"):
        raise _ScopedDataError("Unsupported console stop bits")
    result["stopbits"] = stopbits
    for field, accepted in (
        ("databits", {"set-to-5", "set-to-6", "set-to-7", "set-to-8"}),
        ("parity", {"even", "mark", "none", "odd", "space"}),
        ("media-type", {"rj45"}),
    ):
        value = _value(row, field)
        if value is None:
            result[field] = None
            continue
        value = _object(value)
        if len(value) != 1:
            raise _ScopedDataError("Ambiguous console terminal setting")
        key = next(iter(value)).split(":")[-1]
        if key not in accepted or _value(value, key) != [None]:
            raise _ScopedDataError("Unsupported console terminal setting")
        result[field] = key
    result["source"] = _source(NATIVE_MODULE, CONSOLE_PATH, CONSOLE_FIELDS)
    result["meaning"] = (
        "Configured logical console line 0, shared by the physical console connectors; "
        "omitted settings and active-connector selection remain unknown"
    )
    return result


def _vrf_config(payload, wanted):
    vrf = _object(_value(_object(payload), "vrf"))
    definitions = _value(vrf, "definition")
    result = []
    for row in _rows(definitions) if definitions is not None else []:
        name = _text(_value(row, "name"))
        if name != wanted:
            continue
        rd = _value(row, "rd")
        if rd is not None:
            rd = _text(rd)
        families = _value(row, "address-family")
        configured = []
        if families is not None:
            for family in ("ipv4", "ipv6"):
                value = _value(_object(families), family)
                if value is not None:
                    _object(value)
                    configured.append(family)
        result.append({"name": name, "rd": rd, "address_families": configured})
    if len(result) > 1:
        raise _ScopedDataError("Duplicate management VRF definitions")
    return {"definitions": result, "source": _source(NATIVE_MODULE, VRF_PATH, VRF_FIELDS)}


def _console_connectors(model, member):
    profile = _hardware_source(model, member)
    items = []
    for key, name, connector, position in (
        ("console:rj45", "Console RJ45", "rj-45", "rear"),
        ("console:usb", "Console USB", "usb-mini-b", "front"),
    ):
        source = deepcopy(profile)
        source.update(
            {
                "meaning": "Physical console connector documented for the observed chassis PID",
                "position": position,
                "name_origin": (
                    "Discovery-standardized connector name; not an observed faceplate label"
                ),
                "shared_logical_console": "0",
            }
        )
        items.append({"key": key, "name": name, "type": connector, "label": None, "source": source})
    return items


def collect_stack_consoles(stack):
    """Documented physical connectors on serial-validated, present stack members.

    Console line configuration from the active control plane cannot establish
    terminal settings on every member. Only physical inventory is emitted.
    """
    if not isinstance(stack, dict) or stack.get("is_stack") is not True:
        raise _ScopedDataError("Physical stack consoles require validated stack membership")
    members = stack.get("members")
    if not isinstance(members, list) or len(members) < 2:
        raise _ScopedDataError("Physical stack consoles require multiple present members")
    result = {
        "schema_version": 1,
        "items": [],
        "unresolved": [],
        "observations": {
            "stack_scope": {
                "source": {
                    "module": "Cisco-IOS-XE-stack-oper",
                    "path": "/data/Cisco-IOS-XE-stack-oper:stack-oper-data",
                },
                "meaning": "Physical member connectors; logical console settings are not copied",
            },
        },
    }
    serials, positions = set(), set()
    for owner in members:
        if not isinstance(owner, dict):
            raise _ScopedDataError("Console owner must be a structured stack member")
        serial, position, model = owner.get("serial"), owner.get("position"), owner.get("model")
        if (
            not isinstance(serial, str)
            or not serial.strip()
            or serial != serial.strip()
            or type(position) is not int
            or not 1 <= position <= 255
            or serial in serials
            or position in positions
            or owner.get("state") != "state-ready"
            or owner.get("stack_mode") != "mode-stackwise-rear"
            or not isinstance(owner.get("sources"), dict)
            or not owner["sources"].get("identity")
            or not owner["sources"].get("membership")
        ):
            raise _ScopedDataError("Console owner lacks unique validated physical identity")
        serials.add(serial)
        positions.add(position)
        if model != MODEL:
            result["unresolved"].append(
                {
                    "device_serial": serial,
                    "member": position,
                    "model": model,
                    "reason": "No reviewed console hardware profile for this chassis",
                }
            )
            continue
        for item in _console_connectors(model, position):
            item.update(device_serial=serial, member=position, chassis_model=model)
            item["source"].update(
                device_serial=serial,
                identity=deepcopy(owner["sources"]["identity"]),
                membership=deepcopy(owner["sources"]["membership"]),
            )
            result["items"].append(item)
    return result


def collect(client, interfaces, *, model, member):
    """Inventory reviewed connectors; retain safe optional configuration evidence."""
    console = {"schema_version": 1, "items": [], "unresolved": [], "observations": {}}
    management = {
        "schema_version": 1,
        "interfaces": [],
        "observations": {},
        "writes_deferred_reason": "VRF/IP Namespace mapping has not been selected",
        "unresolved": [],
    }
    if model != MODEL or type(member) is not int or member != 1:
        console["unresolved"].append(
            {"reason": "No reviewed console hardware profile for this chassis/member"}
        )
        return console, management
    profile = _hardware_source(model, member)
    console["items"] = _console_connectors(model, member)
    line = _read(client, CONSOLE_PATH, CONSOLE_FIELDS, "console_line", console["unresolved"])
    observed = _optional(_console_line, line, "console_line", CONSOLE_PATH, console["unresolved"])
    if observed is not None:
        console["observations"]["console_line"] = observed
    eligible = [
        row
        for row in interfaces
        if row.get("name") == MANAGEMENT_INTERFACE
        and row.get("type") == "1000base-t"
        and row.get("type_source") == "C9300-48UXM dedicated 1G copper management port"
    ]
    if len(eligible) != 1:
        management["unresolved"].append(
            {
                "name": MANAGEMENT_INTERFACE,
                "reason": "Reviewed management interface was not observed",
            }
        )
        return console, management
    management_source = deepcopy(profile)
    management_source.update(
        {
            "interface": MANAGEMENT_INTERFACE,
            "value": True,
            "meaning": "Dedicated Ethernet port used exclusively for out-of-band management",
            "documents": list(HARDWARE_DOCUMENTS) + [MANAGEMENT_DOCUMENT],
        }
    )
    eligible[0]["mgmt_only"] = True
    eligible[0]["mgmt_only_source"] = management_source
    for label, path, fields, parse in (
        ("configuration", MANAGEMENT_PATH, MANAGEMENT_FIELDS, _management_config),
        ("operational", MANAGEMENT_OPER_PATH, MANAGEMENT_OPER_FIELDS, _management_oper),
        (
            "vrf_configuration",
            VRF_PATH,
            VRF_FIELDS,
            lambda payload: _vrf_config(
                payload,
                management["interfaces"][0]["vrf"] if management["interfaces"] else None,
            ),
        ),
    ):
        payload = _read(client, path, fields, label, management["unresolved"])
        observed = _optional(parse, payload, label, path, management["unresolved"])
        if observed is None:
            continue
        if label == "configuration":
            management["interfaces"].append(observed)
        else:
            management["observations"][label] = observed
    return console, management


def add_revisions(console, management, interfaces, modules):
    """Annotate existing sources with the already collected module revisions."""
    sources = [item["source"] for item in console["items"]]
    sources.extend(item["source"] for item in management["interfaces"])
    sources.extend(value["source"] for value in console["observations"].values())
    sources.extend(value["source"] for value in management["observations"].values())
    sources.extend(row["mgmt_only_source"] for row in interfaces if "mgmt_only_source" in row)
    for source in sources:
        source["revision"] = modules.get(source["module"])
