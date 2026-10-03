"""Cisco IOS XE 17.9+ identity and interface discovery from RESTCONF JSON only.

Payload access, interface naming and filtered GET behavior are selectively
adapted from nautobot-testsuite/jobs/iosxe_common.py (Apache-2.0). No CLI code
or unstructured software-banner parser is included.
"""

import re

from ..transport_restconf import RestconfError
from . import (
    cisco_access_ports,
    cisco_components,
    cisco_duplex,
    cisco_ipam,
    cisco_layer2,
    cisco_stack,
    cisco_switchport_oper,
)
from .cisco_hardware import interface_type

HOSTNAME_PATH = "/data/Cisco-IOS-XE-native:native/hostname"
HARDWARE_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
INSTALL_PATH = "/data/Cisco-IOS-XE-install-oper:install-oper-data/install-location-information"
INTERFACES_PATH = "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
NATIVE_INTERFACES_PATH = "/data/Cisco-IOS-XE-native:native/interface"
YANG_LIBRARY_PATH = "/data/ietf-yang-library:modules-state"
INSTALL_FIELDS = (
    "fru;slot;bay;chassis;install-version-info("
    "version;version-extension;is-default;current;commit-type)"
)
INTERFACE_FIELDS = (
    "interface(name;interface-type;description;admin-status;oper-status;phys-address;"
    "mtu;speed;ether-state(negotiated-port-speed;negotiated-duplex-mode;auto-negotiate;"
    "media-type);ether-stats/dot3-counters/dot3-error-counters-v2/dot3-duplex-status)"
)
LAG_INTERFACE_FAMILIES = (
    "FastEthernet",
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
)
# The augmentation's module qualifier is essential: the lab accepts a bare
# channel-group filter with HTTP 200 but silently omits the membership leaves.
LAG_FIELDS = ";".join(
    family + "(name;Cisco-IOS-XE-ethernet:channel-group(number;mode))"
    for family in LAG_INTERFACE_FAMILIES
)
MODULES = (
    "Cisco-IOS-XE-native",
    "Cisco-IOS-XE-ethernet",
    "Cisco-IOS-XE-device-hardware-oper",
    "Cisco-IOS-XE-install-oper",
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-platform-oper",
    "Cisco-IOS-XE-switch",
    "Cisco-IOS-XE-vlan",
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-stack-oper",
    "Cisco-IOS-XE-switchport-oper",
)
_PREFIXES = (
    ("TwentyFiveGigE", "Twe"),
    ("AppGigabitEthernet", "Ap"),
    ("Bluetooth", "Bl"),
    ("FiveGigabitEthernet", "Fi"),
    ("FortyGigabitEthernet", "Fo"),
    ("FastEthernet", "Fa"),
    ("GigabitEthernet", "Gi"),
    ("HundredGigE", "Hu"),
    ("Loopback", "Lo"),
    ("Port-channel", "Po"),
    ("TenGigabitEthernet", "Te"),
    ("Tunnel", "Tu"),
    ("TwoGigabitEthernet", "Tw"),
    ("Vlan", "Vl"),
)
_LONG_NAMES = {
    spelling.lower(): long_name
    for long_name, short_name in _PREFIXES
    for spelling in (long_name, short_name)
}
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)([A-Za-z][A-Za-z0-9]*)?(?:\.\d+)*$")
_SPEEDS = {
    "speed-10mb": 10_000_000,
    "speed-100mb": 100_000_000,
    "speed-1gb": 1_000_000_000,
    "speed-2500mb": 2_500_000_000,
    "speed-5gb": 5_000_000_000,
    "speed-10gb": 10_000_000_000,
    "speed-25gb": 25_000_000_000,
    "speed-40gb": 40_000_000_000,
    "speed-50gb": 50_000_000_000,
    "speed-100gb": 100_000_000_000,
    "speed-400gb": 400_000_000_000,
}


class DiscoveryError(ValueError):
    """Structured discovery is incomplete, unsupported or ambiguous."""


def canonical_interface_name(name):
    """Normalize known IOS XE long/short interface names without inventing names."""
    if name is None:
        return None
    text = str(name).strip()
    match = re.fullmatch(r"([A-Za-z][A-Za-z-]*?)(\d[\d/.]*)", text)
    if match:
        return _LONG_NAMES.get(match.group(1).lower(), match.group(1)) + match.group(2)
    return text


def canonical_software_version(value):
    """Normalize a structured release/build token to its release, preserving suffix.

    Numeric build octets in the install version are not release components:
    17.12.8.0.123 -> 17.12.08. Prose banners and unknown formats return None.
    """
    if not isinstance(value, str):
        return None
    match = _VERSION.fullmatch(value.strip())
    if match is None:
        return None
    major, minor, patch, suffix = match.groups()
    return "%d.%d.%02d%s" % (int(major), int(minor), int(patch), suffix or "")


def _value(mapping, name):
    if not isinstance(mapping, dict):
        return None
    return next((value for key, value in mapping.items() if key.split(":")[-1] == name), None)


def _rows(value, label):
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    if any(not isinstance(row, dict) for row in values):
        raise DiscoveryError("%s must contain structured objects" % label)
    return values


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _enum(value):
    return value.split(":")[-1] if isinstance(value, str) else None


def _filtered(client, path, fields, warnings):
    try:
        return client.get(path + "?fields=" + fields)
    except RestconfError as exc:
        if getattr(exc, "status_code", None) != 400:
            raise
        warnings.append("%s: fields filter rejected (HTTP 400); unfiltered JSON read used" % path)
        return client.get(path)


def _install_identity(payload, *, required_members=None, active_member=None):
    locations = _value(payload, "install-location-information")
    if locations is None:
        locations = _value(_value(payload, "install-oper-data"), "install-location-information")
    rows = _rows(locations, "install-location-information")
    # Only control-plane installation rows describe the IOS XE image. PIM
    # firmware entries are outside the initial software-version scope.
    rows = [row for row in rows if _enum(row.get("fru")) == "fru-rp"]
    if not rows:
        raise DiscoveryError("install-oper contains no control-plane installation row")
    for row in rows:
        member = row.get("chassis")
        if isinstance(member, bool) or not isinstance(member, int) or member < 1:
            raise DiscoveryError("install-oper chassis member must be a positive integer")
    if required_members is not None:
        rows = [row for row in rows if row["chassis"] in required_members]
        if {row["chassis"] for row in rows} != set(required_members):
            raise DiscoveryError(
                "Every physical stack member requires a running install-oper image"
            )
        member = active_member
    else:
        members = {row["chassis"] for row in rows}
        if len(members) != 1:
            raise DiscoveryError(
                "Multiple install chassis members require an approved stack mapping"
            )
        member = next(iter(members))
    releases = set()
    evidence = []
    for row in rows:
        versions = _rows(row.get("install-version-info"), "install-version-info")
        selected = []
        for wanted in (
            "install-version-state-provisioned-uncommitted",
            "install-version-state-provisioned-committed",
        ):
            selected = [version for version in versions if _enum(version.get("current")) == wanted]
            if selected:
                break
        if len(selected) != 1:
            raise DiscoveryError(
                "Running software version is missing or ambiguous in install-oper provisioned state"
            )
        version = canonical_software_version(selected[0].get("version"))
        if version is None:
            raise DiscoveryError(
                "install-oper software version is not a supported structured release token"
            )
        # The lab serves a numeric build timestamp as version-extension. It
        # identifies the build and must not become a new release suffix.
        # Unreviewed nonnumeric extensions could identify engineering images;
        # decline those rather than silently equating them with a base image.
        extension = _text(selected[0].get("version-extension"))
        if extension and not extension.isdecimal():
            raise DiscoveryError(
                "install-oper nonnumeric version extension requires a reviewed release mapping"
            )
        evidence.append(
            {
                "fru": row.get("fru"),
                "slot": row.get("slot"),
                "bay": row.get("bay"),
                "chassis": row["chassis"],
                "version": selected[0].get("version"),
                "version-extension": extension,
                "current": selected[0].get("current"),
                "release": version,
            }
        )
        releases.add(version)
    if len(releases) != 1:
        raise DiscoveryError(
            "Control-plane installation rows disagree on the running software version"
        )
    version = next(iter(releases))
    if tuple(int(part) for part in version.split(".")[:2]) < (17, 9):
        raise DiscoveryError("Initial Cisco IOS XE discovery requires version 17.9 or later")
    return version, member, evidence


def _mac(value, name, warnings):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        warnings.append("%s: invalid structured MAC address omitted" % name)
        return None
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        return value.lower() if value.lower() != "00:00:00:00:00:00" else None
    warnings.append("%s: invalid structured MAC address omitted" % name)
    return None


def _uint(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"\d+", value):
        return int(value)
    return None


def _interfaces(payload, model, member, inventory, warnings, *, stack_members=None):
    container = _value(payload, "interfaces")
    if not isinstance(container, dict) or _value(container, "interface") is None:
        raise DiscoveryError("interfaces-oper reply lacks the interface list")
    rows = _rows(_value(container, "interface"), "interface")
    if not rows:
        raise DiscoveryError("interfaces-oper returned no interface rows")
    interfaces, excluded, names = [], [], set()
    for row in rows:
        raw_name = _text(row.get("name"))
        if not raw_name:
            raise DiscoveryError("interfaces-oper interface row has no structured name")
        name = canonical_interface_name(raw_name)
        if name in names:
            raise DiscoveryError("interfaces-oper has duplicate canonical interface name %s" % name)
        names.add(name)
        admin, oper = _enum(row.get("admin-status")), _enum(row.get("oper-status"))
        if oper == "if-oper-state-not-present":
            excluded.append({"name": name, "reason": "Device reports if-oper-state-not-present"})
            continue
        if name.startswith("AppGigabitEthernet"):
            excluded.append({"name": name, "reason": "Internal application-hosting interface"})
            continue
        port_location = re.fullmatch(r"[A-Za-z][A-Za-z-]*(\d+)/(\d+)/(\d+)(?:\.\d+)?", name)
        owner = None
        type_model, type_member, type_inventory = model, member, inventory
        if stack_members is not None:
            # The first coordinate is the device's explicit switch member.
            # Names without that coordinate do not establish physical ownership.
            if port_location:
                owner = stack_members.get(int(port_location.group(1)))
                if owner is None:
                    raise DiscoveryError(
                        "Present interface %s has no validated physical stack owner" % name
                    )
                type_model, type_member = owner["model"], owner["position"]
                type_inventory = cisco_stack.inventory_for_member(inventory, owner)
            else:
                type_model, type_member, type_inventory = None, None, []
        elif port_location and int(port_location.group(1)) != member:
            raise DiscoveryError(
                "Present interface %s belongs to a different stack member; "
                "stack mapping needs review" % name
            )
        # Unsupported families remain explicit observations; the planner can
        # use an existing interface/template type without guessing capability.
        type_, source = interface_type(name, type_model, type_member, type_inventory)
        mtu = row.get("mtu")
        if mtu is not None and (
            isinstance(mtu, bool) or not isinstance(mtu, int) or not 1 <= mtu <= 65535
        ):
            warnings.append("%s: invalid or unsupported MTU omitted" % name)
            mtu = None
        enabled = {"if-state-up": True, "if-state-down": False}.get(admin)
        if enabled is None:
            warnings.append("%s: administrative enabled state is unavailable or unsupported" % name)
        ether = row.get("ether-state") if isinstance(row.get("ether-state"), dict) else {}
        reported_speed = _uint(row.get("speed"))
        mac_duplex = _uint(
            _value(
                _value(_value(row.get("ether-stats"), "dot3-counters"), "dot3-error-counters-v2"),
                "dot3-duplex-status",
            )
        )
        speed = None
        operational_duplex = None
        physical = _enum(
            row.get("interface-type")
        ) == "iana-iftype-ethernet-csmacd" and type_ not in ("virtual", "lag")
        port_type = (
            "8p8c"
            if physical and _enum(ether.get("media-type")) == "ether-media-type-rj45"
            else None
        )
        if physical and oper == "if-oper-state-ready":
            # interfaces-oper speed is current/nominal bandwidth in bps. Down
            # ports commonly publish nominal values, so only a ready physical
            # interface can populate Nautobot's operational speed in Kbps.
            if reported_speed and reported_speed % 1000 == 0:
                speed = reported_speed // 1000
            if type_ in ("1000base-t", "2.5gbase-t", "10gbase-t"):
                negotiated = {"full-duplex": "full", "half-duplex": "half"}.get(
                    _enum(ether.get("negotiated-duplex-mode"))
                )
                # This is current MAC state, including manually configured
                # links. It does not establish Nautobot's duplex setting.
                mac_mode = {2: "half", 3: "full"}.get(mac_duplex)
                if negotiated is not None and mac_mode == negotiated:
                    operational_duplex = negotiated
                elif mac_mode is not None or negotiated is not None:
                    warnings.append("%s: operational duplex lacks agreeing MAC evidence" % name)
        facts = {
            "name": name,
            "type": type_,
            "enabled": enabled,
            "description": _text(row.get("description")),
            "mtu": mtu,
            "mac_address": _mac(row.get("phys-address"), name, warnings),
            "speed": speed,
            "duplex": None,
            "port_type": port_type,
            "type_source": source,
            "observations": {
                "admin_status": admin,
                "oper_status": oper,
                "speed_bps": _SPEEDS.get(_enum(ether.get("negotiated-port-speed"))),
                "media_type": _enum(ether.get("media-type")),
                "reported_speed_bps": reported_speed,
                "negotiated_duplex": _enum(ether.get("negotiated-duplex-mode")),
                "auto_negotiate": ether.get("auto-negotiate"),
                "mac_duplex_status": mac_duplex,
                "corroborated_operational_duplex": operational_duplex,
            },
        }
        if owner is not None:
            facts["stack_member"] = owner["position"]
        interfaces.append(facts)
    return sorted(interfaces, key=lambda row: row["name"]), sorted(
        excluded, key=lambda row: row["name"]
    )


def _lag_memberships(client, interfaces, excluded, warnings):
    """Read configured channel groups, including static and disconnected members.

    Cisco-IOS-XE-ethernet in both the 17.9.1 and 17.12.1 published model sets
    augments native interface lists with channel-group/number (1..512) and
    mode (active, passive, on, auto, desirable). Configuration is authoritative
    for Nautobot membership; LACP operational state describes bundling only.

    https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/1791/Cisco-IOS-XE-ethernet.yang
    https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17121/Cisco-IOS-XE-ethernet.yang
    """
    try:
        payload = _filtered(client, NATIVE_INTERFACES_PATH, LAG_FIELDS, warnings)
    except RestconfError as exc:
        status = " (HTTP %s)" % exc.status_code if exc.status_code else ""
        warnings.append(
            "Configured LAG membership source unavailable%s; existing links are preserved" % status
        )
        return []
    container = _value(payload, "interface")
    if container is None:
        warnings.append(
            "Native interface reply lacks configured LAG evidence; existing links are preserved"
        )
        return []
    if not isinstance(container, dict):
        raise DiscoveryError("Native interface configuration must be a structured container")
    eligible = {row["name"] for row in interfaces}
    excluded_names = {row["name"] for row in excluded}
    memberships, seen = [], set()
    for family, rows in container.items():
        family = family.split(":")[-1]
        if family not in LAG_INTERFACE_FAMILIES and family != "AppGigabitEthernet":
            continue
        for row in _rows(rows, "native " + family):
            if not any(key.split(":")[-1] == "channel-group" for key in row):
                continue
            group = _value(row, "channel-group")
            if not isinstance(group, dict):
                raise DiscoveryError("Native channel-group must be a structured object")
            suffix = _text(_value(row, "name"))
            if suffix is None or not re.fullmatch(r"\d+(?:/\d+){1,2}", suffix):
                raise DiscoveryError("Configured LAG member lacks a supported native interface key")
            member = canonical_interface_name(family + suffix)
            if member in seen:
                raise DiscoveryError("Native configuration has duplicate LAG member %s" % member)
            seen.add(member)
            number = _value(group, "number")
            if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 512:
                raise DiscoveryError(
                    "%s: channel-group number must be an integer from 1 to 512" % member
                )
            mode = _enum(_value(group, "mode"))
            if _value(group, "mode") is not None and mode not in (
                "active",
                "passive",
                "on",
                "auto",
                "desirable",
            ):
                raise DiscoveryError("%s: unsupported structured channel-group mode" % member)
            if member in excluded_names or family == "AppGigabitEthernet":
                warnings.append(
                    "%s: configured LAG membership omitted because the interface "
                    "is absent or internal" % member
                )
                continue
            if member not in eligible:
                warnings.append(
                    "%s: configured LAG member is missing from eligible interface observations"
                    % member
                )
            memberships.append(
                {
                    "member": member,
                    "lag": "Port-channel%d" % number,
                    "source": {
                        "path": NATIVE_INTERFACES_PATH,
                        "module": "Cisco-IOS-XE-ethernet",
                        "field": "%s[name=%s]/Cisco-IOS-XE-ethernet:channel-group/number"
                        % (family, suffix),
                        "mode": mode,
                    },
                }
            )
    return sorted(memberships, key=lambda row: (row["member"], row["lag"]))


def _library_value(mapping, name):
    """Read a library leaf without accepting a foreign namespace or collision."""
    if not isinstance(mapping, dict) or any(not isinstance(key, str) for key in mapping):
        raise DiscoveryError("YANG library requires structured containers with string keys")
    matches = [(key, value) for key, value in mapping.items() if key.split(":")[-1] == name]
    if len(matches) > 1 or any(
        ":" in key and key.split(":", 1)[0] != "ietf-yang-library" for key, _ in matches
    ):
        raise DiscoveryError("YANG library field is ambiguous or belongs to another module")
    return matches[0][1] if matches else None


def collect(client, *, use_ntc_defaults=False):
    """Collect common facts; required identity/interface failures abort application."""
    if type(use_ntc_defaults) is not bool:
        raise DiscoveryError("Use NTC defaults when guessing must be true or false")
    warnings = []
    hostname = _text(_value(client.get(HOSTNAME_PATH), "hostname"))
    if hostname is None:
        raise DiscoveryError("Native hostname leaf is missing or not a structured string")
    hardware = _value(client.get(HARDWARE_PATH), "device-hardware-data")
    device_hardware = _value(hardware, "device-hardware")
    inventory = _rows(_value(device_hardware, "device-inventory"), "device-inventory")
    try:
        stack = cisco_stack.collect(client, inventory, hostname=hostname, warnings=warnings)
    except cisco_stack.StackDiscoveryError as exc:
        raise DiscoveryError(str(exc)) from None
    chassis = [row for row in inventory if _enum(row.get("hw-type")) == "hw-type-chassis"]
    active = stack["active_identity"]
    if active:
        model, serial = active["model"], active["serial"]
    else:
        model, serial = _text(chassis[0].get("part-number")), _text(chassis[0].get("serial-number"))
    install = _filtered(client, INSTALL_PATH, INSTALL_FIELDS, warnings)
    version, member, install_evidence = _install_identity(
        install,
        required_members={row["position"] for row in stack["members"]}
        if stack["members"]
        else None,
        active_member=stack["active_position"],
    )
    # The common release was established from a running image on every physical
    # chassis. Keep the per-chassis join so member inventory never acquires a
    # release merely because the active supervisor reported it.
    for stack_member in stack["members"]:
        position = stack_member["position"]
        member_install = [row.copy() for row in install_evidence if row["chassis"] == position]
        if not member_install or any(row["release"] != version for row in member_install):
            raise DiscoveryError("Stack member software lacks its validated installation evidence")
        stack_member["software_version"] = version
        stack_member["sources"]["software_version"] = {
            "module": "Cisco-IOS-XE-install-oper",
            "path": INSTALL_PATH,
            "requested_fields": INSTALL_FIELDS,
            "field": "install-location-information[chassis=%s]/"
            "install-version-info[current=provisioned-*]/version" % position,
            "chassis": position,
            "install_rows": member_install,
        }
    interfaces, excluded = _interfaces(
        _filtered(client, INTERFACES_PATH, INTERFACE_FIELDS, warnings),
        model,
        member,
        inventory,
        warnings,
        stack_members={row["position"]: row for row in stack["members"]}
        if stack["is_stack"]
        else None,
    )
    lag_memberships = _lag_memberships(client, interfaces, excluded, warnings)
    modules = {}
    library_known = False
    try:
        library = _library_value(
            client.get(YANG_LIBRARY_PATH + "?fields=module(name;revision)"), "modules-state"
        )
        entries = _library_value(library, "module")
        if not isinstance(entries, list):
            raise DiscoveryError("YANG library did not provide a complete module list")
        for module in _rows(entries, "yang-library module"):
            name = _library_value(module, "name")
            revision = _library_value(module, "revision")
            if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name) is None:
                raise DiscoveryError("YANG library module requires a valid structured name")
            if revision is not None and not isinstance(revision, str):
                raise DiscoveryError("YANG library module revision must be structured text")
            if name in MODULES:
                if name in modules:
                    raise DiscoveryError("YANG library has ambiguous relevant module revisions")
                modules[name] = _text(revision)
        library_known = True
        if not modules:
            warnings.append(
                "YANG library did not provide relevant module revisions; "
                "successful data reads remain the evidence"
            )
    except (RestconfError, DiscoveryError) as exc:
        # Only expected optional evidence failures are warnings. Cancellation,
        # worker time limits and programming errors must propagate unchanged.
        # Optional evidence must not mask a required discovery failure, and
        # transport/provider exception bodies are never copied into artifacts.
        modules.clear()
        status = getattr(exc, "status_code", None)
        warnings.append(
            "YANG module revision evidence unavailable%s"
            % (" (HTTP %s)" % status if status else "")
        )
    try:
        ipam = cisco_ipam.collect(
            client,
            interfaces,
            canonical_name=canonical_interface_name,
            excluded_interfaces=excluded,
            revisions=modules if library_known else None,
        )
    except cisco_ipam.IpamDiscoveryError as exc:
        raise DiscoveryError(str(exc)) from None
    try:
        switchport_oper = cisco_switchport_oper.collect(
            client,
            interfaces,
            canonical_name=canonical_interface_name,
            revisions=modules if library_known else None,
            warnings=warnings,
            excluded_interfaces=excluded,
        )
    except cisco_switchport_oper.SwitchportOperDiscoveryError as exc:
        raise DiscoveryError(str(exc)) from None
    try:
        layer2 = cisco_layer2.collect(
            client,
            interfaces,
            # The chassis profile is singular; applying the active model's
            # omitted-leaf defaults across other members would guess capability.
            model=None if stack["is_stack"] else model,
            software_version=version,
            canonical_name=canonical_interface_name,
            warnings=warnings,
            use_ntc_defaults=use_ntc_defaults,
            switchport_oper=switchport_oper,
            lag_memberships=lag_memberships,
        )
    except cisco_layer2.Layer2DiscoveryError as exc:
        raise DiscoveryError(str(exc)) from None
    try:
        configured_duplex = cisco_duplex.collect(
            client,
            interfaces,
            model=None if stack["is_stack"] else model,
            software_version=version,
            member=member,
            canonical_name=canonical_interface_name,
            warnings=warnings,
        )
    except cisco_duplex.DuplexDiscoveryError as exc:
        raise DiscoveryError(str(exc)) from None
    try:
        components = cisco_components.collect(
            client,
            inventory,
            chassis_model=model,
            chassis_serial=serial,
            member=member,
            interfaces=interfaces,
            warnings=warnings,
            stack=stack,
            use_ntc_defaults=use_ntc_defaults,
        )
    except cisco_components.ComponentDiscoveryError as exc:
        raise DiscoveryError(str(exc)) from None
    if stack["is_stack"]:
        reason = cisco_stack.DEFERRED_PLACEMENT
        console_ports = cisco_access_ports.collect_stack_consoles(stack)
        management = {
            "schema_version": 1,
            "interfaces": [],
            "unresolved": [{"reason": reason}],
            "observations": {},
            "writes_deferred_reason": reason,
        }
    else:
        console_ports, management = cisco_access_ports.collect(
            client, interfaces, model=model, member=member
        )
    safe_inventory = [
        {
            key: row.get(key)
            for key in (
                "hw-type",
                "hw-dev-index",
                "dev-name",
                "part-number",
                "serial-number",
                "version",
                "field-replaceable",
            )
            if key in row
        }
        for row in inventory
    ]
    sources = {
        "identity": {
            "hostname": {
                "module": "Cisco-IOS-XE-native",
                "path": HOSTNAME_PATH,
                "field": "hostname",
            },
            "serial": {
                "module": "Cisco-IOS-XE-device-hardware-oper",
                "path": HARDWARE_PATH,
                "field": "device-hardware/device-inventory[hw-type=hw-type-chassis]/serial-number",
            },
            "model": {
                "module": "Cisco-IOS-XE-device-hardware-oper",
                "path": HARDWARE_PATH,
                "field": "device-hardware/device-inventory[hw-type=hw-type-chassis]/part-number",
            },
            "software_version": {
                "module": "Cisco-IOS-XE-install-oper",
                "path": INSTALL_PATH,
                "field": "install-version-info[current=provisioned-*]/version",
            },
        },
        "interface_fields": {
            "module": "Cisco-IOS-XE-interfaces-oper",
            "path": INTERFACES_PATH,
            "fields": {
                "name": "name",
                "enabled": "admin-status",
                "description": "description",
                "mtu": "mtu",
                "mac_address": "phys-address",
                "speed": "speed (bps)/1000; only ready physical interfaces",
                "duplex": (
                    "Separate configured_duplex native source supplies the setting. "
                    "Negotiated and MAC duplex remain operational observations only"
                ),
                "port_type": (
                    "ether-state/media-type=ether-media-type-rj45 on physical IANA Ethernet; "
                    "IEEE RJ45 connector maps to 8p8c, including disconnected ports"
                ),
            },
            "type": (
                "Reviewed chassis/module capability mapping; "
                "interface.type_source identifies the rule"
            ),
            "duplex_reference": "https://www.rfc-editor.org/rfc/rfc3635",
            "connector_references": [
                "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/"
                "hardware/install/b_c9300_hig/connector-cable-specs.html",
                "https://www.cisco.com/c/en/us/td/docs/security/firepower/1100/"
                "hw/guide/hw-install-11001/overview.html",
            ],
        },
    }
    for source in sources["identity"].values():
        source["revision"] = modules.get(source["module"])
    sources["interface_fields"]["revision"] = modules.get("Cisco-IOS-XE-interfaces-oper")
    for membership in lag_memberships:
        membership["source"]["revision"] = modules.get("Cisco-IOS-XE-ethernet")
    cisco_components.add_revisions(components, modules)
    cisco_layer2.add_revisions(layer2, modules)
    cisco_duplex.add_revisions(configured_duplex, modules)
    cisco_access_ports.add_revisions(console_ports, management, interfaces, modules)
    cisco_stack.add_revisions(stack, modules)
    if active:
        sources["identity"]["serial"].update(active["sources"]["identity"])
        sources["identity"]["model"].update(active["sources"]["identity"])
    sources["stack"] = stack["source"]
    sources["configured_duplex"] = configured_duplex
    sources["lag_memberships"] = {
        "module": "Cisco-IOS-XE-ethernet",
        "revision": modules.get("Cisco-IOS-XE-ethernet"),
        "path": NATIVE_INTERFACES_PATH,
        "field": "<physical-family>[name]/Cisco-IOS-XE-ethernet:channel-group/number",
        "meaning": "Configured membership; includes disconnected, static, LACP and PAgP members",
    }
    return {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": hostname,
            "serial": serial,
            "model": model,
            "software_version": version,
        },
        "stack": stack,
        "interfaces": interfaces,
        "lag_memberships": lag_memberships,
        "components": components,
        "console_ports": console_ports,
        "management": management,
        "ipam": ipam,
        "layer2": layer2,
        "excluded_interfaces": excluded,
        "warnings": warnings,
        "evidence": {
            "modules": dict(sorted(modules.items())),
            "requests": list(getattr(client, "trace", [])),
            "inventory": safe_inventory,
            "install": install_evidence,
            "sources": sources,
        },
    }
