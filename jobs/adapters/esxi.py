"""Standalone ESXi v1: reviewed host writes and read-only NFV observations.

SOAP collection patterns adapted from nautobot-testsuite jobs/checks_vmware.py
at 7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9 (Apache-2.0). Inventory mappings
follow Broadcom's vim25 contracts; no vCenter or guest agent is required.
"""

import copy
import re
from uuid import UUID

ADAPTER = "esxi"
CONTRACT = "esxi-host-v1"
IDENTITY_CONTRACT = "esxi-host-identity-v1"
INTERFACE_CONTRACT = "esxi-pnic-v1"
INTERFACE_POLICY_CONTRACT = "esxi-interface-policy-v1"

_PNIC_NAME = re.compile(r"vmnic(?:0|[1-9][0-9]*)")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+){2,3}")
_MAC = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")
_PCI = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]")
_SENTINELS = frozenset(
    {"unknown", "none", "n/a", "null", "0", "not specified", "to be filled by o.e.m."}
)


def _fields(*keys):
    return dict.fromkeys(keys)


# These allowlists also govern evidence retained for later reconstruction.
# Host options, extraConfig, arbitrary backings, and credentials are excluded.
_PRODUCT = _fields(
    "apiType", "apiVersion", "productLineId", "vendor", "version", "build", "fullName"
)
_SYSTEM = {
    **_fields("vendor", "model", "uuid", "serialNumber"),
    "otherIdentifyingInfo": [{"identifierType": {"key": None}, "identifierValue": None}],
}
_HARDWARE = _fields(
    "vendor",
    "model",
    "uuid",
    "cpuModel",
    "numCpuPkgs",
    "numCpuCores",
    "numCpuThreads",
    "memorySize",
    "cpuMhz",
    "numNics",
    "numHBAs",
)
_LINK = _fields("speedMb", "duplex")
_PNIC = {
    **_fields(
        "device",
        "key",
        "mac",
        "pci",
        "driver",
        "driverVersion",
        "firmwareVersion",
        "autoNegotiateSupported",
    ),
    "linkSpeed": _LINK,
    "validLinkSpecification": [_LINK],
    "spec": {"linkSpeed": _LINK},
}
_IP = {
    **_fields("ipAddress", "subnetMask", "dhcp"),
    "ipV6Config": {
        "ipV6Address": [_fields("ipAddress", "prefixLength", "origin", "dadState")],
        "autoConfigurationEnabled": None,
        "dhcpV6Enabled": None,
    },
}
_PORT = _fields("switchUuid", "portgroupKey", "portKey")
_VNIC = {
    **_fields("device", "key", "portgroup"),
    "spec": {
        **_fields("mac", "mtu", "portgroup", "netStackInstanceKey", "pinnedPnic"),
        "ip": _IP,
        "distributedVirtualPort": _PORT,
    },
}
_POLICY = {
    "security": _fields("allowPromiscuous", "macChanges", "forgedTransmits"),
    "nicTeaming": {
        **_fields("policy", "notifySwitches", "rollingOrder"),
        "nicOrder": {"activeNic": [None], "standbyNic": [None]},
    },
}
_REF = _fields("type", "ref")
_BACKING = {
    **_fields(
        "type", "_type", "deviceName", "fileName", "thinProvisioned", "eagerlyScrub", "diskMode"
    ),
    "datastore": _REF,
    "network": _REF,
    "port": _PORT,
}
_DEVICE = {
    **_fields(
        "type",
        "_type",
        "key",
        "controllerKey",
        "unitNumber",
        "macAddress",
        "addressType",
        "capacityInBytes",
        "capacityInKB",
    ),
    "deviceInfo": {"label": None},
    "backing": _BACKING,
    "connectable": _fields("connected", "startConnected", "allowGuestControl"),
}
_HOST_PROPERTIES = {
    "name": None,
    "hardware.systemInfo": _SYSTEM,
    "config.product": _PRODUCT,
    "summary.hardware": _HARDWARE,
    "summary.config.name": None,
    "summary": {
        "hardware": _HARDWARE,
        "config": {"name": None, "product": _PRODUCT},
        "runtime": _fields("connectionState", "powerState", "inMaintenanceMode"),
    },
    "hardware.cpuInfo": _fields("numCpuPackages", "numCpuCores", "numCpuThreads", "hz"),
    "hardware.pciDevice": [
        _fields(
            "id",
            "vendorId",
            "deviceId",
            "subVendorId",
            "subDeviceId",
            "classId",
            "bus",
            "slot",
            "function",
            "vendorName",
            "deviceName",
        )
    ],
    "config.network.pnic": [_PNIC],
    "config.network.vnic": [_VNIC],
    "config.network.vswitch": [
        {
            **_fields("key", "name", "mtu", "numPorts", "numPortsAvailable"),
            "pnic": [None],
            "portgroup": [None],
            "spec": {"policy": _POLICY},
        }
    ],
    "config.network.portgroup": [
        {
            **_fields("key", "vswitch"),
            "spec": {**_fields("name", "vswitchName", "vlanId"), "policy": _POLICY},
            "computedPolicy": _POLICY,
        }
    ],
    "config.virtualNicManagerInfo": {"netConfig": [{"nicType": None, "selectedVnic": [None]}]},
    "config.storageDevice.scsiLun": [
        {
            **_fields("key", "displayName", "canonicalName", "vendor", "model", "lunType"),
            "capacity": _fields("blockSize", "block"),
        }
    ],
    "config.fileSystemVolume.mountInfo": [
        {
            "mountInfo": _fields("mounted", "accessible", "accessMode"),
            "volume": _fields("name", "type", "uuid", "capacity"),
        }
    ],
    "runtime.inMaintenanceMode": None,
    "runtime.powerState": None,
    "vm": [_REF],
    "datastore": [_REF],
}
_GUEST_PROPERTIES = {
    **_fields(
        "name",
        "config.uuid",
        "config.instanceUuid",
        "config.template",
        "config.guestId",
        "config.version",
        "config.files.vmPathName",
        "config.hardware.numCPU",
        "config.hardware.numCoresPerSocket",
        "config.hardware.memoryMB",
        "runtime.powerState",
        "runtime.connectionState",
        "guest.toolsRunningStatus",
    ),
    "runtime.host": _REF,
    "config.hardware.device": [_DEVICE],
    "config.cpuAllocation": _fields("reservation", "limit"),
    "config.memoryAllocation": _fields("reservation", "limit"),
    "config.memoryReservationLockedToMax": None,
    "config.latencySensitivity": {"level": None},
    "guest.net": [
        {
            **_fields("deviceConfigId", "macAddress", "connected", "network"),
            "ipAddress": [None],
        }
    ],
}
_DATASTORE_PROPERTIES = {
    "name": None,
    "summary": {
        **_fields(
            "name",
            "type",
            "url",
            "accessible",
            "capacity",
            "freeSpace",
            "uncommitted",
            "multipleHostAccess",
            "maintenanceMode",
        ),
        "datastore": _REF,
    },
    "info": {
        **_fields("name", "freeSpace", "maxFileSize", "maxVirtualDiskCapacity"),
        "vmfs": {
            **_fields("name", "uuid", "local", "type", "capacity", "version", "blockSize"),
            "extent": [_fields("diskName", "partition")],
        },
        "nas": _fields("name", "remoteHost", "remotePath", "type"),
    },
}


class DiscoveryError(ValueError):
    """The ESXi source contract is incomplete, inconsistent, or altered."""


def _text(value):
    if not isinstance(value, str) or len(value) > 4096:
        return None
    value = value.strip()
    if not value or any(ord(char) < 32 for char in value):
        return None
    return value


def _identity(value):
    value = _text(value)
    return None if value is None or value.casefold() in _SENTINELS else value


def canonical_interface_name(value):
    """Keep exact ESXi names; do not translate aliases or synthesize port identities."""
    return value.strip() if isinstance(value, str) else ""


def canonical_host_uuid(value):
    value = _text(value)
    if value is None or not _UUID.fullmatch(value):
        return None
    identifier = UUID(value)
    return str(identifier) if identifier.int not in (0, (1 << 128) - 1) else None


def canonical_software_version(version, build=None):
    if build is None:
        value = _text(version)
        if value is None:
            return None
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+){2,3}) build-([1-9][0-9]{0,19})", value)
        if match is None:
            return None
        version, build = match.groups()
    version, build = _text(version), _text(build)
    if version is None or build is None or not _RELEASE.fullmatch(version):
        return None
    if re.fullmatch(r"[1-9][0-9]{0,19}", build) is None:
        return None
    return "%s build-%s" % (version, build)


def _integer(value, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is int:
        number = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        number = int(value)
    else:
        return None
    return number if minimum <= number <= maximum else None


def _select(value, schema):
    """Keep reviewed structure and refuse containers disguised as scalar values."""
    if schema is None:
        if value is None or type(value) in (str, int, bool):
            if isinstance(value, str) and _text(value) is None and value:
                raise DiscoveryError("ESXi source scalar is oversized or contains controls")
            return value
        raise DiscoveryError("ESXi source contains a malformed scalar")
    if isinstance(schema, list):
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > 65535:
            raise DiscoveryError("ESXi source array is malformed or exceeds its read budget")
        if isinstance(schema[0], dict) and any(not isinstance(row, dict) for row in value):
            raise DiscoveryError("ESXi source array has a malformed object row")
        return [_select(row, schema[0]) for row in value]
    if value is None:
        return None
    if not isinstance(value, dict):
        raise DiscoveryError("ESXi source object has an invalid shape")
    return {key: _select(value[key], child) for key, child in schema.items() if key in value}


def _records(rows, schema):
    if not isinstance(rows, list):
        raise DiscoveryError("ESXi inventory records must be an explicit list")
    out, refs = [], set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("properties"), dict):
            raise DiscoveryError("ESXi inventory object has no reviewed properties")
        ref = _text(row.get("ref"))
        if ref is None or ref in refs:
            raise DiscoveryError("ESXi inventory contains duplicate or missing object references")
        refs.add(ref)
        out.append({"ref": ref, "properties": _select(row["properties"], schema)})
    return sorted(out, key=lambda row: row["ref"])


def _sanitize(inventory):
    if not isinstance(inventory, dict) or not isinstance(inventory.get("service"), dict):
        raise DiscoveryError("ESXi discovery requires complete service content")
    host = inventory.get("host")
    if not isinstance(host, dict) or host.get("ref") != "ha-host":
        raise DiscoveryError("ESXi discovery requires the standalone ha-host scope")
    properties, completeness = host.get("properties"), inventory.get("completeness")
    if not isinstance(properties, dict) or not isinstance(completeness, dict):
        raise DiscoveryError("ESXi discovery has no host properties or explicit source outcomes")
    if completeness.get("host") is not True:
        raise DiscoveryError("ESXi host collection was not explicitly complete")
    safe_completeness = {
        key: value
        for key, value in completeness.items()
        if key in {"host", "guests", "datastores", "pagination", "permission_scoped"}
        and (value is None or type(value) in (str, int, bool))
    }
    return {
        "service": _select(inventory["service"], _PRODUCT),
        "host": {"ref": "ha-host", "properties": _select(properties, _HOST_PROPERTIES)},
        "guests": _records(inventory.get("guests"), _GUEST_PROPERTIES),
        "datastores": _records(inventory.get("datastores"), _DATASTORE_PROPERTIES),
        "completeness": safe_completeness,
    }


def _validate_inventory_scope(inventory):
    """Recheck host-scoped registered object references before later policy joins."""
    properties = inventory["host"]["properties"]
    for property_name, records_name, object_type in (
        ("vm", "guests", "VirtualMachine"),
        ("datastore", "datastores", "Datastore"),
    ):
        references = properties.get(property_name, [])
        refs = set()
        for reference in references:
            ref = _text(reference.get("ref"))
            if reference.get("type") != object_type or ref is None or ref in refs:
                raise DiscoveryError("ESXi host has duplicate or malformed object references")
            refs.add(ref)
        if refs != {row["ref"] for row in inventory[records_name]}:
            raise DiscoveryError("ESXi registered objects disagree with host-scoped references")
    for row in inventory["guests"]:
        if row["properties"].get("runtime.host") != {"type": "HostSystem", "ref": "ha-host"}:
            raise DiscoveryError("ESXi guest runtime host disagrees with the selected host")


def _corroborate(first, second, label, *, canonical=_identity):
    first, second = canonical(first), canonical(second)
    if first is not None and second is not None and first != second:
        raise DiscoveryError("ESXi source has conflicting %s evidence" % label)
    return first if first is not None else second


def _host_identity(inventory):
    service, properties = inventory["service"], inventory["host"]["properties"]
    system, product = properties.get("hardware.systemInfo"), properties.get("config.product")
    if not isinstance(system, dict) or not isinstance(product, dict):
        raise DiscoveryError("ESXi host identity or product properties are absent")
    for source in (service, product):
        if source.get("apiType") != "HostAgent" or source.get("productLineId") != "embeddedEsx":
            raise DiscoveryError("ESXi discovery requires a standalone ESXi HostAgent")
    for field in ("apiType", "apiVersion", "productLineId", "vendor", "version", "build"):
        first, second = _text(service.get(field)), _text(product.get(field))
        if first is None or second is None or first != second:
            raise DiscoveryError("ESXi service and host product identity disagree")
    summary = properties.get("summary.hardware")
    if summary is None:
        summary = (properties.get("summary") or {}).get("hardware")
    if not isinstance(summary, dict):
        raise DiscoveryError("ESXi host hardware summary is absent")
    host_uuid = _corroborate(
        system.get("uuid"), summary.get("uuid"), "host UUID", canonical=canonical_host_uuid
    )
    if (
        canonical_host_uuid(system.get("uuid")) is None
        or canonical_host_uuid(summary.get("uuid")) is None
    ):
        raise DiscoveryError("ESXi hardware BIOS UUID is absent or invalid")
    model = _corroborate(system.get("model"), summary.get("model"), "host model")
    vendor = _corroborate(system.get("vendor"), summary.get("vendor"), "host manufacturer")
    hostname = properties.get("summary.config.name")
    if hostname is None:
        hostname = ((properties.get("summary") or {}).get("config") or {}).get("name")
    hostname = _corroborate(properties.get("name"), hostname, "host name")
    serial = _identity(system.get("serialNumber"))
    serials = {
        _identity(row.get("identifierValue"))
        for row in system.get("otherIdentifyingInfo", [])
        if (row.get("identifierType") or {}).get("key") in {"ServiceTag", "SerialNumberTag"}
    } - {None}
    if len(serials) > 1 or (serial is not None and serials and serials != {serial}):
        raise DiscoveryError("ESXi system serial sources disagree")
    serial = serial or next(iter(serials), None)
    software_version = canonical_software_version(product.get("version"), product.get("build"))
    if software_version is None:
        raise DiscoveryError("ESXi release/build is not a valid exact product identity")
    return {
        "hostname": hostname,
        "model": model,
        "serial": serial,
        "software_version": software_version,
        "vendor": vendor,
        "host_uuid": host_uuid,
    }


def _pci_id(value):
    if type(value) is int and -(1 << 15) <= value <= 65535:
        return value & 0xFFFF
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,5}", value):
        number = int(value)
        return number & 0xFFFF if -(1 << 15) <= number <= 65535 else None
    return None


def _virtual_vmware_nic(row, properties):
    """Recognize VMXNET3 by its exact PCI device and driver, independent of SMBIOS."""
    if row.get("driver") not in {"nvmxnet3", "vmxnet3"}:
        return False
    matches = [
        device
        for device in properties.get("hardware.pciDevice", [])
        if device.get("id") == row.get("pci")
    ]
    return (
        len(matches) == 1
        and _pci_id(matches[0].get("vendorId")) == 0x15AD
        and _pci_id(matches[0].get("deviceId")) == 0x07B0
    )


def _interfaces(inventory, identity):
    properties = inventory["host"]["properties"]
    rows = properties.get("config.network.pnic", [])
    names, keys, pcis = set(), set(), set()
    interfaces, excluded, warnings = [], [], []
    for index, row in enumerate(rows):
        name, key, pci = _text(row.get("device")), _text(row.get("key")), _text(row.get("pci"))
        if name is None or name in names or (key is not None and key in keys):
            raise DiscoveryError("ESXi physical NIC inventory has duplicate or missing identities")
        if pci is not None and pci in pcis:
            raise DiscoveryError("ESXi physical NIC inventory repeats a PCI function")
        names.add(name)
        if key is not None:
            keys.add(key)
        if pci is not None:
            pcis.add(pci)
        if not _PNIC_NAME.fullmatch(name) or key is None or pci is None or not _PCI.fullmatch(pci):
            excluded.append({"name": name, "reason": "unreviewed physical NIC identity"})
            continue
        virtual = _virtual_vmware_nic(row, properties)
        if row.get("driver") in {"nvmxnet3", "vmxnet3"} and not virtual:
            excluded.append({"name": name, "reason": "unresolved VMXNET3 PCI identity"})
            warnings.append(
                "%s: virtual driver lacks exact joined PCI proof; writes deferred" % name
            )
            continue
        link = row.get("linkSpeed")
        speed = _integer(link.get("speedMb"), 1, 2147483) if isinstance(link, dict) else None
        mac = _text(row.get("mac"))
        if (
            mac is None
            or not _MAC.fullmatch(mac)
            or mac.lower()
            in {
                "00:00:00:00:00:00",
                "ff:ff:ff:ff:ff:ff",
            }
        ):
            mac = None
        else:
            mac = mac.lower()
        source = {
            "contract": INTERFACE_CONTRACT,
            "host_ref": "ha-host",
            "property": "config.network.pnic",
            "index": index,
            "device": name,
            "key": key,
            "pci": pci,
            "classification": "nested-vmxnet3" if virtual else "host-physical-nic",
            "admin_state": "unavailable",
        }
        interfaces.append(
            {
                "name": name,
                "type": "virtual" if virtual else None,
                "type_source": "esxi-reviewed-nested-vmxnet3" if virtual else "esxi-reported-pnic",
                "enabled": None,
                "description": None,
                "mtu": None,
                "mac_address": mac,
                "speed": None if virtual or speed is None else speed * 1000,
                "duplex": None,
                "port_type": None,
                "mgmt_only": None,
                "physical_ethernet": not virtual,
                "physical_ethernet_source": None if virtual else INTERFACE_CONTRACT,
                "source": source,
            }
        )
        warnings.append(
            "%s: administrative state unavailable; creation needs operator policy" % name
        )
    return sorted(interfaces, key=lambda row: row["name"]), excluded, warnings


def observed_physical_ethernet(fact, name):
    """Check the reviewed pNIC provenance after reconstruct() verified the full envelope."""
    if not isinstance(fact, dict) or fact.get("name") != name or not _PNIC_NAME.fullmatch(name):
        return False
    source = fact.get("source")
    if not isinstance(source, dict):
        return False
    return (
        fact.get("physical_ethernet") is True
        and fact.get("physical_ethernet_source") == INTERFACE_CONTRACT
        and source.get("contract") == INTERFACE_CONTRACT
        and source.get("property") == "config.network.pnic"
        and source.get("host_ref") == "ha-host"
        and source.get("device") == name
        and source.get("classification") == "host-physical-nic"
        and _text(source.get("key")) is not None
        and isinstance(source.get("pci"), str)
        and _PCI.fullmatch(source["pci"]) is not None
    )


def _policy(value):
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"contract", "new_enabled"}
        or value.get("contract") != INTERFACE_POLICY_CONTRACT
        or type(value.get("new_enabled")) is not bool
    ):
        raise DiscoveryError("ESXi interface creation policy has an invalid contract")
    return dict(value)


def _guest_observations(inventory, host_uuid):
    counts = {}
    for row in inventory["guests"]:
        identifier = canonical_host_uuid(row["properties"].get("config.uuid"))
        if identifier is not None:
            counts[identifier] = counts.get(identifier, 0) + 1
    rows, unresolved = [], []
    for row in inventory["guests"]:
        identifier = canonical_host_uuid(row["properties"].get("config.uuid"))
        unique = identifier is not None and counts[identifier] == 1
        rows.append(
            {
                **copy.deepcopy(row),
                "identity": {
                    "host_uuid": host_uuid,
                    "guest_uuid": identifier,
                    "unique": unique,
                },
            }
        )
        if not unique:
            unresolved.append({"ref": row["ref"], "reason": "missing or duplicate guest BIOS UUID"})
    return rows, unresolved


def _build(inventory, expected_host_uuid=None, interface_enabled_policy=None):
    _validate_inventory_scope(inventory)
    identity = _host_identity(inventory)
    expected = canonical_host_uuid(expected_host_uuid) if expected_host_uuid is not None else None
    if expected_host_uuid is not None and expected is None:
        raise DiscoveryError("Expected ESXi host UUID must be an explicit non-sentinel UUID")
    if expected is not None and expected != identity["host_uuid"]:
        raise DiscoveryError("Expected ESXi host UUID does not match the selected endpoint")
    interfaces, excluded, warnings = _interfaces(inventory, identity)
    binding = (
        None
        if expected is None
        else {
            "contract": IDENTITY_CONTRACT,
            "expected_uuid": expected,
            "observed_uuid": identity["host_uuid"],
            "host_ref": "ha-host",
            "property": "hardware.systemInfo.uuid",
        }
    )
    guests, unresolved = _guest_observations(inventory, identity["host_uuid"])
    warnings.append("Guest and datastore observations are limited to current-session visibility")
    if not interfaces:
        warnings.append("No eligible pNIC facts; this does not establish complete hardware absence")
    return {
        "adapter": ADAPTER,
        "schema_version": 1,
        "identity": identity,
        "expected_host_uuid": expected,
        "identity_binding": binding,
        "interface_policy": _policy(interface_enabled_policy),
        "interfaces": interfaces,
        "excluded_interfaces": excluded,
        "warnings": warnings,
        "source": {"contract": CONTRACT, "inventory": copy.deepcopy(inventory)},
        "observations": {
            "host": copy.deepcopy(inventory["host"]),
            "service": dict(inventory["service"]),
            "network": {
                key: copy.deepcopy(value)
                for key, value in inventory["host"]["properties"].items()
                if key.startswith("config.network.")
            },
            "guests": guests,
            "guest_identity_unresolved": unresolved,
            "datastores": copy.deepcopy(inventory["datastores"]),
            "completeness": {**inventory["completeness"], "permission_scoped": True},
        },
        "sources": {
            "identity": {
                "contract": IDENTITY_CONTRACT,
                "host_ref": "ha-host",
                "properties": ["hardware.systemInfo", "summary.hardware", "config.product"],
            },
            "interfaces": {
                "contract": INTERFACE_CONTRACT,
                "host_ref": "ha-host",
                "property": "config.network.pnic",
            },
        },
    }


def collect(
    client, *, use_ntc_defaults=False, expected_host_uuid=None, interface_enabled_policy=None
):
    """Read a standalone host; eligible writes require later source reconstruction."""
    if type(use_ntc_defaults) is not bool:
        raise ValueError("Use NTC defaults when guessing must be true or false")
    policy = _policy(interface_enabled_policy)
    if expected_host_uuid is not None and canonical_host_uuid(expected_host_uuid) is None:
        raise ValueError("Expected ESXi host UUID must be an explicit non-sentinel UUID")
    inventory = _sanitize(client.discovery())
    return _build(inventory, expected_host_uuid, policy)


def reconstruct(discovery):
    """Re-derive eligible facts from reviewed properties and reject normalized alterations."""
    if (
        not isinstance(discovery, dict)
        or discovery.get("adapter") != ADAPTER
        or type(discovery.get("schema_version")) is not int
        or discovery.get("schema_version") != 1
    ):
        raise DiscoveryError("ESXi discovery envelope has an unsupported contract")
    source = discovery.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"contract", "inventory"}
        or source.get("contract") != CONTRACT
    ):
        raise DiscoveryError("ESXi discovery lacks its reviewed source contract")
    inventory = _sanitize(source.get("inventory"))
    if inventory != source["inventory"]:
        raise DiscoveryError("ESXi source evidence contains unreviewed fields")
    rebuilt = _build(
        inventory, discovery.get("expected_host_uuid"), discovery.get("interface_policy")
    )
    for key in (
        "identity",
        "interfaces",
        "excluded_interfaces",
        "identity_binding",
        "expected_host_uuid",
        "interface_policy",
    ):
        if discovery.get(key) != rebuilt[key]:
            raise DiscoveryError("ESXi normalized %s no longer matches source evidence" % key)
    return rebuilt


def validate(discovery):
    """Validate source evidence and return the authoritative reconstructed envelope."""
    return reconstruct(discovery)
