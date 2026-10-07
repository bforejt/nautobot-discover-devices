"""Proxmox host v1: exact local Linux host facts and report-only NFV inventory.

Collection patterns adapted from nautobot-testsuite's Proxmox collectors at
7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9 (Apache-2.0). Only GET and fixed
structured Linux reads are used; guests, capacity, storage and host networking
remain observations. Native facts are reconstructed from this allowlisted source.
"""

import copy
import math
import re
from uuid import UUID

ADAPTER = "proxmox"
CONTRACT = "proxmox-host-v1"
IDENTITY_CONTRACT = "proxmox-host-identity-v1"
INTERFACE_CONTRACT = "proxmox-pnic-v1"
_NODE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})")
_IFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}")
_PCI = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]")
_REPRESENTOR_PORT = re.compile(r"(?:c[0-9]+)?(?:p[0-9]+)?pf[0-9]+(?:(?:vf|sf)[0-9]+)?")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_MAC = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")
_RELEASE = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9]+)?")
_SENTINELS = {
    "unknown",
    "none",
    "n/a",
    "null",
    "0",
    "not specified",
    "to be filled by o.e.m.",
    "default string",
    "system serial number",
}
_VIRTUAL_DRIVERS = {"virtio_net", "vmxnet3", "netvsc", "xen-netfront", "vboxnet", "vboxguest"}
_VIRTUAL_SYSTEMS = {
    "kvm",
    "virtual machine",
    "vmware virtual platform",
    "virtualbox",
    "standard pc (i440fx + piix, 1996)",
    "standard pc (q35 + ich9, 2009)",
}
_VIRTUAL_PCI = {(0x15AD, 0x07B0), (0x1AF4, 0x1000), (0x1AF4, 0x1041), (0x80EE, 0xCAFE)}


def _fields(*names):
    return dict.fromkeys(names)


_VERSION = _fields("version", "release", "repoid")
_CLUSTER = _fields(
    "id", "type", "name", "local", "nodeid", "ip", "online", "quorate", "nodes", "version"
)
_USAGE = _fields("total", "used", "free", "avail", "available")
_STATUS = {
    **_fields("uptime", "cpu", "wait", "idle", "pveversion", "kversion"),
    "loadavg": [None],
    "memory": _USAGE,
    "swap": _USAGE,
    "rootfs": _USAGE,
    "cpuinfo": _fields("cpus", "cores", "sockets", "model", "mhz", "hvm", "flags"),
    "current-kernel": _fields("sysname", "release", "version", "machine"),
    "boot-info": _fields("mode", "secureboot"),
}
_NETWORK = _fields(
    "iface",
    "type",
    "active",
    "autostart",
    "method",
    "method6",
    "address",
    "address6",
    "netmask",
    "netmask6",
    "gateway",
    "gateway6",
    "mtu",
    "bridge_ports",
    "bridge_stp",
    "bridge_fd",
    "bridge_vlan_aware",
    "bridge_vids",
    "bond_slaves",
    "bond_mode",
    "bond_miimon",
    "bond_xmit_hash_policy",
    "bond_primary",
    "vlan-id",
    "vlan-raw-device",
    "ovs_type",
    "ovs_bridge",
    "ovs_ports",
    "ovs_bonds",
    "exists",
)
_STORAGE = _fields(
    "storage",
    "type",
    "content",
    "active",
    "enabled",
    "shared",
    "total",
    "used",
    "avail",
    "used_fraction",
)
_GUEST_STATUS = {
    **_fields(
        "vmid",
        "node",
        "name",
        "status",
        "qmpstatus",
        "template",
        "lock",
        "tags",
        "hastate",
        "cpus",
        "maxcpu",
        "maxmem",
        "maxdisk",
        "cpu",
        "mem",
        "disk",
        "diskread",
        "diskwrite",
        "netin",
        "netout",
        "uptime",
        "pid",
        "running-machine",
        "running-qemu",
        "agent",
        "balloon",
        "freemem",
    ),
    "ballooninfo": _fields(
        "actual",
        "max_mem",
        "last_update",
        "major_page_faults",
        "minor_page_faults",
        "mem_swapped_in",
        "mem_swapped_out",
        "free_mem",
        "total_mem",
        "available_mem",
        "disk_caches",
    ),
}
_CONFIG_SCALARS = {
    "name",
    "hostname",
    "ostype",
    "template",
    "cores",
    "sockets",
    "vcpus",
    "memory",
    "balloon",
    "cpulimit",
    "cpuunits",
    "onboot",
    "startup",
    "numa",
    "hugepages",
    "kvm",
    "machine",
    "bios",
    "scsihw",
    "boot",
    "bootdisk",
    "unprivileged",
    "swap",
    "arch",
    "protection",
    "tags",
    "lock",
}
_DEVICE_KEY = re.compile(
    r"(?:net|ide|sata|scsi|virtio|hostpci|usb|mp|unused|efidisk|tpmstate)[0-9]+|rootfs"
)
_PROPERTY_OPTIONS = {
    "net": {
        "bridge",
        "tag",
        "trunks",
        "firewall",
        "link_down",
        "rate",
        "queues",
        "mtu",
        "name",
        "hwaddr",
        "ip",
        "ip6",
        "gw",
        "gw6",
        "type",
        "model",
        "e1000",
        "e1000e",
        "i82551",
        "i82557b",
        "i82559er",
        "ne2k_isa",
        "ne2k_pci",
        "pcnet",
        "rtl8139",
        "virtio",
        "vmxnet3",
        "disconnect",
    },
    "disk": {
        "file",
        "volume",
        "size",
        "cache",
        "aio",
        "discard",
        "iothread",
        "ssd",
        "backup",
        "replicate",
        "ro",
        "shared",
        "media",
        "format",
        "mbps",
        "mbps_rd",
        "mbps_wr",
        "iops",
        "iops_rd",
        "iops_wr",
        "mountoptions",
        "mp",
        "quota",
        "acl",
        "skiplock",
        "scsiblock",
        "serial",
        "wwn",
    },
    "pci": {
        "host",
        "mapping",
        "pcie",
        "rombar",
        "x-vga",
        "mdev",
        "legacy-igd",
        "vendor-id",
        "device-id",
        "sub-vendor-id",
        "sub-device-id",
    },
    "cpu": {"cputype", "flags", "hidden", "hv-vendor-id", "phys-bits", "reported-model"},
    "smbios1": {"uuid"},
}
_DMI = _fields(
    "sys_vendor",
    "product_name",
    "product_version",
    "product_sku",
    "product_serial",
    "chassis_vendor",
    "chassis_type",
    "chassis_serial",
    "product_uuid",
    "board_vendor",
    "board_name",
    "board_serial",
)
_SYSNET = {
    **_fields(
        "name",
        "path",
        "device",
        "driver",
        "physical_function",
        "wireless",
        "address",
        "speed",
        "duplex",
        "operstate",
        "carrier",
        "mtu",
        "flags",
        "type",
        "phys_port_name",
        "phys_switch_id",
    ),
    "virtual_functions": [None],
}
_SYSPCI = {
    **_fields(
        "id",
        "driver",
        "physical_function",
        "vendor",
        "device",
        "class",
        "subsystem_vendor",
        "subsystem_device",
        "numa_node",
        "sriov_numvfs",
        "sriov_totalvfs",
    ),
    "virtual_functions": [None],
}
_HARDWARE_FIELDS = _fields(
    "id",
    "class",
    "description",
    "product",
    "vendor",
    "version",
    "serial",
    "businfo",
    "physid",
    "size",
    "capacity",
    "width",
    "clock",
    "units",
    "disabled",
    "claimed",
)
_HARDWARE_CONFIG = _fields(
    "driver",
    "driverversion",
    "firmware",
    "link",
    "speed",
    "duplex",
    "autonegotiation",
    "broadcast",
    "multicast",
    "latency",
    "cores",
    "enabledcores",
    "threads",
    "uuid",
    "sku",
    "chassis",
)
_HARDWARE_CAPS = _fields(
    "ethernet",
    "physical",
    "wireless",
    "802.11",
    "tp",
    "fibre",
    "mii",
    "100bt",
    "100bt-fd",
    "1000bt-fd",
    "10bt",
    "10bt-fd",
    "10000bt-fd",
    "autonegotiation",
)
_ADDR_INFO = _fields(
    "family",
    "local",
    "prefixlen",
    "scope",
    "label",
    "broadcast",
    "dynamic",
    "temporary",
    "tentative",
    "deprecated",
    "dadfailed",
    "valid_life_time",
    "preferred_life_time",
    "metric",
    "protocol",
)
_LINK_DATA = {
    **_fields(
        "id",
        "protocol",
        "mode",
        "miimon",
        "updelay",
        "downdelay",
        "xmit_hash_policy",
        "primary",
        "active_slave",
        "all_slaves_active",
        "min_links",
        "lacp_rate",
        "ad_select",
        "vlan_filtering",
        "vlan_protocol",
        "vlan_default_pvid",
        "stp_state",
        "forward_delay",
        "group_fwd_mask",
        "mcast_snooping",
        "learning",
        "hairpin",
        "isolated",
        "state",
        "priority",
        "cost",
    ),
    "flags": [None],
    "ingress_qos": [_fields("from", "to")],
    "egress_qos": [_fields("from", "to")],
}
_LINK = {
    **_fields(
        "ifindex",
        "ifname",
        "mtu",
        "qdisc",
        "operstate",
        "linkmode",
        "group",
        "txqlen",
        "link_type",
        "address",
        "broadcast",
        "master",
        "link",
        "link_index",
        "link_netnsid",
        "min_mtu",
        "max_mtu",
        "permaddr",
    ),
    "flags": [None],
    "altnames": [None],
    "linkinfo": {
        **_fields("info_kind", "info_slave_kind"),
        "info_data": _LINK_DATA,
        "info_slave_data": _LINK_DATA,
    },
    "addr_info": [_ADDR_INFO],
}
_BRIDGE_VLAN = {"ifname": None, "vlans": [{"vlan": None, "vlanEnd": None, "flags": [None]}]}


class DiscoveryError(RuntimeError):
    """A bounded source failed the reviewed discovery contract."""


def _text(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        return None
    return value.strip() or None


def _identity(value):
    value = _text(value)
    return None if value is None or value.casefold() in _SENTINELS else value


def canonical_interface_name(value):
    """Linux names are exact, case-sensitive identities, including dotted names."""
    return value if isinstance(value, str) else ""


def canonical_host_uuid(value):
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        return None
    parsed = UUID(value)
    return None if parsed.int in {0, (1 << 128) - 1} else str(parsed)


def canonical_software_version(version, release=None):
    """Retain the exact pve-manager version, never substitute kernel or Debian."""
    if not isinstance(version, str) or not _RELEASE.fullmatch(version):
        return None
    if release is not None and (
        not isinstance(release, str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+", release)
        or version.split("-")[0].split(".")[:2] != release.split(".")
    ):
        return None
    return version


def _integer(value, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is int:
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        result = int(value)
    else:
        return None
    return result if minimum <= result <= maximum else None


def _select(value, schema):
    if schema is None:
        if value is None or type(value) in (str, int, bool, float):
            if isinstance(value, str) and value and _text(value) is None:
                raise DiscoveryError("Proxmox source scalar is oversized or contains controls")
            if type(value) is float and not math.isfinite(value):
                raise DiscoveryError("Proxmox source contains a non-finite number")
            return value
        raise DiscoveryError("Proxmox source contains a malformed scalar")
    if isinstance(schema, list):
        if not isinstance(value, list) or len(value) > 65535:
            raise DiscoveryError("Proxmox source array is malformed or exceeds its read budget")
        if isinstance(schema[0], dict) and any(not isinstance(row, dict) for row in value):
            raise DiscoveryError("Proxmox source array has a malformed object row")
        return [_select(row, schema[0]) for row in value]
    if value is None:
        return None
    if not isinstance(value, dict):
        raise DiscoveryError("Proxmox source object has an invalid shape")
    return {key: _select(value[key], child) for key, child in schema.items() if key in value}


def _property(value, options, positional=False):
    """Select documented property-string options, excluding unreviewed content."""
    if not isinstance(value, str) or not _text(value):
        return None
    selected, seen = [], set()
    for index, part in enumerate(value.split(",")):
        if "=" in part:
            key, item = part.split("=", 1)
            if (
                not re.fullmatch(r"[A-Za-z0-9_-]+", key)
                or not item
                or _text(item) is None
                or key in seen
            ):
                return None
            seen.add(key)
            if key in options and item and _text(item):
                selected.append(key + "=" + item)
        elif positional and index == 0 and re.fullmatch(r"[A-Za-z0-9_./:+-]{1,256}", part):
            selected.append(part)
        elif "=" not in part:
            return None
    return ",".join(selected) or None


def canonical_guest_uuid(smbios1):
    if not isinstance(smbios1, str) or not smbios1:
        return None
    entries = smbios1.split(",")
    keys = [item.split("=", 1)[0] for item in entries]
    if len(keys) != len(set(keys)):
        return None
    if any(
        "=" not in item
        or not re.fullmatch(r"[A-Za-z0-9_-]+", item.split("=", 1)[0])
        or _text(item.split("=", 1)[1]) is None
        for item in entries
    ):
        return None
    matches = [item.split("=", 1)[1] for item in entries if item.split("=", 1)[0] == "uuid"]
    return canonical_host_uuid(matches[0]) if len(matches) == 1 else None


def _config(value):
    if (
        not isinstance(value, dict)
        or len(value) > 4096
        or any(not isinstance(key, str) for key in value)
    ):
        raise DiscoveryError("Proxmox guest configuration is not a bounded named object")
    result = {}
    for key, item in value.items():
        if key == "args":
            # Custom QEMU arguments can override SMBIOS identity. Retain presence
            # as an idempotent marker while excluding arbitrary command content.
            result[key] = True
        elif key in _CONFIG_SCALARS:
            result[key] = _select(item, None)
        elif key == "smbios1":
            result[key] = _property(item, _PROPERTY_OPTIONS["smbios1"])
        elif key == "cpu":
            result[key] = _property(item, _PROPERTY_OPTIONS["cpu"], True)
        elif _DEVICE_KEY.fullmatch(key):
            category = (
                "net"
                if key.startswith("net")
                else "pci"
                if key.startswith(("hostpci", "usb"))
                else "disk"
            )
            result[key] = _property(item, _PROPERTY_OPTIONS[category], True)
    return result


def _pending(value):
    if not isinstance(value, list) or len(value) > 4096:
        raise DiscoveryError("Proxmox guest pending state is not a bounded explicit list")
    result, seen = [], set()
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get("key"), str) or row["key"] in seen:
            raise DiscoveryError("Proxmox guest pending state has missing or duplicate keys")
        key = row["key"]
        seen.add(key)
        if (
            key not in _CONFIG_SCALARS
            and key not in {"smbios1", "cpu", "args"}
            and not _DEVICE_KEY.fullmatch(key)
        ):
            continue
        result.append(
            {
                "key": key,
                **{
                    field: _config({key: row[field]})[key]
                    for field in ("value", "pending")
                    if field in row
                },
                **({"delete": _select(row["delete"], None)} if "delete" in row else {}),
            }
        )
    return sorted(result, key=lambda row: row["key"])


def _hardware(value, depth=0):
    if depth > 32:
        raise DiscoveryError("Proxmox hardware tree exceeds its depth budget")
    if isinstance(value, list):
        if len(value) > 65535:
            raise DiscoveryError("Proxmox hardware tree exceeds its read budget")
        identities = [row.get("id") for row in value if isinstance(row, dict)]
        if (
            len(identities) != len(value)
            or any(not isinstance(name, str) or not name for name in identities)
            or len(set(identities)) != len(identities)
        ):
            raise DiscoveryError(
                "Proxmox hardware tree has missing or duplicate sibling identities"
            )
        return [_hardware(row, depth + 1) for row in value]
    if not isinstance(value, dict):
        raise DiscoveryError("Proxmox hardware tree is malformed")
    result = _select(value, _HARDWARE_FIELDS)
    if "logicalname" in value:
        result["logicalname"] = _select(
            value["logicalname"], [None] if isinstance(value["logicalname"], list) else None
        )
    for key, schema in (("configuration", _HARDWARE_CONFIG), ("capabilities", _HARDWARE_CAPS)):
        if key in value:
            result[key] = _select(value[key], schema)
    if "children" in value:
        result["children"] = _hardware(value["children"], depth + 1)
    return result


def _permissions(value):
    if not isinstance(value, dict):
        raise DiscoveryError("Proxmox permission evidence is not an object")
    result = {}
    for path, rights in value.items():
        if (
            not isinstance(path, str)
            or not re.fullmatch(
                r"/(?:nodes/[A-Za-z0-9-]+|vms(?:/[0-9]+)?|storage(?:/[A-Za-z0-9_-]+)?)?", path
            )
            or not isinstance(rights, dict)
        ):
            raise DiscoveryError("Proxmox permission evidence has an invalid scope")
        result[path] = {
            right: _select(number, None)
            for right, number in rights.items()
            if right in {"Sys.Audit", "VM.Audit", "Datastore.Audit"}
        }
        if any(
            type(number) not in {int, bool} or number not in (0, 1)
            for number in result[path].values()
        ):
            raise DiscoveryError("Proxmox permission evidence contains invalid grant values")
    return result


def _guest_registry(value):
    """Keep pmxcfs's authoritative native JSON guest registrations, including peers.

    status.c cfs_create_vmlist_msg deliberately omits ids when the registry is
    empty. Required version evidence distinguishes that state from missing data.
    """
    if (
        not isinstance(value, dict)
        or type(value.get("version")) is not int
        or not 0 <= value["version"] <= (1 << 32) - 1
    ):
        raise DiscoveryError("Proxmox authoritative guest registry is missing or malformed")
    result = {"version": value["version"]}
    if "ids" not in value:
        return result
    ids = value["ids"]
    if not isinstance(ids, dict) or len(ids) > 65535:
        raise DiscoveryError("Proxmox authoritative guest registry exceeds its object budget")
    result["ids"] = {}
    for vmid, row in ids.items():
        if (
            not isinstance(vmid, str)
            or re.fullmatch(r"[1-9][0-9]{2,8}", vmid) is None
            or not isinstance(row, dict)
            or row.get("type") not in {"qemu", "lxc"}
            or not isinstance(row.get("node"), str)
            or _NODE.fullmatch(row["node"]) is None
            or type(row.get("version")) is not int
            or not 0 <= row["version"] <= (1 << 32) - 1
        ):
            raise DiscoveryError(
                "Proxmox authoritative guest registry has invalid registration identities"
            )
        result["ids"][vmid] = {key: row[key] for key in ("node", "type", "version")}
    return result


def _sanitize(inventory):
    if (
        not isinstance(inventory, dict)
        or not isinstance(inventory.get("api"), dict)
        or not isinstance(inventory.get("ssh"), dict)
    ):
        raise DiscoveryError("Proxmox discovery requires API and Linux sources")
    node = inventory.get("node")
    if not isinstance(node, str) or not _NODE.fullmatch(node):
        raise DiscoveryError("Proxmox selected node name is invalid")
    api, ssh = inventory["api"], inventory["ssh"]
    if any(
        not isinstance(api.get(key), dict) for key in ("version", "node_version", "node_status")
    ):
        raise DiscoveryError("Proxmox required API host objects are missing or malformed")
    complete = inventory.get("completeness")
    if (
        not isinstance(complete, dict)
        or complete.get("host") is not True
        or complete.get("interfaces") is not True
    ):
        raise DiscoveryError(
            "Proxmox host and physical NIC source collection must be explicitly complete"
        )
    safe_api = {
        key: _select(api.get(key), schema)
        for key, schema in (
            ("version", _VERSION),
            ("cluster_status", [_CLUSTER]),
            ("node_version", _VERSION),
            ("node_status", _STATUS),
            ("node_network", [_NETWORK]),
            ("storage", [_STORAGE]),
            ("qemu", [_GUEST_STATUS]),
            ("lxc", [_GUEST_STATUS]),
        )
    }
    # Native network changes is display diff text and may contain arbitrary text.
    # Preserve only its presence, never parse or retain that text as source facts.
    if type(api.get("node_network_changes")) is not bool:
        raise DiscoveryError("Proxmox pending-network outcome is not explicit")
    safe_api["node_network_changes"] = api["node_network_changes"]
    safe_api["permissions"] = _permissions(api.get("permissions"))
    host = ssh.get("host")
    if (
        not isinstance(host, dict)
        or host.get("errors") != []
        or not isinstance(host.get("unavailable"), list)
        or not isinstance(host.get("dmi"), dict)
    ):
        raise DiscoveryError("Proxmox fixed host reader reported incomplete reads")
    safe_host = _select(
        host,
        {
            "hostname": None,
            "dmi": _DMI,
            "net": [_SYSNET],
            "pci": [_SYSPCI],
            "errors": [None],
            "unavailable": [_fields("path", "errno")],
        },
    )
    safe_host["guest_registry"] = _guest_registry(host.get("guest_registry"))
    safe_ssh = {
        "host": safe_host,
        "hardware": _hardware(ssh.get("hardware")),
        "links": _select(ssh.get("links"), [_LINK]),
        "addresses": _select(ssh.get("addresses"), [_LINK]),
        "bridge_vlans": _select(ssh.get("bridge_vlans"), [_BRIDGE_VLAN]),
    }
    guests, keys = [], set()
    if not isinstance(inventory.get("guests"), list) or len(inventory["guests"]) > 4096:
        raise DiscoveryError("Proxmox guests require an explicit list")
    for row in inventory["guests"]:
        if (
            not isinstance(row, dict)
            or row.get("kind") not in {"qemu", "lxc"}
            or _integer(row.get("vmid"), 100, 999999999) is None
            or row.get("node") != node
        ):
            raise DiscoveryError("Proxmox guest is malformed or outside the local node")
        key = (row["kind"], int(row["vmid"]))
        if key in keys:
            raise DiscoveryError("Proxmox guest inventory has duplicate kind/VMID identities")
        keys.add(key)
        guests.append(
            {
                "kind": row["kind"],
                "vmid": key[1],
                "node": node,
                "summary": _select(row.get("summary"), _GUEST_STATUS),
                "config": _config(row.get("config")),
                "current_config": _config(row.get("current_config")),
                "pending": _pending(row.get("pending")),
                "status": _select(row.get("status"), _GUEST_STATUS),
            }
        )
    return {
        "node": node,
        "api": safe_api,
        "ssh": safe_ssh,
        "guests": sorted(guests, key=lambda row: (row["kind"], row["vmid"])),
        "completeness": {
            **_select(
                complete,
                _fields("host", "interfaces", "network", "guests", "storage", "permission_scoped"),
            ),
            # /network filters bridges by separate SDN grants even when GET
            # succeeds. Complete Linux reads do not prove API table coverage.
            "network_configuration": "permission-scoped",
        },
    }


def _walk(tree):
    rows = tree if isinstance(tree, list) else [tree]
    for row in rows:
        yield row
        yield from _walk(row.get("children", []))


def _unique(rows, field, label):
    result = {}
    for row in rows:
        value = row.get(field)
        if value is None or value in result:
            raise DiscoveryError("Proxmox %s has missing or duplicate identities" % label)
        result[value] = row
    return result


def _local_node(rows):
    local = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("type") == "node"
        and type(row.get("local")) in {int, bool}
        and row["local"] == 1
    ]
    if (
        len(local) != 1
        or not isinstance(local[0].get("name"), str)
        or not _NODE.fullmatch(local[0]["name"])
    ):
        raise DiscoveryError("Proxmox API must identify exactly one local node")
    return local[0]["name"]


def _corroborate(first, second, label, canonical=_identity):
    first, second = canonical(first), canonical(second)
    if first is not None and second is not None and first != second:
        raise DiscoveryError("Proxmox source has conflicting %s evidence" % label)
    return first if first is not None else second


def _host_model(dmi, system):
    """Corroborate lshw's exact SMBIOS SKU decoration with named source evidence.

    lshw src/core/dmi.cc appends " (" + configuration.sku + ")" to the
    SMBIOS product. Preserve both original source values; the DMI product_name
    remains the native model, and arbitrary suffixes are never stripped.
    """
    model, hardware_model = _identity(dmi.get("product_name")), _identity(system.get("product"))
    sku = _corroborate(
        dmi.get("product_sku"), (system.get("configuration") or {}).get("sku"), "system SKU"
    )
    if model is not None and hardware_model is not None and hardware_model != model:
        if sku is None or hardware_model != model + " (" + sku + ")":
            raise DiscoveryError("Proxmox source has conflicting host model evidence")
    return model if model is not None else hardware_model


def _host_identity(inventory):
    node, api, ssh = inventory["node"], inventory["api"], inventory["ssh"]
    if _local_node(api["cluster_status"]) != node or ssh["host"].get("hostname") != node:
        raise DiscoveryError("Proxmox API-local node and exact Linux hostname disagree")
    if "Sys.Audit" not in api["permissions"].get("/nodes/" + node, {}):
        raise DiscoveryError("Proxmox selected node lacks exact Sys.Audit permission proof")
    systems = [
        row
        for row in (ssh["hardware"] if isinstance(ssh["hardware"], list) else [ssh["hardware"]])
        if row.get("class") == "system"
    ]
    if len(systems) != 1:
        raise DiscoveryError("Proxmox lshw must identify exactly one system")
    system, dmi = systems[0], ssh["host"]["dmi"]
    host_uuid = canonical_host_uuid(dmi.get("product_uuid"))
    other_uuid = canonical_host_uuid((system.get("configuration") or {}).get("uuid"))
    if host_uuid is None:
        raise DiscoveryError("Proxmox system DMI UUID is absent or invalid")
    if other_uuid is not None and other_uuid != host_uuid:
        raise DiscoveryError("Proxmox lshw and DMI UUID evidence disagree")
    vendor = _corroborate(dmi.get("sys_vendor"), system.get("vendor"), "manufacturer")
    model = _host_model(dmi, system)
    serial = _corroborate(dmi.get("product_serial"), system.get("serial"), "system serial")
    serial = _corroborate(serial, dmi.get("chassis_serial"), "chassis serial")
    for field in ("version", "release", "repoid"):
        if api["version"].get(field) != api["node_version"].get(field):
            raise DiscoveryError("Proxmox API and local-node release evidence disagree")
    software = canonical_software_version(
        api["node_version"].get("version"), api["node_version"].get("release")
    )
    if software is None:
        raise DiscoveryError("Proxmox exact pve-manager release is absent or invalid")
    return {
        "hostname": node,
        "vendor": vendor,
        "model": model,
        "serial": serial,
        "host_uuid": host_uuid,
        "software_version": software,
    }


def _hex(value):
    return (
        int(value, 16)
        if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{4,6}", value)
        else None
    )


def _driver(value):
    return (
        value.rsplit("/", 1)[-1]
        if isinstance(value, str) and re.fullmatch(r"/sys/(?:devices|bus)/[A-Za-z0-9_./:-]+", value)
        else None
    )


def _pci_path(value):
    if not isinstance(value, str) or not re.fullmatch(r"/sys/devices/[A-Za-z0-9_./:-]+", value):
        return None
    name = value.rsplit("/", 1)[-1]
    return name.lower() if _PCI.fullmatch(name) else None


def _mac(value):
    if not isinstance(value, str) or not _MAC.fullmatch(value):
        return None
    value = value.lower()
    return (
        None
        if value in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} or int(value[:2], 16) & 1
        else value
    )


def _affirmative_hardware_capability(value):
    # lshw hw.cc serializes an affirmative capability as True or its nonempty
    # description. The named key is evidence; never parse translated prose.
    return value is True or (isinstance(value, str) and _text(value) is not None)


def _interfaces(inventory):
    ssh = inventory["ssh"]
    links = _unique(ssh["links"], "ifname", "netlink inventory")
    net = _unique(ssh["host"]["net"], "name", "sysfs network inventory")
    pci = _unique(ssh["host"]["pci"], "id", "sysfs PCI inventory")
    hardware, unattached = {}, []
    for row in _walk(ssh["hardware"]):
        if row.get("class") != "network":
            continue
        logical = row.get("logicalname", [])
        names = [logical] if isinstance(logical, str) else logical
        if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
            raise DiscoveryError("Proxmox network logical names are malformed")
        if not names:
            unattached.append(
                {
                    "name": None,
                    "businfo": row.get("businfo"),
                    "reason": "hardware network device has no live logical-name join",
                }
            )
        for name in names:
            if name in hardware:
                raise DiscoveryError("Proxmox lshw contains ambiguous network logical names")
            hardware[name] = row
    interfaces, excluded, warnings = [], list(unattached), []
    if set(net) != set(links):
        warnings.append(
            "Linux netlink and sysfs name sets differ; unmatched links remain unresolved"
        )
    nested = (ssh["host"]["dmi"].get("product_name") or "").casefold() in _VIRTUAL_SYSTEMS or (
        ssh["host"]["dmi"].get("sys_vendor") or ""
    ).casefold() in {"qemu", "bochs", "innotek gmbh"}
    for name in sorted(set(net) | set(links) | set(hardware)):
        kernel, link, device = net.get(name), links.get(name), hardware.get(name)
        reason = None
        if not _IFACE.fullmatch(name):
            reason = "unreviewed Linux interface name"
        elif kernel is None or link is None or device is None:
            reason = "unresolved exact hardware/sysfs/netlink join"
        if reason is None and nested:
            reason = "virtual system hardware requires an independently reviewed NIC classification"
        if reason is None:
            pci_id = _pci_path(kernel.get("device"))
            function = pci.get(pci_id)
            driver = _driver(kernel.get("driver"))
            hwdriver = (device.get("configuration") or {}).get("driver")
            capability = device.get("capabilities") or {}
            if (
                pci_id is None
                or function is None
                or device.get("businfo") != "pci@" + pci_id
                or driver is None
                or driver != _driver(function.get("driver"))
                or driver != hwdriver
            ):
                reason = "unresolved exact PCI/driver/hardware join"
            elif (
                kernel.get("physical_function") is not None
                or function.get("physical_function") is not None
            ):
                reason = "SR-IOV virtual function"
            elif (
                kernel.get("wireless") is not False
                or "wireless" in capability
                or "802.11" in capability
            ):
                reason = "wireless or unresolved wireless classification"
            elif (
                kernel.get("phys_switch_id") is not None
                and (
                    not isinstance(kernel["phys_switch_id"], str)
                    or bool(kernel["phys_switch_id"].strip())
                )
            ) or (
                isinstance(kernel.get("phys_port_name"), str)
                and _REPRESENTOR_PORT.fullmatch(kernel["phys_port_name"]) is not None
            ):
                # A switch function/representor can expose the PF's PCI parent
                # and driver without representing a physical Ethernet socket.
                reason = "unreviewed switch port or network function representor"
            elif (
                driver in _VIRTUAL_DRIVERS
                or (_hex(function.get("vendor")), _hex(function.get("device"))) in _VIRTUAL_PCI
            ):
                reason = "virtual Ethernet hardware"
            elif (
                _hex(function.get("class")) != 0x020000
                or link.get("link_type") != "ether"
                or _integer(kernel.get("type"), 1, 1) != 1
                or not _affirmative_hardware_capability(capability.get("ethernet"))
            ):
                reason = "unproven physical Ethernet hardware"
            elif (link.get("linkinfo") or {}).get("info_kind") is not None:
                reason = "software or stacked Linux link"
        if reason is not None:
            excluded.append({"name": name, "reason": reason})
            continue
        flags = link.get("flags")
        enabled = (
            "UP" in flags
            if isinstance(flags, list)
            and all(isinstance(flag, str) and re.fullmatch(r"[A-Z0-9_]+", flag) for flag in flags)
            else None
        )
        speed = (
            _integer(kernel.get("speed"), 1, 2147483)
            if _integer(kernel.get("carrier"), 1, 1) == 1
            and enabled is not None
            and "LOWER_UP" in flags
            else None
        )
        source = {
            "contract": INTERFACE_CONTRACT,
            "node": inventory["node"],
            "name": name,
            "pci": pci_id,
            "driver": driver,
            "classification": "host-physical-ethernet",
            "hardware_businfo": device["businfo"],
            "admin_state": "netlink-IFF_UP" if enabled is not None else "unavailable",
        }
        interfaces.append(
            {
                "name": name,
                "type": None,
                "type_source": "proxmox-reported-pnic",
                "enabled": enabled,
                "description": None,
                "mtu": _integer(link.get("mtu"), 1, 65535),
                "mac_address": _mac(link.get("address")),
                "speed": None if speed is None else speed * 1000,
                "duplex": None,
                "port_type": None,
                "mgmt_only": None,
                "physical_ethernet": True,
                "physical_ethernet_source": INTERFACE_CONTRACT,
                "source": source,
            }
        )
        if enabled is None:
            warnings.append(
                "%s: complete administrative flags unavailable; creation deferred" % name
            )
    return interfaces, excluded, warnings


def observed_physical_ethernet(fact, name):
    if (
        not isinstance(fact, dict)
        or fact.get("name") != name
        or not isinstance(name, str)
        or not _IFACE.fullmatch(name)
    ):
        return False
    source = fact.get("source")
    return (
        isinstance(source, dict)
        and fact.get("physical_ethernet") is True
        and fact.get("physical_ethernet_source") == INTERFACE_CONTRACT
        and source.get("contract") == INTERFACE_CONTRACT
        and source.get("name") == name
        and source.get("classification") == "host-physical-ethernet"
        and isinstance(source.get("pci"), str)
        and _PCI.fullmatch(source["pci"]) is not None
        and source.get("hardware_businfo") == "pci@" + source["pci"]
        and _text(source.get("driver")) is not None
    )


def _guest_observations(inventory, host_uuid):
    rows, identifiers = [], {}
    for row in inventory["guests"]:
        guest_uuid = (
            canonical_guest_uuid(row["current_config"].get("smbios1"))
            if row["kind"] == "qemu"
            else None
        )
        if guest_uuid is not None:
            identifiers[guest_uuid] = identifiers.get(guest_uuid, 0) + 1
        rows.append(
            {
                **copy.deepcopy(row),
                "identity": {"host_uuid": host_uuid, "guest_uuid": guest_uuid, "unique": False},
            }
        )
    unresolved = []
    for row in rows:
        guest_uuid = row["identity"]["guest_uuid"]
        row["identity"]["unique"] = guest_uuid is not None and identifiers[guest_uuid] == 1
        if not row["identity"]["unique"]:
            unresolved.append(
                {
                    "kind": row["kind"],
                    "vmid": row["vmid"],
                    "reason": "LXC lacks reviewed stable BIOS identity"
                    if row["kind"] == "lxc"
                    else "missing or duplicate QEMU BIOS UUID",
                }
            )
    return rows, unresolved


def _validate_guests(inventory):
    keys = set()
    for kind in ("qemu", "lxc"):
        for row in inventory["api"][kind]:
            vmid = _integer(row.get("vmid"), 100, 999999999)
            if (
                vmid is None
                or (kind, vmid) in keys
                or row.get("node", inventory["node"]) != inventory["node"]
            ):
                raise DiscoveryError(
                    "Proxmox guest list has invalid, duplicate or foreign-node identities"
                )
            keys.add((kind, vmid))
    if keys != {(row["kind"], row["vmid"]) for row in inventory["guests"]}:
        raise DiscoveryError("Proxmox local guest lists disagree with collected guest scopes")
    for row in inventory["guests"]:
        registered = next(
            item for item in inventory["api"][row["kind"]] if int(item["vmid"]) == row["vmid"]
        )
        if (
            row["summary"] != registered
            or row["status"] is None
            or _integer(row["status"].get("vmid", row["vmid"]), 100, 999999999) != row["vmid"]
            or row["status"].get("node", inventory["node"]) != inventory["node"]
        ):
            raise DiscoveryError("Proxmox guest detail disagrees with its local registration")
        if "VM.Audit" not in inventory["api"]["permissions"].get("/vms/%s" % row["vmid"], {}):
            raise DiscoveryError("Proxmox guest lacks exact VM.Audit permission proof")
    local_registry = {
        (row["type"], int(vmid))
        for vmid, row in inventory["ssh"]["host"]["guest_registry"].get("ids", {}).items()
        if row["node"] == inventory["node"]
    }
    if keys != local_registry:
        raise DiscoveryError(
            "Proxmox API guest visibility disagrees with authoritative local registrations"
        )
    if inventory["completeness"].get("guests") is not True:
        raise DiscoveryError(
            "Proxmox complete guest view lacks authoritative local registration proof"
        )


def _build(inventory, expected_node=None, expected_host_uuid=None):
    identity = _host_identity(inventory)
    if expected_node is not None and (
        not isinstance(expected_node, str)
        or not _NODE.fullmatch(expected_node)
        or expected_node != inventory["node"]
    ):
        raise DiscoveryError("Expected Proxmox node does not match the selected endpoint")
    expected = canonical_host_uuid(expected_host_uuid) if expected_host_uuid is not None else None
    if expected_host_uuid is not None and (expected is None or expected != identity["host_uuid"]):
        raise DiscoveryError("Expected Proxmox host UUID does not match the selected endpoint")
    _validate_guests(inventory)
    interfaces, excluded, warnings = _interfaces(inventory)
    guests, unresolved = _guest_observations(inventory, identity["host_uuid"])
    if inventory["completeness"].get("guests") is not True:
        warnings.append("Guest inventory is limited to current-session permission visibility")
    warnings.append(
        "Host Linux network, addresses, capacity and storage are report-only observations"
    )
    if not interfaces:
        warnings.append(
            "No eligible physical NIC facts; this does not prove physical hardware absence"
        )
    binding = (
        None
        if expected is None
        else {
            "contract": IDENTITY_CONTRACT,
            "expected_uuid": expected,
            "observed_uuid": identity["host_uuid"],
            "node": inventory["node"],
            "property": "dmi.product_uuid",
        }
    )
    return {
        "adapter": ADAPTER,
        "schema_version": 1,
        "identity": identity,
        "expected_node": expected_node,
        "expected_host_uuid": expected,
        "identity_binding": binding,
        "interfaces": interfaces,
        "excluded_interfaces": excluded,
        "warnings": warnings,
        "source": {"contract": CONTRACT, "inventory": copy.deepcopy(inventory)},
        "observations": {
            "host": {
                "node": inventory["node"],
                "status": copy.deepcopy(inventory["api"]["node_status"]),
                "hardware": copy.deepcopy(inventory["ssh"]["hardware"]),
                "sysfs": copy.deepcopy(inventory["ssh"]["host"]),
            },
            "service": copy.deepcopy(inventory["api"]["version"]),
            "cluster": copy.deepcopy(inventory["api"]["cluster_status"]),
            "network": {
                "live_links": copy.deepcopy(inventory["ssh"]["links"]),
                "live_addresses": copy.deepcopy(inventory["ssh"]["addresses"]),
                "bridge_vlans": copy.deepcopy(inventory["ssh"]["bridge_vlans"]),
                "configuration": copy.deepcopy(inventory["api"]["node_network"]),
                "configuration_visibility": inventory["completeness"]["network_configuration"],
                "pending_changes_present": inventory["api"]["node_network_changes"],
                "configuration_state": (
                    "API configuration may include staged changes; Linux netlink is current runtime"
                ),
            },
            "guests": guests,
            "guest_identity_unresolved": unresolved,
            "storage": copy.deepcopy(inventory["api"]["storage"]),
            "completeness": copy.deepcopy(inventory["completeness"]),
        },
        "sources": {
            "identity": {
                "contract": IDENTITY_CONTRACT,
                "node": inventory["node"],
                "properties": [
                    "cluster_status.local",
                    "host.hostname",
                    "host.dmi",
                    "hardware.system",
                    "node_version",
                ],
            },
            "interfaces": {
                "contract": INTERFACE_CONTRACT,
                "node": inventory["node"],
                "properties": ["hardware.network", "host.net", "host.pci", "links"],
            },
        },
    }


def _read(client):
    cluster = client.get("/cluster/status")
    if not isinstance(cluster, list):
        raise DiscoveryError("Proxmox cluster status is not an explicit list")
    node = _local_node(cluster)
    base = "/nodes/" + node
    perms = {}
    for scope in (base, "/vms"):
        result = _permissions(client.get("/access/permissions", params={"path": scope}))
        if scope not in result:
            raise DiscoveryError("Proxmox permission query omitted its requested exact scope")
        perms[scope] = result[scope]
    network = client.get_envelope(base + "/network")
    if not isinstance(network, dict) or "data" not in network:
        raise DiscoveryError("Proxmox network source lacks its API envelope")
    api = {
        "version": client.get("/version"),
        "cluster_status": cluster,
        "node_version": client.get(base + "/version"),
        "node_status": client.get(base + "/status"),
        "permissions": perms,
        "node_network": network["data"],
        "node_network_changes": network.get("changes") not in (None, "", [], {}),
        "storage": client.get(base + "/storage"),
    }
    guests = []
    for kind in ("qemu", "lxc"):
        rows = client.get(base + "/" + kind)
        if not isinstance(rows, list):
            raise DiscoveryError("Proxmox guest list is not an explicit list")
        api[kind] = rows
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                raise DiscoveryError("Proxmox guest list row is not an object")
            vmid = _integer(row.get("vmid"), 100, 999999999)
            if vmid is None or vmid in seen:
                raise DiscoveryError("Proxmox guest list has invalid or duplicate VMIDs")
            seen.add(vmid)
            scope = "/vms/%s" % vmid
            result = _permissions(client.get("/access/permissions", params={"path": scope}))
            if scope not in result:
                raise DiscoveryError("Proxmox guest permission query omitted its exact scope")
            perms[scope] = result[scope]
            guest = base + "/" + kind + "/" + str(vmid)
            guests.append(
                {
                    "kind": kind,
                    "vmid": vmid,
                    "node": node,
                    "summary": row,
                    "config": client.get(guest + "/config"),
                    "current_config": client.get(guest + "/config", params={"current": 1}),
                    "pending": client.get(guest + "/pending"),
                    "status": client.get(guest + "/status/current"),
                }
            )
    ssh = {
        "host": client.ssh_json("host"),
        "hardware": client.ssh_json("hardware"),
        "links": client.ssh_json("links"),
        "addresses": client.ssh_json("addresses"),
        "bridge_vlans": client.ssh_json("bridge_vlans"),
    }
    return {
        "node": node,
        "api": api,
        "ssh": ssh,
        "guests": guests,
        "completeness": {
            "host": True,
            "interfaces": True,
            "network": True,
            "network_configuration": "permission-scoped",
            # Validated against the independent pmxcfs JSON registry before
            # normalization. A propagating parent ACL can hide descendant denies.
            "guests": True,
            "storage": "permission-scoped",
            "permission_scoped": True,
        },
    }


def collect(client, *, use_ntc_defaults=False, expected_node=None, expected_host_uuid=None):
    """Read the selected API-local host, with independent exact Linux source joins."""
    if type(use_ntc_defaults) is not bool:
        raise ValueError("Use NTC defaults when guessing must be true or false")
    if expected_node is not None and (
        not isinstance(expected_node, str) or not _NODE.fullmatch(expected_node)
    ):
        raise ValueError("Expected Proxmox node must be an explicit valid node name")
    if expected_host_uuid is not None and canonical_host_uuid(expected_host_uuid) is None:
        raise ValueError("Expected Proxmox host UUID must be an explicit non-sentinel UUID")
    return _build(_sanitize(_read(client)), expected_node, expected_host_uuid)


def reconstruct(discovery):
    """Re-derive authoritative native facts and reject altered normalized fields."""
    if (
        not isinstance(discovery, dict)
        or discovery.get("adapter") != ADAPTER
        or type(discovery.get("schema_version")) is not int
        or discovery.get("schema_version") != 1
    ):
        raise DiscoveryError("Proxmox discovery envelope has an unsupported contract")
    source = discovery.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"contract", "inventory"}
        or source.get("contract") != CONTRACT
    ):
        raise DiscoveryError("Proxmox discovery lacks its reviewed source contract")
    inventory = _sanitize(source.get("inventory"))
    if inventory != source["inventory"]:
        raise DiscoveryError("Proxmox source evidence contains unreviewed fields")
    rebuilt = _build(inventory, discovery.get("expected_node"), discovery.get("expected_host_uuid"))
    for key in (
        "identity",
        "interfaces",
        "excluded_interfaces",
        "identity_binding",
        "expected_node",
        "expected_host_uuid",
    ):
        if discovery.get(key) != rebuilt[key]:
            raise DiscoveryError("Proxmox normalized %s no longer matches source evidence" % key)
    return rebuilt


def validate(discovery):
    return reconstruct(discovery)
