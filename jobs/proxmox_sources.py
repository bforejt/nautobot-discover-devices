"""Fixed structured Linux reads; no device data is inserted into commands.

The named sysfs approach follows nautobot-testsuite/jobs/proxmox_sources.py
(Apache-2.0); this restricted reader omits native configuration and proc cmdline.
"""

import shlex

HOST_SCRIPT = r"""
import errno
import glob
import json
import os
import re
import socket

out = {"hostname": socket.gethostname(), "dmi": {}, "net": [], "pci": [],
       "errors": [], "unavailable": []}
read_count = 0

def read(path):
    global read_count
    read_count += 1
    if read_count > 65536:
        raise ValueError("attribute read budget exceeded")
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as stream:
            value = stream.read(4097)
        if len(value) > 4096:
            raise ValueError("attribute size budget exceeded")
        return value.strip()
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENODATA, errno.ENODEV, errno.EINVAL,
                          errno.EOPNOTSUPP):
            out["unavailable"].append({"path": path, "errno": error.errno})
        else:
            out["errors"].append({"path": path, "error": type(error).__name__})
        return None

def paths(pattern):
    values = sorted(glob.glob(pattern))
    if len(values) > 4096:
        raise ValueError("attribute inventory budget exceeded")
    return values

def link(path):
    return os.path.realpath(path) if os.path.islink(path) else None

try:
    for field in ("sys_vendor", "product_name", "product_version", "product_serial",
                  "product_uuid", "chassis_vendor", "chassis_type", "chassis_serial",
                  "board_vendor", "board_name", "board_serial"):
        out["dmi"][field] = read("/sys/class/dmi/id/" + field)
    for path in paths("/sys/bus/pci/devices/*"):
        name = os.path.basename(path)
        if not re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", name):
            raise ValueError("invalid PCI identifier")
        row = {"id": name, "driver": link(path + "/driver"),
               "physical_function": link(path + "/physfn"),
               "virtual_functions": [link(p) for p in paths(path + "/virtfn*")]}
        for field in ("vendor", "device", "class", "subsystem_vendor", "subsystem_device",
                      "numa_node", "sriov_numvfs", "sriov_totalvfs"):
            row[field] = read(path + "/" + field)
        out["pci"].append(row)
    for path in paths("/sys/class/net/*"):
        name = os.path.basename(path)
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name):
            raise ValueError("invalid netdevice identifier")
        row = {"name": name, "path": os.path.realpath(path),
               "device": link(path + "/device"), "driver": link(path + "/device/driver"),
               "physical_function": link(path + "/device/physfn"),
               "virtual_functions": [link(p) for p in paths(path + "/device/virtfn*")],
               "wireless": os.path.isdir(path + "/wireless")}
        for field in ("address", "speed", "duplex", "operstate", "carrier", "mtu",
                      "flags", "type", "phys_port_name", "phys_switch_id"):
            row[field] = read(path + "/" + field)
        out["net"].append(row)
except Exception as error:
    out["errors"].append({"error": type(error).__name__})
print(json.dumps(out, sort_keys=True, allow_nan=False))
"""

HOST_COMMAND = "python3 -c " + shlex.quote(HOST_SCRIPT)
READ_COMMANDS = {
    "hardware": "lshw -json",
    "links": "ip -j -s -d link show",
    "addresses": "ip -j address show",
    "bridge_vlans": "bridge -j vlan show",
    "host": HOST_COMMAND,
}
