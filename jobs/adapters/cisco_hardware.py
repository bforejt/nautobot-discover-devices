"""Reviewed physical capability mappings; negotiated speed never sets port type.

References: Cisco Catalyst 9300 architecture and installation specifications.
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-architecture-cte-en.html

Only the initial lab chassis/module mapping is approved. Further models use
Nautobot DeviceType templates until their structured identity mapping is reviewed.
"""

import re


def interface_type(name, model, member, inventory):
    """Return (Nautobot type, evidence description) or (None, reason)."""
    if re.fullmatch(r"(?:Vlan|Loopback|Tunnel)\d+(?:\.\d+)?", name):
        return "virtual", "IOS XE logical interface family"
    if re.fullmatch(r"Port-channel\d+", name):
        return "lag", "IOS XE Port-channel family"
    if model != "C9300-48UXM":
        return None, "No reviewed hardware mapping for this chassis"
    if name == "GigabitEthernet0/0":
        return "1000base-t", "C9300-48UXM dedicated 1G copper management port"
    match = re.fullmatch(r"(TwoGigabitEthernet|TenGigabitEthernet)(\d+)/0/(\d+)", name)
    if match and int(match.group(2)) == member:
        port = int(match.group(3))
        if 1 <= port <= 36 and match.group(1) == "TwoGigabitEthernet":
            return "2.5gbase-t", "C9300-48UXM fixed copper ports 1-36"
        if 37 <= port <= 48 and match.group(1) == "TenGigabitEthernet":
            return "10gbase-t", "C9300-48UXM fixed copper ports 37-48"
    # The hardware model has no separate module slot leaf. Require the exact
    # inventory module identity and a single module, avoiding positional guesses.
    modules = [row for row in inventory if row.get("hw-type", "").split(":")[-1] == "hw-type-pim"]
    if len(modules) == 1 and modules[0].get("part-number", "").strip() == "C3850-NM-4-1G":
        match = re.fullmatch(r"GigabitEthernet(\d+)/1/([1-4])", name)
        if match and int(match.group(1)) == member:
            return "1000base-x-sfp", "Installed C3850-NM-4-1G 4x1G SFP uplink module"
    return None, "No reviewed physical capability mapping for this port"
