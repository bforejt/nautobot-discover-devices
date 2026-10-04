"""Documented Catalyst 9300 chassis and native uplink capability profiles.

PIDs are exact hardware identities, not orderable licensing suffixes. Regions
describe physical capability and native interface numbering, never negotiated
link speed, configured defaults, or the presence of a removable module/optic.
Breakout aliases are deliberately absent. Ambiguous mixed-port numbering stays
unmapped even when Cisco publishes the total port counts.
"""

PROFILE = "catalyst-9300-chassis-and-uplinks-v1"
OVERVIEW_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/Product-overview.html"
)
NETWORK_MODULE_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/Installing-a-network-module.html"
)
DATASHEET_URL = (
    "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/"
    "nb-06-cat9300-ser-data-sheet-cte-en.html"
)
ARCHITECTURE_URL = (
    "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/"
    "nb-06-cat9300-architecture-cte-en.html"
)
INTERFACE_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/"
    "configuration_guide/int_hw/b_1715_int_and_hw_9300_cg/configuring_interface_characteristics.html"
)
LEGACY_MODULE_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/hardware/installation/"
    "guide/b_c3850_hig/m_install_netmod.html"
)


def _region(slot, first, last, family, type_, description, *, documents, section):
    return {
        "slot": slot,
        "first": first,
        "last": last,
        "families": (family,),
        "type": type_,
        "description": description,
        "documents": tuple(documents),
        "section": section,
    }


def _fixed(pid, last, family, type_, *, first=1, documents=(OVERVIEW_URL, INTERFACE_URL)):
    return _region(
        0,
        first,
        last,
        family,
        type_,
        f"{pid} fixed ports {first}-{last}",
        documents=documents,
        section="Switch Models; Interface Configuration Mode",
    )


def _uplink(pid, count, family, type_):
    return _region(
        1,
        1,
        count,
        family,
        type_,
        f"{pid} fixed uplink ports 1-{count}",
        documents=(OVERVIEW_URL, INTERFACE_URL),
        section="Switch Models; Interface Configuration Mode",
    )


_C9300_MODULES = ("C9300-NM-4G", "C9300-NM-4M", "C9300-NM-2Q", "C9300-NM-8X", "C9300-NM-2Y")
_C9300X_MODULES = ("C9300X-NM-2C", "C9300X-NM-8M", "C9300X-NM-8Y")


def _chassis(pid, fixed, modules=(), *, deferred_reason=None):
    result = {
        "profile": PROFILE,
        "family": "c9300",
        "documents": (OVERVIEW_URL, DATASHEET_URL, ARCHITECTURE_URL, INTERFACE_URL),
        "fixed_ports": tuple(fixed),
        "network_modules": tuple(modules),
        "management": {
            "name": "GigabitEthernet0/0",
            "type": "1000base-t",
            "description": f"{pid} dedicated 1G copper management port",
            "documents": (OVERVIEW_URL, ARCHITECTURE_URL, INTERFACE_URL),
            "section": "Ethernet Management Port; Chassis design; Interface Configuration Mode",
        },
    }
    if deferred_reason:
        result["deferred_reason"] = deferred_reason
    return result


CHASSIS_PROFILES = {}

# The exact identities below come from Product Overview, Switch Models tables
# 1-4. The shared region builder does not infer an unlisted PID from a suffix.
for _pid in (
    "C9300-24H",
    "C9300-24P",
    "C9300-24T",
    "C9300-24U",
    "C9300-24UB",
):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid, (_fixed(_pid, 24, "GigabitEthernet", "1000base-t"),), _C9300_MODULES
    )
for _pid in (
    "C9300-48H",
    "C9300-48P",
    "C9300-48T",
    "C9300-48U",
    "C9300-48UB",
):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid, (_fixed(_pid, 48, "GigabitEthernet", "1000base-t"),), _C9300_MODULES
    )
for _pid, _count in (("C9300-24S", 24), ("C9300-48S", 48)):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid, (_fixed(_pid, _count, "GigabitEthernet", "1000base-x-sfp"),), _C9300_MODULES
    )
for _pid in ("C9300-24UX", "C9300-24UXB"):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid, (_fixed(_pid, 24, "TenGigabitEthernet", "10gbase-t"),), _C9300_MODULES
    )

# Dedicated architecture model description/highlights and the data sheet both
# describe all 48 downlinks as 5G-capable. The overview/architecture's copied
# ASIC port-mapping bullet list is inconsistent and is not used for this row.
CHASSIS_PROFILES["C9300-48UN"] = _chassis(
    "C9300-48UN",
    (
        _fixed(
            "C9300-48UN",
            48,
            "FiveGigabitEthernet",
            "5gbase-t",
            documents=(ARCHITECTURE_URL, DATASHEET_URL, INTERFACE_URL),
        ),
    ),
    _C9300_MODULES,
)

# Product Overview Figure 2 and Architecture Figure 32 document the split.
CHASSIS_PROFILES["C9300-48UXM"] = _chassis(
    "C9300-48UXM",
    (
        _region(
            0,
            1,
            36,
            "TwoGigabitEthernet",
            "2.5gbase-t",
            "C9300-48UXM fixed copper ports 1-36",
            documents=(OVERVIEW_URL, ARCHITECTURE_URL, INTERFACE_URL),
            section="Front Panel Components, Figure 2; Architecture Figure 32",
        ),
        _region(
            0,
            37,
            48,
            "TenGigabitEthernet",
            "10gbase-t",
            "C9300-48UXM fixed copper ports 37-48",
            documents=(OVERVIEW_URL, ARCHITECTURE_URL, INTERFACE_URL),
            section="Front Panel Components, Figure 2; Architecture Figure 32",
        ),
    ),
    (*_C9300_MODULES, "C3850-NM-4-1G"),
)

for _pid, _count, _uplink_family, _uplink_type in (
    ("C9300L-24T-4G", 24, "GigabitEthernet", "1000base-x-sfp"),
    ("C9300L-24P-4G", 24, "GigabitEthernet", "1000base-x-sfp"),
    ("C9300L-24T-4X", 24, "TenGigabitEthernet", "10gbase-x-sfpp"),
    ("C9300L-24P-4X", 24, "TenGigabitEthernet", "10gbase-x-sfpp"),
    ("C9300L-48T-4G", 48, "GigabitEthernet", "1000base-x-sfp"),
    ("C9300L-48P-4G", 48, "GigabitEthernet", "1000base-x-sfp"),
    ("C9300L-48PF-4G", 48, "GigabitEthernet", "1000base-x-sfp"),
    ("C9300L-48T-4X", 48, "TenGigabitEthernet", "10gbase-x-sfpp"),
    ("C9300L-48P-4X", 48, "TenGigabitEthernet", "10gbase-x-sfpp"),
    ("C9300L-48PF-4X", 48, "TenGigabitEthernet", "10gbase-x-sfpp"),
):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid,
        (
            _fixed(_pid, _count, "GigabitEthernet", "1000base-t"),
            _uplink(_pid, 4, _uplink_family, _uplink_type),
        ),
    )

for _pid, _uplink_count, _uplink_family, _uplink_type in (
    ("C9300L-24UXG-4X", 4, "TenGigabitEthernet", "10gbase-x-sfpp"),
    ("C9300L-24UXG-2Q", 2, "FortyGigabitEthernet", "40gbase-x-qsfpp"),
):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid,
        (_uplink(_pid, _uplink_count, _uplink_family, _uplink_type),),
        deferred_reason=(
            "24UXG mixed downlink numbering remains unresolved: the published "
            "architecture Figure 30 range conflicts with the documented eight mGig ports"
        ),
    )
for _pid, _uplink_count, _uplink_family, _uplink_type in (
    ("C9300L-48UXG-4X", 4, "TenGigabitEthernet", "10gbase-x-sfpp"),
    ("C9300L-48UXG-2Q", 2, "FortyGigabitEthernet", "40gbase-x-qsfpp"),
):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid,
        (
            _fixed(_pid, 36, "GigabitEthernet", "1000base-t", documents=(ARCHITECTURE_URL,)),
            _fixed(
                _pid,
                48,
                "TenGigabitEthernet",
                "10gbase-t",
                first=37,
                documents=(ARCHITECTURE_URL, INTERFACE_URL),
            ),
            _uplink(_pid, _uplink_count, _uplink_family, _uplink_type),
        ),
    )

for _pid, _count in (
    ("C9300LM-48T-4Y", 48),
    ("C9300LM-24U-4Y", 24),
    ("C9300LM-48U-4Y", 48),
):
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid,
        (
            _fixed(_pid, _count, "GigabitEthernet", "1000base-t"),
            _uplink(_pid, 4, "TwentyFiveGigE", "25gbase-x-sfp28"),
        ),
    )
CHASSIS_PROFILES["C9300LM-48UX-4Y"] = _chassis(
    "C9300LM-48UX-4Y",
    (_uplink("C9300LM-48UX-4Y", 4, "TwentyFiveGigE", "25gbase-x-sfp28"),),
    deferred_reason=(
        "48UX mixed downlink numbering remains unresolved: architecture Figure 37 "
        "overlaps port 40 between its 40x1G and 8xmGig regions"
    ),
)

for _pid, _count in (("C9300X-12Y", 12), ("C9300X-24Y", 24)):
    _modules = _C9300X_MODULES + (("C9300X-NM-4C",) if _pid == "C9300X-24Y" else ())
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid, (_fixed(_pid, _count, "TwentyFiveGigE", "25gbase-x-sfp28"),), _modules
    )
for _pid, _count in (("C9300X-48HX", 48), ("C9300X-48TX", 48), ("C9300X-24HX", 24)):
    _modules = _C9300X_MODULES + (("C9300X-NM-4C",) if _count == 48 else ())
    CHASSIS_PROFILES[_pid] = _chassis(
        _pid, (_fixed(_pid, _count, "TenGigabitEthernet", "10gbase-t"),), _modules
    )
CHASSIS_PROFILES["C9300X-48HXN"] = _chassis(
    "C9300X-48HXN",
    (),
    _C9300X_MODULES,
    deferred_reason=(
        "HXN mixed downlink numbering remains unresolved: architecture Figure 35 overlaps "
        "port 40 between the 5G and 10G regions"
    ),
)
# Product Overview Table 6 and the interface guide bound 8M/8Y to six usable
# ports on HXN in IOS XE 17.8.1 and later. Discovery's supported baseline is
# 17.9+. The module's generic eight-port profile must never reach its disabled
# ports 7/8 on this chassis. This override also bounds component ownership.
CHASSIS_PROFILES["C9300X-48HXN"]["network_module_ports"] = {
    "C9300X-NM-8M": (
        _region(
            1,
            1,
            6,
            "TenGigabitEthernet",
            "10gbase-t",
            "Installed C9300X-NM-8M usable copper uplink ports 1-6 on C9300X-48HXN",
            documents=(OVERVIEW_URL, NETWORK_MODULE_URL, INTERFACE_URL),
            section="Network Modules Supported on C9300X-48HXN, Table 6; IOS XE 17.8.1+",
        ),
    ),
    "C9300X-NM-8Y": (
        _region(
            1,
            1,
            6,
            "TwentyFiveGigE",
            "25gbase-x-sfp28",
            "Installed C9300X-NM-8Y usable SFP28 uplink ports 1-6 on C9300X-48HXN",
            documents=(OVERVIEW_URL, NETWORK_MODULE_URL, INTERFACE_URL),
            section="Network Modules Supported on C9300X-48HXN, Table 6; IOS XE 17.8.1+",
        ),
    ),
}


def _network_module(pid, count, family, type_, description):
    return {
        "profile": PROFILE,
        "documents": (NETWORK_MODULE_URL, DATASHEET_URL, INTERFACE_URL),
        "description": description,
        "ports": (
            _region(
                1,
                1,
                count,
                family,
                type_,
                description,
                documents=(NETWORK_MODULE_URL, DATASHEET_URL, INTERFACE_URL),
                section=f"Network Modules Overview; Network Module Port Configurations, {pid}",
            ),
        ),
        # Cisco's tables place each native network-module port in slot 1.
        # This authorizes matching slot-1 structured placement, not inventing a
        # component identifier or claiming a module is installed from a CLI alias.
        "component_placement": "c9300-slot-1",
    }


NETWORK_MODULE_PROFILES = {
    "C9300-NM-4G": _network_module(
        "C9300-NM-4G",
        4,
        "GigabitEthernet",
        "1000base-x-sfp",
        "Installed C9300-NM-4G 4x1G SFP uplink module",
    ),
    "C9300-NM-4M": _network_module(
        "C9300-NM-4M",
        4,
        "TenGigabitEthernet",
        "10gbase-t",
        "Installed C9300-NM-4M 4x10G multigigabit copper uplink module",
    ),
    "C9300-NM-2Q": _network_module(
        "C9300-NM-2Q",
        2,
        "FortyGigabitEthernet",
        "40gbase-x-qsfpp",
        "Installed C9300-NM-2Q 2x40G QSFP+ uplink module",
    ),
    "C9300-NM-8X": _network_module(
        "C9300-NM-8X",
        8,
        "TenGigabitEthernet",
        "10gbase-x-sfpp",
        "Installed C9300-NM-8X 8x10G SFP+ uplink module",
    ),
    "C9300-NM-2Y": _network_module(
        "C9300-NM-2Y",
        2,
        "TwentyFiveGigE",
        "25gbase-x-sfp28",
        "Installed C9300-NM-2Y 2x25G SFP28 uplink module",
    ),
    "C9300X-NM-2C": _network_module(
        "C9300X-NM-2C",
        2,
        "HundredGigE",
        "100gbase-x-qsfp28",
        "Installed C9300X-NM-2C 2x100G QSFP28 uplink module",
    ),
    "C9300X-NM-4C": _network_module(
        "C9300X-NM-4C",
        4,
        "HundredGigE",
        "100gbase-x-qsfp28",
        "Installed C9300X-NM-4C 4x100G QSFP28 uplink module",
    ),
    "C9300X-NM-8M": _network_module(
        "C9300X-NM-8M",
        8,
        "TenGigabitEthernet",
        "10gbase-t",
        "Installed C9300X-NM-8M 8x10G multigigabit copper uplink module",
    ),
    "C9300X-NM-8Y": _network_module(
        "C9300X-NM-8Y",
        8,
        "TwentyFiveGigE",
        "25gbase-x-sfp28",
        "Installed C9300X-NM-8Y 8x25G SFP28 uplink module",
    ),
    # Preserve the observed lab combination. Broader 3850 module or chassis
    # compatibility is intentionally not inferred from the product-series name.
    "C3850-NM-4-1G": {
        **_network_module(
            "C3850-NM-4-1G",
            4,
            "GigabitEthernet",
            "1000base-x-sfp",
            "Installed C3850-NM-4-1G 4x1G SFP uplink module",
        ),
        "documents": (LEGACY_MODULE_URL, DATASHEET_URL),
        "ports": (
            _region(
                1,
                1,
                4,
                "GigabitEthernet",
                "1000base-x-sfp",
                "Installed C3850-NM-4-1G 4x1G SFP uplink module",
                documents=(LEGACY_MODULE_URL, DATASHEET_URL),
                section="Network Module Port Configurations; Existing validated lab combination",
            ),
        ),
        "section": "Existing RESTCONF-validated C9300-48UXM lab combination",
    },
}
