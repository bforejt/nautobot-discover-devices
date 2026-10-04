"""Documented Catalyst 9500 chassis and optional uplink capabilities.

These records classify observed interfaces; they never synthesize ports or
infer an installed module from a chassis bundle PID. Breakout lane names are
deliberately absent. The C9500-32QC alternate 40G/100G names require explicit
port-mode evidence before assigning physical types.
"""

from copy import deepcopy

HARDWARE_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/hardware/"
    "install/b_catalyst_9500_hig/9500_product-overview.html"
)
INTERFACE_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/"
    "release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9500_cg/"
    "configuring_interface_characteristics.html"
)
X_HARDWARE_GUIDE = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/hardware/"
    "install/b-c9500x-hig/9500x_product-overview.html"
)
ORDERING_GUIDE = (
    "https://www.cisco.com/c/en/us/products/collateral/switches/"
    "catalyst-9500-series-switches/nb-06-cat9500-swit-ser-cte-en.html"
)


def _region(first, last, family, type_, description, *, slot=0, x=False, section=None):
    return {
        "slot": slot,
        "first": first,
        "last": last,
        "families": (family,),
        "type": type_,
        "description": description,
        "documents": ((X_HARDWARE_GUIDE if x else HARDWARE_GUIDE), INTERFACE_GUIDE),
        "section": section or "SFP and QSFP Module Ports; native port numbering",
    }


def _chassis(pid, fixed_ports, *, modules=(), x=False, deferred_reason=None):
    guide = X_HARDWARE_GUIDE if x else HARDWARE_GUIDE
    result = {
        "profile": "cisco-" + pid.lower(),
        "family": "c9500",
        "documents": (guide, INTERFACE_GUIDE),
        "fixed_ports": tuple(fixed_ports),
        "network_modules": tuple(modules),
        "management": {
            "name": "GigabitEthernet0/0",
            "type": "1000base-t",
            "description": pid + " dedicated 10/100/1000 copper management port",
            "documents": (guide,),
            "section": "Management Port; front/rear panel RJ-45 Ethernet management port",
        },
    }
    if deferred_reason:
        result["deferred_reason"] = deferred_reason
    return result


_NETWORK_MODULES = ("C9500-NM-8X", "C9500-NM-2Q")
CHASSIS_PROFILES = {
    "C9500-12Q": _chassis(
        "C9500-12Q",
        (_region(1, 12, "FortyGigabitEthernet", "40gbase-x-qsfpp", "12 fixed 40G QSFP+ cages"),),
    ),
    "C9500-24Q": _chassis(
        "C9500-24Q",
        (_region(1, 24, "FortyGigabitEthernet", "40gbase-x-qsfpp", "24 fixed 40G QSFP+ cages"),),
    ),
    "C9500-16X": _chassis(
        "C9500-16X",
        (_region(1, 16, "TenGigabitEthernet", "10gbase-x-sfpp", "16 fixed 1G/10G SFP/SFP+ cages"),),
        modules=_NETWORK_MODULES,
    ),
    "C9500-40X": _chassis(
        "C9500-40X",
        (_region(1, 40, "TenGigabitEthernet", "10gbase-x-sfpp", "40 fixed 1G/10G SFP/SFP+ cages"),),
        modules=_NETWORK_MODULES,
    ),
    "C9500-24Y4C": _chassis(
        "C9500-24Y4C",
        (
            _region(1, 24, "TwentyFiveGigE", "25gbase-x-sfp28", "24 fixed 1G/10G/25G SFP28 cages"),
            _region(
                25,
                28,
                "HundredGigE",
                "100gbase-x-qsfp28",
                "Four fixed 40G/100G QSFP28 uplink cages",
            ),
        ),
    ),
    "C9500-48Y4C": _chassis(
        "C9500-48Y4C",
        (
            _region(1, 48, "TwentyFiveGigE", "25gbase-x-sfp28", "48 fixed 1G/10G/25G SFP28 cages"),
            _region(
                49,
                52,
                "HundredGigE",
                "100gbase-x-qsfp28",
                "Four fixed 40G/100G QSFP28 uplink cages",
            ),
        ),
    ),
    "C9500-32C": _chassis(
        "C9500-32C",
        (_region(1, 32, "HundredGigE", "100gbase-x-qsfp28", "32 fixed 40G/100G QSFP28 cages"),),
    ),
    "C9500-32QC": _chassis(
        "C9500-32QC",
        (),
        deferred_reason=(
            "C9500-32QC has overlapping FortyGigabitEthernet ports 1-32 and "
            "HundredGigE aliases 33-48; enabling a 100G alias deactivates its "
            "paired 40G interfaces. Physical typing requires explicit active "
            "port-mode evidence; interface names or negotiated speeds are insufficient."
        ),
    ),
    "C9500X-28C8D": _chassis(
        "C9500X-28C8D",
        (
            _region(
                1,
                14,
                "HundredGigE",
                "100gbase-x-qsfp28",
                "Fixed 40G/100G QSFP28 cages 1-14",
                x=True,
            ),
            _region(
                15,
                22,
                "FourHundredGigE",
                "400gbase-x-qsfpdd",
                "Eight fixed 400G QSFP-DD cages",
                x=True,
            ),
            _region(
                23,
                36,
                "HundredGigE",
                "100gbase-x-qsfp28",
                "Fixed 40G/100G QSFP28 cages 23-36",
                x=True,
            ),
        ),
        x=True,
    ),
    "C9500X-60L4D": _chassis(
        "C9500X-60L4D",
        (
            _region(
                1,
                30,
                "FiftyGigabitEthernet",
                "50gbase-x-sfp56",
                "Fixed 10G/25G/50G SFP56 cages 1-30",
                x=True,
            ),
            _region(
                31,
                34,
                "FourHundredGigE",
                "400gbase-x-qsfpdd",
                "Four fixed 400G QSFP-DD cages",
                x=True,
            ),
            _region(
                35,
                64,
                "FiftyGigabitEthernet",
                "50gbase-x-sfp56",
                "Fixed 10G/25G/50G SFP56 cages 35-64",
                x=True,
            ),
        ),
        x=True,
    ),
}

# Cisco's bundle table identifies the base chassis. A bundle is not evidence of
# the presently installed optional module; discovery still requires inventory.
_BUNDLE_ALIASES = {
    "C9500-16X-2Q": "C9500-16X",
    "C9500-40X-2Q": "C9500-40X",
    "C9500-24X": "C9500-16X",
    "C9500-48X": "C9500-40X",
}
for _alias, _base in _BUNDLE_ALIASES.items():
    CHASSIS_PROFILES[_alias] = deepcopy(CHASSIS_PROFILES[_base])
    CHASSIS_PROFILES[_alias]["documents"] += (ORDERING_GUIDE,)

# Exact orderable license PIDs from Cisco's ordering table. No unknown suffix is
# removed or interpreted as a matching chassis.
_LICENSE_ALIASES = {
    "C9500-12Q-A": "C9500-12Q",
    "C9500-12Q-E": "C9500-12Q",
    "C9500-24Q-A": "C9500-24Q",
    "C9500-24Q-E": "C9500-24Q",
    "C9500-16X-A": "C9500-16X",
    "C9500-16X-E": "C9500-16X",
    "C9500-40X-A": "C9500-40X",
    "C9500-40X-E": "C9500-40X",
    "C9500-24Y4C-A": "C9500-24Y4C",
    "C9500-24Y4C-E": "C9500-24Y4C",
    "C9500-48Y4C-A": "C9500-48Y4C",
    "C9500-48Y4C-E": "C9500-48Y4C",
    "C9500-32C-A": "C9500-32C",
    "C9500-32C-E": "C9500-32C",
    "C9500-32QC-A": "C9500-32QC",
    "C9500-32QC-E": "C9500-32QC",
    "C9500-16X-2Q-A": "C9500-16X",
    "C9500-16X-2Q-E": "C9500-16X",
    "C9500-40X-2Q-A": "C9500-40X",
    "C9500-40X-2Q-E": "C9500-40X",
    "C9500-24X-A": "C9500-16X",
    "C9500-24X-E": "C9500-16X",
    "C9500-48X-A": "C9500-40X",
    "C9500-48X-E": "C9500-40X",
}
for _alias, _base in _LICENSE_ALIASES.items():
    CHASSIS_PROFILES[_alias] = deepcopy(CHASSIS_PROFILES[_base])
    CHASSIS_PROFILES[_alias]["documents"] += (ORDERING_GUIDE,)

NETWORK_MODULE_PROFILES = {
    "C9500-NM-8X": {
        "profile": "cisco-c9500-nm-8x",
        "documents": (HARDWARE_GUIDE, INTERFACE_GUIDE),
        "description": "Installed C9500-NM-8X eight-port 1G/10G SFP/SFP+ uplink module",
        "ports": (
            _region(
                1,
                8,
                "TenGigabitEthernet",
                "10gbase-x-sfpp",
                "C9500-NM-8X eight 1G/10G SFP/SFP+ cages",
                slot=1,
                section="Network Modules; Interface Configuration Mode, uplink slot 1",
            ),
        ),
        "component_placement": None,
    },
    "C9500-NM-2Q": {
        "profile": "cisco-c9500-nm-2q",
        "documents": (HARDWARE_GUIDE, INTERFACE_GUIDE),
        "description": "Installed C9500-NM-2Q two-port 40G QSFP+ uplink module",
        "ports": (
            _region(
                1,
                2,
                "FortyGigabitEthernet",
                "40gbase-x-qsfpp",
                "C9500-NM-2Q two 40G QSFP+ cages; 4x10G breakout aliases deferred",
                slot=1,
                section="Configuring a Breakout Interface, C9500-NM-2Q tables 2 and 3",
            ),
        ),
        "component_placement": None,
    },
}
