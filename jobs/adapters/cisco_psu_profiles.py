"""Bounded Catalyst 9300 PSU profiles reviewed against Cisco documentation.

Exact hardware PIDs are required: suffixes are never stripped or inferred.
The profile documents physical bays and inlet connectors, not asset presence,
operational health, electrical allocation, or a maximum input draw. Cisco's
published total-input figures are specified at selected input voltages; they
are not an unconditional maximum AC input rating.
"""

PROFILE = "catalyst-9300-psu-bays-and-inlets-v1"
OVERVIEW_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/Product-overview.html"
)
INSTALL_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/Installing-a-power-supply.html"
)
DATASHEET_URL = (
    "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/"
    "nb-06-cat9300-ser-data-sheet-cte-en.html"
)
SPECS_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/"
    "b_c9300_hig/technical-specs.html"
)
BAY_LABELS_URL = (
    "https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-switch/"
    "217759-configure-and-troubleshoot-stackpower-an.html"
)
C6_DATASHEET_URL = (
    "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/"
    "nb-06-cat9200-ser-data-sheet-cte-en.html"
)

# Product Overview, Switch Models tables 1-4, table 18 and Power Supply Modules.
CHASSIS_FAMILIES = {
    "C9300": frozenset(
        (
            "C9300-24H",
            "C9300-24P",
            "C9300-24S",
            "C9300-24T",
            "C9300-24U",
            "C9300-24UB",
            "C9300-24UX",
            "C9300-24UXB",
            "C9300-48H",
            "C9300-48P",
            "C9300-48S",
            "C9300-48T",
            "C9300-48U",
            "C9300-48UB",
            "C9300-48UN",
            "C9300-48UXM",
        )
    ),
    "C9300L": frozenset(
        (
            "C9300L-24T-4G",
            "C9300L-24P-4G",
            "C9300L-24T-4X",
            "C9300L-24P-4X",
            "C9300L-48T-4G",
            "C9300L-48P-4G",
            "C9300L-48T-4X",
            "C9300L-48P-4X",
            "C9300L-48PF-4G",
            "C9300L-48PF-4X",
            "C9300L-24UXG-4X",
            "C9300L-24UXG-2Q",
            "C9300L-48UXG-4X",
            "C9300L-48UXG-2Q",
        )
    ),
    "C9300LM": frozenset(("C9300LM-48T-4Y", "C9300LM-24U-4Y", "C9300LM-48U-4Y", "C9300LM-48UX-4Y")),
    "C9300X": frozenset(
        (
            "C9300X-12Y",
            "C9300X-24Y",
            "C9300X-48HX",
            "C9300X-48TX",
            "C9300X-24HX",
            "C9300X-48HXN",
        )
    ),
}

# Installing a Power Supply, table 1; Overview table 18 also explicitly names
# PWR-C1-350WAC-P as the default for C9300/C9300L data-only models.
FAMILY_PSUS = {
    "C9300": frozenset(
        (
            "PWR-C1-350WAC",
            "PWR-C1-715WAC",
            "PWR-C1-1100WAC",
            "PWR-C1-350WAC-P",
            "PWR-C1-715WAC-P",
            "PWR-C1-1100WAC-P",
            "PWR-C1-1900WAC-P",
            "PWR-C1-1900WHV-T",
            "PWR-C1-715WDC",
        )
    ),
    "C9300L": frozenset(
        (
            "PWR-C1-350WAC",
            "PWR-C1-715WAC",
            "PWR-C1-350WAC-P",
            "PWR-C1-715WAC-P",
            "PWR-C1-1100WAC-P",
            "PWR-C1-1900WAC-P",
            "PWR-C1-715WDC",
        )
    ),
    "C9300LM": frozenset(("PWR-C6-600WAC", "PWR-C6-1KWAC")),
    "C9300X": frozenset(
        (
            "PWR-C1-350WAC-P",
            "PWR-C1-715WAC-P",
            "PWR-C1-1100WAC-P",
            "PWR-C1-1900WAC-P",
            "PWR-C1-1900WHV-T",
            "PWR-C1-715WDC",
        )
    ),
}

# Catalyst 9300 datasheet tables 21 and 22 state inlet receptacles explicitly.
# The same exact C6 PSU PIDs have C16 documented in Catalyst 9200 table 16;
# their Catalyst 9300LM compatibility comes from the 9300 installation guide.
PSU_CONNECTORS = {
    "PWR-C1-350WAC": "iec-60320-c14",
    "PWR-C1-350WAC-P": "iec-60320-c14",
    "PWR-C1-715WAC": "iec-60320-c16",
    "PWR-C1-715WAC-P": "iec-60320-c16",
    "PWR-C1-1100WAC": "iec-60320-c16",
    "PWR-C1-1100WAC-P": "iec-60320-c16",
    "PWR-C1-1900WAC-P": "iec-60320-c22",
    "PWR-C1-1900WHV-T": "saf-d-grid",
    "PWR-C1-715WDC": "dc-terminal",
    "PWR-C6-600WAC": "iec-60320-c16",
    "PWR-C6-1KWAC": "iec-60320-c16",
}


def family_for_chassis(model):
    return next((family for family, models in CHASSIS_FAMILIES.items() if model in models), None)


def supported_psu(chassis_model, model):
    family = family_for_chassis(chassis_model)
    return family is not None and model in FAMILY_PSUS[family]


def bay(slot):
    return {
        "name": "Power Supply %s" % slot,
        "position": "PSU-%s" % slot,
        "label": "Power Supply %s" % slot,
    }


def power_port(model):
    """One documented supply inlet; unknown ratings remain unset observations."""
    return {
        "name": "Power Input",
        "type": PSU_CONNECTORS[model],
        "maximum_draw": None,
        "allocated_draw": None,
        "power_factor": None,
        "source": {
            "method": "reviewed-profile",
            "profile": PROFILE,
            "documentation": C6_DATASHEET_URL if model.startswith("PWR-C6-") else DATASHEET_URL,
            "section": "Power supply input receptacles, table 16"
            if model.startswith("PWR-C6-")
            else "Power supply input receptacles, tables 21 and 22",
            "model": model,
            "meaning": "One inlet on the identified PSU; upstream feed/cable is unknown",
            "unresolved": {
                "maximum_draw": (
                    "Output capacity and voltage-specific total-input ratings do not establish "
                    "an unconditional maximum input draw"
                ),
                "allocated_draw": "No operator power allocation is supplied by discovery",
                "power_factor": "No documented or measured power factor is available",
                **(
                    {"type": "Inlet connector has not been reviewed"}
                    if not PSU_CONNECTORS[model]
                    else {}
                ),
            },
        },
    }
