# Reported hardware discovery

IOS XE discovery uses reported identity, classification and relationships before
optional product profiles. An unfamiliar chassis or component PID does not by
itself block collection. The target Device and its matching DeviceType must
already exist, and the switch must expose the supported RESTCONF JSON schemas.
No custom fields, CLI fallback or product-name heuristics are used.

## Interfaces with unknown capability

An observed interface can be created with Nautobot's native `Other` type when
`interfaces-oper` explicitly reports the IANA Ethernet classification, its
administrative state is known, and its canonical name identifies an ordinary
native physical Ethernet interface. `Other` means maximum physical capability
is unresolved; it does not infer a connector, cage type or speed rating.

The report retains `physical_ethernet_source` and the plan's
`unknown_interface_capabilities`. Known descriptions, MAC addresses, MTU,
administrative state, explicit RJ45 media and ready-link operational speed
remain eligible. Down-link nominal speed does not become operational speed.
Duplex remains blank when Nautobot cannot represent it without a known copper
type. An existing populated type or a unique DeviceType template takes priority.
Discovery never automatically upgrades a populated `Other` value later.

Subinterfaces, breakout lane names, internal interfaces, unsupported logical
families and interfaces without explicit Ethernet classification cannot use
this physical fallback. Existing interfaces remain preserved.

## Component identity and placement

| Evidence | Native outcome |
| --- | --- |
| Unique physical hardware PID/serial, matching platform identity and reported manufacturer | Resolve or create Manufacturer and ModuleType, even when placement is unresolved |
| Compatible reported component classes, explicit replaceability/presence and a parent reference resolving to a verified chassis or Module | Create an installed Module and its reported attachment bay |
| Identity known but parent, presence, class or replaceability unresolved | Preserve the catalog identity; keep installed placement unresolved in the report |
| Manufacturer, PID or serial unavailable, or identity ambiguous | Retain the observations; do not infer the missing identity |
| Documented capability or independently reviewed relationship | Enrich using the optional hardware profiles |

The generic path recognizes the published hardware classes for network modules,
transceivers, power supplies, fan trays and SSDs. These are YANG enumeration
meanings, not per-PID lists. A new BiDi PID needs no catalog entry in the code.
Exact trimmed PID/serial joins corroborate identity; numeric inventory indexes
never join sources. Reported manufacturer names are used directly, rather than
assuming Cisco from the device vendor or PID spelling.

Reported `state/parent` references and unique component names establish a parent
chain to a serial-verified physical chassis. Cycles, unresolved parents,
incompatible classifications and unclear presence remain unresolved. Existing
reviewed rules run first and retain their safeguards for known Cisco quirks.
The generic path cannot bypass a rejected reviewed placement.

Generic attachment bays use the reported component name as an opaque name and
position identifier. They describe an observed attachment to the reported
parent; location strings are never decoded into slot numbers. Physical labels
remain blank, and no unobserved empty bay is created. The bay identifier is
independent of the occupant PID and serial. Existing occupied bays, serialized
assets and populated ownership are preserved; replacement or relocation needs
operator review.

Generic transceiver placement also requires agreeing canonical hardware/platform
interface names and an explicitly classified observed physical Ethernet port.
Logical, subinterface and breakout aliases cannot establish a cage. When an
ordinary three-coordinate name reports a member, it must agree with the verified
parent's member. A reported chassis parent permits device-level attachment;
discovery does not invent a nested uplink parent. A reported module parent
permits nesting after that module is independently resolved.

Generic components do not claim Interface ownership, create power inlets, infer
connector types, copy capabilities from negotiated speed, or populate printed
labels. Reported identity and observations are retained separately from these
unknown facts. `platform-oper` version can mean hardware, firmware or software;
the generic hardware revision comes only from the explicit hardware inventory
version, and remains report evidence rather than a custom field.

## Optional profiles and future hardware

The [Catalyst hardware library](catalyst-hardware-profiles.md) supplies documented
maximum port capability, compatible uplink regions and reviewed placement
conventions. The [PSU library](power-supply-discovery.md) supplies documented
empty bays and inlet specifications. They improve detail without becoming
requirements for basic identity or reported containment.

For new hardware such as a 9350, identity, supported interface configuration and
IPAM can proceed when the existing schemas provide valid evidence. Unmapped
Ethernet interfaces use `Other`; unmapped connector, power and cage details stay
blank. A different or missing schema may still need an adapter change. This
increment validates constructed unlisted-chassis sources, not a live 9350.

## Validation

The `0.17.0-dev` increment passes 684 offline tests and 150 rollback-only checks
against Nautobot 3.2.5, leaving zero persistent test changes. Constructed unlisted
chassis and component sources cover unknown-capability interfaces, identity-only
catalogs, generic module/PSU/fan placement, nested optics and repeat-run idempotence.
Ambiguous identities, missing parents, incompatible classes, cycles and optical
subinterface/breakout aliases remain unresolved.

Live RESTCONF collection on the C9300-48UXM running IOS XE 17.18.4 validates without
inventory writes. Queued dry-run and apply runs both succeed with guessing disabled
and preserve existing inventory, IPAM, ownership, cables and custom fields. The
apply repeat proposes no changes. Existing unresolved observations and the
populated `Vlan2` type conflict remain preserved. Unlisted hardware creation is
validated by fixtures and native models, rather than a live 9350.

Primary semantics:

- [Cisco hardware inventory YANG](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/Cisco-IOS-XE-device-hardware-oper.yang)
- [Cisco component identity and parent YANG](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/Cisco-IOS-XE-platform-oper.yang)
- [Nautobot Interface choices](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/dcim/choices.py)
- [Nautobot ModuleType identity](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/moduletype/)
- [Nautobot ModuleBay containment](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/modulebay/)
