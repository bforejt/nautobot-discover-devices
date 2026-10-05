# Nautobot device discovery

`Discover Device` verifies an existing Nautobot Device against structured facts
from the device, then fills missing identity, interface, console connector,
reported serialized hardware inventory, scoped 802.1Q assignments, configured
static IPv4/IPv6 addressing, and explicitly mapped named VRFs. The first adapter
supports Cisco IOS XE switches on 17.9
or later using RESTCONF JSON exclusively. PAN-OS schema v1 adds SSH/XML identity
and conservative interface collection. Version `0.20.0-dev` records
separate applied and runtime HA/IPsec facts under `observations.ha` and
`observations.vpn`; these facts are report-only. The
[HA/VPN collection contract](docs/panos-ha-vpn-collection.md) defines source
scope, privacy and collection limits. Version `0.21.0-dev` adds
[static PAN-OS IPAM processing](docs/panos-ipam-discovery.md) with explicit
vsys/virtual-router mappings to existing Namespaces and VRFs. The
[capacity contract](docs/panos-capacity-discovery.md) in `0.22.0-dev` adds
Palo-only processing of existing Device capacity fields: verified VM core count
may fill `vcpus`; memory and primary-disk capacity remain unresolved until their
structured source meanings are established. The
[VM-Series validation contract](docs/panos-vm-validation.md)
defines explicit UUID binding for PA-VM on KVM and reviewed virtual templates;
the [first-pass history](docs/panos-discovery.md) records initial lab evidence.
Physical-appliance capability remains unresolved.
The job defaults to a preview.

This project targets Nautobot 3.2. Native `SoftwareVersion` is used for
the main Device software field; that model requires Nautobot 2.2 or later.
Nautobot 3.2.5 and 3.2.6 have been tested. Compatibility with older releases is not
claimed until the same implementation has been tested on them, including native
Module inventory and template suppression.

Verified on the lab's Nautobot 3.2.5 and C9300-48UXM running IOS XE 17.12.8
and 17.18.4.
The PAN-OS live helper also validated PA-VM 11.2.8 on KVM with strict SSH trust
and guessing disabled: it created two virtual interfaces, filled software
version 11.2.8, preserved blank serial, and repeated with zero inventory DML.
A third unconfigured guest adapter was observed and deferred at that checkpoint. Normal
queued preview/apply/repeat then preserved that populated baseline; a queued
wrong-UUID apply failed without changing inventory. See the
[VM-Series evidence](docs/panos-vm-validation.md) for the exact scope and lab
endpoint setup. The HA/IPsec increment subsequently passed live collection on
the active/passive pair and VPN peer, 904 offline tests, 22 PAN-OS and 150 Cisco
native rollback checks on Nautobot 3.2.6, and an installed/queued preview with
unchanged inventory. Its facts remain report-only.
The static IPAM increment passed 970 offline tests and 189 native rollback
checks. It also validated live dual-stack Job preview/apply/repeat inside an
outer rollback.
The [IPAM contract](docs/panos-ipam-discovery.md) records explicit mapping setup,
HA sharing deferral, native model behavior and compatibility limits.
The Cisco live worker apply created 57 missing interfaces and enriched one existing
interface; a second worker apply produced zero inventory changes. Real ORM
checks verified software catalog creation, fill-only
updates, repeat-run idempotence, and rollback after an injected late validation
failure. All temporary integration changes were rolled back.
The LAG increment also linked `TwoGigabitEthernet1/0/22` and
`TwoGigabitEthernet1/0/23` to `Port-channel1` using the switch's configured data.
The serialized-component worker apply created two ModuleTypes, two ModuleBays,
and two Modules: the `C3850-NM-4-1G` uplink module (serial `FOC1928CGGZ`) and
`PWR-C1-1100WAC-P` PSU B (serial `DCC2436D3M4`). It adopted the four existing
`GigabitEthernet1/1/1`–`GigabitEthernet1/1/4` interfaces into the uplink Module.
All 58 interface UUIDs, names, and LAG assignments were preserved. A second
worker apply produced zero catalog, bay, module, interface, or LAG changes, with
equal inventory snapshots before and after.
The switching, speed, and connector increment is described below; these recorded
worker results cover the earlier interface and serialized-component increments.

## Install and run

The lab development copy is installed and enabled as **Device Discovery →
Discover Device**, from the shared Jobs package
`/opt/stacks/nautobot-composer/jobs/nautobot_discover_devices/`. Choose
`9300-lab` and keep Dryrun checked. For this lab's self-signed HTTPS
certificate, uncheck Verify TLS. Default status fields can remain empty.
Verify TLS defaults to enabled on each new form; uncheck it for both preview
and apply runs against this lab switch.
Local preview and ORM verification reports are in the ignored `artifacts/`
directory of this workspace.

Provide this repository through Nautobot's Git Repositories datasource with
`Jobs` selected as provided content. Sync the repository, then enable
`Device Discovery / Discover Device` in Nautobot's Jobs administration. The
`jobs/__init__.py` entry point registers the job. Workers need Nautobot and
`requests`; PAN-OS workers also need `netmiko` (which supplies Paramiko).
Repository synchronization does not install Python packages.

Before running, select an existing Device with:

- A Cisco DeviceType whose model matches the structured chassis part number.
- An IOS XE Platform (`cisco_ios` or `cisco_iosxe` network driver, or an IOS XE
  platform name).
- A primary management IP, or a DNS-resolvable Device name.
- A Secrets Group providing a username and password. Credential lookup tries
  supported RESTCONF, HTTP, REST, then Generic access types.
- RESTCONF reachable over HTTPS and permission to read the required models.

For PAN-OS, select an existing Palo Alto Networks DeviceType and a PAN-OS
Platform (`paloalto_panos` or `panos`). SSH credentials resolve SSH then Generic
access in the selected Secrets Group. SSH host-key checking defaults to enabled
and reads the worker account's known hosts. Use the explicit host-key checkbox
for a lab connection without installed keys. For PA-VM reporting family `vm`
and VM mode `KVM`, the optional **Expected PAN-OS VM UUID** input must match
the exact structured system UUID independently verified on the hypervisor.
When the firewall supplies no serial, this permits a blank selected Device
serial to remain blank while preserving all populated serial and
physical-appliance identity checks. It does not
require a license or create a serial/custom field. Review exact DeviceType
interface templates and explicit applied up/down state before creating guest
adapters; omitted/automatic state remains unresolved. Cisco-only inventory
options and the guessing checkbox do not grant PAN-OS new mapping/default rules.

The job form contains these inputs:

| Input | Default | Behavior |
| --- | --- | --- |
| Device | Required | Existing Device to verify and enrich |
| Dry run | Enabled | Collect, compare, and validate without inventory writes |
| Verify TLS | Enabled | Verify the device HTTPS certificate |
| RESTCONF port | 443 | Cisco HTTPS port |
| SSH port | 22 | PAN-OS SSH port |
| Verify SSH host key | Enabled | Validate PAN-OS host keys against worker known hosts |
| Expected PAN-OS VM UUID | Blank | Bind selected PA-VM/KVM inventory to an independently verified guest UUID; permit an absent serial without fabricating one |
| Maximum VPN flow details | 256 | PAN-OS limit, 1–65535; fail before detail reads if the complete flow summary exceeds it, with no partial VPN result |
| Secrets Group | Device's group | Optional credential override |
| Interface status | Applicable `Active` | Status for newly created interfaces |
| Software version status | Applicable `Active` | Status for newly created software versions |
| Module status | Applicable `Active` | Status for newly created serialized Modules |
| VLAN Group | None | Explicit Layer-2 domain required for VLAN catalog and interface switching writes |
| VLAN status | Applicable `Active` | Operator-selected status for newly created VLANs |
| Use NTC defaults when guessing | Disabled | Apply the reviewed Network to Code Device Onboarding fallback for eligible down dynamic switchports and Nautobot's 0.95 power-factor default for new PSU inlets; mark inferred values in the report |
| Default IPAM namespace | None | Cisco: select an existing Namespace to enable static IPv4/IPv6 and VRF reconciliation; blank keeps IPAM report-only |
| PAN-OS routing domain mappings | Blank | JSON list of exact vsys/virtual-router bindings to existing Namespace and VRF identifiers; explicit `null` VRF selects global routing, blank keeps PAN-OS IPAM report-only |
| Override IPAM namespace | None | Optional Namespace for RFC1918 and manually entered override networks |
| Use override for RFC1918 | Enabled | With an override selected, match the three exact IPv4 RFC1918 ranges |
| Additional override networks | Blank | IPv4 or IPv6 network CIDRs, one per line, combined with RFC1918 matches |
| Create missing networks | Enabled | Create exact connected Network Prefixes attached to the Prefix Location |
| Group matching user VRF names across devices | Disabled | Explicitly group matching user VRF names within one Namespace |
| Keep these VRF names device-local | `Mgmt-vrf` | Exact exceptions to grouping, one per line |
| Prefix Location | Closest Site ancestor, otherwise Device Location | Optional Device ancestor override; Location Type must permit Prefixes |
| New Prefix status | Applicable `Active` | Status for newly created connected Prefixes |
| New IP Address status | Applicable `Active` | Status for newly created configured IPv4/IPv6 hosts |

Start with Dry run enabled. The main job log shows progress, readable change
counts, and brief notices for preserved differences and skipped observations.
Only changes with nonzero counts are listed; a repeat run explicitly says when
no inventory changes are needed. Preview messages say "Would add" or "Would
update"; apply messages say "Added" or "Updated" after changes are saved.
Documented defaults, dynamic switchport configuration, and interfaces where
switchport VLAN mapping does not apply are informational. Missing source data,
unsupported interpretations, and preserved inventory disagreements remain
warnings. A missing model/serial warning explains why serialized hardware was
not created; it does not report a failed write. Reviewed interface-type
conflicts identify the interface and the preserved/discovered choice labels.
Enabling the NTC fallback produces an explicit opt-in notice and inference
counts. Matching policy observations are counted separately from new inferred
VLAN assignments, so a repeat can report eligible ports while making zero
inventory changes.

Open **Advanced → Worker → Meta → discovery_report** for the complete discovery
result data, or download the attached `discovery_<device UUID>.json` report.
The job does not return the large report into the main **Result Data** field.
The Advanced data and download include discovered facts,
structured source fields, YANG module revisions when available, request
metadata, TLS/SSH verification, port, expected VM UUID and NTC-fallback settings,
proposed changes, conflicts,
exclusions, and missing interfaces. Individual warning messages and field
conflict values are kept in that report. Expected discovery failures log the
cause and retain the report under Advanced, as well as attaching a download,
without terminating the Celery worker. If the download cannot be attached,
the report remains available under Advanced.
Run again with Dry run disabled to apply the current discovery. The apply path
re-reads inventory under locks, rebuilds the plan, validates the complete
change set, and saves it in one database transaction.

Dry run still produces Nautobot's ordinary JobResult and report attachment;
it issues no inventory INSERT, UPDATE, or DELETE statements, including software
and module catalogs, Module Bays, Modules, interface ownership, VLANs, and
tagged-VLAN relationships. Unsaved catalog and component objects are validated
before an apply is offered.
Cisco requests are GET-only in both modes. PAN-OS inventory uses three exact
read-only SSH commands for system, operational interfaces and applied configuration.
PA-VM reporting family `vm` and VM mode `KVM` also requires the documented
`debug show vm-series interfaces all` XML read, because healthy operational
views can omit recognized guest adapters. Its failure blocks collection;
physical targets retain those three inventory reads. HA/VPN observations add
six fixed reads for applied deviceconfig/network ancestors, HA state, IKE SAs,
IPsec SAs and the flow summary, plus one fenced numeric detail read per flow.
IPAM reuses the network parent and adds one fixed applied vsys-parent read
for explicit interface imports; no address or routing-domain name enters a query.
Applied configuration and runtime stay separate, with no HA/VPN inventory
writes or Nautobot VPN model imports. A blank IKE response remains unknown
with a static unresolved reason; it is never converted to zero SAs. Session
presentation settings prepare XML output. No unstructured output fallback is
present. Authentication values and raw response bodies are omitted
from request diagnostics. The report contains inventory facts such as serials,
MAC addresses, and descriptions.

## Catalyst hardware library

Documented exact chassis and uplink profiles cover Catalyst 9300/9300L/9300LM/
9300X and 9500/9500X families. They classify only eligible observed interfaces
using documented physical capability and compatible installed-module identity.
The [hardware library reference](docs/catalyst-hardware-profiles.md) lists exact
PIDs, regions, compatibility, source evidence and unresolved special cases.
These profiles enrich physical capability and reviewed placement. Unlisted
chassis and parts can use [reported hardware discovery](docs/reported-hardware-discovery.md)
without a product matrix: explicit Ethernet ports use `Other` when capability
is unknown, and reported component identities/parent references remain eligible.
9500-specific serialized placement conventions remain deferred; generic
containment can proceed when the returned data meets the same evidence rules.

## Initial interpretation rules

| Discovery fact | Nautobot behavior |
| --- | --- |
| Native hostname | Fill blank `Device.name`; preserve and report populated disagreement |
| Chassis serial | Fill blank `Device.serial`; populated disagreement blocks apply |
| Chassis model | Verify existing DeviceType; disagreement blocks apply |
| Multiple ready StackWise members | Create or reuse a native VirtualChassis and serial-matched member Devices; record positions, priorities and active master |
| Provisioned install release | Fill blank native software field using a matching platform SoftwareVersion, creating one if needed |
| Present interface | Match canonical name within the Device; create missing or enrich blank fields |
| Configured channel-group | Fill blank member `Interface.lag` with its discovered port-channel |
| Explicit Ethernet with unknown capability | Create with native `Other`; retain known facts and flag unresolved capability |
| Complete reported component identity | Match or create native Manufacturer and ModuleType independently of placement |
| Verified reported or reviewed component placement | Match or create native ModuleBay and Module inventory |
| Reviewed module interface ownership | Fill blank `Interface.module` using the existing interface record |
| Ready physical interface speed | Fill blank `Interface.speed` in Kbps from the structured operational value |
| Explicit operational RJ45 media | Fill blank `Interface.port_type` with `8p8c` |
| Configured copper duplex | Fill blank `Interface.duplex` from explicit configuration or the narrowly reviewed configured default |
| Reviewed dedicated management hardware | Mark the confirmed `Gi0/0` as management-only using the narrow purpose-correction policy below |
| Reviewed physical console connectors | Create or adopt native ConsolePorts, preserving existing names, UUIDs and cables |
| Configured static IPv4/IPv6 and named VRFs | Reconcile connected Prefixes, hosts and explicit routing memberships after a default Namespace is selected; otherwise report-only |
| Supported user VRF import/export targets | Fill empty native RouteTarget associations from complete literal policy; preserve populated sets and management isolation |
| Negotiated and MAC duplex | Retain as observations; never substitute for the configured duplex setting |
| Supported configured 802.1Q bundle | Fill blank mode and VLAN assignments in the selected VLAN Group |
| Directly reported ordinary dynamic access/trunk mode | Use the actual mode with known configured VLAN policy to fill the existing 802.1Q fields |
| Known configuration with unresolved forwarding mode | Retain separate access/native/allowed settings and provenance in the report; leave unsupported native assignments blank |
| Eligible down dynamic switchport with NTC fallback enabled | Fill blank 802.1Q mode as `tagged-all` and assign its known native VLAN, with explicit inference provenance |
| Complete structured VLAN database | Reconcile all named VLANs in the selected group, including VLANs without current interface membership |
| Absent alias / internal application port | Exclude and explain |
| Existing interface absent from discovery | Report; preserve |

“Blank” means `None` or empty text. Explicit `False`, zero, and the interface
type `other` are populated values. Existing descriptions, MTUs, MACs, types,
administrative settings, speeds, duplex values, names, UUIDs, and statuses are
preserved when populated; existing LAG and VLAN assignments are also preserved.
Differing observations
appear as conflicts. Interfaces are never
deleted or renamed. Serial/model conflicts, incomplete identity, and ambiguous
canonical names block application. The documented dedicated-management purpose
correction below is the only exception that changes an existing Boolean `False`.

The software release comes from explicit `install-oper` version/state leaves.
An uncommitted provisioned release takes precedence over an older committed
release. Numeric build suffixes are retained as evidence while releases such
as `17.12.8` and `17.12.08.0.770` match as `17.12.08`. Software banners are
not parsed. Unsupported image extensions require another interpretation increment.
For multiple physically present StackWise members, the provisioned installation
release must be established for every member and agree across the stack.

Interfaces include present physical ports, management ports, SVIs, loopbacks,
and port-channels. Disconnected ports remain eligible. Administrative state
maps to `Interface.enabled`; operational state remains an observation and does
not change lifecycle status. The supported fields are type, enabled, description,
MTU, MAC, operational speed, supported connector type, documented management-only
purpose, and configured 802.1Q assignments, including directly reported
access/trunk selection for ordinary dynamic ports when available.
Configured static IPv4/IPv6 and named VRFs are reconciled through the selected
Namespace policy below. Generated or link-local IPv6, dynamic addressing, shared/FHRP addressing,
cables, unreviewed transceiver placements, and additional component profiles
are future increments.

LAG membership comes from native interface configuration's structured
`Cisco-IOS-XE-ethernet:channel-group/number` leaf. The collector includes
configured members even when they are down or not currently bundled, across
LACP, static, and PAgP modes. It links physical members to a `lag` interface on
the selected Device, matching short and long names. Preview validates both
existing and newly planned parents without saving. Apply creates interfaces
before assigning relationships, in the same transaction. A populated
different assignment is reported as a conflict; it is never moved or cleared.
Unavailable membership data produces a warning and preserves existing links.

Physical type comes from an explicit hardware capability mapping or an
unambiguous existing DeviceType interface template, never negotiated link
speed. The expanded [hardware library](docs/catalyst-hardware-profiles.md) covers
exact documented 9300 and 9500 PIDs; the original lab mappings remain:

- `C9300-48UXM`: access ports 1–36 are 2.5G copper; ports 37–48 are 10G copper.
- Its management `GigabitEthernet0/0`: 1G copper.
- Installed `C3850-NM-4-1G`: four 1G SFP uplink ports for the identified member.
- SVIs and loopbacks: virtual; port-channels: LAG.

An explicitly reported ordinary Ethernet port with known administrative state
can be created with native `Other` when its physical capability is unknown.
Unclassified ports or ports with unknown administrative state skip creation
with an explicit warning. Existing interfaces can still receive independently
known blank fields; populated types are preserved.

## IPAM and named VRFs

For PAN-OS, use **PAN-OS routing domain mappings** and the
[static IPAM contract](docs/panos-ipam-discovery.md). Static addresses require
explicit applied routing membership and standalone HA-disabled evidence.
Existing exact logical Interfaces are supported; HA shared-address ownership
remains unresolved.

For Cisco, select **Default IPAM namespace** to enable configured static IPv4/IPv6 and named
VRF reconciliation. Leaving it blank keeps IPAM report-only even when other
inventory changes are applied. To use the common split, choose **Internet** as
the default, **Corporate** as **Override IPAM namespace**, and leave **Use override
for RFC1918** checked. Add internally used public ranges or other exceptions to
**Additional override networks**, one IPv4 or IPv6 network CIDR per line. Add
`fd00::/8` explicitly if ULA should use the override. Unchecking
RFC1918 makes only those manual networks match. The names are operator labels;
all unmatched addresses use the default without an inferred public designation.

The complete connected network must resolve to one selected Namespace.
A rule covering only part of its reported subnet remains unresolved. Discovery
uses explicit configured host/mask data, including shutdown interfaces and
secondary addresses. With **Create missing networks** enabled, an absent
connected Prefix is created as a Network and attached to **Prefix Location**.
The default Location is the closest Site ancestor or the Device's own Location;
its Location Type must permit Prefix records. Existing network types, Locations,
IP masks, populated Interface VRFs, statuses and assignments stay preserved.

New named VRFs are device-local by default: local `Mgmt-vrf` on `switch-A`
becomes canonical **switch-A / Mgmt-vrf**, with the actual name and reported RD
stored on its VRF Device Assignment. Unused named VRFs are included; newly
created ones without static addressing use the default Namespace. Existing Device Assignments
establish identity on repeats, including after a Device rename. **Group matching
user VRF names across devices** explicitly enables shared names within a
Namespace; **Keep these VRF names device-local** defaults to `Mgmt-vrf` and
retains local exceptions. One named VRF cannot span the two selected Namespaces.
Changing grouping does not migrate existing assignments.

The preview lists rule matches, VRF identities, networks, hosts, assignments and
hierarchy effects. More specific Prefixes can reparent existing inventory;
changes to inherited VRF associations, incompatible masks, duplicate/shared
hosts, exclusive ranges and conflicting site scope are deferred or blocked.
DHCP, unnumbered, generated and link-local IPv6 remain observations. Both address
families within a named VRF must select one Namespace. Device primary IPs are preserved.
No custom fields are created. Namespace policy is independent of NTC guessing.

Ordinary user VRFs can also receive supported literal import/export RouteTargets.
Each direction is filled only when empty; conflicting populated sets are preserved.
Management `Mgmt-vrf` targets stay report-only. Address-family policies that cannot
fit one native import/export pair, automatic targets and stitching stay unresolved.
Equal targets do not establish a shared VRF identity. A shared VRF already assigned
to another Device is not enriched from one Device's observations alone.

See [IPAM discovery](docs/ipam-discovery.md) for the exact input fields,
RESTCONF/YANG sources, preservation guards, report structure and test coverage.

## StackWise discovery

Stacking follows NtC Device Onboarding's native VirtualChassis/member model and
`hostname:position` naming for newly created additional members. The selected
Device keeps its identity, interface ownership, addressing and credentials.
Stack role selects the VirtualChassis master independently of member number.
Reported serials join stack nodes to hardware records; response ordering and
physical inventory indexes never establish member identity. Standalone switches
remain standalone, and provisioning alone cannot create a physical Device.

See [stacking.md](docs/stacking.md) for the source fields, preservation rules,
differences from NtC, and current placement limits. Each member's verified running
release fills its native software-version field using its own Platform. Reviewed
PSU bays, assets and inlets, network modules, nested SFPs and physical console
connectors belong to their serial-matched member Devices. Network interfaces stay
on the selected Device; cross-member Module links are deferred separately.

## Console and dedicated management ports

The physical console profile is limited to validated `C9300-48UXM` chassis,
including each confirmed stack member. Cisco documents a rear RJ45 console connector and a
front five-pin USB mini-B console connector for this model. The collector uses
that reviewed hardware specification and observed chassis PID as evidence,
independently of **Use NTC defaults when guessing**. It records the profile,
model, source leaf, document URLs, and physical position in each fact.

These connectors become native Nautobot `ConsolePort` records with types
`rj-45` and `usb-mini-b`. They are not Ethernet Interfaces or ConsoleServerPorts.
Names default to **Console RJ45** and **Console USB**; their provenance identifies
them as discovery-standardized names. Faceplate labels remain blank without
verified label evidence. The USB Type-A storage connector is not inventoried as
a console connector.

An existing unique chassis connector of the same type is adopted without
changing its name or UUID. A unique matching DeviceType template supplies a
preferred creation name. Ambiguous templates/ports block application; an
unidentified existing connector defers creation, and matching Module-owned
ports remain attached to their Modules. Populated labels, descriptions,
connector types, and cables are preserved. The job never creates cable links
or guesses a remote console-server endpoint.

The native `console=0` configuration represents one logical line shared by
both connectors; its settings are not copied to other stack members. Explicit
speed, receive/transmit speeds, data bits, parity,
stop bits, and configured medium are structured report observations. Missing
settings remain unknown; the factory baud rate is not assumed. Disagreeing
receive/transmit rates do not establish one baud rate. Nautobot 3.2.5 has no
native ConsolePort fields for these serial settings, so no custom fields are
created or populated. Targeted reads never retry with an unfiltered terminal
configuration, which could include credentials. Optional configuration gaps
do not invalidate confirmed physical connector inventory.

The observed dedicated `GigabitEthernet0/0` is marked `mgmt_only=True` only
when its reviewed chassis/port profile establishes exclusive out-of-band
purpose and its physical type is compatible. Nautobot defaults this field to
`False`; changing it to `True` for this documented port is an explicit narrow
exception to ordinary fill-only reconciliation. Discovery never sets it to
`False`, marks an SVI from its reachable address, or replaces populated type,
connector, Module ownership, LAG membership, or VLAN settings to make the
classification fit. Those incompatible settings defer the purpose correction
and remain visible as conflicts.

Management VRF definitions and configured static IPv4/IPv6 addresses are
collected separately under `discovery.management`. Operational address values
remain observations: `0.0.0.0` is not assigned, and an IPv6 address without a
prefix length does not establish a mask. DHCP, autoconfiguration, EUI-64 and
anycast flags retain their explicit meaning. The broader `discovery.ipam`
collector supplies static IPv4/IPv6 and all named VRF facts independently of this
hardware profile. Select the Namespace policy above to enable those writes;
Generated/link-local IPv6 and dynamic addressing stay observation-only. Existing primary IPs and
populated assignments remain preserved.

The lab exposes shutdown `Gi0/0` in `Mgmt-vrf` with no configured address;
its existing primary management address belongs to `Vlan2`. Its console line
explicitly reports one stop bit, with baud rate and other omitted settings
unresolved. See [Cisco's connector specification](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/b_c9300_hig/connector-cable-specs.html),
[model diagrams](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/b_c9300_hig/Product-overview.html),
and [management-port guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9300_cg/configuring_ethernet_management_port.html).

## Serialized components

Uplink and transceiver profiles cover explicitly compatible documented 9300-family
chassis and uplink modules, with independently corroborated slot-1 placement.
The existing `C9300-48UXM` / `C3850-NM-4-1G` lab mapping is preserved.
Generic classification and explicit parent references also support unlisted
chassis and parts. Unknown capability, connector and physical label remain blank;
unknown containment permits catalog identity without an installed Module. See
[reported hardware discovery](docs/reported-hardware-discovery.md). Specific
9500 slot conventions await verified structured evidence. See the
[hardware library](docs/catalyst-hardware-profiles.md) for exact coverage.
PSU profiles cover exact reviewed C9300, C9300L,
C9300LM and C9300X chassis and compatible power supplies. Resolved parts use
Nautobot's native `ModuleType`, `ModuleBay`, and `Module` models and
appear in the normal module inventory GUI. The Device's module bays represent
placement; its uplink interfaces reference their installed Module. Existing
interfaces are adopted in place, preserving UUIDs, names, Device association,
and LAG membership.

To review the lab result, open `9300-lab` and its **Module Bays** tab. Inspect
**Uplink Module 1** and **Power Supply B**, then open the installed uplink
Module's **Interfaces** tab to review its four ports. Each Module's **Module
Type** link opens the corresponding PID catalog record. These labels and paths
were checked against the installed Nautobot 3.2.5 views and templates.

Identity comes from `device-hardware-oper`; a unique trimmed PID plus serial
joins it to `platform-oper` for parent and location validation. The two sources
use different numeric indexes, which are retained as evidence and never used
to join records. Interface ownership follows the reviewed hardware and slot
profile: this switch does not report an explicit uplink-to-interface child
relationship. The report identifies that interpretation and its sources.

Component reconciliation is fill-only. Populated identities, occupied bays,
module placement, and interface ownership are preserved; conflicting
observations are reported. Modules and bays are never automatically deleted or
moved, and interfaces are never reassigned from an existing Module. ModuleType templates
are suppressed during new Module creation so they cannot instantiate duplicate
ports before the discovered interfaces are adopted. On a release without the
required suppression support, populated templates block apply.

PSU A and three fans in the lab have no structured PID or serial and remain
unresolved assets. Both documented PSU bays can be created independently of
asset identity. A disabled PSU reporting `no-input` does not establish that its
bay is vacant; no recorded Module means that no identified asset is recorded.
Unlisted serialized parts can retain their reported catalog identity, and
explicit parent relationships can establish placement. Missing or ambiguous
identity and placement remain unresolved with their source evidence. Exact
reviewed stack aggregate aliases are excluded; matching a chassis serial alone
does not exclude another component.

Identified PSUs can own native PowerPorts with documented inlet connector
types. Strict mode defers new inlets when their required power factor is
unknown. The existing guessing option permits Nautobot's 0.95 default and marks
it as inferred. Existing inlet values and cables are preserved; output ratings
and operational readings do not become configured input draw. See
[power-supply-discovery.md](docs/power-supply-discovery.md) for coverage,
stack-member placement and validation.

Optics installed in corroborated, documented 9300 optical uplink ports are
serialized native Modules in nested ModuleBays under the uplink Module, following
[Nautobot's documented transceiver model](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/modulebay/).
The existing `c9300-48uxm-c3850-nm-4-1g-transceivers-v1` lab profile and
new documented uplink profiles require a physical,
field-replaceable `hw-type-transceiver`, complete PID/serial, a unique matching
platform identity, explicit nonempty presence, and agreement between the
hardware interface name, platform component name, and an observed eligible
uplink port. The parent uplink Module must itself pass discovery. Individual
port placement comes from those matching names and the resolved module port
region; copper uplinks cannot establish optical cages. Exact documented
interface aliases are normalized before the identity comparison; numeric inventory
indexes and the generic location string do not identify an individual SFP slot. Platform `comp-port` and
`removable=False` are retained as the observed lab representation; the explicit
hardware transceiver classification establishes the serialized asset type.

Manufacturer comes from the platform's structured `state/mfg-name` leaf, whose
[YANG definition](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17111/Cisco-IOS-XE-platform-oper.yang)
explicitly permits a component vendor different from the device vendor.
Whitespace is trimmed without replacing vendor names or assuming Cisco from a
Cisco-compatible PID. A missing Manufacturer can be created only from this
reviewed source evidence, with its exact reported name; ambiguous matches block
apply. New manufacturer and ModuleType catalog entries validate before saving
and participate in the same atomic transaction as the asset. Catalog records
from reviewed asset-only sources are not created for a blocked occupied slot.
The generic reported-identity path can resolve catalogs independently of placement.
Missing manufacturer or identity prevents catalog creation; missing parent or
placement evidence keeps installation unresolved.

The lab SFP reports `GLC-SX-MM`, serial `ZZ306221998`, revision `V03`, and
manufacturer `CISCO-EQUIV` on `GigabitEthernet1/1/1`. Its nested bay identifies
that port. Existing interfaces keep their UUIDs, names, uplink Module ownership,
LAGs, and cables: discovery does not reassign a populated Interface.module to
the SFP or create duplicate interfaces. The report retains the exact associated
interface and the reviewed nesting interpretation; Nautobot has no separate
native SFP-to-existing-Interface association. Hardware revision remains a report
observation because Module has no corresponding native field. No connector,
optical specification, absence, replacement, or relocation is inferred from
the PID, link state, or operational speed. No custom fields are used.

## Switching and interface fields

Choose a **VLAN Group** explicitly to enable switching writes. The job does not
infer the Layer-2 domain from a VID or create a group. Without a selection,
switching observations remain unresolved while independently usable identity,
interface, and component discovery can proceed. A selected group must be global
or belong to the Device's location hierarchy. An existing VLAN must likewise be
global or associated with the Device's location or an ancestor.

VLAN identity is the selected group plus VID. Other groups can reuse a VID.
With a successfully read complete structured VLAN database, all observed named
VLANs are eligible for reconciliation, including VLANs with no interface
membership. Earlier discovery schemas without the completeness marker retain
their referenced-only behavior. A new VLAN needs a unique structured name,
and its VID must be from 1 through 4094 and inside the group's allowed range.
New VLANs are global within that group. Missing names or incompatible existing
VLAN locations leave the affected interface bundle unresolved; they never cause
duplicate catalog entries. Existing populated VLAN names are preserved. New
VLAN status comes from the operator's selection, defaulting to an applicable
`Active` status; operational VLAN status is evidence, not lifecycle status.

Configured native-interface JSON supplies explicit access or trunk mode and
the native/allowed VLAN configuration. Access mode requires a known untagged
VID. An explicit trunk allowed list maps to `tagged`, with its native VLAN kept
untagged and omitted from the tagged set. An all-VLAN trunk maps to `tagged-all`
without expanding thousands of tagged relationships. Operational membership,
an SVI, or the absence of switchport configuration does not establish a mode.

The reviewed `C9300-48UXM` profile for IOS XE 17.9, 17.12, 17.15, and 17.18 permits documented
defaults of dynamic auto, access VLAN 1, trunk native VLAN 1, all allowed trunk
VLANs, and disabled global native tagging. These defaults apply only after
successful complete reads of the relevant native configuration and an
identified supported switchport; the report records explicit versus default
provenance. An explicitly configured ordinary access port with an omitted
access VID can therefore receive `access` and untagged VLAN 1. An omitted mode
alone does not establish `access`: dynamic auto can negotiate a trunk. The
optional actual-mode source below can resolve that distinction.

Partial known configuration is retained in **Advanced → Worker → Meta →
discovery_report → discovery → layer2 → settings**, and in the report download.
This includes administrative mode, access VLAN, trunk native VLAN, allowed
VLAN policy, and available source evidence. Access and trunk-native settings
stay separate when they differ. A common untagged VID is recorded only when
their equality and ordinary untagged semantics are established. Even then,
Nautobot requires a nonempty 802.1Q mode before assigning `untagged_vlan`, so a
dynamic port's native mode and VLAN relationships remain blank unless the
complete mapping is established or the operator enables the narrow fallback
below. This increment creates no custom fields.

Management, SVI, and explicitly routed interfaces are classified as not
applicable to switchport mapping rather than missing switchport information.
Dynamic administrative modes without a usable actual-mode source are
informational; source failures, unknown configuration outside a reviewed
default profile, voice VLANs, private VLANs, 802.1Q tunnels, incremental
allowed-list operations, and unsupported native tagging remain unresolved.
Disconnected switchports use the same configuration
and default rules as connected ports.

### Optional operational switchport mode

When the YANG library advertises `Cisco-IOS-XE-switchport-oper`, discovery reads
`switchport-oper-data/switchport-info/port-details/oper-mode`. Cisco's
[published IOS XE 17.14.1 model](https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17141/Cisco-IOS-XE-switchport-oper.yang),
revision `2024-03-01`, defines this as actual status after negotiation. A usable
ordinary dynamic port reported as access or trunk can therefore fill the
existing Nautobot 802.1Q mode as **Access**, **Tagged**, or **Tagged all**, with
its VLAN assignments, without enabling guessing. The configured access/native
VID, allowed policy, and native-tagging checks still determine the VLAN
assignment; operational VLAN IDs or ranges never substitute for configuration.
Explicit configured access or trunk mode retains precedence.

The source's `enabled` leaf means switchport rather than routed operation;
it does not set Nautobot `Interface.enabled`. Usable rows also require present
hardware and compatible ordinary administrative mode. A directly reported
dynamic administrative enum can establish an omitted mode on a complete native
configuration row, but does not extend the reviewed VLAN-default profile to
other models or releases. Reported voice/private-VLAN/tunnel semantics, routed
operation, suspended aggregation, or disagreement with configured LAG membership
block the affected mapping. Down or unknown actual mode leaves unresolved
assignments blank. The existing opt-in down-port fallback remains available
only with its independent link-down proof and other guards; it never replaces
a positive or conflicting actual-mode report.

All raw per-interface facts remain in `discovery.layer2.operational_interfaces`,
including interfaces without a native configuration row. Compatible
configuration rows also retain actual
mode and raw evidence in `discovery.layer2.settings`. Operational VLAN IDs,
pruning, voice, and aggregation details remain observations. This adds no custom
fields or new Interface column. `discovery.layer2.operational_source` records
source status: `not-advertised`, `unsupported`, `unavailable`, `invalid`, or
`available`. A complete YANG library that does not advertise the module skips
the request. If the library is unreadable or invalid, the job probes the
endpoint directly and accepts only validated structured facts, with revision
left unknown. `capability_status` and `probed_without_advertisement` distinguish
library evidence from a direct probe. Partial invalid library results are
discarded rather than supplying module revisions.

The optional operational source uses a 15-second read timeout. HTTP 400 permits
one unfiltered read of the same endpoint; HTTP 404/501 means `unsupported`,
and other expected read failures mean `unavailable`. Successful HTTP responses
with invalid JSON, a non-object body, or malformed or ambiguous structured
replies mean `invalid`: the entire source is discarded, discovery
continues, and NTC mode guessing is disabled for that invalid scope even when
the Job's guessing flag is enabled. Independently validated explicit native
configuration remains usable. No invalid row or partial result becomes a
configured default. Required device identity, interfaces, collector input
validation, cancellation, and unexpected programming errors remain fatal.
There is no new software-version minimum, SSH transport, or CLI parser.
Summary `switching_operational` counts positive access/trunk observations;
`switching_dynamic_resolved` counts complete dynamic bundles resolved from
those observations, rather than newly written assignments.

Operational rows that match the mandatory interface collector's exact excluded
names remain observations with `applicability.eligible = false`, `usable = false`,
and no normalized operational mode. This covers explicitly absent uplink aliases
and the internal application-hosting interface. They cannot create interfaces,
contribute positive mode counts, or supply VLAN assignments. Every excluded row
still receives full schema and duplicate-name validation. A genuinely unknown
name, inconsistent input exclusion, or malformed row is not silently skipped.

The earlier IOS XE 17.12.8 lab did not advertise this module, and a separate read-only
probe returned HTTP 404. Three correctly keyed RESTCONF VTP-MIB probes timed
out after 30 seconds each; the job does not use that alternative. OpenConfig
VLAN `state/interface-mode` represents
[applied configuration](https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/openconfig-extensions.yang#L159),
which does not prove the negotiated DTP result. No device configuration or MIB
access changes were made. The subsequent IOS XE 17.18.4 live validation is
recorded below; positive 17.15 behavior remains covered by schema-based fixtures.

### Optional NTC inference

**Use NTC defaults when guessing** is disabled by default. With it disabled,
unresolved forwarding modes and their native VLAN relationships remain blank.
With it enabled, the job can apply one reviewed policy from
[Network to Code Device Onboarding 5.4.1](https://github.com/nautobot/nautobot-app-device-onboarding/blob/812746dc6f09077b8fe099da2318315e4e7cab23/nautobot_device_onboarding/jinja_filters.py#L86):
a dynamic switchport that is down and permits all VLANs maps to `tagged-all`
with its known trunk-native VLAN. This is an onboarding normalization policy,
not a switch-reported forwarding mode or a Cisco configuration default.

The initial fallback requires a supported physical switchport, known
dynamic-auto/dynamic-desirable configuration, a complete known all-VLAN
allowed policy, a known native VID, and proven disabled native tagging. Its
structured RESTCONF operational state must be exactly `if-oper-state-no-pass`
or `if-oper-state-lower-layer-down`. Up, testing, dormant, missing, and other
states do not qualify. Failed/incomplete reads, malformed data, finite VLAN
restrictions, voice/private/tunnel configurations, and unsupported tagging
semantics remain subject to the existing unresolved or validation behavior.
The flag enables no general guessing of interface or device fields.
An explicit `ALL` setting or the validated exact allowed-list literal
`1-4094` qualifies. Composed ranges that happen to cover the same VIDs and
other finite lists remain excluded for parity with the reviewed upstream
rule. A configured `1-4094` list remains recorded as a configured list;
the separate inference evidence explains the proposed `tagged-all` mode.

The report records `use_ntc_defaults` at its top level. Eligible settings carry
`inference` evidence under `discovery.layer2.settings`; resulting complete
bundles carry `source.ntc_inference`. That evidence identifies the policy,
upstream source, actual RESTCONF operational state and its source, configured
administrative mode, inferred fields, and the assumption being made. Main-log
counts distinguish matching observations from newly planned inferred
assignments. VLAN Group selection, valid catalog identity, location checks,
atomic validation, and existing-value preservation still apply.

Disabling the option on a later run does not erase already populated inferred
inventory: the job's fill-only policy preserves existing mode and VLAN
assignments. Review the original report to identify their inferred origin.

Each interface's mode, untagged VLAN, and tagged set form one fill-only bundle.
A populated disagreement skips the entire bundle. An empty tagged set can be
filled; a populated set must match exactly, with no partial merge, removal, or
replacement. A failed bundle does not independently create referenced VLANs;
the complete VLAN database can still establish those records as device
inventory. Existing UUIDs and manual assignments are preserved. Nautobot clears tagged memberships when
saving an interface outside `tagged` mode, so validation also blocks a save
that would discard existing membership while enriching another field.

Operational speed is accepted only for a ready physical interface, converting
the structured bits-per-second value to Nautobot's Kbps unit. It does not
determine hardware capability. The exact structured media value
`ether-media-type-rj45` identifies an RJ45 (8P8C) connector and can fill blank
`Interface.port_type` with `8p8c` on a physical interface. Connector type is not
inferred from copper capability, speed, or a generic media value. Both fields
follow the same blank-only policy; a later change is reported as a conflict.

Negotiated duplex and MAC duplex status remain report observations, even when
they agree. Nautobot's duplex field is treated as the configured `auto`, `full`,
or `half` setting. A separate complete native RESTCONF configuration read
captures explicit duplex values on supported copper interfaces. A narrowly
reviewed default profile also establishes configured `auto` for
`C9300-48UXM` on IOS XE 17.9/17.12, member 1, fixed
`TwoGigabitEthernet1/0/1`–`1/0/36` and management `GigabitEthernet0/0`, provided
the interface is present in the complete native read with its expected copper
type. Omitted duplex on TenGigabitEthernet, optical, other-member, or unreviewed
ports remains blank. Every accepted value records its configuration/default
source; a ready link or matching operational duplex does not establish it.
Existing populated settings are preserved on disagreement.

See the [Interface field mapping](docs/interface-fields.md) for all native
fields, source evidence, model constraints, deferred routing and relationship
decisions, and version compatibility limits.

## Structured sources

All paths are relative to `https://<management address>:<port>/restconf` and
request `application/yang-data+json`.

| Purpose | RESTCONF data path |
| --- | --- |
| Hostname | `/data/Cisco-IOS-XE-native:native/hostname` |
| Chassis and installed module identity | `/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data` |
| Optional component identity corroboration and placement | `/data/Cisco-IOS-XE-platform-oper:components` |
| Software release | `/data/Cisco-IOS-XE-install-oper:install-oper-data/install-location-information` |
| Interfaces | `/data/Cisco-IOS-XE-interfaces-oper:interfaces` |
| Optional logical console settings | `/data/Cisco-IOS-XE-native:native/line/console=0` with safe terminal-setting fields only |
| Optional management configuration | `/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet=0%2F0` with VRF/address fields |
| Optional management operational evidence | `/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface=GigabitEthernet0%2F0` with VRF/address fields |
| Optional named VRF definitions | `/data/Cisco-IOS-XE-native:native/vrf` with definition name/RD/address-family fields |
| Optional legacy named VRFs | `/data/Cisco-IOS-XE-native:native/ip/vrf` with name/RD fields |
| Optional configured IPAM | `/data/Cisco-IOS-XE-native:native/interface` with safe family/key/VRF/address field filters |
| Configured duplex | `/data/Cisco-IOS-XE-native:native/interface` with scoped qualified `Cisco-IOS-XE-ethernet:duplex` fields |
| Configured LAG membership | `/data/Cisco-IOS-XE-native:native/interface` with qualified `Cisco-IOS-XE-ethernet:channel-group` field filters |
| Configured 802.1Q mode, native VLAN, and allowed VLANs | `/data/Cisco-IOS-XE-native:native/interface` with complete scoped switchport containers |
| Optional actual switchport mode, advertised or directly probed when capability is unknown | `/data/Cisco-IOS-XE-switchport-oper:switchport-oper-data` with `switchport-info(if-name;enabled;admin-mode;hardware-present;port-details)` fields |
| Global native-VLAN tagging configuration | `/data/Cisco-IOS-XE-native:native/vlan` |
| Structured VLAN names and operational evidence | `/data/Cisco-IOS-XE-vlan-oper:vlans` |
| Optional model revision evidence | `/data/ietf-yang-library:modules-state` |

Install/interface/platform requests initially use field filters. A filter
rejection with HTTP 400 triggers an unfiltered JSON read of the same endpoint
and a warning. Missing required data fails discovery. Missing optional YANG revision
evidence produces a warning while successful structured reads remain usable.
Unavailable platform component data leaves serialized parts unresolved and
preserves the usable Device and interface discovery. Malformed or contradictory
serialized identity blocks discovery.
Unavailable switching sources leave affected bundles unresolved; malformed or
ambiguous native configuration or VLAN identity data blocks discovery. Invalid
optional actual switchport data is discarded as described above. Defaults do
not replace failed or incomplete source reads.
IPAM and console/management configuration reads never retry without safe field
filters; unavailable or malformed IPAM sources preserve existing routing
inventory and remain in the report. An HTTP 204 VRF subtree records explicit
absence. HTTPS redirects are rejected. A legacy TLS retry is available only
when the operator explicitly disables certificate verification.

The channel-group mapping follows the published Cisco Ethernet YANG module
for [IOS XE 17.9.1](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/1791/Cisco-IOS-XE-ethernet.yang)
and [17.12.1](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17121/Cisco-IOS-XE-ethernet.yang).
Component placement fields follow the published
[Cisco platform YANG model](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17111/Cisco-IOS-XE-platform-oper.yang).
The accepted parent/location patterns are reviewed profile rules, since the
model represents location as a string.

## Extend and test

The architecture separates four boundaries:

1. `jobs/transport_restconf.py` owns the GET-only JSON session.
2. `jobs/adapters/` converts vendor data into versioned common facts and source evidence.
3. `jobs/reconcile.py`, with component, VLAN and IPAM subplanners, builds a pure,
   deterministic fill-only plan.
4. `jobs/nautobot_inventory.py`, with component, VLAN and IPAM staging helpers,
   validates and applies it through the Nautobot ORM in one transaction.

RESTCONF, credential resolution, payload helpers, and interface naming reuse
selected Apache-2.0 work from `/opt/stacks/nautobot-testsuite`. The discovery
repository is self-contained at runtime. Testsuite CLI fallback paths were
not included.

For the next component or family, capture a sanitized structured fixture,
agree on its interpretation, add an adapter or mapping, review a preview,
then verify the application and repeat-run behavior. Cisco, Palo Alto,
OpenGear, Proxmox, and VMware can add collection adapters while preserving
the reconciliation and Nautobot boundaries. This release's planner accepts
the versioned Cisco IOS XE and PAN-OS adapter schemas.

The [PAN-OS discovery handoff](docs/panos-discovery-handoff.md) preserves the
platform's starting sources, lab prerequisites, modeling decisions and initial
scope. The current [VM-Series validation contract](docs/panos-vm-validation.md)
records UUID binding, reviewed interface templates and live validation evidence.
The [HA/VPN collection contract](docs/panos-ha-vpn-collection.md) records the
report-only extension in `0.20.0-dev`; its reviewed PA-VM 11.2.8 XML shapes do
not establish full OS coverage or native VPN model compatibility on Nautobot 2.4.
The [PAN-OS IPAM contract](docs/panos-ipam-discovery.md) records the explicit
routing-domain policy, static IPv4/IPv6 source requirements and native capability
checks in `0.21.0-dev`.

Run offline regressions without a Nautobot installation or lab credentials:

```bash
python3 -m pip install 'requests>=2,<3'
python3 -m unittest discover -s tests -t . -v
python3 -m compileall -q jobs tests
```

To exercise the actual ORM inside a configured Nautobot environment, run
`tests/nautobot_integration.py` through `nbshell` and `runpy.run_path`. Its
outer transaction always rolls back test inventory changes. The independent
`tools/lab_preview.py` harness performs live collection with the real Job,
checks zero database mutation statements, and captures the JSON report.
Both accept `NAUTOBOT_DISCOVERY_DEVICE_ID`; the preview also accepts
`NAUTOBOT_DISCOVERY_VERIFY_TLS` and `NAUTOBOT_DISCOVERY_REPORT_PATH`.
`tests/nautobot_panos_ipam_integration.py` separately validates explicit PAN-OS
IPAM mappings, native static IPv4/IPv6 assignment, preservation, repeat behavior
and late-failure rollback inside an unconditional outer rollback.

The tests cover structured identity selection, the 71-row alias/presence
fixture, physical capability mapping despite misleading negotiated speeds,
fill-only conflicts, preserved UUIDs, ambiguous names, source gaps,
idempotency, software catalog matching, and the RESTCONF request boundary.
The ORM harness also verifies that a failed apply writes no inventory and that
the failed task's Billiard exception wrapper can be unpickled without importing
the dynamically loaded Jobs package.
LAG regressions cover down configured members, source gaps, alias matching,
new parent/member validation, relationship conflicts, idempotence, and rollback
after a final membership-save failure.
Component regressions cover trimmed identities across different source indexes,
optional-source gaps and HTTP 400 fallback, exact alias exclusions, unknown parts,
unresolved PSU/fan identity, contradictory identity, reviewed placement, and
missing interface observations. The real ORM harness checks zero-DML preview
with unsaved ModuleType/ModuleBay/Module parents, existing-interface adoption,
template suppression, repeat-run idempotence, occupied-bay and relocation
conflicts, and rollback of catalogs, parts, and ownership after a late failure.
Fixtures contain synthetic identities and omit unrelated lab data.

The serialized-component increment passed 101 offline unit tests and 25 real
ORM checks on Nautobot 3.2.5. The ORM checks left zero persistent test inventory
or catalog changes after their outer rollback. Live Job preview recorded zero
inventory mutation statements, including component and catalog tables.

The readable-log increment passes 111 offline tests. Logging regressions cover
Advanced metadata preservation on success and failure, report-download equality,
final apply summaries, nonzero change counts, and download failure fallback.
Real worker preview and TLS failure checks retained both Advanced reports and
matching downloads while preserving inventory; the preview report was absent
from the main result panel and present on Advanced.

The switching increment adds regressions for selected-group identity and range,
location applicability, unknown names, planned interfaces and LAGs, strict
bundle conflicts, exact tagged-set idempotence, and unused-catalog prevention.
Speed cases distinguish ready operational facts from down-link placeholders;
connector cases require the exact RJ45 media enum, and duplex cases distinguish
configured settings from negotiated and MAC observations.
The `0.4.0-dev` increment passed 160 offline tests and 34 rollback-only real ORM
checks on Nautobot 3.2.5, plus lint, formatting, and syntax checks. Both live
preview checks recorded zero inventory mutation statements, and the real worker
preview preserved the inventory snapshot. The successful worker apply created
five VLANs in the selected lab group (VIDs 1, 2, 3, 4, and 999), filled 19
switching bundles (14 access and five tagged), and filled 49 physical connector
fields with `8p8c`. It filled speed with 2,500,000 Kbps on
`TwoGigabitEthernet1/0/1` and `TenGigabitEthernet1/0/47`; duplex remained blank.
Tagged-all is supported and tested but was not observed in the lab. The apply
updated 50 distinct interfaces while preserving all 58 interface UUIDs, names,
Module ownership, and LAG assignments. A second successful worker apply
reported zero changes across every inventory count, with equal before/after
snapshots including VLAN catalogs and tagged memberships. The 39 unknown modes
and four unresolved serialized components remained unresolved, and the existing
`Vlan2` interface's populated type `other` was preserved as a reported conflict.

The `0.5.0-dev` increment adds complete VLAN-catalog reconciliation, explicit
access-port VLAN defaults, partial switchport configuration reports, configured
duplex/default provenance, and clearer expected-discovery notices. Its
regressions distinguish dynamic/default/not-applicable cases from real source
gaps, and preserve full Advanced/download reports and failure behavior.
It passed 202 offline tests, 37 rollback-only real ORM checks with zero
persistent test changes, and lint, formatting, and syntax checks. The live
GET-only preview recorded zero inventory mutation statements, and the
successful worker preview preserved inventory and custom fields. The worker
apply succeeded, added VLANs 1002–1005 to the selected `lab` group, and filled
37 blank configured duplex fields with documented `auto`. It added no
interface VLAN assignments and preserved all 58 interface UUIDs, names,
Module ownership, and LAG assignments. Custom-field definitions and values
were unchanged. A second successful worker apply reported zero across every
inventory change counter and an equal full inventory snapshot, including the
nine-VLAN catalog. Reports retain 53 interfaces with documented defaults,
34 dynamic switchport configurations, and five interfaces where switchport
mapping is not applicable; these are informational, with zero genuinely
unresolved switching observations. Four missing hardware identities and the
existing `Vlan2` type `other` discrepancy remain clearly explained warnings.

The `0.6.0-dev` increment adds the default-disabled NTC inference option,
its structured source/assumption evidence, and separate observation/write
counts. Collection remains RESTCONF JSON only, and no custom fields are
created or populated. Its regressions cover the strict default, exact down
states, eligible dynamic/all-VLAN ports, excluded source/configuration gaps,
preserved conflicts, and repeat-run behavior.
It passed 221 offline tests and 40 real Nautobot ORM checks. Live GET-only
previews with the option disabled and enabled both recorded zero inventory
mutation statements and preserved inventory. The strict preview proposed zero
changes. The enabled preview proposed 34 inferred mode/native assignments for
existing down dynamic switchports with blank assignments, with 34 matching
inference observations and 34 proposed writes. No inferred assignments were
persisted in the lab during these previews.
Both settings also succeeded through the real Celery worker, attached their
reports, and preserved the full inventory and custom-field snapshots. The
installed Job form renders the checkbox after Dry run with a disabled default
and help describing the fallback and its limits.

The `0.7.0-dev` increment adds physical console connectors and dedicated
management-purpose discovery for the reviewed C9300-48UXM/member-1 profile.
It passed 262 offline tests and 47 real Nautobot ORM checks, with zero persistent
integration-test changes. The new checks cover zero-DML previews, whole-plan
validation, rollback after a late console save failure, repeat-run idempotence,
operator names, and preservation of actual cables and termination identities.
Live GET-only previews with NTC inference disabled and enabled preserved the
full inventory and recorded zero inventory mutation statements. The real
worker preview also preserved inventory. The successful strict worker apply
created `Console RJ45` (`rj-45`) and `Console USB` (`usb-mini-b`) and set
`Gi0/0` to Management only. All existing interface identities, Module ownership,
LAG memberships, VLANs, custom fields, routing inventory, and the Device's
primary IP were preserved. A second successful worker apply reported zero
inventory changes and equal before/after snapshots, including console UUIDs.
The report retains the configured `Mgmt-vrf`, shutdown state, and observed
absence of a management IP; no VRF or IP assignments were written because
Namespace mapping remains deferred. Console line 0 settings remain report
observations. The existing `Vlan2` type conflict and four unresolved serialized
hardware identities remain the same documented warnings.

The `0.8.0-dev` increment adds reviewed uplink SFP inventory and native
Manufacturer creation from explicit structured vendor evidence. It passed 278
offline tests and 54 real Nautobot ORM checks, with zero persistent integration
changes. The new checks validate an unsaved Manufacturer without DML, reject
invalid native catalog values before writing, roll back catalogs and the nested
bay after a late SFP save failure, and preserve a real cabled port's alias, UUID,
uplink ownership, LAG and cable terminations. Occupied-slot replacement,
relocation and missing observations preserve inventory. Lint, formatting,
syntax and diff checks passed.
The live GET-only preview issued zero inventory mutation statements, and the
real worker preview succeeded with an equal inventory snapshot. The successful
strict worker apply created one Manufacturer (`CISCO-EQUIV`), one ModuleType
(`GLC-SX-MM`), one nested bay (`SFP GigabitEthernet1/1/1`) and one SFP Module
(serial `ZZ306221998`) under the existing uplink Module. All 58 interfaces,
existing Module and console inventory, VLANs, IPAM and custom fields were
preserved. A second successful worker apply reported zero inventory changes
and identical complete snapshots, including the new SFP UUID. The previously
documented four missing hardware identities and `Vlan2` type conflict remain
unchanged; there are no new unresolved SFP observations on the lab switch.

The `0.11.0-dev` increment makes optional operational switchport RESTCONF
discovery best effort while retaining strict validation of required facts.
It passed 383 offline regressions, lint/format/syntax checks, and 73 real
Nautobot 3.2.5 ORM checks with zero persistent integration changes. Four live
GET-only preview cases on the unchanged IOS XE 17.12.8 lab issued zero
inventory mutation statements: normal discovery; an injected unavailable
YANG library followed by a real endpoint probe returning HTTP 404; an invalid
optional structured reply; and an invalid successful-HTTP JSON response.
The invalid-source cases kept NTC guessing enabled to verify that rejected
evidence produces zero inferred bundles. The two invalid responses and the
unavailable library were process-local test injections, not device changes.
Both the real worker preview and strict apply succeeded with identical
before/after inventory snapshots and attached reports. The existing `Vlan2`
type conflict and four unresolved hardware identities remained unchanged.
At that stage, positive operational-mode cases on 17.15/17.18 were covered by
offline schema-based tests, and the omitted-leaf default profile had been
reviewed only for 17.9/17.12/17.15.

The `0.11.1-dev` increment was validated live on IOS XE 17.18.4. Its advertised
operational switchport model (revision `2024-03-01`) returned HTTP 200 and 66
rows: 53 eligible interfaces, 12 explicitly absent uplink aliases, and one
internal application-hosting interface. Only exact exclusions already
established by required interface discovery are retained as observation-only
records; unknown names, malformed rows and duplicate canonical names still
invalidate the whole optional source. The eligible observations include
access on `TwoGigabitEthernet1/0/1`, trunk on `TenGigabitEthernet1/0/47`, and 51
down ports. Down dynamic ports do not establish negotiated access/trunk mode.
The narrow C9300-48UXM configuration-default profile now includes documented
17.18 defaults; the separate duplex and hardware profiles are unchanged.

Validation passed 388 offline regressions, lint/format/syntax checks, and 73
real Nautobot 3.2.5 ORM checks with zero persistent integration changes. Live
strict and opt-in GET-only previews issued zero inventory mutation statements.
A process-local unavailable-library injection also successfully probed the
real operational endpoint, retaining an unknown revision and issuing zero
inventory writes. Real registered worker preview and strict apply both
succeeded with attached reports and equal before/after inventory snapshots.
All proposed inventory changes were zero. The source produced no discovery
warnings. Two suspended LACP member observations (ports 22 and 23) remained
unresolved without changing their existing configuration or LAG membership;
the previously recorded `Vlan2` type conflict and four missing hardware
identities also remain preserved.
