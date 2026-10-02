# Nautobot device discovery

`Discover Device` verifies an existing Nautobot Device against structured facts
from the device, then fills missing identity, interface, reviewed serialized
hardware inventory, and scoped 802.1Q assignments. The first adapter supports Cisco IOS XE switches on 17.9
or later using RESTCONF JSON exclusively. The job defaults to a preview.

This project targets Nautobot 3.2. Native `SoftwareVersion` is used for
the main Device software field; that model requires Nautobot 2.2 or later.
Only Nautobot 3.2.5 has been tested. Compatibility with older releases is not
claimed until the same implementation has been tested on them, including native
Module inventory and template suppression.

Verified on the lab's Nautobot 3.2.5 and C9300-48UXM running IOS XE 17.12.8.
The live worker apply created 57 missing interfaces and enriched one existing
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
`requests`; repository synchronization does not install Python packages.

Before running, select an existing Device with:

- A Cisco DeviceType whose model matches the structured chassis part number.
- An IOS XE Platform (`cisco_ios` or `cisco_iosxe` network driver, or an IOS XE
  platform name).
- A primary management IP, or a DNS-resolvable Device name.
- A Secrets Group providing a username and password. Credential lookup tries
  supported RESTCONF, HTTP, REST, then Generic access types.
- RESTCONF reachable over HTTPS and permission to read the required models.

The job form contains these inputs:

| Input | Default | Behavior |
| --- | --- | --- |
| Device | Required | Existing Device to verify and enrich |
| Dry run | Enabled | Collect, compare, and validate without inventory writes |
| Verify TLS | Enabled | Verify the device HTTPS certificate |
| RESTCONF port | 443 | Device HTTPS port |
| Secrets Group | Device's group | Optional credential override |
| Interface status | Applicable `Active` | Status for newly created interfaces |
| Software version status | Applicable `Active` | Status for newly created software versions |
| Module status | Applicable `Active` | Status for newly created serialized Modules |
| VLAN Group | None | Explicit Layer-2 domain required for VLAN catalog and interface switching writes |
| VLAN status | Applicable `Active` | Operator-selected status for newly created VLANs |

Start with Dry run enabled. The main job log shows progress, readable change
counts, and brief notices for preserved differences and skipped observations.
Only changes with nonzero counts are listed; a repeat run explicitly says when
no inventory changes are needed. Preview messages say "Would add" or "Would
update"; apply messages say "Added" or "Updated" after changes are saved.

Open **Advanced → Worker → Meta → discovery_report** for the complete discovery
result data, or download the attached `discovery_<device UUID>.json` report.
The job does not return the large report into the main **Result Data** field.
The Advanced data and download include discovered facts,
structured source fields, YANG module revisions when available, request
metadata, the TLS verification and port settings, proposed changes, conflicts,
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
Device requests are GET-only in both modes. No CLI or unstructured output
fallback is present. Authentication values and raw response bodies are omitted
from request diagnostics. The report contains inventory facts such as serials,
MAC addresses, and descriptions.

## Initial interpretation rules

| Discovery fact | Nautobot behavior |
| --- | --- |
| Native hostname | Fill blank `Device.name`; preserve and report populated disagreement |
| Chassis serial | Fill blank `Device.serial`; populated disagreement blocks apply |
| Chassis model | Verify existing DeviceType; disagreement blocks apply |
| Provisioned install release | Fill blank native software field using a matching platform SoftwareVersion, creating one if needed |
| Present interface | Match canonical name within the Device; create missing or enrich blank fields |
| Configured channel-group | Fill blank member `Interface.lag` with its discovered port-channel |
| Reviewed serialized component | Match or create native ModuleType, ModuleBay, and Module inventory |
| Reviewed module interface ownership | Fill blank `Interface.module` using the existing interface record |
| Ready physical interface speed | Fill blank `Interface.speed` in Kbps from the structured operational value |
| Explicit operational RJ45 media | Fill blank `Interface.port_type` with `8p8c` |
| Negotiated and MAC duplex | Retain as observations; await explicit configured duplex before filling `Interface.duplex` |
| Supported configured 802.1Q bundle | Fill blank mode and VLAN assignments in the selected VLAN Group |
| Absent alias / internal application port | Exclude and explain |
| Existing interface absent from discovery | Report; preserve |

“Blank” means `None` or empty text. Explicit `False`, zero, and the interface
type `other` are populated values. Existing descriptions, MTUs, MACs, types,
administrative settings, speeds, duplex values, names, UUIDs, and statuses are
preserved when populated; existing LAG and VLAN assignments are also preserved.
Differing observations
appear as conflicts. Interfaces are never
deleted or renamed. Serial/model conflicts, incomplete identity, and ambiguous
canonical names block application.

The software release comes from explicit `install-oper` version/state leaves.
An uncommitted provisioned release takes precedence over an older committed
release. Numeric build suffixes are retained as evidence while releases such
as `17.12.8` and `17.12.08.0.770` match as `17.12.08`. Software banners are
not parsed. Unsupported image extensions and multi-member stacks require
another interpretation increment.

Interfaces include present physical ports, management ports, SVIs, loopbacks,
and port-channels. Disconnected ports remain eligible. Administrative state
maps to `Interface.enabled`; operational state remains an observation and does
not change lifecycle status. The supported fields are type, enabled, description,
MTU, MAC, operational speed, supported connector type, and configured 802.1Q assignments.
Routing/Namespace interpretation, IP addresses, cables, transceiver inventory,
and additional component profiles are future increments.

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
speed. The initial hardware map covers:

- `C9300-48UXM`: access ports 1–36 are 2.5G copper; ports 37–48 are 10G copper.
- Its management `GigabitEthernet0/0`: 1G copper.
- Installed `C3850-NM-4-1G`: four 1G SFP uplink ports for the identified member.
- SVIs and loopbacks: virtual; port-channels: LAG.

An unsupported physical type or unknown administrative state skips creation
with an explicit warning. Existing interfaces can still receive independently
known blank fields. No generic physical type is invented.

## Serialized components

The current component profile covers only the `C9300-48UXM` chassis with a
`C3850-NM-4-1G` uplink module and `PWR-C1-1100WAC-P` power supplies. Resolved
parts use Nautobot's native `ModuleType`, `ModuleBay`, and `Module` models and
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
unresolved observations. A disabled PSU reporting `no-input` does not establish
that its bay is vacant. Unknown serialized parts and unreviewed placement also
remain unresolved, with evidence for the next interpretation increment. Exact
reviewed stack aggregate aliases are excluded; matching a chassis serial alone
does not exclude another component. Transceiver inventory remains a future
increment.

## Switching and interface fields

Choose a **VLAN Group** explicitly to enable switching writes. The job does not
infer the Layer-2 domain from a VID or create a group. Without a selection,
switching observations remain unresolved while independently usable identity,
interface, and component discovery can proceed. A selected group must be global
or belong to the Device's location hierarchy. An existing VLAN must likewise be
global or associated with the Device's location or an ancestor.

VLAN identity is the selected group plus VID. Other groups can reuse a VID.
Only referenced missing VLANs with a unique structured name are created, and
their VIDs must be from 1 through 4094 and inside the group's allowed range.
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

The reviewed `C9300-48UXM` profile for IOS XE 17.9 and 17.12 permits ordinary
trunk defaults of native VLAN 1, all allowed VLANs, and global native tagging
disabled. These defaults apply only after successful complete reads of the
scoped native configuration; the report identifies every applied default.
An access VLAN default is not assumed. The lab's 39 interfaces without a
supported explicit configured mode remain unresolved. Dynamic modes, voice
VLANs, private VLANs, 802.1Q tunnels, incremental allowed-list operations, and
native-tagging configurations outside the supported interpretation also remain
unresolved rather than being guessed.

Each interface's mode, untagged VLAN, and tagged set form one fill-only bundle.
A populated disagreement skips the entire bundle. An empty tagged set can be
filled; a populated set must match exactly, with no partial merge, removal, or
replacement. Failed bundles do not create unused VLANs. Existing UUIDs and
manual assignments are preserved. Nautobot clears tagged memberships when
saving an interface outside `tagged` mode, so validation also blocks a save
that would discard existing membership while enriching another field.

Operational speed is accepted only for a ready physical interface, converting
the structured bits-per-second value to Nautobot's Kbps unit. It does not
determine hardware capability. The exact structured media value
`ether-media-rj45` identifies an RJ45 (8P8C) connector and can fill blank
`Interface.port_type` with `8p8c` on a physical interface. Connector type is not
inferred from copper capability, speed, or a generic media value. Both fields
follow the same blank-only policy; a later change is reported as a conflict.

Negotiated duplex and MAC duplex status remain report observations, even when
they agree. Nautobot's duplex field is treated as the configured `auto`, `full`,
or `half` setting. The current collector does not obtain that explicit
configured source, and the lab has none, so discovery leaves blank duplex
fields blank. Public guidance and historical configuration-generation behavior
leave operational-versus-configured semantics ambiguous; an agreed configured
source is required before enabling writes. Down-link placeholders, unsupported
types, and contradictory observations do not establish a configured value.

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
| Configured LAG membership | `/data/Cisco-IOS-XE-native:native/interface` with qualified `Cisco-IOS-XE-ethernet:channel-group` field filters |
| Configured 802.1Q mode, native VLAN, and allowed VLANs | `/data/Cisco-IOS-XE-native:native/interface` with complete scoped switchport containers |
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
ambiguous structured switching data blocks discovery. Defaults do not replace
failed or incomplete source reads.
HTTPS redirects are rejected. A legacy TLS retry is available only when the
operator explicitly disables certificate verification.

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
3. `jobs/reconcile.py`, with component and VLAN subplanners, builds a pure,
   deterministic fill-only plan.
4. `jobs/nautobot_inventory.py`, with component and VLAN staging helpers,
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
only the initial Cisco adapter schema until those adapters are introduced.

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
connector cases require the exact RJ45 media enum, and duplex cases retain
negotiated and MAC values without writing an inferred configuration setting.
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
