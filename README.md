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
| Use NTC defaults when guessing | Disabled | Apply the reviewed Network to Code Device Onboarding fallback for eligible down dynamic switchports; mark inferred values in the report |

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
metadata, the TLS verification, port, and NTC-fallback settings, proposed changes, conflicts,
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
| Configured copper duplex | Fill blank `Interface.duplex` from explicit configuration or the narrowly reviewed configured default |
| Negotiated and MAC duplex | Retain as observations; never substitute for the configured duplex setting |
| Supported configured 802.1Q bundle | Fill blank mode and VLAN assignments in the selected VLAN Group |
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

The reviewed `C9300-48UXM` profile for IOS XE 17.9 and 17.12 permits documented
defaults of dynamic auto, access VLAN 1, trunk native VLAN 1, all allowed trunk
VLANs, and disabled global native tagging. These defaults apply only after
successful complete reads of the relevant native configuration and an
identified supported switchport; the report records explicit versus default
provenance. An explicitly configured ordinary access port with an omitted
access VID can therefore receive `access` and untagged VLAN 1. A missing mode
does not become `access`: dynamic auto can negotiate a trunk.

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
Known dynamic administrative modes are informational; source failures, unknown
configuration outside a reviewed default profile, voice VLANs, private VLANs,
802.1Q tunnels, incremental allowed-list operations, and unsupported native
tagging remain unresolved. Disconnected switchports use the same configuration
and default rules as connected ports.

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
| Configured duplex | `/data/Cisco-IOS-XE-native:native/interface` with scoped qualified `Cisco-IOS-XE-ethernet:duplex` fields |
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
