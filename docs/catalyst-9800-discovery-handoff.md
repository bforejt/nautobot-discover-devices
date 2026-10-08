# Catalyst 9800 controller and WAP discovery handoff

Implement this in a new task using the shared Device Discovery framework and
the structured 9800 collectors in `/opt/stacks/nautobot-testsuite`. This handoff
defines the user's authorized controller-wide behavior; it does not implement
the adapter or configure a lab controller.

## Authorized behavior and scope

The user explicitly chose these entry paths:

| Input in Nautobot | Required behavior |
| --- | --- |
| An existing 9800 controller Device / configured logical Controller | Resolve that controller's endpoint and discover its full current connected-AP roster. Enrich existing APs, create eligible newly found AP Devices, and update proven AP locations, running software and other reviewed AP-owned facts. |
| An existing WAP | Resolve its primary configured controller through Nautobot metadata, then perform the **same full controller-level discovery**. The WAP is a seed for choosing the controller, not a filter limiting reconciliation to that WAP. |
| A WAP with no configured controller | Stop with actionable setup guidance before any network connection. Do not contact the WAP, scan for controllers or guess a controller from its name/address. |

**Selecting one WAP can add or update other APs at other sites.** Controller
location, seed WAP location and the selected managed group do not restrict the
roster to a local site. Expose this behavior clearly in Job help and preview.
If multiple seeds resolve to one logical controller, collect it once; if a
future bulk selector resolves several controllers, deduplicate each and process
their combined observations without duplicating a physical AP.

Here, connected devices means the controller's AP inventory. Wireless client
stations, mobility peers and CDP/LLDP neighbor switches are not automatically
onboarded as managed APs. Define current connected/joined/in-progress states
from the reviewed operational source; historical join records do not establish
current connection or authorize onboarding. An AP downloading software is not
automatically excluded merely because it is not yet in a registered state.

This instruction intentionally extends the older **existing-device / fill-only**
policy for controller-managed APs. AP creation and evidence-backed replacement
of populated location/software values are authorized. Do not deliver an
existing-AP-only writer, or silently preserve an outdated location/version just
because it is populated. Keep that exception local to the reviewed AP domains;
do not introduce a global overwrite mode for switches or other platforms.

No guessing remains a rule. Missing facts or required admission metadata leave
the relevant proposal unresolved. Unknown location/software preserves an
existing value; it never clears it. An unresolved AP does not prevent attempts
to process the other eligible APs in the complete roster.

## Baseline and project references

Snapshot checked **2026-10-07**. Fetch and verify the actual combined baseline
before creating a `codex/` branch; preserve unrelated work and all completed
IOS XE, PAN-OS, ESXi and Proxmox behavior.

| Item | Inspected reference |
| --- | --- |
| Discovery workspace / remote | `/opt/stacks/nautobot-device-discovery`; `https://github.com/bforejt/nautobot-discover-devices.git` |
| Inspected checkout | `codex/standalone-esxi-discovery`, commit `700e7c8`; Job `0.24.0-dev`. Recheck later platform work and installed sources rather than assuming this is the newest combined release. |
| Testsuite workspace / source | `/opt/stacks/nautobot-testsuite`, commit `7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9` |
| Native target | Nautobot 3.2; Controller/group fields were checked on the lab's 3.2.6. Detect installed capabilities; do not claim untested older-version compatibility. |
| Framework references | [PAN-OS handoff](panos-discovery-handoff.md), [ESXi contract](esxi-discovery.md), [Proxmox handoff](proxmox-discovery-handoff.md), [reported hardware](reported-hardware-discovery.md) |

The inspected workspace already has unrelated README edits and the Proxmox
handoff. Keep them intact. Historical versions and fill-only launch instructions
in older handoffs do not override the scope above.

## Resolve the controller before device transport

Use the native relationship:

```text
selected WAP Device
  -> Device.controller_managed_device_group
  -> ControllerManagedDeviceGroup.controller
  -> Controller.controller_device / approved logical controller endpoint
```

Nautobot has one managed-group relationship per Device and no separate native
`primary_wlc` field. For this workflow, **primary configured WLC** means the
Controller selected by that relationship and its explicitly configured usable
endpoint. This is not proof of the AP's Cisco primary/secondary preference or
its momentary active registration. Retain those observed facts separately.
Use the native
[Controller](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/controller/)
and [managed-group models](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/controllermanageddevicegroup/);
create no controller custom fields.

For a controller Device input, resolve exactly one linked Controller definition,
or require an explicit logical Controller selection when associations are
ambiguous. Before live onboarding, configure its target managed group/admission
policy. If the logical Controller/group setup is missing, explain what native
records must be supplied; do not arbitrarily choose the first record. A logical
Controller input can select its configured endpoint directly.

Perform this resolution **before** the current vendor dispatcher, AP hostname
lookup or Secrets resolution. APs do not need a management IP, DNS record,
RESTCONF/SSH credential or direct reachability to be discovered through a WLC.
Resolve the controller's own Secrets Group and endpoint. The WLC may be remote
and may serve many sites; its Location never becomes an AP location by default.

If a WAP lacks a group, Controller, endpoint or supported association, stop that
selection before network I/O. Show the WAP name/UUID and the missing link. A
bulk entry point should validate all seed associations before starting writes.
Do not fall back to AP SSH, AP RESTCONF, DHCP/DNS hints, controller-name guessing
or subnet scans.

An optional future repair tool could search explicitly selected known WLC
rosters for a verified AP serial/MAC mapping. That establishes an observed
manager, not necessarily a configured primary. It is not this Job's default
fallback and must not silently assign the missing relationship.

### HA and controller endpoint identity

Native Controllers can use a controller Device or a Device Redundancy Group;
those deployment fields are mutually exclusive. A redundancy group does not
identify its active endpoint by itself. Define a shared management endpoint or
a documented structured active-member selection policy before collecting APs.
Never sort priorities/member names and call the first one active.

Treat one SSO logical controller as one collection scope while preserving the
individual physical controller assets. Verify endpoint identity and role; do
not count mirrored AP databases as two fleets. Unsupported/ambiguous HA source
selection stops with a specific reason. Do not parse `show redundancy` text.
An AP changing controller or HA member remains the same physical asset.

Review source identity for both physical controllers and `C9800-CL` deployments.
A configured/authenticated logical endpoint needs its own verified contract;
do not fabricate a virtual controller chassis serial or borrow Palo's VM binding
exception. Keep unresolved controller-host hardware facts separate from AP
identity, and do not automatically run the switch's physical-chassis planner
against every controller deployment.

Existing configured source bindings remain administrative intent unless a
specific controller-domain migration policy is reviewed. Temporary registration
on another WLC does not silently replace a WAP's configured primary association.
For a new AP, assign the explicitly selected managed group of the collecting
logical Controller as its discovery-source binding. This bootstrap policy does
not claim to discover the AP's own preferred-primary configuration.

## Structured 9800 source contract

Use RESTCONF GETs with JSON exclusively, as for IOS XE. Keep TLS verification
enabled by default; any lab exception is explicit. The
[Cisco programmability guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/technical-reference/catalyst-9800-programmability-telemetry-deployment-guide.html)
and [AP operational YANG](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/Cisco-IOS-XE-wireless-access-point-oper.yang)
are starting references. Validate the lab's actual advertised module revisions
and returned structures; published schemas and fixtures alone are not live proof.

| Candidate resource | Purpose / boundary |
| --- | --- |
| `Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/capwap-data` | Current AP roster; reported identity, model, running software, AP state and location/tag observations |
| Same parent: `ap-name-mac-map` and supported explicit MAC mapping resources | Join exact reported WTP/radio and Ethernet identities; names are labels |
| Same parent: `cdp-cache-data`, `lldp-neigh` | Wired neighbors received by APs, including AP/switch port identities; not radio/RRM adjacency |
| Same parent: `ethernet-if-stats` | Observed AP Ethernet interface names and operational facts; link state is not automatically administrative state |
| `Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data` | Join/connection evidence and history; history alone never drives current onboarding |
| Reviewed AP/site/RF/WLAN configuration resources | Configuration/effective assignment evidence where a native mapping is defined; omit secrets and unrelated diagnostics |

Read shared inventories once per logical controller and normalize locally.
Reuse field filters; allow one validated unfiltered retry when the server
specifically rejects a filter. Preserve completeness and resource budgets;
never present truncated data as a full roster. A failed required roster read
is not an empty fleet. A recognized valid empty roster causes no retirement,
deletion or clearing of existing inventory.

Keep current association, configuration intent, effective assignments and join
history separate. If the roster changes while related tables are read, validate
joins and retry within bounds or defer affected proposals. Optional missing
uplink/configuration data can leave location or a field unresolved while valid
identity/software proceeds. Failed/unknown sources never become `False`, zero
or a complete empty list.

Record controller identity, managed AP identity, module/path, observation and
collection times, completeness, and live/cached/unspecified semantics. Preserve
available neighbor update/age evidence; adapt filters to retain required fields.
Do not invent an expiry timestamp or freshness guarantee when the model does
not provide one. No WLAN keys, passwords or client identifiers enter reports.

## Identity, admission and updates

Keep roster rows until their identities are validated. Do not use AP names,
controller-local indexes, IPs, radio MACs and Ethernet MACs interchangeably.
The testsuite's name-keyed comparison dictionaries can overwrite duplicate
names; they are not suitable inventory identity maps.

Resolve an existing Device through unique verified physical identity, normally
reported AP serial with compatible manufacturer/model. Corroborate MAC joins
using reported mappings; never calculate another MAC by arithmetic. A name
match alone cannot attach an observation to a blank-serial Device. An explicitly
configured source-identity binding can resolve such a Device when independently
validated; otherwise retain the ambiguity. Serial/model conflicts and duplicate
claims must not overwrite or repurpose an existing Device. Replacement hardware
with the same AP name is a different asset, not a serial update.

Admission policy must supply legitimate native requirements: AP Manufacturer,
Platform, role, new-device status, target managed group, naming policy and
Location resolution. These are explicit operator choices, not facts inferred
from PoE or inherited from the WLC's own Platform/Location.

Resolve DeviceType by exact reported AP model in the selected Manufacturer's
catalog. A missing type can use an approved, natively valid bootstrap from
documented facts/profile; otherwise report the missing catalog requirement.
Do not fabricate rack dimensions, connector capability or templates. A product
matrix is optional enrichment, not a prerequisite for observing an unknown AP.
Reject naming collisions rather than invent a random suffix or hijack a record.

| Native domain | Controller-AP reconciliation policy |
| --- | --- |
| Device identity / name | Fill verified blank identity; preserve existing serial, DeviceType and operator alias. New AP names follow the declared naming policy. |
| Location | Create or replace with the uniquely proven existing Location under the placement policy below. Missing/ambiguous evidence preserves an existing value and can defer new AP admission. |
| Running SoftwareVersion | Fill or replace from the AP's verified running version in its own Platform catalog, including deliberate downgrades. Preserve exact reviewed AP version/build semantics; do not copy the WLC version or apply switch version truncation. |
| AP interfaces / radios / assignments | Store only reviewed native meanings. Define which observed fields may replace values and which remain operator intent; report unknown/unsupported fields. |
| Lifecycle status / role / tenant | Use admission selections for new APs; do not translate join/link state into lifecycle status or overwrite unrelated intent. |
| Source controller/group | Bind new APs through the explicit admission group. Existing configured-primary bindings follow the administrative policy above, with observed differences reported. |

Software catalog creation can reuse the shared native SoftwareVersion boundary;
do not delete previous versions or create software image files. Record every
replacement as before/after with source and reason. No AP custom fields are
created, and Palo's capacity exception does not extend to this workflow.

AP-wide administration, radio administration and Ethernet-port administration
are distinct. Negotiated speed does not establish maximum physical capability.
Verified Ethernet with unknown capability may use native `Other` under a reviewed
AP evidence contract; otherwise defer the interface. Validate required values
and units instead of inheriting ORM defaults. Review DeviceType template side
effects during new Device creation so automatic ports/defaults cannot bypass
the source contract or create duplicates.

## Location and attachment policy

CDP/LLDP can establish a switch/port attachment. The switch's own Location does
not establish the AP's floor, and its site applies only when an explicit policy
declares that port/switch serves that site. An IDF can serve other floors or
buildings. PoE can corroborate an attachment; it does not identify an AP.

Accept Location proposals from explicit bindings to existing native Locations:

- A declared AP identity-to-Location mapping.
- A controller-scoped mapping of verified AP location/floor/tag labels to a
  Location UUID. A `site-tag` name alone is not a geographical Site.
- A verified port/service-area or cabling-endpoint mapping.
- An approved switch service-site rule, sufficient only for its declared level
  of geographical precision.

Store these rules in explicit Job policy or existing native configuration
objects; no new location custom fields are needed. Conflicting rules or stale
attachment evidence leave location unresolved. Do not choose the first neighbor
or score a likely floor. If Site is proven but floor is not, use Site-level
placement only where the policy/native Location Type permits it; never invent
the floor. A new AP without a valid required Location stays unresolved while
other eligible APs are still created.

Location updates are authorized, but must respect rack/Location hierarchy and
other native constraints. Do not clear rack, cables, primary IP, tenant or IPAM
relationships merely to force a move. Preserve existing cable records and feed
attachment observations to the existing topology process; this increment does
not silently rewire connections. Mesh parents and radio neighbors do not prove
a wired cable or the leaf AP's geographical location.

Switch discovery is a prerequisite for resolving a reported neighbor to a known
switch/port, not for AP identity/software discovery. Missing neighbors preserve
independent known facts. An AP no longer seen by this WLC is not automatically
retired, deleted, relocated or removed from its configured group.

## Reuse and integration work

| Existing source | Starting point |
| --- | --- |
| [testsuite wireless checks](/opt/stacks/nautobot-testsuite/jobs/checks_iosxe_wireless.py) | `_capwap()`, `_ap_names()`, `_normalize_ap_inventory()`, `_normalize_uplinks()`, `_collect_ap_uplinks()` and reviewed filtered paths |
| [testsuite common helpers](/opt/stacks/nautobot-testsuite/jobs/iosxe_common.py) | Structured GET/cache handling; adapt strict numeric/boolean validation rather than comparison fallbacks |
| [testsuite scope](/opt/stacks/nautobot-testsuite/jobs/scope.py), [snapshot job](/opt/stacks/nautobot-testsuite/jobs/snapshot_job.py) | Remote native controller traversal and dependency deduplication; replace its site-limited manifest semantics with the full-roster write scope authorized here |
| [wireless tests](/opt/stacks/nautobot-testsuite/tests/test_checks_iosxe_wireless.py) | Synthetic identity, radio, tag and uplink cases |
| [CAPWAP fixture](/opt/stacks/nautobot-testsuite/tests/fixtures/wlc_capwap_data.json), [MAC map](/opt/stacks/nautobot-testsuite/tests/fixtures/wlc_ap_name_mac_map.json) | Serial/model/software and distinct AP MAC identities |
| [CDP](/opt/stacks/nautobot-testsuite/tests/fixtures/wlc_cdp_cache_data.json), [LLDP](/opt/stacks/nautobot-testsuite/tests/fixtures/wlc_lldp_neigh.json), [Ethernet](/opt/stacks/nautobot-testsuite/tests/fixtures/wlc_ethernet_if_stats.json) | Attachment and port observations; live source validation still required |

Keep this repository self-contained and preserve attribution. Do not call the
entire testsuite: the wireless platform check still includes human-readable
`show redundancy`, and comparison normalizers can drop identities or missing
values. Reuse the structured inventory subset and validate the actual release.

The current dispatcher sends a Cisco IOS-XE controller Device to the switch
adapter. Introduce controller/managed-AP source resolution before that dispatch,
and keep source endpoint identity separate from each AP subject identity. AP
facts must not pass the switch's selected-Device/Platform proof as if the AP
were the WLC itself.

Add a controller snapshot contract, deterministic per-AP identity resolver,
admission policy and narrow AP update policy. Shared software snapshots must
cover the target AP Platforms; location changes need their own native staging
and validation. Reuse locking, resnapshot/replan, native validation and report
handling; do not weaken all existing fill-only planners.

Collect/validate the required controller index before writing. Apply each
independent AP graph atomically, including its catalogs/interfaces, with locks
and stale-plan checks. A late failure rolls back that AP graph; report any mixed
batch outcome explicitly. Required shared-source failure blocks the affected
controller run. Existing APs with unresolved placement may still receive an
independently valid software proposal; new APs missing required admission data
remain candidates. Unchanged full-roster repeats must issue zero inventory DML.

## Lab prerequisites, acceptance and delivery

The read-only lab inventory check found **no native Controller records and no
DeviceType containing `9800`** at this checkpoint. Provide an existing 9800
Device/logical Controller, usable RESTCONF endpoint and Secrets Group, its
actual IOS XE release, managed group and admission/placement policy. APs need
no direct-access setup. Include one linked existing AP and one real missing AP,
plus location and version changes that can be validated safely. HA requires the
explicit endpoint policy above. Do not fabricate a target from fixture names.

Run source/fixture work while the lab inputs are being supplied. Validate the
full-roster behavior as one coherent feature: AP onboarding and authorized
location/software replacement are part of the first end-to-end deliverable,
not optional later work. Unknown native wireless mappings remain report-only.

Required tests include both entry paths, no AP credential lookup/connections,
missing-controller failure before I/O, remote-site expansion from one AP,
controller deduplication, HA ambiguity, duplicate names/identities, replacement
hardware, missing catalogs/locations, valid empty and failed rosters, software
changes/downgrades, proven Location moves, ambiguous floors, template effects,
stale plans, late rollback, per-AP outcomes and zero-DML repeats.

Keep all existing platform regression suites. Run standard unittest, Ruff,
format, compile and diff checks. Add rollback-only native tests against the
configured Nautobot environment, then a pinned live controller snapshot and
actual Job preview/apply/repeat. Preview must show the entire roster's proposed
creates/updates/moves and unresolved reasons, not just the seed WAP. Main logs
contain counts; Advanced/JSON retain per-AP proof and outcomes.

For authorized deployment, verify all active package copies and source hashes,
restart only the relevant worker, and wait for its actual ready state before
queueing validation. Deliver scoped commits/PRs with exact tested releases and
capabilities; do not merge automatically. No code or live inventory changes
are authorized merely by creation of this handoff document.

## New-task opening prompt

> Read `/opt/stacks/nautobot-device-discovery/docs/catalyst-9800-discovery-handoff.md`
> and the current shared framework/testsuite sources. Implement 9800-managed AP
> discovery with two equivalent full-controller entry paths: controller input,
> or WAP input resolved through its configured native controller relationship.
> Stop missing-controller WAPs before I/O and never connect directly to APs.
> The user authorized creation of eligible new APs and evidence-backed updates
> to populated AP locations/software across the entire current controller roster,
> including remote sites; do not retain the old existing-only/fill-only scope for
> those domains. Keep no guessing, exact identity, native validation, explicit
> admission/placement policy, unrelated intent preservation and atomic idempotence.
> Verify the merged baseline and actual lab inputs, continue independent source
> work when inputs are missing, and add fixture/native/live preview-apply-repeat
> validation. Preserve all other platform behavior, use RESTCONF JSON exclusively,
> report unresolved facts and submit scoped PRs without automatic merge.
