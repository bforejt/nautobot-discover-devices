# Proxmox VE discovery handoff

This is the original planning handoff. The implemented ESXi-equivalent scope,
reviewed mappings and current validation evidence are in
[Proxmox discovery](proxmox-discovery.md). Its initial increment/deferred-domain
plan is historical; the runtime read and preservation rules remain applicable.

Use this document to start Proxmox discovery in a new task. Reuse the structured
collection work in `/opt/stacks/nautobot-testsuite` and the current shared
discovery framework. Start with identity and physical NICs on an **existing
selected physical host Device**, then add independently reviewed increments.
This document plans the work; it does not implement a Proxmox adapter.

## Current baseline

Checked on **2026-10-05**, using the current
[PAN-OS handoff](panos-discovery-handoff.md), its current contracts, and both
workspaces. Recheck branch, merge, source and installed-package state at launch.

| Item | Checked reference |
| --- | --- |
| Discovery workspace / remote | `/opt/stacks/nautobot-device-discovery`; `https://github.com/bforejt/nautobot-discover-devices.git` |
| Local implementation | `codex/panos-network-inventory`, commit `6c5df3b967a5dff6fc9659ed41e821aff7964168`, Job `0.23.0-dev` |
| Advertised discovery `main` | `ea9cd56a92e5e79ef7347e0c3d31e8e2dfa4a761`; the named local network-inventory branch was not advertised on the remote at this check |
| Testsuite workspace / source | `/opt/stacks/nautobot-testsuite`; `codex/proxmox-platform`, commit `7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9` |
| Nautobot target | 3.2; current PAN-OS native validation is documented on 3.2.6 |
| Installed lab package locations | `nautobot:/opt/nautobot/jobs/nautobot_discover_devices/` and host `/opt/stacks/nautobot-composer/jobs/nautobot_discover_devices/`; verify the active datasource/package copies before deployment |

The PAN-OS handoff's opening sections describe the current implemented framework.
Its original `0.17.0-dev`, Cisco-only migration and old pending-PR instructions
are historical. Do not repeat that migration or start from an older `main`
assuming it already contains all current PAN-OS work. Verify the intended
published/merged baseline, preserve unrelated changes, and create a `codex/`
branch containing the required implementation. Do not merge other work merely
to prepare this task.

The current PAN-OS handoff records 1,076 offline tests and 241 native checks,
including 150 Cisco checks, plus live PAN-OS collection and job validation.
These are existing checkpoint results, not Proxmox proof or permanent test
counts. The testsuite Proxmox implementation is fixture-tested and imports in
Nautobot, but its README and coverage document still mark the live release walk
as pending. Synthetic PVE `9.0.3` fixture data does not establish a supported
minimum or live release compatibility.

## Carry forward the chosen framework

- One Device Discovery Job, with explicit platform dispatch and versioned
  adapter/domain source contracts. Keep Cisco RESTCONF/JSON and PAN-OS SSH/XML
  behavior intact; Proxmox is the third adapter.
- Structured collection, a pure deterministic planner, and a native Nautobot
  boundary. Apply locks, resnapshots and replans before validating and saving the
  related graph in one transaction. Preview and unchanged repeats issue no
  inventory DML; late failures roll back all related writes.
- **No guessing.** Missing, ambiguous and unsupported facts remain blank or
  unresolved with source evidence. Reconstruct eligible facts from their
  approved source contracts rather than trusting arbitrary normalized values.
- Preserve populated values, including `False`, zero and `Other`, plus UUIDs,
  aliases, ownership, cables, IP assignments, existing intent and unrelated
  custom-field values. Do not rename, relocate, replace or delete inventory
  automatically. Identity conflicts block writes.
- Native model semantics govern mappings. Detect installed fields, choices,
  relationships and validation capabilities; do not use Nautobot version-string
  branches or bypass validation. Older versions remain eligible where the same
  code works, but untested compatibility must not be claimed.
- Create no custom-field schema. PAN-OS has an explicit authorization to use
  existing `vcpus`, `memory_mb` and `disk_gb` Device fields. That narrow
  [capacity contract](panos-capacity-discovery.md) does **not** approve new
  Proxmox-host or guest mappings. Review their meaning and authorization before
  extending writes; preserve existing sizing intent.
- Software image maintenance remains a separate job. A verified running PVE
  release may use the existing native SoftwareVersion mechanism after a
  reviewed Platform/version contract. Kernel, Debian and package versions are
  separate observations, not interchangeable release identities.
- Credentials stay in Nautobot Secrets Groups. Keep errors, traces, artifacts
  and the main log free of credentials. Preserve worker-safe exception handling,
  summary logging and the detailed Advanced/JSON report.
- Native targets express operator intent. The
  [PAN-OS IPAM contract](panos-ipam-discovery.md) explicitly selects existing
  Namespace/VRF targets; source names do not choose them. A Proxmox routing policy
  needs its own review. Missing policy remains report-only.

Use [reported-hardware discovery](reported-hardware-discovery.md) as the scaling
principle: collect known identity and relationships without requiring a product
matrix. Optional reviewed profiles can enrich capability. Do not invent a PID,
maximum speed, connector, cage, physical slot or serialized asset to complete a
row. Do not inherit Cisco's guessing checkbox behavior as Proxmox defaults.

## Structured transports and credentials

Start from the testsuite's **token-authenticated HTTPS JSON GETs plus independently
credentialed, exact Linux SSH reads returning JSON**. Cisco's RESTCONF-only rule
does not prohibit these Proxmox sources. Keep the discovery repository
self-contained at runtime: adapt selected code with source/license attribution,
rather than importing the other installed Jobs package or its entire catalog.

The API uses `/api2/json`, normally on port 8006. The existing Secrets convention
uses HTTP Username for `user@realm!token` and HTTP Password for the token secret;
SSH has a separate Linux Username/Password pair. Choose and test Proxmox-specific
access-type precedence instead of accidentally selecting an existing RESTCONF
association or reusing the token as an SSH login. Proxmox documents stateless
tokens and intersecting user/token grants in its
[official API-token documentation](https://raw.githubusercontent.com/proxmox/pve-docs/master/pveum.adoc).

Keep TLS verification enabled by default, with a configured trust path or explicit
lab exception. Preserve strict/pinned SSH host-key behavior. The testsuite's old
TLS-off default and Linux `AutoAddPolicy()` are not discovery security defaults.
Use direct SSH execution with complete UTF-8 output, validated exit status and
bounded stdout/stderr handling. Never install tools, escalate with sudo, open
consoles, execute guest programs, refresh packages, reload networking, reboot,
or perform API/host configuration writes.

**JSON wrapping text is not structured fact collection.** The full testsuite
network collector reads native configuration text; its bundled kernel reader
includes `/proc/cmdline` text. Those declared testsuite exceptions are not
authorized discovery mappings. Adapt a small fixed JSON reader for the required
named sysfs/PCI fields, and use genuine API/netlink/lshw JSON. Never parse wrapped
`interfaces` text, `ip` tables, default `ethtool` output or shell diagnostics into
inventory facts.

## Reusable testsuite sources

All paths below are under `/opt/stacks/nautobot-testsuite`.

| Source | Reuse / limitation |
| --- | --- |
| [transport_proxmox.py](/opt/stacks/nautobot-testsuite/jobs/transport_proxmox.py) | `ProxmoxClient`, `get()`, `discovery()`; fenced GETs, token headers, envelope validation, safe errors, redirects refused and read budgets |
| [proxmox_paths.py](/opt/stacks/nautobot-testsuite/jobs/proxmox_paths.py) | `fence_path()` and endpoint/query validation; narrow the actual discovery read set |
| [proxmox_ssh.py](/opt/stacks/nautobot-testsuite/jobs/proxmox_ssh.py) | `LazySsh`; resolve separate SSH credentials only when needed |
| [transport_ssh.py](/opt/stacks/nautobot-testsuite/jobs/transport_ssh.py) | Linux `SshRunner`, `_open_linux()`, `_send_linux()`; adapt its execution/completeness behavior with strict host-key policy |
| [checks_proxmox.py](/opt/stacks/nautobot-testsuite/jobs/checks_proxmox.py) | `_collect_host_identity()`, `_hardware()`, `_tree()`, `_network()`, `_collect_pnics()`; study source joins, do not copy broad collectors wholesale |
| [proxmox_sources.py](/opt/stacks/nautobot-testsuite/jobs/proxmox_sources.py) | Named sysfs net/PCI reads, device/driver paths and PF/VF relations; extract a reviewed structured subset |
| [proxmox_common.py](/opt/stacks/nautobot-testsuite/jobs/proxmox_common.py) | `scrub()`, `keyed()`, `Capture.node()`, `Capture.visibility()` and source outcomes; comparison normalization is not an approved inventory mapping |
| [checks_proxmox_visibility.py](/opt/stacks/nautobot-testsuite/jobs/checks_proxmox_visibility.py) | Scoped grant validation and authoritative completeness principles; avoid imposing its full guest/storage/SDN capture requirements on a host-only increment |
| [snapshot_job.py](/opt/stacks/nautobot-testsuite/jobs/snapshot_job.py), [creds.py](/opt/stacks/nautobot-testsuite/jobs/creds.py) | `_proxmox_ssh()`, `_open_host()` and separate transport credential lookup; retain discovery's sanitized provider errors |
| [checks_proxmox_linux.py](/opt/stacks/nautobot-testsuite/jobs/checks_proxmox_linux.py) | `_collect_bridges()`; later JSON bridge/VLAN evidence |
| [checks_proxmox_guests.py](/opt/stacks/nautobot-testsuite/jobs/checks_proxmox_guests.py), [checks_proxmox_cluster.py](/opt/stacks/nautobot-testsuite/jobs/checks_proxmox_cluster.py) | Later guest current/pending configuration and cluster/local scope; outside the first increment |

Permission-filtered HTTP-success lists are not proof of complete inventory.
Check exact required scopes and reconcile with authoritative structured sources
for each domain being written. A present valid `0` in a permission dictionary
can mean a non-propagating grant; do not test grant presence by truthiness.
Validate this contract against the installed release. No guest-agent, log,
storage or SDN privileges are required merely because the full testsuite uses
them; establish the actual privileges of each selected discovery read.

## First increment: host identity and physical NICs

Build a field/source table for review using official Proxmox/Linux documentation
and installed Nautobot models. Keep source scope, units, completeness and
configured/pending/runtime meaning explicit. Candidate reads are:

- `/version`, `/cluster/status`: reported release and exactly one API-local node.
- `/access/permissions` at required scope paths; `/nodes/{node}/version` and
  `/nodes/{node}/status`: verified local-node read permissions and metadata.
- `lshw -json`: system identity and hardware/network tree.
- `ip -j -s -d link show`, `ip -j address show`: live link and address observations.
- A fixed, reviewed JSON reader of named sysfs net/PCI fields when necessary to
  distinguish physical attachment, PF/VF relationships and current link facts.
- `/nodes/{node}/network` only as explicitly scoped configuration evidence.

Pin the selected endpoint and expected node scope. Corroborate that API-local
node, SSH host and hardware describe the same selected Device. Do not mix a
cluster-proxied peer's API records with local SSH hardware, choose the first node
in a list, or silently visit/create peer Devices. If chassis identity is missing,
review a Proxmox-specific binding before allowing writes; PAN-OS's PA-VM UUID
exception does not apply. A machine ID, SMBIOS UUID, motherboard serial or NIC
MAC must not become a chassis serial.

| Fact | Initial mapping / no-guessing boundary |
| --- | --- |
| System vendor, product, chassis serial and hostname | Verify unique scoped hardware identity against the selected Device/DeviceType; preserve names and populated values. Proxmox is software, so the hardware Manufacturer can be Lenovo, Dell, HPE, etc. |
| PVE version/build | Verify the selected Platform and define exact version normalization; do not strip tokens using Cisco rules or fill from a kernel/package version |
| NIC identity | Join exact Linux names/logical-name lists, hardware attachment and typed source identities. `ifindex` is a runtime reference, not a persistent inventory key. Renames need review, not automatic replacement. |
| Physical classification | `class=network`, `link_type=ether`, an `en*` name or a PCI function alone does not prove a physical Ethernet port. Distinguish wireless, virtual hardware, SR-IOV VFs, passthrough and software interfaces. |
| Native type | Existing populated type/template takes priority. Verified physical Ethernet with unknown capability can use native `Other` after a Proxmox-specific evidence contract is reviewed. Otherwise defer creation. |
| Administrative state | Complete live netlink flags can establish current admin state through `IFF_UP`. Missing flags are unknown; `operstate`, carrier and Proxmox `autostart` are different facts. Never infer disabled from an unplugged port. |
| MAC / MTU | Use independently validated live fields; distinguish current and permanent MAC where available. A NIC's lshw `serial` may be its MAC, not a serialized Module identity. |
| Operational speed / duplex | Validate source units, link readiness and native eligibility. Current sysfs/lshw rate does not establish maximum capability or connector. Unknown/sentinel values remain unresolved. |
| Description / management purpose | Require a proven applied source. Candidate config comments, a bridge named `vmbr0`, or the SSH/API-reachable IP do not prove a dedicated management-only port. |
| Addresses | Keep literal runtime/configuration observations separately. Initial collection does not copy bridge IPs onto a physical NIC or enable IPAM writes. |
| Hardware-only or unmatched ports | Retain evidence and unresolved joins, including down, unaddressed and unconfigured NICs; never discard them because the API config table lacks a row |

Linux documents the distinction between administrative flags and operational
state in its [operational-state contract](https://docs.kernel.org/networking/operstates.html).
Nautobot's [Interface semantics](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/interface/)
and installed validators constrain physical/virtual type, speed, duplex,
connector and relationship writes. A required unknown value defers creation;
an ORM default is not source evidence.

## Applied state, pending state and completeness

Proxmox stages network changes separately before activation, as documented in
its [network guide](https://raw.githubusercontent.com/proxmox/pve-docs/master/pve-network.adoc).
The [network API implementation](https://raw.githubusercontent.com/proxmox/pve-manager/master/PVE/API2/Network.pm)
also returns a `changes` envelope attribute outside `data` and applies access
filtering. Preserve these distinctions. API configuration is not automatically
proof of applied persistent settings, and live links are not proof of intended
boot configuration. Deferred changes must not overwrite current inventory.

Collect and validate complete required sources before proposing writes. HTTP
403, missing tools, malformed JSON, duplicate identities, truncated SSH output,
read-budget exhaustion and permission-filtered views remain explicit failures
or unresolved source scopes, never healthy empty inventories. An optional
documented unavailable capability can remain unresolved while independent known
facts proceed. Do not infer feature absence from every 404/500 or arbitrary
command failure, and never fall back to human-readable parsing.

Read shared parent inventories once and normalize locally. Fence names obtained
from device data before using them in API paths; do not interpolate them into
shell commands. Preserve complete source outcomes and relevant unknown fields
without copying secrets or raw native configuration into reports.

## Later increments requiring separate mappings

| Increment | Decision boundary |
| --- | --- |
| Host bonds, bridges and VLAN interfaces | Review eligible native virtual/LAG types, actual relationship evidence and bond modes. Bridge `master` membership is not LAG membership. OVS/VNets/taps/veths and transient guest devices need explicit inclusion rules. |
| 802.1Q policy | A VLAN netdevice ID or VLAN-aware bridge flag does not establish Access/Tagged/Tagged all on another interface. Review per-port PVID, tagged/untagged egress and filtering semantics plus an explicit existing VLAN domain. |
| Static host IPAM | Review host network-namespace/VRF evidence and explicit existing Namespace/VRF targets, with `null` for deliberate global routing and blank policy report-only. A Linux routing table, bridge, bond, SDN zone, VNet or cluster name does not automatically choose a VRF/Namespace. DHCP/SLAAC/link-local and management primary-IP fill need separate policies. |
| Namespace UI | Preserve the agreed easy default Namespace plus RFC1918/manual-prefix override as a possible address-placement UI; explicitly review its interaction with Proxmox routing-domain mappings. Classification alone does not establish routing ownership. |
| Cluster and guests | Use native virtualization models only after identity/lifecycle review. Proxmox cluster/HA is not Cisco VirtualChassis or automatic DeviceRedundancyGroup membership. Scope guest IDs by proven cluster or explicit standalone host plus guest kind; moving nodes must not create duplicates, and VMID reuse needs handling. Review QEMU/LXC, stopped guests and templates explicitly. |
| Capacity and storage | Separate physical cores/threads, installed RAM, guest allocations, disk capacities, pool totals and utilization. Do not sum partitions, shared pools or rootfs usage into hardware/primary-disk capacity. Existing capacity fields need a separately approved Proxmox meaning; no new schema. |
| Serialized components / BMC | Real manufacturer/model/serial and verified containment are required. PCI IDs, bus addresses and NIC MACs are not PSU/NIC/optic serials or bay labels. A later explicitly associated Redfish BMC can enrich the same host using the testsuite's existing interface/credential relationship; do not create a second server Device. |

Do not add guest inventory, cluster peers, storage assets, routing tables,
SDN/firewall policy, topology/cables or BMC queries just because their testsuite
collectors exist. Address observations remain host-only; guest inventory remains
deferred in the first pass.

## Lab prerequisites and immediate questions

A read-only Nautobot inventory check found this **candidate**, not a validated
Proxmox discovery target:

| Candidate | Checked inventory |
| --- | --- |
| `se350-lab-1` | UUID `a6409f62-7d96-4480-a572-5fd99284b82e`; Lenovo ThinkSystem SE350; Platform driver `proxmox` |
| Endpoint / credentials | No primary IP and no Device Secrets Group at this check |
| Historical BMC evidence | Testsuite [BMC handoff](/opt/stacks/nautobot-testsuite/docs/plans/bmc-capture-handoff.md) describes XCC/Redfish validation; it does not validate Proxmox API/SSH reads |

Select this host or supply another existing Device. Before live collection,
establish the direct node endpoint, API-local node name, installed PVE/kernel
release, physical versus nested scope, and API/SSH host binding. Provide the
separate token and Linux credentials through Secrets Groups, exact required read
grants, ports, trusted TLS/SSH identities and required JSON tool availability.
Do not write credentials here or automatically provision the missing setup.

Confirm whether network changes are pending and whether Linux bridges, bonds,
OVS, SDN or SR-IOV are present. A down/unaddressed NIC is valuable for validating
completeness. Host-wide JSON hardware visibility must be sufficient without
installations or privilege escalation. No live PVE minimum is selected by this
handoff. Source audit, mapping proposals and offline fixtures can proceed before
the lab prerequisites are complete.

## Third-adapter integration and validation

Reuse current framework boundaries rather than rebuild them:

- `jobs/discovery_job.py`: add explicit Proxmox dispatch, hardware-independent
  Platform checks and an adapter-appropriate API/SSH lifecycle with explicit
  relevant settings. Do not expose API tokens as normal job inputs.
- `jobs/credentials.py`: add/review HTTP token credential semantics and separate
  SSH access while preserving Cisco/PAN-OS lookup order and sanitized errors.
- `jobs/reconcile.py`: add a Proxmox schema and source-proof contract, exact name
  and version canonicalization, identity guards and platform-specific domain
  gating. Do not fabricate Cisco/PAN-OS source evidence or call their domain
  planners on Proxmox facts.
- `jobs/nautobot_inventory.py` and `jobs/nautobot_ipam.py`: review adapter-aware
  interface identity and snapshot scopes; these currently dispatch Cisco/PAN-OS
  explicitly. Reuse native staging, locks and validation without weakening them.
- Add domain subcontracts only when their meanings are reviewed. Source support
  and installed Nautobot write capabilities are separate; neither is established
  by a version string or a healthy response alone.

Testsuite fixture sources are largely Python dictionaries in
[test_checks_proxmox.py](/opt/stacks/nautobot-testsuite/tests/test_checks_proxmox.py),
[test_transport_proxmox.py](/opt/stacks/nautobot-testsuite/tests/test_transport_proxmox.py),
[test_proxmox_integration.py](/opt/stacks/nautobot-testsuite/tests/test_proxmox_integration.py)
and the Linux/guest/cluster test modules. Do not assume a dedicated Proxmox JSON
fixture directory. Adapt sanitized evidence while preserving ambiguous, pending
and missing-data cases, then capture the actual lab release independently.

Run the project's standard offline checks:

```sh
python3 -m unittest discover -s tests -t . -v
ruff check .
ruff format --check .
python3 -m compileall -q jobs tests tools __init__.py
git diff --check
```

Test token/SSH separation, exact read fencing, strict transport identities,
safe failures, valid zero-valued grants, cross-node source mismatches, chassis
versus board/NIC identity, duplicate joins, down/unaddressed ports, PF/VF/virtual
classification, pending versus runtime conflicts, unknown admin/capability and
counter/unit sentinels. Add native rollback-only checks for zero-DML preview,
fill-only apply, exact preservation, unchanged repeats and late-failure rollback.
Keep the existing Cisco and PAN-OS regression suites passing.

The durable native harness is `tests/nautobot_integration.py`; extend its
platform contracts. `tools/lab_preview.py` already requires an explicit selected
Device and can pin expected adapter/endpoint. Extend it for Proxmox without
reusing the Palo-specific VM UUID rule. Pin each live proof to the reviewed
source commit, selected Device, expected local node and endpoints, then validate
actual Job preview/apply/repeat. Install only the authorized package, verify
source hashes and wait for worker readiness before queueing. Preserve unrelated
jobs and inventory; `/tmp` scripts are not durable implementation.

Deliver scoped commits/PRs with the reviewed mapping, validation results and
unresolved facts; do not merge automatically. Record exact PVE/Nautobot releases
and host/NIC scope actually validated. Never claim full hypervisor discovery
from a successful identity/physical-interface increment.

## New-task opening prompt

> Read `/opt/stacks/nautobot-device-discovery/docs/proxmox-discovery-handoff.md`,
> the current PAN-OS handoff/contracts and referenced testsuite code. Verify the
> actual published/merged baseline containing the current Cisco/PAN-OS framework.
> Start a Proxmox third adapter using fenced token-authenticated JSON GETs and
> independently credentialed exact Linux JSON reads. First audit sources and
> propose native mappings for one existing physical host's identity and complete
> physical NIC inventory, including down/unaddressed ports. Keep API-local/SSH
> host binding, pending/applied/runtime distinctions, no guessing, no new custom
> fields, native validation, preservation and atomic idempotence. Identify only
> missing lab setup and genuine modeling decisions while continuing independent
> source/fixture work. Present the first increment for review before implementing
> new discovery behavior. Keep bridges/bonds/VLANs, IPAM, guests, clusters, storage,
> capacity-field extensions and BMC enrichment in subsequent reviewed increments.
