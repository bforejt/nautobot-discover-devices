# PAN-OS static IPAM discovery

Job `0.21.0-dev` adds applied static IPv4/IPv6 processing for PAN-OS. Collection
remains SSH/XML and read-only. Native processing requires an explicit mapping
from an observed vsys and virtual router to an existing Nautobot Namespace and
either an existing VRF or explicitly selected global routing. Blank mappings
retain the facts in the report without IPAM writes.

This increment reuses the shared IPAM planner and native validation boundary:
preview performs no inventory DML, apply saves the validated plan atomically,
and repeated discovery preserves existing records and assignments. The reviewed
live source is PA-VM/KVM running PAN-OS 11.2.8; other devices, releases and
advanced-routing logical routers require evidence before their schemas become
writable.

## Select routing domains

Enter a JSON list in **PAN-OS routing domain mappings**. For example, after
creating the intended Namespace and VRF in Nautobot:

```json
[
  {
    "vsys": "vsys1",
    "virtual_router": "lab-vpn-vr",
    "namespace": "Lab",
    "vrf": "Lab VPN"
  }
]
```

Namespace and VRF identifiers accept exact existing names or UUIDs. The VRF
must belong to the selected Namespace. Set `"vrf": null` to explicitly select
global routing in that Namespace; omitting `vrf` is an error. Every source
domain needs its own mapping. Different domains may deliberately select the
same native target, and domains with overlapping addresses may select separate
Namespaces. All selected Namespace catalogs are locked during apply.

Duplicate JSON keys, repeated source domains, malformed mappings, ambiguous
names and missing native targets fail before credentials or collection. No
source name automatically selects or creates a VRF. Cisco Namespace overrides,
RFC1918 classification, name grouping and route-distinguisher heuristics do not
select PAN-OS targets. Selecting **Default IPAM namespace** alone does not
enable PAN-OS processing.

**Create missing networks**, **Prefix Location**, **New Prefix status** and
**New IP Address status** retain their shared meanings. Prefix creation can be
disabled to require existing compatible Network Prefixes. The mapped Namespace
and VRF, existing prefix hierarchy, range exclusions and native constraints
must all agree before an address is proposed.

## Applied source contract

The report retains top-level `discovery.ipam`, with `schema_version=1` and
contract `panos-ipam-v1`. It contains allowlisted interfaces, router membership,
vsys imports, unresolved/excluded observations and exact source paths. The
outer adapter remains schema v1. The normalized operator policy is
`panos-ipam-policy-v1`; proposals and unresolved reasons appear in `plan.ipam`.

The collector reuses the existing HA/VPN network-parent result and adds one
fixed read:

| Exact command | Retained scope |
| --- | --- |
| `show config effective-running xpath devices/entry/network` | Applied interface addresses and explicit virtual-router interface membership |
| `show config effective-running xpath devices/entry/vsys` | Explicit vsys interface imports and observed virtual-router imports |

The network parent is queried once. No query interpolates an interface, vsys or
router name. On the reviewed VM with one IPsec flow, the complete collector
issues 12 reads: four identity/interface reads, six HA/VPN reads, one fenced
numeric flow-detail read and one vsys read. Cost grows with observed flow
details, not with addresses, interfaces or routing domains. Missing vsys imports
or virtual-router membership stay unresolved; neither `vsys1` nor a default
router is inferred. Conflicting or duplicate source membership fails validation.
Full parent XML and unrelated configuration never enter reports.

## Writable address and interface evidence

Reviewed applied families are Ethernet, Ethernet subinterfaces,
aggregate-Ethernet, aggregate subinterfaces, loopback and tunnel units. Names
remain exact PAN-OS identities; Cisco aliases and case folding do not apply.
Subinterfaces require direct parent evidence. Unsupported names and modes in
these families remain excluded or unresolved; additional families require
independent source review. HA, Layer-2 and virtual-wire interfaces are excluded
from Layer-3 address processing.

Logical interface processing requires an exact existing Nautobot Interface.
This increment does not create subinterfaces, aggregates, loopbacks or tunnels
from incomplete administrative-state evidence. An Ethernet Interface already
approved by the existing identity/interface planner may also receive IPAM
assignments. Interface VRFs are filled only when blank; conflicting populated
VRFs are preserved and prevent incompatible address assignment.

Addresses must be literal host/prefix strings in applied XML. Missing prefix
lengths, address-object names and DNS names remain unresolved. IPv4 primary or
secondary role is not inferred. IPv6 additionally requires explicit interface
and address enablement and evidence that the configured entry is neither a
generated prefix nor anycast. DHCP, PPPoE, inherited/generated addresses,
IPv6 link-local addressing and ambiguous flags remain observations. Operational
addresses, VPN peer addresses and selectors do not become interface IPs.
Management-plane addressing is outside this applied network-interface contract.

Any observed enabled HA state keeps PAN-OS Layer-3 IPAM proposals report-only.
Explicit disabled HA evidence is required for native proposals. The lab's
active/passive shared addresses do not prove ownership or authorize assigning
one shared address to multiple Devices. A reviewed sharing policy is a later
increment; normal identity/interface discovery and HA/VPN reporting continue.

Existing address assignments, roles, primary Device IPs, native UUIDs and
populated Interface values are preserved. An address assigned to another
Interface is not moved or adopted. Existing VRFs are referenced without
inventing a local alias or route distinguisher; matching Device/VRF assignments
retain their name and RD. HA peers, VPN objects and route targets receive no
new writes in this increment.

For a new assignment, Nautobot requires a non-null `is_secondary` Boolean. The
writer uses its native `False` default, also used by the shared IPv6 writer;
that value does not assert an observed PAN-OS primary role. Existing assignment
flags are preserved, and discovery never selects a Device primary IP.

A new Device/VRF assignment stages no PAN-derived local alias or RD. Nautobot
3.2.6 [native model validation](https://github.com/nautobot/nautobot/blob/v3.2.6/nautobot/ipam/models.py)
inherits the name and RD from the explicitly selected existing VRF; this is
native model behavior, not a virtual-router name mapping.
Existing local assignment values remain unchanged.

## Native capability and compatibility

The implementation detects native capabilities rather than selecting behavior
from a Nautobot version string. IPAddressRange is optional, and an absent
VRFDeviceAssignment virtual-device-context field is handled without assuming
it exists. PAN-OS bypasses an unused component snapshot that would otherwise
require newer component fields.

The shared write-free preview currently requires the IPAddress model's staged
parent cache. If that capability is absent, IPAM remains report-only with an
explicit reason; native validation is never skipped to enable writes. Earlier
Nautobot 2.4 releases lack this capability. A full Nautobot 2.4 runtime is not
validated by this increment. Native write validation is performed on Nautobot
3.2.6; collection and explicit mappings remain independent of native VPN models.

## Validation evidence

The fixture catalog distinguishes actual sanitized PA-VM 11.2.8 parent shapes
from synthetic expanded/adversarial cases. The standalone VPN peer was given
an explicit `2001:db8:103::1/128` loopback address, with both IPv6 enable flags,
to validate IPv6 alongside its three configured IPv4 addresses. This separately
authorized lab setup used a scoped configuration change and successful commit;
production discovery performs only reads.

Validation on 2026-10-05 passed all 970 offline tests on Python 3.14.4 and
Python 3.12.14, Ruff 0.11.13 lint/format checks, syntax compilation and whitespace
checks. The isolated Python sources matched all 110 workspace Python files.

Native rollback checks on Nautobot 3.2.6/Python 3.12.14 passed 17 PAN-OS IPAM,
22 existing PAN-OS and 150 Cisco checks. The IPAM suite processed 12 synthetic
static IPv4/IPv6 addresses across all six supported interface kinds. It verified
existing VRF and explicit global mappings, locks for every mapped Namespace,
Namespace isolation, preservation of native UUIDs/local VRF aliases/RDs and
operator address roles/primary IPs, no assignment stealing, no implicit logical
interface creation, zero-DML preview/repeat, enabled-HA deferral and complete
late-failure rollback. A final targeted IPAM rerun also verified native
Device/VRF assignment creation and inheritance from the explicitly selected
existing catalog VRF. Every suite restored its tracked catalogs with zero
persistent changes. The missing staged-parent-cache case was a capability
simulation on 3.2.6, not a Nautobot 2.4 runtime test.

The production collector also passed strict SSH and independently expected VM
UUID checks on all three dedicated firewalls from the frozen source copy:

| VM | HA evidence | Static IPv4 / IPv6 hosts | Collector reads |
| --- | --- | --- | --- |
| 101 | enabled, active | 3 / 0 | 12 |
| 102 | enabled, passive | 3 / 0 | 12 |
| 103 | explicitly disabled | 3 / 1 | 12 |

Each run reused the network parent exactly once and read the vsys parent last.
VM 103 exposed the actual configured IPv6 loopback host and both explicit
enable flags. VM 102's blank IKE response remained unknown with incomplete
runtime evidence. These were inventory reads; no discovery probe, HA action or
firewall configuration operation ran.

The actual `0.21.0-dev` Job then processed VM 103 through normal Secrets lookup,
strict host-key checks and its independently expected UUID, using temporary
Nautobot objects inside an unconditional outer rollback. Preview issued zero
database mutation statements. Apply created four connected Prefixes, four
IPAddresses, four Interface assignments and four existing-VRF Prefix
associations; repeat issued zero DML. Both IPv4 and IPv6 were assigned to the
exact Ethernet/loopback/tunnel Interfaces. Populated fields, existing VRF/local
assignment names and RDs, and operator primary/secondary selections were
preserved. Reports matched their Advanced metadata and the main result remained
empty in each phase. All tracked catalogs and the original anchor were restored.

The lab Jobs package is installed as `0.21.0-dev`, with all 43 executable modules
matching the workspace. The installed selected-device preview used normal
Secrets lookup and strict SSH, issued zero DML and preserved inventory. The
normal queued worker preview also succeeded as JobResult
`fe548ba3-8393-433f-a9d3-2a0fb01e2516`, with all 12 reads, unchanged inventory,
an empty main result and its attachment equal to Advanced metadata. The active
HA Device retained three static address observations and proposed zero native
IPAM writes. Only normal Job/log/report records persisted for that queued run.

Private proof stays in ignored `artifacts/panos-ipam/`; no credentials or full
configuration are published.
