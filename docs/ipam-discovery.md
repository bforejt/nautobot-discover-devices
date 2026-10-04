# Static IPv4/IPv6 and VRF discovery

IPAM discovery uses configured RESTCONF JSON addressing and routing contexts.
Selecting **Default IPAM namespace** enables inventory reconciliation. Leaving
it blank keeps IPAM report-only, including when the rest of discovery is applied.
**Dry run** still previews the complete job without inventory writes.
Namespace policy is separate from **Use NTC defaults when guessing**.
No custom fields or automatically created Namespaces are used.

## Job inputs

| Input | Default | Meaning |
| --- | --- | --- |
| Default IPAM namespace | Blank | Existing Namespace for addresses that do not match the override; blank keeps IPAM report-only |
| Override IPAM namespace | Blank | Optional existing Namespace for the RFC1918/manual override matches |
| Use override for RFC1918 | Checked | IPv4 only: with an override selected, matches exactly `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` |
| Additional override networks | Blank | IPv4 or IPv6 network CIDRs, one per line, combined with the selected RFC1918 ranges |
| Create missing networks | Checked | Create exact connected Network Prefixes; unchecked defers addresses whose connected Prefix is missing |
| Group matching user VRF names across devices | Unchecked | Explicitly treat matching names within a Namespace as one shared domain |
| Keep these VRF names device-local | `Mgmt-vrf` | Exact, case-sensitive exceptions to grouping, one per line |
| Prefix Location | Device's closest Site ancestor, otherwise Device Location | Optional ancestor override; its Location Type must permit Prefix associations |
| New Prefix status | Applicable Active | Lifecycle status for newly created Prefixes |
| New IP Address status | Applicable Active | Lifecycle status for newly created IP Addresses |

For a common deployment, select **Internet** as the default, **Corporate** as
the override and leave RFC1918 checked. Add any internally used public ranges
or shared address space such as `100.64.0.0/10` to the manual list. Add `fd00::/8`
explicitly to send ULA to the override; IPv6 has no RFC1918 match. Unchecking
RFC1918 makes only the manual ranges match. Selecting a default alone places
all eligible addressing there. Both selectors may also point to the same
Namespace.

The selectors express organizational policy. Namespace labels carry no built-in
meaning, and a match in the default does not establish public reachability.
Non-RFC1918 special-purpose ranges follow the default unless explicitly entered
in the manual override. Only the three RFC1918 blocks are matched by the checkbox;
a library's broader `is_private` classification is not used.

Manual entries must include a mask and the actual network boundary:
`198.51.100.0/24` and `fd00::/8` are accepted, while host-bit CIDRs such as
`198.51.100.1/24` or `fd00::1/64` and bare hosts are rejected before device requests.
Manual entries require an override
Namespace. Duplicate and overlapping entries describe the same union rather
than introducing rule priority.

Classification covers the **entire connected Prefix**, not just the host.
For example, overriding `10.40.12.0/25` cannot place a reported
`10.40.12.1/24` into that Namespace: its `/24` crosses the policy boundary and
remains unresolved. Adding the other half, `10.40.12.128/25`, covers the complete
network and allows it. Namespace policy never splits a configured connected
network or changes its reported mask.

## VRF identity

Every explicitly configured named VRF is collected, including unused VRFs.
The default routing table is represented by a null local VRF, not by a fabricated
VRF named `default` or `global`. Reported names identify a local configuration;
matching names alone do not establish shared identity across devices.

With grouping disabled, a new local `Mgmt-vrf` on `switch-A` creates the canonical
Nautobot VRF **switch-A / Mgmt-vrf** and a **VRF Device Assignment** retaining
local name **Mgmt-vrf**. `switch-B` receives its own canonical VRF. This also
applies to ordinary named VRFs until the operator opts into shared grouping.
New canonical VRFs have no inferred RD; a reported RD is retained on the Device
Assignment, where different devices can preserve different local RDs.

Grouping enabled makes an ordinary local `CORP` reuse or create canonical **CORP**
within its selected Namespace. Names in **Keep these VRF names device-local**
continue to receive separate instances. `Mgmt-vrf` is the initial exception;
the operator may edit or extend the list. This policy is about new identity and
reuse, not a migration tool: existing Device Assignments take precedence and
are never split, renamed or consolidated by changing the checkbox.

An existing Device Assignment's effective local name establishes the next
run's identity. The Device UUID supplies the assignment scope. Renaming the
Device therefore preserves the existing canonical VRF and its UUID. Ambiguous
assignments, incompatible Namespace selections, and an unassigned collision
with a proposed local canonical name remain unresolved rather than adopting
an unrelated routing domain. Populated local RDs are preserved on disagreement.
RDs and route targets are not used as automatic shared-domain identifiers.
A new shared assignment cannot silently inherit a canonical RD that the device
did not report; such an ambiguous inherited value is deferred.

All classified configured IPv4 and IPv6 Prefixes within a named VRF must select one
Namespace, because a Nautobot VRF belongs to one Namespace. A named VRF crossing
the two selected Namespace policies is deferred with its affected interfaces.
A new named VRF with no eligible static addressing uses the selected
default Namespace, including a management VRF with an unaddressed management
port; its name does not establish an RFC1918 match. Without new address evidence,
an existing Device Assignment retains its established Namespace.

Device-local VRFs may share a Namespace and a connected Prefix when their
numbering belongs to the same address space. A Prefix can be associated with
multiple VRFs when explicit interface observations require them and doing so
preserves existing inherited routing associations. Independent domains reusing
identical hosts require separate Namespaces; two sites or two VRF names do not
create separate IP identities within one Namespace.

## Supported configuration and sources

Writable addressing includes configured static IPv4 primary/secondary addresses
and literal configured IPv6 addresses with explicit prefix lengths, including
shutdown interfaces. The safe native filter
covers FastEthernet, GigabitEthernet, TwoGigabitEthernet, FiveGigabitEthernet,
TenGigabitEthernet, TwentyFiveGigE, FortyGigabitEthernet, HundredGigE,
TwoHundredGigE, FourHundredGigE, Loopback, Port-channel, Port-channel
subinterfaces, Vlan and Tunnel. This includes management ports independently
of the separate console/management hardware profile and accepts validated
physical stack-member interface names.

| Purpose | Endpoint and selected evidence |
| --- | --- |
| Interface addressing and membership | `/data/Cisco-IOS-XE-native:native/interface`, filtered by interface family to keys, VRF forwarding, `ip/address`, `ip/unnumbered` and `ipv6/address` |
| Modern named VRFs | `/data/Cisco-IOS-XE-native:native/vrf`, filtered to definition name, RD/automatic-RD flag and address families |
| Legacy named VRFs | `/data/Cisco-IOS-XE-native:native/ip/vrf`, filtered to name and RD |
| Modern/legacy route-target policy | Separate scoped GETs on the VRF endpoints, limited to names, direct targets, IPv4/IPv6 target policies and automatic-target evidence |

Both modern `vrf/forwarding` and documented legacy native forwarding forms are
read. Ambiguous multiple forms and unresolved symbolic forwarding forms cannot
establish a routing identity. Static primary/secondary objects require explicit
host and contiguous dotted mask; secondary rows require their YANG empty flag.
An absent mask, sentinel host, duplicate address or inconsistent structure
cannot drive a write.

IPv6 uses explicit `ipv6/address/prefix-list` values and the reported prefix
length. EUI-64, anycast, DHCP, SLAAC, named-prefix derivation and link-local
addresses stay observations; no host, mask or interface scope is invented.
The parser accepts the legacy link-local list and the 17.18 replacement
`link-local-address-container`. Ordinary IPv6 static facts do not inherit IPv4
network/broadcast address restrictions; `/127` and `/128` remain eligible.
Legacy single-protocol `ip vrf forwarding` places IPv4 in a VRF while IPv6 stays
in the global routing table. Nautobot has one VRF field per Interface, so this
split cannot be represented faithfully. IPv4 remains eligible; IPv6 on a legacy
forwarding or legacy-only VRF definition stays unresolved with source evidence.
A complete modern VRF definition that omits the IPv6 address family also
defers IPv6 while preserving known IPv4 and routing identity.
See [Cisco's single-protocol and multiprotocol VRF documentation](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mp_l3_vpns/configuration/xe-16/mp-l3-vpns-xe-16-book/mpls-vpn-vrf-cli-for-ipv4-and-ipv6-vpns.html).

The module is `Cisco-IOS-XE-native`; its included interfaces/IP submodules
supply the schema. Source records include the exact safe request, relevant
module revision when available, completeness, HTTP status and model references.
The published models are
[Cisco IOS XE 17.9.1 interfaces](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/1791/Cisco-IOS-XE-interfaces.yang),
[Cisco IOS XE 17.18.1 interfaces](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/Cisco-IOS-XE-interfaces.yang)
and [Cisco IOS XE 17.18.1 IP](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/Cisco-IOS-XE-ip.yang).

The reviewed native revision `2022-07-01` uses the published 17.9.1 field
profile, omitting unsupported `rd-auto` and `vnid` leaves and recording that
schema evidence. Other revisions request the complete scoped projection and
retain unavailable-source results rather than infer defaults.

Reads are optional, use a 15-second timeout and never retry without field
filters. An HTTP 400 is an unavailable source, not permission to obtain full
native configuration. Successful malformed data, duplicate/foreign-qualified
fields, ambiguous canonical names, unrecognized interface joins, or unknown
VRF references invalidate the affected source. Previously valid core identity
and interface discovery remain usable. HTTP 204 for a VRF subtree establishes
an empty configured subtree.

Every native interface must join the mandatory interface inventory or an exact
known exclusion. Known absent uplink aliases and internal AppGigabitEthernet
records receive the same schema validation, but remain outside the writable
interface list. Missing eligible interfaces are not fabricated from names or
incomplete configuration.

DHCP, negotiated and unnumbered IPv4 remain observation-only: no current host,
lease, borrowed mask or guessed connected Prefix is created. Unsupported IPv6
forms and dynamic IPv6 method flags are retained as observations. Operational
addresses do not replace static configuration. Device primary IP selection,
FHRP/shared addressing and route-table import are
outside this increment.

## User VRF route targets

The existing local/shared VRF identity policy applies to ordinary user VRFs.
Literal import/export targets are stored in native RouteTarget records and the
resolved VRF's import/export relationships. Route targets never identify or merge
a VRF. `Mgmt-vrf` remains device-local by default and its targets are report-only;
other device-local names remain eligible for supported user routing policy.

Route-target projections are independent of the identity/addressing reads. A
failed or unsupported projection defers only targets and does not erase a known
VRF or prevent static addressing. Proven absence produces empty target sets.
Direct and address-family policies must have one accurate native import/export
representation. Distinct IPv4/IPv6 policies, automatic targets, stitching and
unsupported wire forms remain unresolved rather than being flattened. Numeric
ASN, nonzero-high ASDOT and IPv4 administrator literals follow the encoded widths
in [RFC 4360](https://www.rfc-editor.org/rfc/rfc4360.html) and
[RFC 5668](https://datatracker.ietf.org/doc/html/rfc5668).

Each native direction is filled only when its existing set is empty. Matching
sets issue no writes; populated differences are conflicts and remain unchanged.
No targets or bindings are removed. A shared VRF already assigned to other
Devices is not enriched from one Device's observations alone. Catalog rows are
created only for accepted bindings and reuse unique exact identities. Before a
new Device adopts an existing VRF with populated targets, discovery must confirm
that its complete observed policy matches those sets; otherwise the entire new
VRF adoption and associated addressing are deferred.

## Native records and preservation

For `10.40.12.1/24`, discovery proposes connected **10.40.12.0/24** in the
selected Namespace, an IP Address with actual host **10.40.12.1** and mask
length **24**, and its interface assignment. New Prefixes are type **Network**
and attach to the selected Prefix Location. No aggregate, parent container,
role, VLAN relation or public/private designation is guessed.

Likewise, `2001:db8:12::1/64` proposes network **2001:db8:12::/64**, host
**2001:db8:12::1** with mask length **64**, and its interface assignment. IPv6
has no configured primary/secondary distinction; new relationships use the
native ordinary assignment default without selecting a Device primary IPv6.

Missing connected networks can be created only when **Create missing networks**
is enabled and the selected Location permits Prefix records. Existing Prefix
types and Location associations remain preserved. An existing network scoped
to a different Location is deferred; discovery does not add another site to
make it fit or convert a Pool/Container into a Network.

An IP Address's identity is Namespace plus host, not its displayed mask.
An existing different mask therefore remains a conflict rather than creating
another IP Address. Existing statuses, names, UUIDs, primary IP choices and
assignments are preserved. Interface VRFs are filled only when blank and their
existing address assignments support the same routing context. Discovery adds
missing explicit secondary assignment flags on new relationships and preserves
existing relationship values, reporting a disagreement in the primary/secondary
flag. A connected Prefix reported in both the global routing table and a named
VRF is deferred as a whole bundle; associating it with the named VRF would
change the global address semantics.

Nautobot requires the closest containing Prefix as an IP Address's parent.
If a more specific existing Prefix contains the configured host, that Prefix
must have compatible routing associations; its size does not change the
address's configured mask. Connected-prefix creation can automatically reparent
existing child Prefixes, IP Addresses and ranges. The preview identifies affected
record UUIDs and validates the resulting hierarchy before writes. It defers
changes that would alter existing inherited VRF associations or split a range,
and rejects conflicts with exclusive IP Address ranges. These checks also
cover existing device assignments outside the selected Namespace scopes.

Addresses already assigned elsewhere, duplicate hosts on several observed
interfaces, and existing non-host address types require explicit shared
addressing semantics and remain unresolved. Existing conflicting Interface
VRFs and routing relationships are not moved, cleared or guessed.

## Preview and apply

The full report is under **Advanced → Worker → Meta → discovery_report** and
in the attached JSON download. `discovery.ipam` holds configured facts, sources,
known exclusions and unresolved observations; `plan.ipam` holds namespace rule
matches, VRFs, Device Assignments, interface memberships, connected Prefixes,
IP Addresses, assignments, RouteTargets, import/export bindings, hierarchy effects
and conflicts. The main job log
summarizes proposed or saved counts and unresolved observations.

Inspect the namespace and matched rule for each configured address, the new
VRF canonical/local names and RDs, Prefix Location, connected masks, and any
hierarchy effects before applying. Unresolved facts have no invented substitute.
Dry run validates native unsaved parents and relationships without inventory
INSERT, UPDATE or DELETE statements. Ordinary JobResults and attachments still
persist as Nautobot's normal job records.

Apply locks the selected Namespace catalogs and relevant inventory, rebuilds
the plan from the current database, validates it, and saves the complete job's
accepted changes in one transaction. A late assignment failure rolls back the
VRFs, networks, hosts and earlier inventory changes. A repeat run reuses UUIDs
and adds no inventory changes when the discovered configuration is unchanged.

## Verification references

- `tests/test_cisco_ipam.py`: safe native reads, static/dynamic boundaries,
  aliases, malformed data, VRF joins, primary/secondary masks and sanitized
  17.18.4 configuration fixtures.
- `tests/test_ipam_policy.py`: form normalization, exact RFC1918/manual policy,
  valid CIDRs and explicit Namespace selectors.
- `tests/test_ipam_reconcile.py`: pure namespace/VRF planning, shared/local
  identity, idempotence, existing values and hierarchy preservation.
- `tests/nautobot_ipam_integration.py`: native Nautobot ORM preview, relationship
  creation, scoped snapshots, shared/local VRFs, inherited routing checks,
  repeat behavior and transaction rollback.
- `tests/nautobot_ipv6_integration.py`: real dual-stack hierarchy, IPv6 namespaces,
  assignment preservation, zero-write preview/repeat and late-failure rollback.
- `tests/test_route_targets_reconcile.py` and
  `tests/nautobot_route_targets_integration.py`: direction/identity preservation,
  management exclusions, scoped native catalogs and transactional bindings.

Nautobot's model documentation describes
[Namespaces](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/docs/user-guide/core-data-model/ipam/namespace.md),
[VRFs](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/docs/user-guide/core-data-model/ipam/vrf.md),
[Prefixes](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/docs/user-guide/core-data-model/ipam/prefix.md)
and [IP Addresses](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/docs/user-guide/core-data-model/ipam/ipaddress.md).

## Lab validation — 2026-10-03

Job `0.12.0-dev` was validated against Nautobot 3.2.5 and the C9300-48UXM
running IOS XE 17.18.4. All 458 offline regressions and 85 real ORM checks
passed. The ORM checks rolled back all test inventory, including temporary
Namespaces and two-device shared/local VRF scenarios. Native end-to-end checks
also covered default, RFC1918 and manually entered Namespace overrides.

The live job used the existing `Global` Namespace, with no override and VRF
grouping disabled. The existing `Lab` Location Type was enabled for Prefix
associations so that connected networks could attach to the device's `lab`
Location. This was a lab prerequisite change; discovery does not modify
Location Type permissions itself.

Filtered interface and modern VRF reads returned HTTP 200. The empty legacy
VRF endpoint returned HTTP 204 and established valid absence. A GET-only preview
issued zero inventory DML. The registered worker preview succeeded with an
attached report and identical inventory snapshots.

The worker apply added:

| Observed configuration | Nautobot result |
| --- | --- |
| SVI 3: configured static `/24` | Host assigned to existing interface; connected Network attached to the device Location |
| SVI 4: configured static `/24` | Host assigned to existing interface; connected Network attached to the device Location |
| `GigabitEthernet0/0`: `Mgmt-vrf`, no address | Device-local management VRF, local Device Assignment name `Mgmt-vrf`, Interface VRF filled |
| `Vlan2`: DHCP | Observation retained; existing address and Device primary IP preserved |

Existing interface UUIDs, cables, LAGs, module ownership, VLANs, console ports,
statuses, IPAM rows and custom-field values were preserved. The repeat worker
apply produced no inventory changes. The only unresolved IPAM observation was
DHCP on `Vlan2`. The previously reported `Vlan2` type difference, two Layer 2
gaps and four components without serial/model evidence remained unchanged.

Full JobResult identifiers and addressing remain in local, ignored validation
artifacts. Published fixtures replace configured hosts with RFC5737 example
addresses. An earlier queue-startup attempt was revoked, and a diagnostic
enqueue with malformed Device serialization failed before discovery; the final
registered worker preview, apply and repeat succeeded.

## IPv6 and RouteTarget validation, 2026-10-04

The increment passed 580 offline tests, Ruff lint/format and compilation.
The full Nautobot 3.2.5 integration harness passed 135 checks with all temporary
changes rolled back. Coverage includes native IPv6 `/127` and `/128` records,
dual-stack namespaces, ULA overrides, equivalent dotted-tail IPv6 identities,
legacy/inactive-family deferrals, assignment preservation, route-target
relationships, shared-VRF policy adoption, and late-failure atomic rollback.

A strict live RESTCONF preview on IOS XE 17.18.4 accepted the scoped modern
route-target filter; the absent legacy subtree returned HTTP 204. The preview
issued zero inventory DML and proposed zero inventory changes. The lab has no
configured static IPv6 or non-management route-target policies; those creation
paths use synthetic structured fixtures and actual Nautobot models. DHCP on
Vlan2 remains a deliberate unresolved observation. Ignored local reports are
in `artifacts/ipv6-vrf/`.
