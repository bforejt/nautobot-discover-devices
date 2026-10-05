# PAN-OS HA and IPsec collection

This document records the collection contract introduced in `0.20.0-dev`.
[Network inventory processing](panos-network-inventory.md) in `0.23.0-dev`
consumes these unchanged observations for explicitly selected HA and native VPN
inventory. The collector itself continues to make no native inventory writes.

Job version `0.20.0-dev` adds HA and IPsec observations to the existing PAN-OS
adapter. Applied configuration and operational state have separate versioned
contracts. These facts are report-only: collection imports no Nautobot VPN
models, creates no HA peer or VPN objects, and does not widen the existing
identity/interface write contract. The outer adapter retains `schema_version=1`.

The reviewed XML shapes come from the dedicated PA-VM/KVM lab running PAN-OS
11.2.8. They do not establish physical-appliance support, Panorama-wide scope,
multi-dataplane support, or equivalent schemas on other releases. The
[VM-Series contract](panos-vm-validation.md) continues to govern selected-device
UUID binding and interface eligibility. The
[first-pass history](panos-discovery.md) preserves the earlier checkpoint.

## Collection and scaling

The existing identity/interface reads remain. Exact PA-VM/family-`vm`/KVM
targets additionally retain the reviewed VM-Series guest-interface read. HA and
VPN collection adds six fixed reads to every PAN-OS target:

| Exact command | Reviewed result scope |
| --- | --- |
| `show config effective-running xpath devices/entry/deviceconfig` | `result/deviceconfig`; retain only approved HA fields |
| `show high-availability all` | Selected firewall's observed HA group/state |
| `show config effective-running xpath devices/entry/network` | `result/network`; retain only approved IKE/IPsec configuration |
| `show vpn ike-sa` | Unfiltered IKE rows at `result/entry` |
| `show vpn ipsec-sa` | IPsec SA rows at `result/entries/entry` |
| `show vpn flow` | IPsec flow summary at `result/IPSec/entry`, with dataplane scope |

For each observed flow, the collector adds exactly one
`show vpn flow tunnel-id <observed integer>` read. The transport permits only
whole decimal IDs from 1 through 65535, with no name interpolation or arbitrary
CLI suffix. Parsers validate complete successful XML before accepting observations.
The collector checks the summary/detail identity before associating counters;
a missing, deleted, reassigned or changed flow fails that association.

**Maximum VPN flow details** defaults to 256 and accepts 1 through 65535.
The collector checks the complete summary against this limit before issuing
detail reads. Exceeding it fails discovery with an instruction to increase the
limit; it does not publish a truncated list. Collection cost is six fixed
HA/VPN reads plus one detail read per flow, rather than a query per configured
gateway, profile or selector. Queries do not initiate traffic, negotiations,
HA actions, session clearing, or configuration changes.

The relative CLI XPath matters. On the reviewed lab, querying an absent leaf
subtree returned plain-text `Server error : No such node`, despite XML
presentation being enabled. The deviceconfig/network ancestors supplied
successful structured parents, allowing absent HA/VPN child configuration to
be recorded without treating an error as an empty collection. Only reviewed
children enter facts; unrelated ancestor configuration is discarded.

The [PAN-OS 11.2 operational hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-cli-ops-command-hierarchy)
documents the operational reads. The
[11.2 configuration hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy)
provides configuration field context. Runtime acceptance follows the captured
SSH/XML shapes and explicit parser checks; a CLI name alone does not establish
an XML schema.

## Report contracts and source identity

| Report location | Contract | Meaning |
| --- | --- | --- |
| `observations.ha` | `panos-ha-v1` | Separate `configuration` and `runtime`, with field paths/presence metadata |
| `observations.vpn` | `panos-vpn-v1` | IPsec scope, configured/runtime observations, `native_writes=False` |
| `observations.vpn.configuration` | `panos-vpn-config-v1` | Applied gateway, tunnel and crypto-profile lists, with source paths and container presence |
| `observations.vpn.runtime` | `panos-vpn-runtime-v1` | Independent IKE SAs, IPsec SAs, flow summaries and flow details |

Missing optional values remain `None`. Explicit `False` and zero remain observed
values. Unknown scalar enums and algorithm labels remain literal observations;
they do not select an inferred native choice or a documented default. Empty
structured collections differ from unavailable evidence. Sources identify the
exact command, XML path, row index where applicable, and observed dataplane
scope for flows.

Declared runtime counts are retained as coverage evidence and checked for
contradictions. The reviewed IPsec response has one SA row per distinct tunnel
ID with matching `ntun`; count-bearing responses with repeated tunnel IDs or
different coverage fail as unsupported. No rekey capture establishes whether
`ntun` counts SAs or tunnels during overlap, so that meaning is not inferred.
Distinct SPI rows without a declared count remain independent observations.
Flows require explicit dataplane scope and matching declared IPsec row counts;
multiple-dataplane envelopes remain unsupported pending actual evidence.

`runtime.complete` describes availability of the reviewed runtime reads. It
does not establish complete PAN-OS feature coverage or support for every
deployment/schema. A structured successful empty IKE result yields `ike_sas=[]`.
The reviewed passive member instead returned blank SSH output: collection
records `ike_sas=None`, `complete=False`, and an unresolved source with the
static reason `Blank SSH output; no structured IKE SA evidence`. The same
unknown treatment applies if another member returns blank output; it is not a
passive-role inference. Nonblank invalid/error output still fails collection.

HA runtime local/peer values describe observations from the selected endpoint.
The reviewed HA source supplies no VM UUID path, so local and peer HA UUIDs
remain `None`, and the peer identity remains unresolved. A peer serial,
management address, or identical model does not bind a second Nautobot Device.
The selected PA-VM's UUID binding remains independent system evidence.

IKE `Init`/`Resp` roles are SA roles, not active/passive firewall roles. IPsec
SA and flow names retain the full reported selector identity. The collector
does not split names at a colon to invent a configured tunnel relationship,
collapse rekey SAs, or infer cross-device relationships from matching names.
Summary/detail association checks tunnel ID, gateway ID, full name,
inner/outer interfaces, local/peer addresses and dataplane scope. Operational
state may change between reads; the report does not claim one atomic firewall
snapshot or prove traffic continuity from an `active`/synchronized label alone.

## Retained fields

| Source | Retained meaning and limits |
| --- | --- |
| Applied HA | Explicit enabled state, group ID/description/mode, peer IP, election settings, HA1/HA2 configured ports/addressing, and configured synchronization settings |
| HA runtime | Explicit enabled/mode, local/peer roles and reported identities, HA1/HA2 link observations, running-config synchronization and state-synchronization observations |
| Applied IKE gateways | Exact names, explicit disabled state, configured local interface/IP/floating IP, configured peer IP/FQDN/dynamic choice, IKE version and IKEv1/IKEv2 profile references |
| Applied IPsec tunnels | Auto/manual/unknown key mode, exact tunnel interface, explicit disabled/monitor settings, auto-key gateway/profile references, and configured IPv4/IPv6 selectors |
| Manual-key tunnel | Safe configured local/peer addressing, interface, local/remote SPI and ESP/AH protocol identifier; no key material or authentication subtree |
| IKE crypto profiles | Ordered encryption/hash/DH algorithm labels and explicit lifetime units |
| IPsec crypto profiles | ESP/AH algorithm labels, explicit scalar DH group, lifetime and lifesize units |
| IKE SAs | Gateway ID/name, role, mode, algorithm label and literal created/expires observations exposed by the reviewed unfiltered shape |
| IPsec SAs | Gateway/tunnel identities, full name, peer address, protocol/algorithm labels, independent inbound/outbound SPIs and lifetime observations |
| Flow details | Observed identity, interfaces/endpoints, operational state, SPIs, crypto labels, MTU, lifetime observations, negotiated selectors or unnegotiated proxy ID, monitor observations and counters |

Configured selectors and negotiated selectors remain separate. Configured
FQDN/dynamic peers are not resolved into runtime IP addresses. Addresses,
interfaces, HA links, zones or tunnel names do not create IPAM, VRF, topology or
VPN relationships. Monitor disabled/absent state does not imply tunnel failure.

Configured lifetimes/lifesize retain the explicit XML unit; absent units supply
no default. Packet/byte counter names retain their source meaning and unsigned
whole-token values. Missing counters remain unknown rather than zero. Runtime
`last_rekey` remains unqualified because the XML field itself has no reviewed
unit declaration. IPsec lifetime/remaining-time seconds and the raw KB value
are supported by Palo Alto's
[SA diagnostic example](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000004NxUCAU&lang=en_US).
The [VPN status/counter reference](https://knowledgebase.paloaltonetworks.com/articles/en_US/Knowledge/CLI-Commands-to-Status-44-Clea-55917)
provides diagnostic context; display text is not scraped into facts.

## Privacy, validation and future writes

Pure parsers use approved fields only. Reports and public fixtures omit
pre-shared keys, certificate/private-key material, passwords, usernames,
authentication hashes and manual-key authentication/encryption key branches.
Crypto cipher/hash **algorithm labels** remain safe observations. No complete
configuration tree or unknown child XML is retained. Errors and transport
diagnostics omit remote error bodies and credential values. Reports still
contain ordinary inventory/network facts such as names, addresses and SPIs.

The fixture catalog distinguishes sanitized actual PA-VM 11.2.8 shapes from
synthetic absent/error/adversarial examples. The synthetic successful absent
responses used by offline/native helpers are test inputs, not evidence of a
successful lab query. Historical first-pass and VM-Series proof counts remain
in their original documents.

Validation on 2026-10-05 passed 904 offline tests on Python 3.14.4, Ruff
0.11.13 lint/format checks, syntax compilation and whitespace checks. On
Python 3.12.14, the isolated container copy passed 900 offline tests and then
all 26 configuration tests after adding the last four semantic-error cases.
Native rollback checks on Nautobot 3.2.6 passed 22 PAN-OS and 150 Cisco checks
with zero persistent changes. Parsed active/passive HA role and VPN packet
counter changes produced identical plans and zero native DML; all installed
redundancy and VPN model counts remained unchanged.

The production SSH client and collector read all three UUID-bound lab VMs:

| VM | HA observation | IKE SAs | IPsec SAs / flow details | Runtime read coverage |
| --- | --- | --- | --- | --- |
| 101 | enabled, active | 1 | 1 / 1 | reviewed reads available |
| 102 | enabled, passive | unknown: blank response | 1 / 1 | explicitly incomplete IKE evidence |
| 103 | disabled; HA configuration absent | 1 | 1 / 1 | reviewed reads available |

Each collection used strict host-key checking and 11 exact reads, including
one numeric flow-detail read. The installed `0.20.0-dev` Job also passed a
selected-device preview through normal Secrets lookup, strict SSH, and the
reviewed expected VM UUID. Executable hashes matched the workspace. It issued
zero database mutation statements, preserved inventory and serial, and kept
HA/VPN facts identical between Advanced and the JSON attachment. The existing
interface plan still proposed one exact-template `ethernet1/3` create and
preserved three populated-value conflicts; no inventory apply ran.

The normal queued worker preview also succeeded as JobResult
`1c607787-1259-465e-85e7-85fd8c5463d8`, with the new default detail limit,
all 11 reviewed reads, unchanged inventory, an empty main result, and the
attachment equal to Advanced data. The queued run persisted only its normal
Job/log/report records; it applied no inventory changes.

Private ignored proof is under `artifacts/panos-ha-vpn-collection/`: live
collector results, native suite results, installed Job preview/validation, and
queued preview/report evidence.

No Nautobot 2.4 compatibility run is claimed. A future native HA/VPN writer is
a separate increment: feature-detect the installed 2.4/3.x models and field
semantics, propose identity/relationship mappings, and independently validate
fill-only preservation, zero-write preview, atomic rollback and repeat-run
idempotence. Collection must remain useful when such native models are absent.
