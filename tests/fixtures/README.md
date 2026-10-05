The IOS XE fixtures are reduced, sanitized RESTCONF JSON; the PAN-OS XML
fixtures are described at the end of this document.

The 71 interface names and presence states preserve the useful shape of the
`iosxe_interfaces_oper_lab.json` fixture in `/opt/stacks/nautobot-testsuite`:
48 access ports, four present uplink ports, management, five logical interfaces,
12 absent aliases, and one internal application port. Descriptions and MAC
addresses are synthetic; counters, addresses, neighbor data, and unrelated
configuration are omitted. All negotiated speeds deliberately say 1G so tests
cannot accidentally use link speed to identify physical port capability.

The chassis, module, hostname, install-version, and YANG-library documents are
small synthetic examples using the structured envelopes found in that
testsuite. Serial numbers, revisions, and other values identify no real device.
The hardware software banner deliberately lacks a usable version: install-oper
must supply the running release through explicit leaves.

`iosxe_native_lag_memberships.json` projects only native interface keys and
the qualified Ethernet `channel-group` number/mode leaves. Two disconnected
physical members retain their configured membership in `Port-channel1`.
The document has no addresses, counters, credentials, or unrelated configuration.

`iosxe_platform_components.json` contains synthetic serialized uplink/PSU
identities and their observed parent/location envelopes. It retains the lab's
`comp-port` uplink classification, chassis aggregate alias, and PSU A's
`empty=false` plus disabled/no-input state. Fan identities remain unavailable.
Flat inventory indexes deliberately differ from platform identifiers; joins
must use uniquely corroborated PID and serial, never those numeric indexes.

`iosxe_stack_oper.json` is a synthetic two-member StackWise roster with member 2
active. Stack tests combine it with reduced hardware and per-member install
fixtures, deliberately reorder records and vary inventory indexes, and add
provisioned absent slots. It is not a capture from a physical multi-member lab
stack. The live lab 9300 currently reports a single ready active member.

`iosxe_1718_switchport_oper.json` is a sanitized IOS XE 17.18.4 live operational
capture. It preserves all 66 switchport rows: 53 names eligible in mandatory
core discovery and 13 explicitly excluded names (12 absent uplink aliases and
one internal AppGigabitEthernet interface). VLAN names are synthetic;
administrative/operational modes, presence leaves, VLAN IDs/ranges and aggregate
context are retained. The internal port's positive access observation must not
become a third eligible positive mode or an inventory assignment. Excluded rows
still require full schema and duplicate validation before evidence is retained.

`iosxe_ipam_live_1718.json` preserves the shape of safe filtered native reads from
IOS XE 17.18.4: interface keys, configured IP addressing/VRF forwarding, and
named VRF definitions. It preserves 71 interface records, including known
absent aliases and the internal AppGigabitEthernet interface. Vlan3 and Vlan4
have synthetic RFC5737 hosts with the observed mask shape; Vlan2 uses DHCP; management belongs to
Mgmt-vrf without a configured address. The legacy VRF subtree returned HTTP
204 and is represented as an empty list for offline clients. No authentication,
route tables, unrelated native configuration, or operational addresses are
included. Actual lab addresses are replaced with documentation-only examples.
Link state never substitutes for configured address evidence.

`iosxe_ipam_configured.json` is a synthetic expansion covering primary and
secondary IPv4, /31 and /32 masks, stack-member interface names, modern and
legacy VRF forwarding, unused named VRFs, Port-channel subinterfaces, and IPv6
configuration. Literal static IPv6 is writable in the IPv6 increment; generated,
link-local and dynamic IPv6, DHCP, negotiated and unnumbered configuration remain
observations. The collectors validate
known excluded interfaces before retaining them outside the writable list.
The native schema references are the Cisco-published IOS XE 17.9.1 and 17.18.1
`Cisco-IOS-XE-interfaces.yang` and `Cisco-IOS-XE-ip.yang` model sets in YangModels.


`panos_system_info.txt` and `panos_interfaces.txt` are sanitized XML fixtures
adapted from nautobot-testsuite commit
`7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9` (Apache-2.0), with only trailing
blank lines removed. They describe a
synthetic PA-5250 / 11.1.4-h7 identity and three hardware rows, including down,
unaddressed `ethernet1/7`, plus logical observations. They are parser evidence,
not a live compatibility claim. `panos_applied_interfaces.xml` is newly created
synthetic applied configuration with explicit link-state and selected MTU/comment
leaves. These fixtures contain no credentials. The first-pass unlicensed PA-VM 11.2.8
had empty hardware/logical/applied Ethernet containers and no usable serial;
its report is retained separately in ignored artifacts.


`panos_vm_system_info.xml`, `panos_vm_guest_interfaces.xml`,
`panos_vm_empty_interfaces.xml`, `panos_vm_configured_interfaces.xml` and
`panos_vm_applied_interfaces.xml` preserve XML captured from the dedicated
PA-VM / PAN-OS 11.2.8 KVM lab on 2026-10-05. Hostname, management addressing,
VM UUID, CPU ID and MAC values are sanitized. Commands are respectively
`show system info`, `debug show vm-series interfaces all`, `show interface all`
(before configuration and after configuration), and
`show config effective-running xpath devices/entry/network/interface`.
The guest enumeration recognizes three adapters; the normal hardware view
includes only the two configured adapters. The third remains unconfigured.
Explicit applied up/down and MTU 1400/1500 are retained. PCI identities and
base-OS port/name relationships preserve the observed schema; they do not
classify native type, native MAC or administrative state. These payloads
contain no credentials, license keys or unrelated configuration.

`panos_ha_active.xml`, `panos_ha_passive.xml`, `panos_ha_disabled.xml`,
`panos_ha_configured.xml` and `panos_ha_unconfigured_deviceconfig.xml` preserve
reviewed dedicated PA-VM/KVM PAN-OS 11.2.8 HA shapes. The configured payload is
scoped to the approved HA branch within the effective-running deviceconfig
ancestor; unrelated system configuration and key-bearing branches are removed.
The notes in `panos_ha_fixture_notes.json` record exact commands and sanitizing
scope. Unknown peer serials do not become UUID/device identity. Explicit
disabled HA differs from missing configuration or missing runtime evidence.

`panos_vpn_applied_network.xml` is an allowlisted projection of the actual
effective-running network-parent SSH/XML read captured on 2026-10-05. It retains
IKE gateways, IPsec auto-key tunnels/selectors, and IKE/IPsec crypto profiles.
Gateway authentication, unrelated network branches, certificates, key material
and private authentication values are removed. IPsec crypto-profile
`esp/authentication/member` retains safe algorithm labels such as `sha256`,
which are not authentication hashes or keys. Configured lifetime units and
the observed scalar IPsec DH group/list-valued IKE DH groups retain their shape.

`panos_vpn_ike_sas.xml`, `panos_vpn_ike_single.xml`,
`panos_vpn_ipsec_sas.xml`, `panos_vpn_peer_ipsec_sas.xml`,
`panos_vpn_flows.xml`, `panos_vpn_flow_detail.xml` and
`panos_vpn_local_flow_detail.xml` preserve sanitized reviewed PA-VM 11.2.8
unfiltered SA/flow and numeric flow-detail shapes. Names and addresses are
sanitized while full selector-name structure, identity fields, reciprocal SPI
relationships, negotiated selectors and counter values remain meaningful.
`panos_vpn_flow_inactive.xml` is a synthetic numeric-detail adaptation of
previously captured name-filtered unnegotiated fields, with explicit `dp0`
scope added for parser coverage. It does not establish a live numeric
inactive-flow capture. Production transport and parsers accept only the
reviewed numeric tunnel-ID detail query. None of these payloads contains key material.

The new pure tests also construct absent, empty, malformed, duplicate,
future-enum, IPv6/manual-mode and synthetic secret-exclusion cases in memory.
Successful absent XML used by offline/native helpers is synthetic test evidence,
not a substitute for an actual missing-subtree lab read. The
[collection contract](../../docs/panos-ha-vpn-collection.md) defines the exact
report-only scope. These fixtures do not establish other hardware/releases,
complete OS support, or Nautobot 2.4/3.x native VPN writer compatibility.

`panos_ipam_live_network.xml` and `panos_ipam_live_vsys.xml` project actual
effective-running network and vsys parent reads over SSH from the standalone
PA-VM/KVM 11.2.8 VPN peer on 2026-10-05 at 12:06:53 UTC. They retain applied
interface addresses, virtual-router membership and explicit vsys imports only.
The IPv6 loopback host has explicit interface and address enable flags following
a separately authorized lab configuration/commit. Network values and names are
sanitized; unrelated network, authentication and configuration branches are
omitted. These shapes establish three IPv4 hosts and one literal IPv6 host,
not broader platform/version support.

`panos_ipam_network.xml` and `panos_ipam_vsys.xml` are synthetic expansions
covering the six reviewed interface kinds, multiple routing domains, static
IPv4/IPv6, dynamic configuration and unresolved object references. Pure tests
construct malformed membership, unsupported names, missing flags and parent
evidence, generated/anycast and duplicate cases. Synthetic expansions are
parser/planner checks, not live deployment evidence. The
[IPAM contract](../../docs/panos-ipam-discovery.md) defines native eligibility.
