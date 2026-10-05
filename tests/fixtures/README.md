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
leaves. These fixtures contain no credentials. The live unlicensed PA-VM 11.2.8
had empty hardware/logical/applied Ethernet containers and no usable serial;
its report is retained separately in ignored artifacts.
