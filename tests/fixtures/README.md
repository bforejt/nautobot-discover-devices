These are reduced, sanitized RESTCONF JSON fixtures, not raw lab captures.

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
