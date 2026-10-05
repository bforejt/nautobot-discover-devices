# PAN-OS logical interface inventory

The `panos-logical-interfaces-v1` contract reads the successful complete
effective-running `devices/entry/network` XML already collected over SSH. It
does not introduce another transport or retain raw network configuration.

| Explicit configuration family | Native Interface type | Relationship evidence |
| --- | --- | --- |
| Ethernet layer 2/3 `units/entry` | `virtual` | Direct XML container identifies its parent Ethernet interface |
| Aggregate Ethernet layer 2/3 `units/entry` | `virtual` | Direct XML container identifies its parent AE interface |
| Aggregate Ethernet layer 2/3 entry | `lag` | Explicit Ethernet `aggregate-group` scalar identifies each member's target |
| Loopback `units/entry` | `virtual` | No inferred parent |
| Tunnel `units/entry` | `tunnel` | No inferred parent |

Names validate the explicit family and parent association; they never establish
physical capacity or supply an absent VLAN tag. Unsupported aggregate modes
remain unresolved. VLAN interface inventory remains outside this contract.

## Administrative semantics

For these reviewed logical families, native `enabled=True` represents an
instantiated logical interface present in effective configuration. It is a
reviewed mapping of configured existence, not a statement that the parent link,
IPsec security associations, routing protocols or tunnel monitoring are up.
Source provenance identifies this meaning as
`effective-configured-logical-instantiation`.

The PAN-OS 11.2 configuration references describe the loopback, tunnel and
subinterface controls without a separate generic logical administrative-disable
setting. The official SDK's `LoopbackInterface`, `TunnelInterface`,
`Layer2Subinterface`, `Layer3Subinterface` and `AggregateInterface` schemas agree
with the reviewed XML paths. That schema review supports this mapping; it is not
a vendor guarantee that logical interfaces are always operationally up.

Read-only pinned SSH probes against the original lab PA-VM on PAN-OS 11.2.8
verified its canonical VM UUID before issuing `show interface loopback.1`,
`show interface tunnel.1` and `show interface all`. The per-unit XML responses
contained identity and logical configuration facts, but no independent
administrative state. Family pseudo-interface operational state from
`show interface all` is not assigned to individual logical units.

An observed direct `link-state`, generic enable/disable, administrative control
or shutdown marker makes a logical interface unresolved. Protocol-specific
IPv6 address enablement is a separate IPAM fact. Existing native `enabled=False`
is populated intent and is preserved with a mismatch report.

Sources reviewed on 2026-10-05:

- [PAN-OS 11.2 loopback interface settings](https://docs.paloaltonetworks.com/ngfw/help/11-2/network/network-interfaces-loopback).
- [PAN-OS 11.2 tunnel interface settings](https://docs.paloaltonetworks.com/ngfw/help/11-2/network/network-interfaces-tunnel).
- [PAN-OS 11.2 layer 3 subinterface settings](https://docs.paloaltonetworks.com/ngfw/help/11-2/network/network-interfaces/layer-3-subinterface).
- [Palo Alto Networks official Python SDK network schemas](https://github.com/PaloAltoNetworks/pan-os-python/blob/develop/panos/network.py).

## Preservation and native validation

Configured comments and byte MTU values may fill empty native fields. Absent
values stay unknown. Explicit encapsulation tags are report-only; this contract
does not infer Nautobot VLAN mode, untagged VLAN or tagged membership.

Native type choices, parent field and LAG field are detected from the installed
Interface model. Missing capabilities are unresolved. Parent and LAG targets
must resolve unambiguously to the selected Device's existing or prospective
interfaces. Module ownership and populated relationship assignments are
preserved; cycles and changed ownership fail validation.

Native virtual vNICs cannot acquire ordinary LAG membership. Their explicit
configured AE membership is reported unresolved while their native type stays
virtual. Discovery never creates physical types or fake breakout relationships
to circumvent that constraint. Existing explicitly physical members can acquire
an empty LAG assignment.

Preview binds prospective objects and runs native model validation without DML.
The shared atomic apply saves Interface endpoints before parent and LAG
relationships. Repeat discovery proposes zero native changes. Installed native
validation was exercised on Nautobot 3.2.6; feature detection supports safe
deferral on other releases and does not imply that Nautobot 2.4 has been tested.
