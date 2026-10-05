# PAN-OS logical, management, HA and native VPN inventory

Job `0.23.0-dev` adds these domains to the existing Palo-only SSH/XML discovery.
Production collection changes presentation settings and issues allowlisted reads;
it never configures the firewall or queries a hypervisor. Native inventory uses
explicit existing targets, preserves populated values, previews without writes,
and applies a freshly rebuilt plan in one transaction.

## Logical interfaces

Applied network XML supplies exact aggregate Ethernet, Ethernet subinterface,
aggregate subinterface, loopback and tunnel identities. Direct parent paths
supply parent relationships; applied aggregate-group entries supply membership.
Configured logical instantiation is separate from operational link/tunnel state.
Unknown administrative controls defer inventory. VLAN tags remain observations
and do not create VLANs or invent switching intent. A native virtual Interface
cannot become a physical LAG member. See the reviewed
[logical contract](panos-logical-interfaces.md).

## Dedicated management inventory

`show interface management` supplies its exact `Management Interface` name,
dedicated MAC, address/mask, addressing mode and operational link facts. Applied
`deviceconfig/system` corroborates static addresses or the explicit DHCP client
choice. Only allowlisted fields survive collection; configuration secrets and
management service settings are excluded. An up operational link with configured
auto state establishes an enabled interface; a down link alone does not establish
administrative disablement. PA-VM supplies virtual identity independently of its
hypervisor. Other models require an exact native DeviceType interface template.

The management policy deliberately selects an existing Namespace:

```json
{"namespace":"Management","include_dhcp":false,"fill_primary":true}
```

Blank policy keeps addresses report-only. Static addresses require matching
applied literals and masks. `include_dhcp:true` permits the current corroborated
IPv4 lease as native DHCP type; it never labels that lease static or creates a
DHCP reservation. Changed leases preserve existing assignments and primary IPs
for review. Dynamic IPv6 and link-local addresses remain observations.

Management and routed addresses enter one shared IPAM hierarchy plan. Prefix
inheritance, VRF intent, existing foreign assignments and duplicate incoming
hosts are checked together. Management addresses are never HA-shared.

`fill_primary:true` fills only a blank primary IP after its exact management
assignment exists in Nautobot. A new assignment therefore needs another discovery
pass before primary fill. This permits complete native `Device.clean()` validation
without preview writes or bypassing assignment checks. Populated primary IPs and
all unrelated custom fields retain their exact values.

## HA ownership

The operator selects existing peer and redundancy group UUIDs:

```json
{
  "peer_device":"<existing peer Device UUID>",
  "peer_vm_uuid":"<Palo-reported peer VM UUID>",
  "redundancy_group":"<existing DeviceRedundancyGroup UUID>"
}
```

The selected Device also requires its existing identity verification. This
increment reviews UUID-bound PA-VM peers with reciprocal active/passive HA,
matching group and HA1 peer addresses, reciprocal link identities, healthy
configuration/state synchronization and independently collected applied interface
addresses. The Job connects directly to the explicit peer using its normal
Secrets Group, or the explicit Secrets override. Neither a peer management
address, hostname, serial placeholder nor PAN group number selects a Device.

Native group strategy, memberships and configured priorities fill only blanks.
Conflicting memberships or priorities suppress sharing. The group cannot contain
an unrelated third Device. Each shared static address requires an exact existing
peer Interface and matching applied address/routing context on both firewalls.
One native IPAddress can then have both verified Interface assignments. Management
and HA link addresses are excluded. HA links never become FHRP objects.

Without this selection, incomplete peer evidence or compatible native models,
HA Layer-3 addressing retains the existing report-only boundary. Locks cover
the explicit existing group and both Devices in deterministic order.

## Native VPN processing

Exact applied auto-key IPsec tunnels, a single IKE gateway, explicit IKE version,
reviewed crypto alternatives and lifetimes can enter native VPN models. Namespace
and native object selections are operator intent; runtime SA counters remain
observations. See the [VPN processing contract](panos-native-vpn.md).

Native model capabilities are detected at runtime. A Nautobot installation
without compatible VPN models retains the same collection/report behavior and
imports no optional VPN model unconditionally. This is the compatibility boundary
for Nautobot 2.4; native runtime proofs are recorded separately by exact tested
version rather than claiming an untested release matrix.

## Reviewed sources

- Palo [management telemetry and equivalent command](https://docs.paloaltonetworks.com/pan-os/u-v/pan-os-device-telemetry-metrics-reference/device-health-and-performance/metric-dt-dhp-177).
- Palo [management DHCP configuration](https://docs.paloaltonetworks.com/ngfw/networking/dhcp/configure-the-management-interface-as-a-dhcp-client).
- Palo [HA synchronization scope](https://docs.paloaltonetworks.com/ngfw/administration/high-availability/reference-ha-synchronization).
- Palo [active/passive configuration requirements](https://docs.paloaltonetworks.com/ngfw/administration/high-availability/set-up-activepassive-ha/configuration-guidelines-for-activepassive-ha).
- Nautobot [DeviceRedundancyGroup](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/deviceredundancygroup/) and [IP addresses](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/ipam/ipaddress/).

Live source coverage is currently PA-VM/PAN-OS 11.2.8 on three dedicated devices.
Unknown source shapes and unavailable native fields remain explicit deferrals;
they do not inherit guesses from Cisco, Panorama or a hypervisor.

The frozen implementation passed 1,076 offline tests on Python 3.14 and 3.12,
and 241 native rollback checks on Nautobot 3.2.6. The native suite includes Cisco
regressions, prospective logical Interface/IPAM validation, management primary
ownership, reciprocal HA sharing, multiple tunnels on a shared WAN, preservation
and late-failure rollback. It does not claim a full Nautobot 2.4 runtime result.

## Installed live lab proof

The dedicated lab now runs the matching `0.23.0-dev` Jobs source. Deliberate lab
setup created `panos-ha-peer`, `panos-vpn-peer` and `PAN-OS Lab HA` before
discovery; these are existing selected targets for production processing. Both
peer Devices use the original Device's Location, Role, PA-VM DeviceType, PAN-OS
Platform and Secrets Group. Verified clone host pins were added without
disabling SSH trust. Production discovery creates none of these prerequisites.

The lab explicitly maps `vsys1` / `lab-vpn-vr` to existing Namespace `Global`
with global routing. Management also selects `Global`, opts into current DHCP
lease inventory and permits blank primary-IP fill. This is lab policy rather
than a production default. All three Devices now have their separate management
Interface, guest MAC, DHCP address/assignment and primary IP, plus `loopback.1`
and `tunnel.1`. The standalone peer retains its applied IPv6 loopback address.

The live normal-Secrets/strict-SSH Job's preview issued zero inventory DML. Its
first combined apply created the original's eligible Interface/IPAM/HA/VPN
objects. A following pass filled its management primary IP, created the local
VPN endpoint and linked it to the native tunnel. Complete repeats on the original,
passive peer and standalone peer issued zero DML. Reverse discovery on the
passive peer added exactly three assignments, without creating duplicate IPs:
`198.18.101.1/29`, `10.255.101.1/32` and `198.18.102.1/30` each have one native
IPAddress with both verified HA Interface assignments.

`PAN-OS Lab VPN` / `PAN-OS Lab IPsec` have real WAN/tunnel/IP endpoint bindings
and both protected host Prefixes. The selected `PAN-OS Lab VPN Profile` does not
exist, so its relationship and phase-policy assignments remain unresolved;
reviewed Phase 1/Phase 2 catalogs were created independently. Populated names,
the original's earlier disabled HA-port intent/description and all unrelated
Device custom fields were preserved. Those mismatches remain in the report.

The normal queued worker preview also succeeded with equal before/after
fingerprints for every relevant inventory model. Its FileProxy attachment exactly
matches the Advanced report and its main result contains no discovery payload.
Installed web and worker executable source hashes match the workspace.

Private ignored artifacts under `artifacts/panos-network-inventory/` record
source hashes, native rollback proofs and complete live reports.
