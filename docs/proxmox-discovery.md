# Proxmox VE discovery for NFV hosts

Device Discovery supports a selected existing Proxmox physical host through
its direct HTTPS API and independently credentialed Linux SSH connection. It
collects hardware identity, the exact PVE release and physical NIC facts, plus
host networking, cluster, capacity, storage and local QEMU/LXC observations.
Explicit QEMU BIOS UUID mappings can add **Hosted On** relationships to existing
NFV guest Devices. The scope matches the ESXi host workflow; it creates no host,
cluster peer, guest Device or virtualization cluster.

This implements the structured source and preservation principles in the
[Proxmox handoff](proxmox-discovery-handoff.md). The implementation includes host and local guest observations with explicit
Hosted On mappings to existing NFV Devices. Runtime discovery permits only
bounded GETs and fixed structured SSH reads.

## Run the Job

Select an existing physical host Device with an existing matching hardware
DeviceType and Proxmox Platform. The endpoint comes from the Device's primary
IP, then its DNS-resolvable name. Hardware Manufacturer/DeviceType describe the
reported server, such as Lenovo; the Proxmox software vendor does not select a
hardware manufacturer. The network driver is `proxmox` or `proxmox_ve`; a Platform
with no driver may use the normalized name `Proxmox` or `Proxmox VE`.

| Job input | Contract |
| --- | --- |
| Device | Existing selected host; hardware identity conflicts block writes. |
| Secrets Group / override | HTTP Username is `user@realm!token`; HTTP Password is its token secret. HTTP, then REST precedence selects a complete pair from one access type. SSH uses its own complete SSH Username/Password pair. Token credentials are never Linux credentials. |
| Verify HTTPS certificate (`verify_tls`) | Enabled by default. Configure worker trust for the server certificate. `False` is an explicit lab exception. |
| Proxmox HTTPS port (`proxmox_port`) | Default `8006`; valid integer ports `1–65535`. |
| SSH port (`ssh_port`) | Independent Linux SSH port, normally `22`. |
| Expected Proxmox node (`expected_proxmox_node`) | Optional exact API-local node name; must match the independently read SSH hostname. |
| Expected Proxmox host UUID (`expected_proxmox_host_uuid`) | Optional explicit non-sentinel DMI product UUID. Must match the source. Required for native writes when chassis/system serial is unavailable; never copied to serial. |
| Proxmox SSH host-key fingerprint (`proxmox_ssh_host_key`) | Optional explicitly pinned `SHA256:` fingerprint. Without a pin, the worker must already trust the host key. Unknown/changed keys fail; no automatic acceptance. |
| Proxmox Hosted On guest mappings (`proxmox_guest_mappings`) | Explicit JSON BIOS UUID to existing Device UUID mappings. Blank is report-only guest inventory. |
| Dry run | Validates the plan without inventory writes. Review the Advanced/JSON evidence. |

Provider errors are sanitized and stop credential resolution. TLS verification
and SSH host-key verification are independent. Leave other adapters' VLAN,
module, IPAM, routing, management, VPN and HA write policies unset. NTC guessing
supplies no Proxmox capabilities or inventory defaults.

## Local scope and identity

`/cluster/status` must identify exactly one `type=node, local=1` row. Every node
read is fenced to that node. Its name must exactly equal the fixed Linux reader's
`socket.gethostname()` result. The collector neither selects the first listed
node nor queries cluster peers through a proxy. Cluster name, membership and
quorum remain observations rather than native HA or VirtualChassis membership.

The retained envelope uses adapter `proxmox`, integer schema version `1` and
source contract `proxmox-host-v1`. `reconstruct()` selects the reviewed source
fields again, checks the API/Linux joins, rebuilds native facts, and rejects
altered normalized identity, interfaces, exclusions or binding. Injected
unreviewed source fields also fail reconstruction. Source outcomes distinguish
complete reads, permission-limited views and unavailable named attributes.

| Fact | Source | Native behavior |
| --- | --- | --- |
| Hostname | API-local node plus independently read exact Linux hostname | Fill blank Device name; preserve populated names. |
| Manufacturer/model | DMI `sys_vendor/product_name`, corroborated with the lshw root system vendor/product | Verify selected Manufacturer/DeviceType; no catalog guessing or creation. |
| Chassis/system serial | DMI `product_serial/chassis_serial`, corroborated with root-system lshw `serial` | Fill blank serial only after identity validation. Placeholders stay unavailable; conflicting usable serials block writes. Board/NIC serials never supply chassis identity. |
| BIOS UUID | DMI `product_uuid`, corroborated with root-system lshw configuration UUID when supplied | Stable host-scope evidence and `proxmox-host-identity-v1` binding; excludes nil/all-ones UUIDs. No custom field or serial substitution. |
| PVE software | Exact `/version` and `/nodes/{node}/version` `version/release/repoid` agreement | Native SoftwareVersion under the existing Platform uses exact pve-manager version, for example `9.2.2`. Kernel, Debian and package observations never substitute. |
| CPU, memory, storage | Node status and reviewed lshw/sysfs/storage JSON | Report-only. Physical cores, logical CPUs, configured guest vCPUs, installed RAM, allocated guest RAM, storage capacity and usage remain distinct. |

Some lshw releases append the system SKU to the product name. Discovery accepts
exact `product_name + " (" + sku + ")"` only when the named DMI `product_sku`
and/or lshw `configuration.sku` establish that same SKU. Conflicting SKU evidence
or arbitrary suffixes fail identity validation; the native model remains the
undecorated DMI product. This follows the
[lshw SMBIOS reader](https://raw.githubusercontent.com/lyonel/lshw/master/src/core/dmi.cc).

The [official node API implementation](https://raw.githubusercontent.com/proxmox/pve-manager/master/PVE/API2/Nodes.pm)
distinguishes the installed pve-manager version, PVE release, build repository
identity and kernel. Discovery preserves those reported values; it does not
normalize away a package revision or derive an installer update label. Build
repository identity remains provenance; native SoftwareVersion does not
distinguish custom rebuilds reporting the same pve-manager version.

## Host physical NICs

An eligible NIC requires an exact live Linux name joined across lshw network
logical names, the fixed sysfs netdevice and PCI records, and netlink. The lshw
`pci@...` bus identity must match the sysfs device PCI address, and all three
hardware/sysfs driver identities must agree. Ethernet PCI class, Ethernet
lshw capability, Linux ARPHRD Ethernet type and live `link_type=ether` are
required together.

Wireless devices, SR-IOV virtual functions, software/stacked links and reviewed
virtual driver/PCI identities are excluded. On recognized virtual systems,
physical NIC writes are deferred because emulated Ethernet can expose genuine
hardware PCI IDs. Unmatched hardware ports and transient links remain explicit
excluded/unresolved observations. Names and interface indices are not guessed
or translated; `ifindex` is a runtime reference. Existing interface names,
UUIDs, types, cable ownership and assignments are preserved.

The lshw JSON capability keys can carry either `true` or a nonempty description,
as defined by its [JSON serializer](https://raw.githubusercontent.com/lyonel/lshw/master/src/core/hw.cc).
Description content is retained rather than parsed. False, null, numeric and
empty values do not prove capability. Linux switch IDs and reviewed PF/VF/SF
representor names defer physical inventory even when a driver exposes a PCI
parent: a [representor](https://docs.kernel.org/networking/representors.html)
is a virtual switch endpoint. The sysfs `bonding_masters` control file is not a
netdevice and is skipped; failures reading actual netdevice attributes remain
explicit.

| NIC field | Reviewed behavior |
| --- | --- |
| Type | Preserve populated native type and exact DeviceType template. Proven physical Ethernet of unknown maximum capability can use native `Other`; negotiated speed never chooses maximum capability. |
| Enabled | Complete live netlink `flags` establishes current administration through `UP` (`IFF_UP`). Missing/malformed flags stay unknown and defer creation. Carrier, operational state and API `autostart` do not choose administration. |
| MAC | Validate live netlink colon-separated unicast MAC; nil/broadcast/multicast/invalid values remain unavailable. Fill blank native MAC only. Permanent MAC remains a separate observation. |
| MTU | Positive live netlink MTU in bytes, within native bounds. Bridge or staged API configuration does not supply physical NIC MTU. |
| Speed | Positive sysfs Mbps only when carrier is up and netlink reports `LOWER_UP`; multiply by `1000` for native Kbps. Invalid, zero, sentinel and carrier-down values remain unknown. Physical-only eligibility prevents virtual speed writes. |
| Duplex | Current sysfs/lshw duplex remains report-only; it does not establish configured native duplex. |
| Description, connector, management-only | Unavailable native facts. API comments, reachability, a `vmbr0` name, physical-port labels or negotiated rates do not establish them. |

[Linux operational states](https://docs.kernel.org/networking/operstates.html)
define the independent administrative/carrier state.
[The Linux sysfs net ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net)
defines current MAC, byte MTU, Mbps speed and current/latest duplex. No source
here establishes a serialized NIC Module, physical bay, cable or maximum
connector capability. Installed Nautobot validators and the existing
[interface field contract](interface-fields.md) govern native writes.

## NFV and Linux network observations

The adapter retains allowlisted genuine JSON and named sysfs fields:

| Observation | Meaning and limit |
| --- | --- |
| Host links | Current `ip -j -s -d link show` identities, flags, master/lower references and reviewed bridge, bond and VLAN details. Bridge master membership is not native LAG membership. |
| Host addresses | `ip -j address show` literal IPv4/IPv6 address, prefix, family, scope and dynamic/lifetime/state flags. Addresses remain on their observed Linux link; bridge addresses are not copied to physical NICs. |
| Bridge VLANs | `bridge -j vlan show` VLAN IDs/ranges and PVID/egress flags. These do not select a native VLAN domain or native tagged/access mode on another interface. |
| API host networking | `/nodes/{node}/network` allowlisted structured configuration, kept apart from current netlink. Its envelope `changes` is retained only as an explicit presence boolean because the display diff is arbitrary text. |
| Hardware/capacity | Reviewed lshw tree, named PCI/netdevice attributes and node CPU/memory/swap/rootfs status. Disk hardware size differs from partitions, pool totals and used space. No summed host capacity/custom-field writes. |
| Storage | Host-local visible storage IDs/types/content, active/enabled/shared flags and total/used/available measurements. Lists are permission-limited and are not a complete cluster-storage asset catalog. |
| QEMU/LXC registration | Each host-local family list, kind, VMID, name, template, lock and state observations. Guest IDs are scoped by the selected node and kind. No cluster-wide uniqueness or lifecycle join is inferred from a VMID. |
| Guest configuration | Separate `/config`, `/config?current=1`, and `/pending` sources. Reviewed allocation, CPU/memory, network and disk property strings retain their native semantics. Pending deletions are distinct from current values. |
| Guest runtime | `/status/current` power/status, allocation/runtime sizes and counters. Current readings do not overwrite configured allocations or native sizing intent. |
| Guest identity | QEMU current configuration `smbios1` unique `uuid=` property. Nil, duplicate and malformed UUIDs remain unresolved. LXC remains report-only because this contract provides no reviewed stable BIOS identity. |

Proxmox [network documentation](https://raw.githubusercontent.com/proxmox/pve-docs/master/pve-network.adoc)
explains that configuration changes are staged separately before activation.
Runtime Linux state and candidate API configuration therefore remain different
observations. The [QEMU guide](https://raw.githubusercontent.com/proxmox/pve-docs/master/qm.adoc)
describes emulated hardware and scoped VM IDs; these do not establish native
physical devices or persistent guest ownership.

Native configuration files, shell tables, arbitrary user data, cloud-init
passwords/SSH keys/snippets, hook scripts, raw QEMU arguments and unknown
property options are omitted. Custom QEMU argument presence remains a boolean
marker because those arguments can override SMBIOS identity; such guests cannot
qualify for native Hosted On mappings. Named property-string options are selected before
source retention; malformed/duplicate grammar cannot produce a valid BIOS join.
No guest-agent endpoint, guest execution, console, snapshot, log, package refresh,
storage write, SDN/firewall query or BMC is used. This contract creates no host
virtual network objects, IPAM, VLANs, LAGs, storage assets, guest interfaces,
capacity schema or VirtualMachine/Cluster objects.

## Explicit Hosted On mappings

Guests use existing Devices and the existing one-to-many `hosted_on`
relationship: `dcim.device` host/source to `dcim.device` guest/destination.
An explicit selection looks like:

```json
[
  {
    "vm_uuid": "00000003-0000-4000-8000-000000000003",
    "device": "00000004-0000-4000-8000-000000000004"
  }
]
```

These UUIDs are examples. The first selects the observed QEMU BIOS UUID; the
second selects an existing native guest Device. The policy records exact host,
guest Device and existing relationship definition identities using
`proxmox-guest-policy-v1` and `proxmox-hosted-on-v1`.

A mapping requires a complete guest view with propagating VM.Audit permission,
a unique QEMU BIOS UUID, one matching local registration, matching config/current
BIOS identity, known consistent current/listed `running` or `stopped` state,
non-template status and no locks, custom QEMU arguments or pending BIOS/template/lock/argument identity change.
Omitted template values use Proxmox's native false default. Stopped guests can
qualify; templates and LXC cannot. Names, VMIDs, guest IPs and arbitrary source
UUIDs never select existing guest Devices. Existing matching associations and
UUIDs are preserved. Foreign or ambiguous ownership blocks reparenting, and
absence from a visible list never deletes an association.

## Grants, bounded reads and apply

The token authenticates without a ticket/session. Proxmox evaluates token and
owning-user grants together as described in its
[API-token documentation](https://raw.githubusercontent.com/proxmox/pve-docs/master/pveum.adoc).
The adapter requests exact permission scopes through `/access/permissions`:

| Scope | Evidence requirement |
| --- | --- |
| `/nodes/{local-node}` | `Sys.Audit` must be present. `0` is valid exact non-propagating permission, not absence. |
| `/vms/{visible-vmid}` | `VM.Audit` must be present for each guest detail. Both guest families are collected without a running-only filter. |
| `/vms` | Parent grants are observed but cannot prove complete descendant visibility: deeper ACLs can replace inherited grants, including with `NoAccess`. |
| Local guest registry | The fixed Linux reader parses genuine `/etc/pve/.vmlist` JSON independently. Exact local `(kind, VMID)` sets must match both API family lists; hidden, additional, foreign-node or mismatched-kind evidence blocks collection. |
| Storage listing | Remains explicitly permission-scoped; successful/empty output does not prove complete global absence. |
| Network configuration | Remains permission-scoped: the API can filter bridges by SDN grants despite a successful `Sys.Audit` read. Complete netlink sources remain independent. |

The [pmxcfs contract](https://raw.githubusercontent.com/proxmox/pve-docs/master/pmxcfs.adoc)
defines `.vmlist` as the cluster VM list. The
[JSON producer](https://raw.githubusercontent.com/proxmox/pve-cluster/master/src/pmxcfs/status.c)
defines its version, ID, node and guest-kind fields, including omission of `ids`
for a genuinely empty registry. Remote-node records remain observations and
never trigger peer discovery. Duplicate keys, malformed JSON and unavailable
authoritative registry evidence cannot become healthy empty inventory.

GET success is not substituted for permission proof. HTTP errors, omitted
required scopes, malformed JSON, duplicate source identities, SSH nonzero exits,
invalid UTF-8, truncated output, reader errors and budget exhaustion fail
collection. Documented unavailable sysfs attributes remain explicit; optional
unknown facts are not guessed. A transient software link mismatch between
netlink and sysfs remains unresolved rather than discredit independent physical
joins. No human-readable parsing fallback is available.

The transport fences API paths and node/kind/VMID references, disables redirects
and proxy inheritance, validates JSON envelopes, and bounds requests, response
bytes and guest inventory. SSH commands are fixed constants with checked exit
status and complete bounded stdout/stderr. Neither device names nor credentials
are interpolated into remote commands. Errors and traces contain sanitized
operation names rather than credentials or remote diagnostics.

Apply reconstructs source facts, locks catalog and selected Devices/relationship
context, resnapshots and replans, validates the proposed native graph, and saves
one transaction. Preview and unchanged repeats write no inventory. Late failure
rolls back software, Device, Interface and Hosted On writes together. Existing
populated values, including `False`, zero and `Other`, custom-field dictionaries,
UUIDs, ownership, cables, IP assignments and sizing intent are preserved.

Implementation: [transport](../jobs/transport_proxmox.py),
[fixed Linux sources](../jobs/proxmox_sources.py),
[adapter](../jobs/adapters/proxmox.py),
[host planner](../jobs/reconcile_proxmox.py),
[guest policy](../jobs/proxmox_guest_policy.py),
[guest planner](../jobs/reconcile_proxmox_guests.py) and
[native guest boundary](../jobs/nautobot_proxmox_guests.py).

## Validation checkpoint

Validated on **2026-10-07** against Proxmox VE **9.2.2**, release `9.2`,
repository ID `b9984c6d90a4bd80`, and Nautobot **3.2.6**.

| Live fact | Verified scope |
| --- | --- |
| Endpoint and node | `10.40.3.253`; API-local and independently read SSH node `pve`. |
| Hardware | Intel(R) Client Systems `NUC8i3BEK`; SKU `BOXNUC8i3BEK`; system serial `G6BE91500LQ9`; BIOS UUID `1f261432-e23e-6911-841c-94c691a36f58`. DMI and lshw agree after exact SKU corroboration. |
| Host NIC | One wired `nic1`, PCI `0000:00:1f.6`, driver `e1000e`, live admin up, MTU 1500 and 1,000,000 Kbps. Native maximum capability remains `Other`; current duplex does not become configured duplex. Wireless `wlp0s20f3` and transient software links remain excluded observations. |
| Guests | Seven QEMU registrations, including two templates; no LXC registrations in the matching authoritative local registry. Five non-template guests remain observations. |
| Storage and network | Two storage entries, current links/addresses and bridge VLANs, plus separately scoped API configuration/pending state. |
| Privileges | Exact node `Sys.Audit` and per-guest `VM.Audit` reads succeed; root SSH can read all required DMI/sysfs/registry fields and genuine JSON tools. Parent grants do not establish guest completeness. |

The lab lacked `lshw`; it was installed as an authorized development prerequisite.
Discovery itself never installs tools or changes the host. No reboot was needed.
HTTPS certificate verification was explicitly disabled for the self-signed lab
certificate; SSH used the independently checked SHA256 host-key pin. Production
HTTPS verification remains enabled by default.

Full collection completed **50 bounded reads** and passed source reconstruction.
The real Job exercised normal separate HTTP/SSH Secrets Group associations and
actual environment-variable providers. Preview issued **zero inventory DML**.
Applying its collected report created one eligible host Interface, assigned
software `9.2.2`, and created two explicit live QEMU Hosted On links to temporary
existing guest Devices. Repeat preserved Interface/association UUIDs and issued
**zero inventory DML**. All fixture inventory, native apply, catalogs, Secret
references and relationships completed unconditional outer rollback with
**zero persistent changes**. The Lenovo `se350-lab-1` supplied only existing
role/location/status context; Intel facts were never applied to that Device.

Native fixture validation passed **41 checks**: 20 host and 21 Hosted On checks.
Replay of the actual live source added one host check, yielding **42 checks**.
These cover source/identity conflicts, authoritative registry discrepancies,
exact custom-field and operator-intent preservation, missing values, competing
ownership, zero-write previews/repeats and late-write rollback. Existing ESXi
native regression harnesses also passed 30 checks. The complete offline suite
passed **1,335 tests**; repository Ruff, formatting, compilation and whitespace
checks passed.

The durable [live Job harness](../tools/proxmox_lab_validation.py) accepts explicit
BIOS UUIDs for optional temporary guest mapping proof. The
[queued preview harness](../tools/proxmox_worker_validation.py) uses separate
worker-readable Secret references, validates Advanced and attachment evidence,
and removes its temporary inventory while retaining JobResult/FileProxy audit
records. The tested package was installed with all **70 Python source hashes**
matching; the existing Discover Device Job identity and enabled state were
preserved, and refreshed web/worker processes loaded `0.25.0-dev`.

The real Celery queued preview completed successfully as JobResult
`358dc186-3fa0-49eb-a4e7-f8a22ab07375`. It performed all 50 reads, verified
seven authoritative registrations, planned exactly two explicit guest links,
and produced a JSON FileProxy identical to the Advanced report. Exact native
row hashes remained unchanged during preview. All temporary host/guest/catalog
inventory, Secret references and four private worker credential files were
removed; the JobResult/FileProxy remain as audit evidence. Web and worker health
checks passed. A missing provider-file run also failed with sanitized errors,
restored its fixture baseline, and prompted a readability preflight in the
queued harness before any fixture creation or enqueue.

This proves the named lab host/release and real nonempty QEMU path. LXC,
multiple physical ports, SR-IOV/switch representors, nested hosts, incomplete
permissions and adverse lifecycle cases have fixture coverage rather than broad
live hardware/release claims.

```bash
python3 -m unittest discover -s tests -t .
ruff check jobs tests tools
ruff format --check jobs tests tools
python3 -m compileall -q jobs tests tools
```
