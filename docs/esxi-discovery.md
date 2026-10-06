# Standalone ESXi discovery for NFV hosts

Device Discovery Job `0.24.0-dev` supports independent VMware ESXi hosts through their
own HTTPS `vim25` SOAP endpoint, `/sdk`. Each run selects an existing host Device.
It discovers host identity, an exact software release/build and eligible host
NICs, and can add explicit **Hosted On** links to existing NFV guest Devices.
Guest configuration, host switching, VMkernel networking and storage remain
structured observations. A vCenter server is not required or accepted.

This implementation follows the shared framework in the
[Proxmox discovery handoff](proxmox-discovery-handoff.md): structured collection,
reviewed source contracts, deterministic planning, installed native validation,
fill-only updates, and one atomic apply transaction. It does not implement the
planned Proxmox adapter. Existing Cisco IOS XE and PAN-OS discovery use their
own adapters and source contracts.

## Run the Job

Prepare the selected host Device with an existing matching hardware DeviceType,
an ESXi Platform, and an endpoint reachable from the Nautobot worker. Endpoint
selection uses the Device's primary IP, then its DNS-resolvable name. Hardware
manufacturer/model must match the host's reported hardware, including QEMU for
the nested lab; the VMware software vendor does not choose the hardware vendor.
Manufacturer comparison is trimmed and case-insensitive, without a vendor alias
catalog. A model or populated serial conflict blocks application.

The Platform network driver must be `esxi` or `vmware_esxi`. A Platform without
a driver is also accepted when its normalized name is `ESXi` or `VMware ESXi`.
Discovery does not create or change the DeviceType, Platform or Manufacturer.

| Job input | Operating contract |
| --- | --- |
| Device | Existing standalone ESXi host Device; no host or peer Device is created. |
| Secrets Group / override | A complete Username/Password pair from HTTP, then REST, then Generic access. Both values must come from the same access type. RESTCONF and SSH credentials are not ESXi fallbacks. Provider failures stop resolution and are sanitized. |
| Verify HTTPS certificate (`verify_tls`) | `True` by default. Configure worker trust for the host certificate. `False` is an explicit lab exception. |
| ESXi HTTPS port (`esxi_port`) | Default `443`; integer range `1–65535`. |
| Expected ESXi host UUID (`expected_esxi_host_uuid`) | Optional explicit, non-sentinel BIOS UUID binding. It must match the observed host UUID. Required for writes when the host does not report a usable serial; the UUID is never copied into `Device.serial`. |
| New interface administrative state (`esxi_new_interface_state`) | Default `report-only` defers new interfaces. `enabled` or `disabled` supplies operator intent only for newly created interfaces. Existing administrative state is preserved. |
| ESXi Hosted On guest mappings (`esxi_guest_mappings`) | Optional explicit JSON selections of observed guest BIOS UUIDs and existing guest Device UUIDs, described below. Blank retains guest evidence in the report. |
| Dry run | Plans and validates without inventory DML. Review the Advanced/JSON report before applying. |

Leave Cisco VLAN/module/IPAM and PAN-OS routing/management/HA/VPN policies unset
for ESXi. The Job rejects those write policies for this adapter. The existing
NTC guessing input does not supply ESXi hardware capability or interface defaults.

## Source identity and native host mapping

The transport requires `ServiceContent.about.apiType=HostAgent` and
`productLineId=embeddedEsx`, discovers exactly one visible HostSystem, and reads
its registered guest/datastore references. The adapter requires the standalone
`ha-host` scope and corroborates service identity against `config.product`.
A VirtualCenter endpoint is rejected before inventory collection.
[Broadcom AboutInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.AboutInfo.html)
defines the standalone scope and product identifiers.

The retained envelope has adapter `esxi`, integer schema version `1`, and source
contract `esxi-host-v1`. Before planning, `reconstruct()` repeats source parsing
and checks normalized identity, interface facts and explicit binding/policy
against reviewed retained properties. Changed normalized facts, conflicting
source identities, injected unreviewed fields or unsupported write domains
block application. Guest records must match the host's typed VM references, and
each guest runtime host must identify that same HostSystem.

| Fact | Reviewed source | Native behavior |
| --- | --- | --- |
| Hostname | `HostSystem.name`, corroborated with `summary.config.name` when present | Fill a blank Device name; preserve and report an existing different name. |
| Hardware vendor/model | `hardware.systemInfo.vendor/model`, corroborated with `summary.hardware` | Verify the selected Manufacturer/DeviceType. No hardware catalog is created or guessed. |
| Serial | `hardware.systemInfo.serialNumber`; typed `ServiceTag`/`SerialNumberTag` fallback | Fill a blank serial only after identity validation. Placeholder/ambiguous values remain unavailable. Conflicting serial sources block writes. |
| BIOS UUID | `hardware.systemInfo.uuid`, corroborated with `summary.hardware.uuid` | Host-scope evidence and explicit `esxi-host-identity-v1` binding. Excludes nil/all-ones UUIDs. Never a chassis serial or new custom field. |
| Running software | Exact `config.product.version` and `build`, corroborated with service AboutInfo | Fill native SoftwareVersion under the existing ESXi Platform using `8.0.3 build-24677879` form. Different builds remain different releases. Preserve an existing software relationship. |
| CPU and installed memory | `hardware.cpuInfo`, `summary.hardware` | Observations. Packages, physical cores and threads remain distinct; physical memory is bytes. They do not populate guest `vcpus` or Device capacity custom fields. |

These meanings follow
[HostSystemInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.SystemInfo.html),
[HostHardwareSummary](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.Summary.HardwareSummary.html),
and [HostCpuInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.CpuInfo.html).
ESXi API version, product version and build are separate values. The adapter does
not derive an update-letter release label from an installer filename or CPU data.

## Host NICs

Only exact `vmnicN` names with unambiguous pNIC key and PCI identity can produce
native interface facts. Source provenance uses `esxi-pnic-v1`. All pNIC rows
remain in the report, including excluded, disconnected and unaddressed adapters.
Duplicate names, keys or PCI functions fail collection rather than choose a row.

| pNIC fact | Mapping |
| --- | --- |
| MAC | Validated pNIC `mac`, normalized to colon-separated lowercase; missing/zero/broadcast sentinels stay unresolved. Fill blank native MAC only. |
| Current speed | Positive `linkSpeed.speedMb`, converted from Mbps to native Kbps by multiplying by `1000`, within native field bounds. Omitted/down/invalid rates stay unresolved. Virtual native types do not receive a physical speed. |
| Current duplex | Retained in source/network observations. It does not populate native configured `Interface.duplex`, including when a copper template exists. |
| Administrative state | Unavailable from the collected pNIC contract; normalized `enabled` remains `None`. Absence of `linkSpeed` means link down, not administratively disabled. New enabled/disabled state comes only from explicit operator policy. |
| Physical type | Preserve existing native types and exact DeviceType templates. A reported physical NIC with unknown maximum capability can create native `Other` when creation policy is explicit. Negotiated speed does not choose maximum capability. |
| VMXNET3 | Exact pNIC PCI join to vendor `15ad`, device `07b0`, plus `nvmxnet3`/`vmxnet3`, supplies native `virtual`. BIOS vendor/model does not override this virtual-device evidence. A known VMXNET3 driver without that joined PCI proof stays report-only. |
| Connector, description, MTU, management-only | No reviewed pNIC source is collected for these native fields; leave unresolved and preserve existing values. VMkernel/vSwitch MTU is not pNIC MTU. |

[Broadcom PhysicalNic](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.PhysicalNic.html)
and [PhysicalNicLinkInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.PhysicalNic.LinkSpeedDuplex.html)
define pNIC identity, link state and Mbps units. VMware's
[device identifier source](https://github.com/vmware/open-vm-tools/blob/master/open-vm-tools/lib/include/vm_device_version.h)
identifies the VMXNET3 PCI tuple. A physical-adapter view inside ESXi can describe
virtual hardware when ESXi itself runs as a VM. PCI IDs/addresses and MACs do
not establish a real connector, chassis slot, serialized NIC Module or cable.
Native eligibility follows the installed validators and existing
[interface field contract](interface-fields.md).

## NFV observations

The host property allowlist contains these 15 paths; fields inside each property
are also explicitly allowlisted:

```text
name
hardware.systemInfo
hardware.cpuInfo
hardware.pciDevice
summary
config.product
config.network.pnic
config.network.vnic
config.network.vswitch
config.network.portgroup
config.storageDevice.scsiLun
config.fileSystemVolume.mountInfo
vm
datastore
config.virtualNicManagerInfo
```

| Observation | Retained implemented fields and limits |
| --- | --- |
| Standard vSwitches | Name/key, MTU, current/available port counts, pNIC/portgroup references and reviewed security/team policies. Membership does not create a LAG, bridge relationship or cable. |
| Portgroups | Name, parent switch, VLAN ID and own/effective security/team policy. VLAN `0` has no VLAN association; `1–4094` selects a VLAN; `4095` is guest-controlled trunking, never a native VLAN 4095 creation. |
| VMkernel adapters | Name/key, portgroup, MAC, MTU, IPv4 address/mask/DHCP, reviewed IPv6 origin/prefix/state, TCP/IP stack key, distributed-port reference and pinned pNIC where supplied. Selected vNIC service references remain observations. No native VMkernel Interface or IPAM writes. |
| Guest identity/state | Name, BIOS UUID, optional vCenter instance UUID, template flag, configured guest ID/hardware version, runtime host, power/connection state and Tools-running status. Guest names and registration IDs never select native Devices. |
| Guest allocation/tuning | Configured CPU count/cores per socket/memory MB; CPU/memory reservation and limit; reservation-locked flag and latency-sensitivity level. No guest sizing/custom-field writes. |
| Guest devices/network | Allowlisted Ethernet subclasses and VirtualDisk devices with device key/label/controller/unit, MAC, backing and connection fields; virtual disk byte/KB capacity and storage backing policy. Tools NIC network/MAC/connected/deviceConfigId/bare IP lists remain telemetry. Other device classes and guest programs are not queried. |
| Host storage/datastores | SCSI LUN identity/model/type/block capacity, filesystem mount state/volume identity, datastore summary and VMFS/NFS info including reviewed extents. Capacity/free space are raw observations and useful only with valid accessibility evidence. No storage assets or aggregate host disk capacity are created. |

The switching semantics follow
[HostVirtualSwitch](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.VirtualSwitch.html),
[HostPortGroupSpec](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.PortGroup.Specification.html)
and [HostVirtualNic](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.VirtualNic.html).
Distributed/opaque references do not establish a complete vCenter DVS or NSX
inventory. Portgroup and TCP/IP stack names do not choose Namespace/VRF policy.

[GuestInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.GuestInfo.html)
explains Tools telemetry; absent guest addresses do not prove no addresses.
[VirtualDisk](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualDisk.html)
separates virtual disk capacity from occupied space and guest filesystems.
[DatastoreSummary](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.Datastore.Summary.html)
limits capacity validity to accessible datastores; `multipleHostAccess` is
vCenter-only, so omission cannot prove a datastore is local.

The collector does not request annotations, user data, host advanced options,
`extraConfig`, custom values, license secrets, guest execution, snapshots,
performance counters or a BMC. This increment does not write IPAM, VLANs,
Cisco/PAN-OS domains, hardware components, guest Interfaces, guest attributes,
VirtualMachine/Cluster objects or capacity custom fields.

## Existing NFV guest Devices and Hosted On

Guests continue to be modeled as existing Devices. The only native guest action
is adding a relationship through the existing `hosted_on` definition:

```text
one-to-many: dcim.device (ESXi host/source) -> dcim.device (NFV guest/destination)
```

Enter explicit mappings, for example:

```json
[
  {
    "vm_uuid": "00000000-0000-4000-8000-000000000001",
    "device": "00000000-0000-4000-8000-000000000002"
  }
]
```

The first UUID must be the guest's reported `config.uuid`; the second must select
an existing Nautobot guest Device. These are example UUIDs, not lab selections.
The Job resolves existing native objects, and `esxi-guest-policy-v1` plus
`esxi-hosted-on-v1` preserve the exact selected host, guest and definition UUIDs.
No relationship schema, guest Device or virtualization cluster is auto-created.
The current lab definition has UUID `6295555f-c43f-4a18-b9d1-ec91c0ee2eef`;
this is a verified lab object, not a hardcoded relationship ID. Other installations
resolve their own existing `hosted_on` definition and validate its native shape.
[Broadcom VirtualMachineConfigInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.ConfigInfo.html)
defines `config.uuid` as the guest SMBIOS identity and `instanceUuid` as
VirtualCenter-specific. The latter is an observation, not the standalone join.

A mapped guest must have one unique observed BIOS UUID, one host-local typed VM
reference, matching runtime host, explicit `config.template=False` and
`runtime.connectionState=connected`. A stopped, connected, non-template guest
can qualify. Missing/unknown/duplicate identity, foreign host evidence, duplicate
mapping, unavailable native capability or a missing selected Device blocks the
proposed links. An existing matching link and association UUID are preserved.
Foreign or ambiguous existing ownership blocks reparenting; disappearance from
the visible API inventory never deletes a link. No name, globally interpreted
MOID, guest IP or instance UUID is substituted for an explicit mapping.

## Bounded reads and visibility

The transport permits exactly five methods: `RetrieveServiceContent`, `Login`,
`Logout`, `RetrievePropertiesEx`, and `ContinueRetrievePropertiesEx`. Login/logout
manage the necessary session; no ESXi configuration, refresh, power, console,
SSH or guest operation is available. Requests use HTTPS with redirects disabled,
proxy-environment inheritance disabled, and sanitized method/property traces.
XML entities/DTDs, malformed envelopes, duplicate fields/identities, nil arrays,
unexpected methods and out-of-scope references fail validation.

Default transport budgets are 128 requests, 32 pages per retrieval, 4,096
returned objects, 4 MiB per SOAP request/response, 65,536 XML nodes and nesting
depth 64. HTTPS uses a 10-second connection timeout and a default 30-second read
timeout. Continuation tokens must drain completely without repetition. Source
budgets and failures cannot masquerade as healthy empty inventory.

Core host coverage requires `name`, `summary`, `hardware.systemInfo`,
`hardware.cpuInfo` and `config.product`. Guest core coverage requires name, BIOS
UUID, template flag, configured CPU/RAM and runtime host/power/connection state.
Datastore name/summary are required. Optional properties can be omitted without
fabricated values. **Any `missingSet`, including on a guest or datastore, fails
the entire collection** in this version; there is no partial host-only apply.

Guest/datastore lists are always labeled `permission-scoped`. Successful reads
and empty lists do not prove complete visibility or feature absence.
[PropertyCollector](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.html)
performs access evaluation, and
[MissingProperty](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.MissingProperty.html)
distinguishes failed property retrieval. The implementation does not call
vCenter-only privilege-check methods or claim that role/permission enumeration
proves complete standalone inventory.
[AuthorizationManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.AuthorizationManager.html)
documents those limitations.

## Native preservation and validation

Apply reconstructs facts, locks the existing relationship definition when guest
mapping is requested, locks catalog context and selected host/guest Devices in
stable order, resnapshots/replans, validates the complete proposed graph, then
saves in one transaction. Definition and association identities are rechecked at
the native boundary. Competing ownership or a late save failure rolls back
software, Device, Interface and guest relationship writes together.

Existing values remain authoritative, including `False`, zero and `Other`.
Host and existing Interface custom-field dictionaries are restored exactly
after native cleaning so unrelated default insertion or value normalization
cannot become discovery updates. Existing interface UUIDs, names, types,
ownership, cables, assignments and sizing intent are preserved. Discovery
creates no custom-field definitions. New objects still undergo normal native
creation validation and use explicit supported input/policy. Preview and an
unchanged repeat issue zero inventory DML.

Implementation boundaries are in [transport](../jobs/transport_esxi.py),
[adapter](../jobs/adapters/esxi.py), [host policy](../jobs/reconcile_esxi.py),
[guest policy](../jobs/esxi_guest_policy.py),
[guest planner](../jobs/reconcile_esxi_guests.py), and
[native guest boundary](../jobs/nautobot_esxi_guests.py).

## Validation checkpoint

Live collection from the nested development ESXi host reported:

| Item | Verified observation |
| --- | --- |
| Endpoint | `10.40.3.124`, direct HostAgent `/sdk` |
| Product | `8.0.3`, build `24677879`; canonical native version `8.0.3 build-24677879` |
| Hardware | QEMU, `Standard PC (i440FX + PIIX, 1996)`; serial unavailable |
| BIOS UUID | `9b460af4-d4fa-4332-b4cc-18523af80110` |
| Host NIC | One `vmnic0`, verified VMXNET3 virtual hardware through PCI/driver evidence |
| Registered guests/datastores | Zero returned in this session; permission-scoped, not proof of global absence |

The installation ISO's `8.0U3e` label is not reconstructed from API version
`8.0.3`. This live capture verifies this development host/build, not broad
release/hardware coverage. Nonempty guest/storage cases use adversarial
structured fixtures and the native rollback harnesses.

Configured Nautobot **3.2.6** passed **31 native checks**: 20 host checks and
11 Hosted On checks. These verify source/identity guards, True/False creation
policy, exact host/Interface custom-field preservation including raw integer
normalization and omitted defaults, preview/repeat zero DML, unchanged cables
and relationships, late-write rollback, and application of the real collected
ESXi source in an ephemeral native copy. Both harnesses completed unconditional
outer rollback with **zero persistent changes**; the existing Hosted On
relationship definition remained exact. The complete offline suite passed
**1,203 tests**. Repository Ruff checks and formatting checks across 153 Python
files, compilation and whitespace checks also passed.

The real Job `0.24.0-dev` separately passed against `10.40.3.124` using normal
HTTP Secrets Group associations, the actual environment-variable secret
provider, real SOAP collection and the explicit matching BIOS UUID. Preview
issued **zero inventory DML**. Applying the collected report through the
production native boundary assigned `8.0.3 build-24677879` and created one
native **virtual** `vmnic0` Interface. The unchanged repeat issued **zero DML**.
All fixture setup, Secrets records, native apply and catalog changes completed
inside unconditional outer rollback with **zero persistent changes**. This
proves the live host path; nonempty guest links were validated by the 11 native
Hosted On fixture checks, since the live session returned no guests.

Run the complete offline checks from the repository:

```bash
python3 -m unittest discover -s tests -t .
ruff check jobs tests tools
ruff format --check jobs tests tools
python3 -m compileall -q jobs tests tools
```

For real ORM proof, run `tests/nautobot_esxi_integration.py` and
`tests/nautobot_esxi_guests_integration.py` in a configured Nautobot Django
process through `nbshell`/`runpy`. Set `NAUTOBOT_DISCOVERY_DEVICE_ID` to an explicit
existing anchor; the lab anchor was
`a6409f62-7d96-4480-a572-5fd99284b82e` (`se350-lab-1`). The host harness can use
`NAUTOBOT_ESXI_SOURCE_PATH` for an already-collected sanitized transport/adapter
JSON file. It never resolves credentials or connects to ESXi. Both harnesses
place fixture catalogs/Devices and all writes inside unconditional outer
rollback; the guest harness uses the existing Hosted On definition and checks
that its metadata is unchanged.


[The durable live Job harness](../tools/esxi_lab_validation.py) additionally
exercises normal Secrets Group resolution with temporary HTTP associations and
the actual environment-variable secret provider, calls the real Job preview
against an explicitly supplied ESXi endpoint, and applies/repeats its collected
report through the production native boundary. Credentials remain in temporary
process environment values; the temporary Secret records contain provider
references, and reported data/traces contain no password. This harness creates
an ephemeral selected host/catalog context inside unconditional outer rollback,
checks zero preview/repeat inventory DML and unchanged inventory/Secret counts,
and removes its temporary environment values. Its completed live Job proof is
separate from mock transport tests and the host/guest ORM fixture harnesses;
the measured results are recorded above.
