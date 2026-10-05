# PAN-OS VM-Series validation contract

This increment validates inventory on the existing selected `panos-lab` Device.
It builds on the [PAN-OS first-pass contract](panos-discovery.md) and
[handoff](panos-discovery-handoff.md). The lab is PA-VM, family `vm`, VM mode
`KVM`, running PAN-OS 11.2.8 on Proxmox. Guest network adapters and physical
firewall connectors have different evidence requirements. Nothing in this
increment establishes physical-appliance capability or a universal VM-Series
port count.

## Lab authorization and collection boundary

The user has authorized changes to the dedicated PAN-OS VM and its Proxmox
environment to validate discovery. Controlled lab setup can attach isolated
VirtIO adapters, reboot the guest, and commit explicit interface configuration.
Keep the existing management adapter and endpoint available. Inventory
collection itself remains read-only SSH/XML, with the three first-pass reads
and one reviewed conditional VM read described below. Discovery never reconfigures the firewall, acquires a
license, or uses Proxmox to manufacture PAN-OS operational observations.

Proxmox credentials and firewall credentials stay in their private environment
files. Sanitized fixtures preserve XML paths, response semantics, interface
names, row IDs, missing leaves, and reported token meanings. Private reports
can retain selected-target evidence; credentials, full configuration, and
unreviewed subtrees must not be committed.

## Native mapping and identity protection

| Evidence | Native meaning and destination | Required conditions | Missing or conflicting evidence |
| --- | --- | --- | --- |
| Strict successful `show system info`, `result/system/vm-uuid` | Identity of the selected guest instance. Compare with the explicit expected VM UUID input; report the binding. | Reported model `PA-VM`, family `vm`, VM mode `KVM`, a canonical UUID, and exact agreement with the expected UUID independently verified on Proxmox. The operator selects the existing Device. | An absent, malformed, nil, sentinel, or different UUID blocks writes. A model/name/endpoint alone cannot substitute for this binding. |
| Missing `system/serial` on the reviewed PA-VM/KVM deployment | `Device.serial` remains blank. | UUID binding may satisfy the missing-serial identity requirement only for the reviewed VM-Series case and only while the selected Device serial is also blank. | A populated native serial remains protected. Physical-appliance serial requirements and serial conflicts retain their existing blocking rules. No UUID, MAC, hostname, or synthetic token becomes a serial. |
| `system/hostname`, `model`, `sw-version`, selected Platform | Existing selected Device identity and native SoftwareVersion. | Preserve the first-pass hostname/model/version/Platform validation and fill-only behavior. | Preserve the selected alias and existing relationships; report conflicts. No Cisco release normalization. |
| Exact ordinary Ethernet adapter from the reviewed VM XML source, plus an exact existing DeviceType template | `Interface.type="virtual"` for this lab's software adapters. | The template is reviewed against actual Proxmox VirtIO adapter configuration and observed guest enumeration. The shared template contract matches the exact observed name unambiguously. | No template or ambiguous templates leaves type unresolved. Do not infer type from `PA-VM`, `KVM`, `hw`, an Ethernet name, numeric `type`, or negotiated speed. |
| Explicit applied Ethernet `link-state=up` or `down` | Administrative `Interface.enabled=True` or `False`. | Complete successful effective-running interface configuration joined to the exact observed adapter. | `auto`, absent state, invalid tokens, and operational `down` remain unresolved. An omitted leaf does not grant an ORM default. |
| Explicit applied `comment` and `layer3/mtu` | Fill blank Interface description and validated MTU. | Existing first-pass strict source, identity join, whole-token bounds, and fill-only checks. | Omission stays unresolved; operational MTU does not replace configured evidence. |
| Guest adapters, runtime speed/duplex/MAC, logical rows, zones, vsys, addresses | Structured observations for review. | Preserve every observed hardware row including down and unaddressed ports, plus separate logical/configuration-only rows. | No fabricated physical connector, cable, parent, LAG, IPAM, zone-to-VRF, or vsys-to-Namespace writes. |

The expected UUID is a Job input and report binding, not a new inventory
identity field. No native Device UUID is changed and no custom field is added.
Strict canonical comparison accepts hexadecimal letter case consistently,
without accepting alternative UUID encodings, arbitrary prose, or sentinel
values. Passing an expected UUID cannot bypass the model, Platform, software,
selected-target, or existing serial checks. It cannot enable a physical
firewall lacking its required serial. The binding is independent of the
`vm-license` observation; it neither asserts licensing entitlement nor infers
a serial from license state. A genuinely reported serial retains the existing
fill-only behavior.

Palo Alto's [VM-Series license activation reference](https://docs.paloaltonetworks.com/vm-series/activation-and-onboarding/vm-series-models/activate-the-license)
documents that unactivated instances lack a serial, their dataplane MACs are
not unique, and licensing derives a serial from the VM UUID and CPU ID. The
[official OpenConfig XML API example](https://docs.paloaltonetworks.com/openconfig/2-0/openconfig-admin/pan-os-models/pan-os-openconfig-xmlapi)
also shows `vm-uuid` inside the system-info response. The live XML capture must
corroborate that exact path for this lab. A future clone requires independent
expected-UUID review; trusting a newly observed endpoint UUID without that
check is not identity protection.

## Why VM deployment markers do not determine interface type

Palo Alto's [KVM requirements](https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-the-vm-series-firewall-on-kvm/vm-series-on-kvm-requirements-and-prerequisites)
support software bridges with VirtIO/e1000 adapters, PCI passthrough, and
SR-IOV. A VM deployment can therefore contain interfaces with different
hardware relationships. `model=PA-VM`, `family=vm`, and `vm-mode=KVM` prove the
guest deployment kind; those fields do not prove each adapter is VirtIO or
establish a physical connector.

The [official PCI ordering reference](https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-the-vm-series-firewall-on-kvm/install-the-vm-series-firewall-on-kvm/verify-pci-id-for-ordering-of-network-interfaces-on-the-vm-series-firewall)
orders guest interfaces by PCI ID and demonstrates that bridge adapters and
passed-through devices can be mixed. Proxmox `netN` labels must not become a
universal name-derived join to PAN-OS `ethernet1/N`. For this controlled lab,
retain the host adapter configuration and guest before/after enumeration as
setup evidence. Use exact templates as reviewed operator input; do not encode
the lab's port count or release into the adapter.

The documented `debug show vm-series interfaces all` command returned
successful structured XML on this lab and is now a required conditional
production read under the reviewed contract below. A display table rather than
successful structured XML still fails collection; setup observations never
justify scraping a table to populate fields.

Installed Nautobot 3.2.5 permits a Device Interface of native type `virtual`.
This does not require replacing the selected Device with a VirtualMachine.
The installed Interface validators prohibit physical cabling, `port_type`,
speed, and duplex on this type, and prohibit ordinary LAG membership. Leave
those fields blank. Runtime observations remain available in the report.
See the [versioned native Interface documentation](https://raw.githubusercontent.com/nautobot/nautobot/v3.2.5/nautobot/docs/user-guide/core-data-model/dcim/interface.md)
and [model](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/dcim/models/device_components.py).

Palo Alto's [PAN-OS 11.2 Layer 3 interface reference](https://docs.paloaltonetworks.com/ngfw/help/11-2/network/network-interfaces/layer-3-interface)
distinguishes explicit up/down selection from automatic link determination.
The reviewed Boolean mapping remains limited to explicit up/down. Test an
unconfigured or automatic-state adapter separately and require it to stay
observed but unresolved unless a later administrative contract is established.

## Conditional VM XML collection and provenance

The empty healthy hardware view and independently recognized guest adapters
justify a fourth exact SSH/XML read. The source is documented in Palo Alto's
[Virt-Manager installation reference](https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-the-vm-series-firewall-on-kvm/install-the-vm-series-firewall-on-kvm/install-the-vm-series-firewall-using-virt-manager),
and its complete live XML is captured. Collection chooses this additional read
from reported deployment evidence, without release heuristics or a port-count
profile:

| Exact command | Collection scope | Reviewed source |
| --- | --- | --- |
| `show system info` | Every PAN-OS target | `response/result/system` identity and deployment markers |
| `show interface all` | Every PAN-OS target | `response/result/hw/entry` and separate `ifnet/entry` operational observations |
| `show config effective-running xpath devices/entry/network/interface` | Every PAN-OS target | `response/result/interface/ethernet/entry` applied configuration |
| `debug show vm-series interfaces all` | Mandatory only when model=`PA-VM`, family=`vm`, VM mode=`KVM` | `response/result/entry` guest adapter enumeration |

The VM read is required whenever those deployment markers match, independently
of licensing or whether the expected UUID input is supplied. It is a documented
read despite the CLI's `debug` prefix. Missing, malformed, truncated, ambiguous,
unsuccessful or unstructured output fails collection. There is no optional
failure-to-empty behavior or fallback to the hardware view. Physical targets
retain the original three reads.

The fact/source contract is `panos-vm-interface-v1`. It preserves exact guest
`Interface_name`, `Base-OS_port`, `Base-OS_MAC`, and `Base-OS_BUS` observations,
with the exact command and `result/entry` provenance. Ordinary Ethernet names
allow the narrowly reviewed `Ethernet`/`ethernet` prefix normalization observed
between the VM debug and operational/applied sources. The original guest name
is retained as evidence; arbitrary case folding, Cisco aliases, inferred PCI
order, or a Proxmox `netN` suffix cannot establish an identity join. Duplicate
or conflicting guest names, base-OS ports, or PCI identities fail the read.
Non-Ethernet rows remain observations rather than new ordinary Ethernet facts.

Every recognized guest adapter remains observed, including one omitted from
`show interface all`, one without an address, or one with no applied
configuration. Exact applied configuration supplies description, validated MTU
and explicit up/down administrative state. Auto or omission remains unresolved
and defers creation. A configured or runtime rate does not supply capability.
Each new adapter still requires an unambiguous native DeviceType template;
this lab's reviewed templates are virtual. Neither guest deployment markers
nor the internal hardware type numeric code supply that type.

Guest base-OS MAC and PCI identity prove guest-source identity and can support
controlled lab host mapping. They remain report observations, not an assumed
PAN-OS dataplane MAC, physical connector, or hardware serial. Logical addresses,
security/forwarding contexts, LAGs and parent relationships retain their existing
report-only scope. The original physical `panos-interface-v1` provenance checks
remain in place for hardware-source facts.

## Validation required before claiming live apply

1. Record the selected VM identity, release, initial Proxmox adapter list, and
   successful scoped system/operational/applied XML reads.
2. Attach isolated VirtIO dataplane adapters without changing management.
   Verify guest enumeration after any required reboot; keep the actual rows
   regardless of addresses or operational link state.
3. Commit explicit up/down settings, descriptions, and explicit MTUs, including
   a non-default value, for distinct test ports. Leave another port unconfigured or automatic to test
   unresolved creation. Confirm applied XML matches the committed settings.
4. Review exact native templates for the observed VirtIO ports. Verify normal
   worker SSH trust before the installed Job uses this endpoint.
5. Run preview using the explicit expected UUID and assert zero inventory DML.
   Review all proposed writes and unresolved reasons, including blank serial.
6. Apply through native Nautobot validation in an atomic transaction. Confirm
   expected objects and native fields, with existing Device/Interface UUIDs,
   names, False values, populated fields, cables, and relationships preserved.
7. Repeat with identical input and assert no inventory changes. Run native
   rollback/preservation checks and the existing Cisco regressions.

Successful SSH collection, fixtures, or rollback-only synthetic checks do not
on their own establish successful live inventory apply. Delivery must record
the exact source revision/Job version, tested model/release, preview/apply/repeat
results, persisted interface outcomes, unresolved rows, and retained lab setup.
Licensed VM-Series, physical appliances, Panorama-effective configuration,
HA-specific MAC meaning, general automatic administrative state, and IPAM
remain separate evidence increments.

## Lab setup evidence, 2026-10-05

Proxmox node `pve`, VM `101` (`PanoS`), reports SMBIOS UUID
`56fe4cc8-e0f4-44c1-b0c5-2a5927c77a8b`. The original management adapter
`net0`, MAC `BC:24:11:56:F2:97`, remains VirtIO on `vmbr0`. Three additional
VirtIO adapters are attached to `vmbr101`, an isolated software bridge without
physical ports or host addressing. This is lab setup evidence, not a general
PAN-OS interface-count profile.

The cold boot temporarily made SSH unavailable. It recovered at the original
management address `10.40.3.232` after approximately six minutes, preserving
the VM UUID. An authenticated Proxmox VNC capture then showed the ordinary
`PA-VM login:` prompt, with no maintenance/error banner. No console keyboard
input was required. Early `show interface all` returned an unstructured server
error during initialization; the adapter rejected the read rather than treating
it as an empty successful inventory.

A read-only setup probe, with CLI XML output enabled, returned a complete
successful structured `debug show vm-series interfaces all` response:

| Exact guest `Interface_name` | `Base-OS_port` | `Base-OS_MAC` | `Base-OS_BUS` | Exact Proxmox adapter match |
| --- | --- | --- | --- | --- |
| `Ethernet1/1` | `eth1` | `02:15:d4:7c:70:37` | `0000:00:13.0` | `net1`, VirtIO on `vmbr101` |
| `Ethernet1/2` | `eth2` | `02:b3:22:a0:09:98` | `0000:00:14.0` | `net2`, VirtIO on `vmbr101` |
| `Ethernet1/3` | `eth3` | `02:9f:f8:0c:d9:cd` | `0000:00:15.0` | `net3`, VirtIO on `vmbr101` |

The matches use the actual base-OS MAC values from the guest XML and exact
Proxmox adapter configuration. They do not use the unlicensed dataplane MAC,
assume a driver field that was not returned, or derive a name from `netN`.
Palo Alto's [Virt-Manager installation reference](https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-the-vm-series-firewall-on-kvm/install-the-vm-series-firewall-on-kvm/install-the-vm-series-firewall-using-virt-manager)
documents this command for verifying host/guest interface ordering before
configuring the interfaces.

At this point, `show interface hardware` returned successful XML with explicit
empty `hw`; the ordinary all-interface view was also still empty. The three
recognized guest adapters therefore establish that an empty operational view
alone does not prove there are no attached adapters. Cause is not attributed
to licensing. `show system software status` returned a display table despite
the XML toggle, reporting all groups/processes running, including data_plane,
dagger, ifmgr, monitor-dp and vm_agent. This table is private setup evidence and
is not accepted as production inventory data.

Private setup artifacts are retained under `artifacts/panos-vm-validation/`:
Proxmox configuration/network proof, `proxmox-console.png`, and
`read-only-probes.json`. They remain ignored by Git. The reviewed guest XML
read is incorporated through the explicit contract below; the hardware and
software-status diagnostic reads remain outside the production fence. These
setup results do not on their own prove native inventory application.

The rollback-only native Nautobot 3.2.5 PAN-OS harness passed 21 checks: the
original 11 checks plus ten VM identity/preservation/provenance checks. Valid synthetic
UUID binding and exact virtual templates permit explicit up/down creation;
auto/absent administration defer. Missing/mismatched UUIDs, tampered source or
contract, wrong VM mode, and a populated selected serial with no reported
serial fail before inventory DML. Synthetic apply leaves serial blank, repeat
issues zero DML, and a late injected failure rolls back related writes. The
anchor Device and tracked catalog counts were restored; persistent test
changes were zero. A further check validates the VM enumeration command,
path, original name, base-OS port and PCI bus against unique raw observations
and rejects missing, duplicated or tampered provenance before inventory DML.
All 150 native Cisco regression checks also passed with zero persistent changes
and restored baselines/catalogs. Complete results are retained in ignored
`native-panos.json` and `native-cisco.json` beside the lab captures. These checks
establish native behavior with fixtures, not successful live interface apply.


## Applied interface evidence, 2026-10-05

A successful lab commit configured two of the exact recognized adapters while
leaving the third unconfigured. The scoped effective-running XML and refreshed
operational XML corroborate these fields:

| Canonical name | Explicit applied `link-state` | Native enabled fact | Explicit applied `layer3/mtu` | Applied comment | Fact provenance |
| --- | --- | --- | --- | --- | --- |
| `ethernet1/1` | `up` | `True` | `1400` | `PANOS discovery enabled lab port` | `panos-interface-v1`, operational hardware ID `16` |
| `ethernet1/2` | `down` | `False` | `1500` | `PANOS discovery disabled lab port` | `panos-interface-v1`, operational hardware ID `17` |
| `ethernet1/3` | Absent | Unresolved | Absent; unresolved | Absent | `panos-vm-interface-v1`, explicit guest `Ethernet1/3` / `eth3` / PCI `0000:00:15.0` |

The ordinary `hw`/`ifnet` views now contain the two configured adapters. The
VM XML source still reports all three. The merged inventory contains exactly
three adapter facts: it preserves original hardware provenance for the two
operational rows and supplies the additional reviewed VM provenance for the
otherwise missing unconfigured adapter. This demonstrates why the conditional
fourth read is needed for completeness.

MTU `1500` is accepted only because that exact applied leaf is present; its
usual default value does not authorize an omitted-leaf substitution. The third
adapter has no inferred enablement, MTU, description, MAC, connector or type.
All three have native type unresolved until exact reviewed templates are
considered. Base-OS and dataplane MAC observations remain report-only. Live
preview/apply/repeat results follow below.


## Live helper validation, 2026-10-05

The durable `tools/lab_apply.py` helper ran the actual Job `0.19.0-dev` in
configured Nautobot 3.2.5 against selected Device
`ed010564-cfd9-4039-bfad-a40ea4487157`, using expected VM UUID
`56fe4cc8-e0f4-44c1-b0c5-2a5927c77a8b`. It used normal Device-name endpoint
resolution with no process endpoint override, `ssh_strict=True`, normal Secrets
Group lookup, and `use_ntc_defaults=False`.

| Phase | Inventory DML | Verified outcome |
| --- | --- | --- |
| Preview | `0` | Unblocked native validation proposes two virtual interfaces and the software relationship; inventory snapshot unchanged. |
| Apply | `4` total statements | Creates `ethernet1/1` as virtual/enabled/MTU 1400 and `ethernet1/2` as virtual/disabled/MTU 1500; assigns native software version 11.2.8. |
| Repeat apply | `0` | No catalog, Device, interface or relationship changes; inventory snapshot unchanged. |

Every phase retained all three observed adapters; `ethernet1/3` remained deferred
because its administrative state was absent. Serial remained blank. Existing
rows, UUIDs, populated values, names, cables, IP assignments, tagged VLAN
assignments and other native relationships passed preservation assertions.
The single reported conflict was the preserved selected alias `panos-lab`
versus observed hostname `PA-VM`; it was not the unresolved third adapter.
No custom field or fabricated management interface was created.

Complete private evidence is retained in `live-validation.json`,
`panos-preview.json`, `panos-apply.json` and `panos-repeat.json` under ignored
`artifacts/panos-vm-validation/`. The live helper calls the actual Job and native
ORM directly; it does not by itself prove Celery queue delivery. The separate
queued worker evidence below verifies that delivery path against the resulting
live inventory.

The full offline suite passed 784 checks. Native verification passed all 21
PAN-OS and 150 Cisco checks with no persistent test inventory changes.

## Persistent lab endpoint and SSH trust

The selected Device's primary IP remains blank. A native primary IP requires
an actual interface assignment, and dedicated management-interface/IPAM
mapping remains outside this increment. The worker resolves the preserved
Device name `panos-lab` to the verified management address `10.40.3.232` instead.

The initial queued worker attempt failed because an ad hoc container alias was
lost when the worker restarted. That failure changed no inventory and remains
in Job history. The persistent lab correction is in the separate deployment's
`/opt/stacks/nautobot-composer/docker-compose.yml`: `extra_hosts` maps
`panos-lab:10.40.3.232` on both the `nautobot` and `celery_worker` services.
The shared volume configuration mounts the public host-key file
`./ssh/known_hosts` read-only at `/opt/nautobot/.ssh/known_hosts`. The host file
includes the independently verified target's IP/name identities. No credential
is stored there. These are local lab deployment settings outside this discovery
repository, not a production endpoint hardcoded in the Job.

To repeat on this lab, retain the persistent name mapping or provide ordinary
DNS, and keep the worker's known-host entries for the exact endpoint the Job
will use. After recreating the affected containers, wait for worker readiness
and verify name resolution and readable known hosts before queueing. Select
`panos-lab`, supply the independently verified expected VM UUID above, leave
SSH host-key verification enabled, and leave guessing disabled. Preview first,
then apply and repeat with identical inputs. A different endpoint or cloned VM
requires renewed UUID/host-key review rather than changing the discovered
serial or inventing an interface to bypass endpoint prerequisites.


## Queued worker validation, 2026-10-05

After recreating the web and worker services with the persistent alias and
SSH trust mount, four normal queued JobResult runs used the deployed Job
`0.19.0-dev`. Executable source hashes matched the validated workspace source.
All four used strict SSH host-key checking, normal Secrets Group credentials,
ordinary Device-name resolution, guessing disabled, and the exact four required
XML reads. No process endpoint override or direct-helper Job subclass supplied
these queued executions.

| Run | JobResult ID prefix | Final status | Report `applied` | Inventory outcome |
| --- | --- | --- | --- | --- |
| Preview | `89b15d5e` | `SUCCESS` | `False` | No inventory change. |
| Apply | `b40323ab` | `SUCCESS` | `True` | No inventory change. |
| Repeat apply | `ab9137c2` | `SUCCESS` | `True` | No inventory change. |
| Deliberately wrong expected VM UUID | `5d16c2e4` | Expected `FAILURE` | `False` | UUID mismatch and required-serial protection block apply; no inventory change. |

The three positive queue runs began after the live helper had created the two
interfaces and software relationship. They verify normal queued collection,
validation, report delivery and idempotence against that populated baseline;
they do not claim the initial native object creation occurred in the queue.
The initial persistent writes are the four helper apply statements recorded
above. Inventory snapshots were unchanged across all four queued runs.

Each attached JSON report matched the complete Advanced discovery evidence.
The main result contained no discovery payload; the framework stored its
ordinary empty result for successful runs. The expected wrong-UUID failure is
an identity-protection check and is separate from the earlier DNS setup
failure. Both remain in normal Job history. Full JobResult identities, statuses,
source hashes, comparison results and negative plan errors are retained in
ignored `artifacts/panos-vm-validation/queued-validation.json`.

The validated live scope is PA-VM 11.2.8 on KVM, three recognized VirtIO guest
adapters, two explicit configured virtual interfaces, and a third unconfigured
adapter retained without guessed administration. Native serial remains blank.
Physical appliance capability, other VM deployments/releases, Panorama/HA
behavior, general automatic administrative state and IPAM remain unvalidated.
