# PAN-OS capacity discovery

Job `0.22.0-dev` adds `panos-capacity-v1` and fill-only processing for the
existing Device custom fields `vcpus`, `memory_mb` and `disk_gb`. The user's
request explicitly authorizes these existing fields. Discovery does not create
or change custom-field definitions.

All capacity evidence comes from Palo Alto responses over the existing SSH/XML
transport. There is no hypervisor connection, credential, lookup, sizing profile
or model-based default. The existing `show system info` read is reused, so this
increment adds no firewall queries.

## Current field/source contract

| Device field | Palo source | Meaning and unit | Current write eligibility |
| --- | --- | --- | --- |
| `vcpus` | `show system info`, `result/system/vm-cores` | Reported VM-Series core count | Explicit `PA-VM` model and `vm` family, strict positive integer scalar and validated selected-Device identity |
| `memory_mb` | `result/system/vm-mem` retained as raw evidence | The XML scalar does not declare a verified unit or mapping to integer memory capacity | Unresolved; no conversion, rounding, allocation estimate or default |
| `disk_gb` | No reviewed structured primary-disk source | Primary disk capacity must not be inferred from partition totals, free space or disk usage | Unresolved; no native proposal |

Palo's [PAN-OS attribute reference](https://docs.paloaltonetworks.com/iot/integration/attribute-reference/attribute-reference-panos)
identifies `vm-cores` as VM cores. Its
[OpenConfig XML API example](https://docs.paloaltonetworks.com/openconfig/2-0/openconfig-admin/pan-os-models/pan-os-openconfig-xmlapi)
shows these exact system-info scalars, including `vm-cores=4`, but does not
establish the required memory unit. VM mode is not a capacity eligibility
condition; these facts do not assume KVM, Proxmox or another hypervisor.

The separate existing identity contract remains in force. A Device with known
serial identity does not need a VM UUID for capacity processing. The existing
reviewed UUID binding is still required when that binding supplies identity for
an unlicensed PA-VM with a blank serial; this increment does not widen that
identity contract.

## Lab source audit

The PA-VM/PAN-OS 11.2.8 lab reports `vm-cores=4` in successful structured XML.
It reports `vm-mem=8157848` at the live source-audit checkpoint; guest-memory
readings can vary and are retained exactly, without interpreting them as the
hypervisor's allocation.

Read-only source investigation also checked `show system resources`,
`show system disk-space`, platform state filters and documented resource state.
They returned display text or a dictionary-like display despite XML session
mode. Those responses are not production discovery sources. The platform memory
display and resource units suggest fractional MiB, which also cannot be written
exactly to the existing Integer field. Storage observations describe partitions
and usage rather than an unambiguous primary-disk capacity. These probes neither
enter the production SSH allowlist nor establish support for another release.

## Planning and native application

The pure planner independently recomputes capacity facts from the approved
system-info evidence. It rejects altered paths, quantities, units and added
unreviewed facts. Missing and malformed CPU values remain unresolved.

The native boundary detects Device JSON custom-field storage, existing Integer
definitions, Device scope and native value validation capabilities. Missing,
incompatible, constrained or unsupported definitions remain unresolved.
Nonempty custom-field scope filters require a separate reviewed applicability
policy. Existing validation bounds are honored. Labels and defaults do not
establish a capacity value.

Only `None` and empty text are blank. Populated values, including zero and
`False`, remain exact; differences appear in the report. The Proxmox deployment
job uses these fields as sizing intent, so discovery can seed empty intent from
verified Palo evidence but does not change populated intent to match observations.

Preview performs native field and full Device validation without inventory
writes. Apply locks and resnapshots the Device and definitions, rechecks blanks,
validates, and saves together with the existing transaction. Native validation
may normalize unrelated custom-field values or introduce defaults, so the
capacity context preserves their exact staged raw values after validation.
A repeat with no changes saves nothing. Late failure rolls back all related
inventory writes.

The report includes `discovery.capacity`, `plan.capacity`,
`capacity_fields_updated` and `unresolved_capacity`. Raw observations and source
details belong in Advanced and the JSON attachment; the main log reports counts.

## Validation

The durable native harness is `tests/nautobot_panos_capacity_integration.py`.
It covers CPU population, zero-DML preview/repeat, existing intent preservation,
schema guards, native validation and complete rollback. Memory and storage are
explicitly checked to remain unchanged. Current native validation uses Nautobot
3.2.6; no Nautobot 2.4 runtime result or broader PAN-OS version support is claimed.

The final increment passed 995 offline tests on Python 3.14 and 3.12, plus
15 capacity, 22 existing PAN inventory, 17 PAN IPAM and 150 Cisco native checks
on Nautobot 3.2.6. Native fixture suites rolled back all changes. Ruff lint,
formatting, compilation and whitespace checks passed.

Strict SSH production collection succeeded on all three PA-VM/PAN-OS 11.2.8
lab members, including HA active, HA passive and the standalone VPN peer. Each
used the existing twelve-read set and reported core count four. The passive
member's unresolved IKE observation remains unrelated report-only evidence.

The installed `0.22.0-dev` Job preview used normal Secrets lookup and strict
SSH with zero DML. Reviewed apply filled `panos-lab.vcpus=4` and created the
already eligible missing virtual `ethernet1/3` Interface. It issued two inventory
writes; the repeat issued zero DML. `memory_mb` and `disk_gb` stayed `None`, and
every other custom-field value remained exact. The Advanced report matched the
captured JSON attachment. All 46 installed runtime modules matched the workspace.

A normal Celery queued preview also completed successfully as JobResult
`52bb64a7-cff2-4f78-9c9f-c8bcfd98fc1a`. It used normal Secrets and strict SSH,
preserved inventory and all stored custom-field values, reported no pending
capacity changes and retained the two unresolved quantities. Its FileProxy JSON
attachment matched Advanced. Only ordinary Job/result/log/report records were
created by this queued preview.
