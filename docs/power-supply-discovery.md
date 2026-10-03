# Power supply discovery

Discovery uses native Nautobot ModuleBays, Modules and PowerPorts. Collection
uses RESTCONF GET requests and JSON only; no custom fields are created.

## Bays and serialized assets

Exact reviewed chassis profiles cover 40 Catalyst C9300, C9300L, C9300LM and
C9300X models. Cisco documents two replaceable PSU positions, A and B, for
these models. Both bays can be created independently of an installed PSU's
identity, including when the optional platform response is unavailable.
An unpopulated Nautobot bay means that no identified Module is recorded there;
it does not prove that the physical bay is vacant.

Automatic asset creation still requires a complete PID and serial, a unique
hardware/platform identity match, and verified parent and location information.
Numeric inventory indexes never join the two sources. Existing occupied bays,
Module serials, locations and status values are preserved. An unidentified
nonempty PSU remains an observation, and a manually recorded occupant remains
in place. Replacements and moves are reported as conflicts for operator review.

The exact chassis and PSU compatibility lists, inlet connector specifications,
and their Cisco documentation links are in
[cisco_psu_profiles.py](../jobs/adapters/cisco_psu_profiles.py). This broader
PSU coverage does not expand the separate uplink, transceiver, console or
management-port profiles.

## Power inlets

A uniquely identified PSU can own a native PowerPort. An exact reviewed PID
supplies its documented inlet connector type; unresolved connector types stay
blank. Templates on an existing ModuleType are considered when naming a port,
and automatic template instantiation is suppressed so discovery does not
duplicate ports. Existing names, cables and populated values are preserved.
Upstream outlets and power cables are not inferred.

Maximum draw and allocated draw remain blank unless their documented meaning
can be established. A PSU's output capacity is not its maximum input draw.
Voltage-specific input specifications do not establish an unconditional maximum.

Nautobot requires a power-factor ratio between 0.01 and 1.00 on every PowerPort.
In strict mode, a new inlet is deferred when that value is unknown; its bay and
serialized Module can still be created. The existing **Use NTC defaults when
guessing** option permits Nautobot's model default of **0.95**, explicitly marked
as inferred in the report and job log. Existing power factors are preserved.
The lab's native operational response reports `88.4` without a documented
conversion to the required ratio. Discovery retains that raw property as
evidence and does not convert it.

## Stack placement and operational observations

PSU bays, Modules and inlets belong to the physical Device whose chassis serial
and member position are verified by the stack plan. This includes a newly
created stack member. A missing or conflicting owner prevents placement.
Other serialized component types on multi-member stacks retain their existing
deferred behavior.

The job-selected Module Status describes the new asset's lifecycle. Operational
power state does not change that Status. Platform presence, enabled state,
input/output properties and equipment observations remain in the JSON report
with source information; they do not become lifecycle status or configured draw.

## Validation

Offline tests cover independent bays, identity conflicts, positional aliases,
reviewed PID compatibility, strict and inferred power factor, and member
ownership. Rollback-only tests against Nautobot 3.2.5 verify bay-only preview,
new stack-member placement, Module-owned inlets, repeat-run idempotence, cable
preservation, template suppression and transaction rollback.

Live collection uses the standalone C9300-48UXM on IOS XE 17.18.4. Other reviewed
chassis profiles and multi-member stacks are covered by structured fixtures and
ORM tests; they have not received live hardware validation.

## Lab validation — 2026-10-03

Job `0.13.0-dev` was validated against Nautobot 3.2.5 and the C9300-48UXM
running IOS XE 17.18.4. All 488 offline regressions and 98 real ORM checks
passed; the ORM harness rolled back all test inventory. Strict and opt-in
GET-only previews both issued zero
inventory mutation statements. The registered worker preview succeeded with
an attached report and unchanged inventory.

The strict worker apply added the previously missing **Power Supply A** bay.
It preserved existing assets, interfaces, LAGs, VLANs, IPAM, console ports,
custom-field values and power cables. A second worker apply succeeded with an
identical inventory snapshot and no proposed inventory changes.

PSU A reports nonempty presence and no input power but still omits PID and
serial; it remains an unidentified occupant. PSU B's documented C16 inlet is
eligible when the defaults option is enabled. The opt-in preview proposed one
PowerPort with explicitly inferred power factor `0.95` and no input draw
rating. That inferred plan was validated but was not applied to the lab.

Rollback-only ORM checks include the complete combined stack/PSU workflow:
zero-DML preview with a new DeviceType and member Device, serial-matched PSU
and inlet ownership, repeat-run zero writes, and rollback of the entire stack
and power graph after a late inlet failure. Full reports and JobResult
identifiers remain in ignored local validation artifacts.
