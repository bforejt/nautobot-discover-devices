# Cisco StackWise discovery

This increment implements native VirtualChassis and physical member Devices.
The behavior was compared with NtC Device Onboarding **5.6.0**, specifically
its [stack adapter](https://github.com/nautobot/nautobot-app-device-onboarding/blob/v5.6.0/nautobot_device_onboarding/diffsync/adapters/sync_devices_adapters.py)
and [native models](https://github.com/nautobot/nautobot-app-device-onboarding/blob/v5.6.0/nautobot_device_onboarding/diffsync/models/sync_devices_models.py).
The implementation uses RESTCONF JSON exclusively. No custom fields are added.

## Sources and identity

The published [Cisco-IOS-XE-stack-oper YANG model](https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17121/Cisco-IOS-XE-stack-oper.yang)
defines the member roster. Hardware identity comes from
`Cisco-IOS-XE-device-hardware-oper:device-hardware-data`; running releases come
from `Cisco-IOS-XE-install-oper:install-oper-data/install-location-information`.

| Source | Meaning and destination |
| --- | --- |
| `stack-node/chassis-number` | Reported member position → `Device.vc_position` |
| `stack-node/priority` | Reported election priority → `Device.vc_priority`; unavailable values remain blank |
| `stack-node/role=role-active` | The uniquely identified active physical member → `VirtualChassis.master` |
| `stack-node/serial-number` | Join to a unique hardware chassis serial |
| Chassis `part-number`, `serial-number` | Exact member model and physical serial → DeviceType and Device serial |
| `node-state=state-ready`, `stack-mode=mode-stackwise-rear` | Supported physically confirmed StackWise member |
| Provisioned, removed or unprovisioned roster slot without chassis hardware | Evidence only; no physical Device created |
| Per-member provisioned RP installation version/state | Each member's native `Device.software_version`, only when every present member is represented and releases agree |

Serial joins are case-sensitive after trimming surrounding whitespace.
An explicit inventory `Switch N` name cross-checks the reported position.
`hw-dev-index` and response array order are retained as evidence and never used
as member numbers. Ready roster entries missing physical identities, duplicate
serials/positions, conflicting names, unknown roles, non-ready hardware,
unsupported stack modes and inconsistent running versions block discovery.
Stack size and ring state alone cannot establish physical presence.

Missing optional stack data on a single chassis does not prevent ordinary
discovery. Multiple chassis require complete supported stack evidence.
One physically present member remains standalone; existing VirtualChassis
records are never dissolved automatically.

## Native reconciliation

At least two validated members create or reuse a VirtualChassis named after
the hostname. The selected Device is matched by its physical serial, even when
another member is active. A blank selected serial binds to the reported active
member only if that physical identity is not already assigned to another Device.

On a new stack whose selected Device is the active member, that Device keeps
the hostname and new additional members use `hostname:position`, matching NtC.
Existing member names and UUIDs are preserved when matched by serial. When the
selected Device already represents a non-active member, its name remains and
new members, including the active member, use `hostname:position`. This exception
avoids renaming the existing Device or giving two Devices the same name.
The active member still becomes the VirtualChassis master.

Additional new Devices inherit the selected Device's **location, role, status,
platform and tenant**. Their DeviceType uses the observed PID under the selected
Cisco manufacturer, creating an exact model catalog entry when needed.
No capabilities or templates are inferred from that PID. Automatic DeviceType
component creation is suppressed, so discovery does not instantiate unevidenced
ports. Older releases without the suppression API can use DeviceTypes with no
component templates; populated templates block apply.

Primary IPs, SecretsGroups, rack positions, custom fields,
cables and other operator settings are not copied to additional Devices.
The selected Device's blank software field and each additional member's blank
`Device.software_version` reference native `SoftwareVersion` catalog rows.
Each assignment requires that member's validated provisioned RP installation
evidence, rather than copying an active member's assignment. The catalog is
scoped to the member's own Platform. New members inherit the selected Platform;
existing member Platforms are preserved. Missing or explicitly incompatible
Platforms, incomplete installation evidence and populated conflicting versions
defer that member's software assignment while preserving its other inventory.
Identical releases on the same Platform share one catalog row; no custom fields
or software image records are created.

Existing members can be adopted by a unique serial or by a unique matching
member name with blank serial and the same model, manufacturer, location and
tenant. Ambiguous identities, occupied names/positions, model/vendor/location
disagreements and foreign VirtualChassis membership block apply. An established
VirtualChassis name is preserved and a hostname disagreement is reported.
Existing unobserved members remain in place.

Reported **priority and active master** follow fresh operational facts on
subsequent runs. These are explicit exceptions to fill-only reconciliation.
Established member positions are preserved; conflicting renumbering requires
review and blocks apply. No member is deleted, detached, renamed or moved to
another VirtualChassis automatically.

## Interfaces and placement scope

NtC's Sync Devices stack step builds member Devices, while its network-data
sync keys interfaces to the hostname Device. This increment likewise retains
all interfaces on the selected Device, including ports whose structured names
identify other members. Existing interface UUIDs, aliases, module relationships,
LAGs, IP assignments and cables keep their ownership.

Physical port capability is evaluated using the explicitly identified member's
model and scoped hardware inventory. An unknown member cannot inherit the active
member's port type. Explicit configuration remains eligible for duplex, LAG and
VLAN discovery; single-member default profiles are not extended across a stack.
The NTC guessing checkbox does not relax stack identity or placement checks.

Reviewed PSU bays, serialized assets and native power inlets belong to their
physical serial-matched member Device, including newly created members. See
[power-supply-discovery.md](power-supply-discovery.md) for identity, inlet and
strict-mode requirements. Compatible 9300 network modules in the
[Catalyst hardware library](catalyst-hardware-profiles.md) also create native
ModuleBays and serialized Modules on their physical members when structured
placement agrees. Eligible optics use nested ModuleBays under the confirmed
network module.
Hardware, platform and stack sources must agree on model, serial and member;
an optic's parent identity and eligible physical interface must also agree.
The [reported hardware path](reported-hardware-discovery.md) can also use explicit
parent references for unlisted parts and chassis. Unmapped capabilities remain
unknown; ambiguous ownership remains unresolved in the report.

Nautobot requires an Interface and its Module to share a root Device. Interfaces
remain on the selected Device, so a network module on another physical member
can be inventoried accurately while its Interface links are deferred separately.
These expected deferrals are informational; they do not block valid hardware
inventory. Existing modules are never moved between member Devices automatically.

Each validated C9300-48UXM member also receives the documented rear RJ45 and
front USB mini-B native ConsolePorts. Connector adoption and DeviceType template
selection are scoped to that member; existing names, labels, UUIDs and cables
are preserved. The shared logical `console=0` settings are not copied to other
members. Dedicated management-port placement on multi-member stacks remains
unresolved. StackWise link cabling is not inferred from ring status.

## Preview and apply

Preview validates staged DeviceTypes, VirtualChassis, members and the ordinary
interface plan without inventory DML. Apply re-reads inventory under locks and
saves the complete plan in one transaction: catalog and chassis parents, member
Devices, active master, then ordinary device/interface changes. A later validation
or save failure rolls back the complete stack and ordinary discovery changes.
Repeat runs with unchanged facts issue no inventory writes.

Stack-specific counts and evidence appear in the normal discovery report and
the job's concise change log. Real-model tests target Nautobot 3.2.5; other
versions require the same native fields and compatible validators.

## Stack member inventory validation

The `0.14.0-dev` increment passes 522 offline tests and 118 real Nautobot 3.2.5
ORM checks for preview, apply, repeat and rollback. Those checks cover
member-specific Platforms and software catalogs, nested network modules/SFPs,
physical consoles, preserved cables and interface ownership, and late save
failures. Fixtures and ORM mutations run inside rollback transactions. The lab
C9300-48UXM on IOS XE 17.18.4 provides the live standalone regression check;
a registered worker preview and repeat apply both preserve the inventory.
A live multi-member stack is still needed to confirm actual stacked responses.
