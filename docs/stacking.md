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
| Per-member provisioned installation version/state | Shared running release only when every present member is represented and releases agree |

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

Primary IPs, SecretsGroups, rack positions, software assignments, custom fields,
cables and other operator settings are not copied to additional Devices.
The shared release continues to fill the selected Device's blank software field.

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
strict-mode requirements. Network modules, transceivers, physical console ports
and dedicated management-port placement on multi-member stacks remain unresolved
with hardware evidence in the report. Existing records are preserved. StackWise
link cabling is not inferred from ring status.

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
