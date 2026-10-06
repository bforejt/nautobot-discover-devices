# PAN-OS discovery first pass

This document preserves the first-pass checkpoint delivered in PR #15, with
Job version `0.18.0-dev`, before dataplane adapters were added to the lab.
Its blocked identity, empty inventory and installed-version statements describe
that checkpoint. Follow the [current VM-Series validation contract](panos-vm-validation.md)
for the optional PA-VM/KVM UUID binding, reviewed virtual templates and subsequent
live results. The collection and conservative field mappings below remain the
base contract; the current increment does not infer physical capability.

This increment establishes SSH/XML collection and a conservative inventory
contract for an existing selected Device. Keep every observed hardware row,
including down, unaddressed and unconfigured ports, and preserve separately
observed logical rows. Unknown facts remain unresolved. Physical appliances and
VM-Series require separate evidence contracts; a hardware-view row does not
establish a physical chassis connector.

## Scope and evidence

The live lab on 2026-10-05 reported **PA-VM**, family `vm`, VM mode **KVM**, PAN-OS
**11.2.8**, HA disabled, multi-vsys off and Advanced Routing off. The first
successful `show interface all` returned a successful response with explicit
empty `hw` and `ifnet` containers. This proves an empty operational view at that
moment; it does not prove that the guest has no unconfigured network adapters.
The system also reported `vm-license` as `none`. No physical appliance or
licensed non-empty dataplane inventory had been validated live. Its reported
serial was unavailable and is normalized to missing identity. The first-pass
live plan was therefore blocked; that checkpoint established neither live inventory apply nor
a confirmed chassis serial.

The older testsuite identity fixture reports a sanitized PA-5250 running
`11.1.4-h7`. That fixture proves parser behavior, not live PA-5250 support.
Follow the [handoff](panos-discovery-handoff.md) for fill-only preservation,
atomic validation, no custom fields and no guessed defaults.

## Structured collection

Use Netmiko's `paloalto_panos` driver and the exact session presentation setup:

```text
set cli pager off
set cli op-command-xml-output on
```

The first-pass collection used these three fixed reads:

```text
show system info
show interface all
show config effective-running xpath devices/entry/network/interface
```

The current [VM-Series increment](panos-vm-validation.md) retains these reads
and additionally requires structured `debug show vm-series interfaces all`
for exact PA-VM/family-vm/KVM targets. That fourth source preserves recognized
guest adapters omitted from healthy operational hardware views. Physical
targets keep the three-read collection.

The
[PAN-OS 11.2 operational hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-cli-ops-command-hierarchy)
documents those reads, the output toggle and scoped operational configuration
reads. Use a small exact command fence instead of inheriting the testsuite's
general `show ` prefix or diagnostic catalog. There is no HTTPS fallback.

Accept only complete successful XML with the expected structure. Syntax errors,
error responses, missing status, malformed/truncated XML and duplicate identities
are failed reads. An explicitly present empty `hw`/`ifnet` view differs from
missing containers. Do not turn an unknown/failed source into an empty inventory.
Numeric fields require whole-token validation and native bounds, not a helper
that extracts digits from arbitrary prose. XML extraction and successful-response
validation are separate operations.

## Proposed field/source mapping

Paths below are relative to `response/result`, except applied configuration
paths. Native semantics are defined by the versioned
[Nautobot 3.2.5 Interface documentation](https://raw.githubusercontent.com/nautobot/nautobot/v3.2.5/nautobot/docs/user-guide/core-data-model/dcim/interface.md),
[model](https://github.com/nautobot/nautobot/blob/v3.2.5/nautobot/dcim/models/device_components.py)
and [existing field contract](interface-fields.md). Installed validators determine
valid writes where prose and implementation differ.

| Fact and XML source | Scope, meaning and units | Native destination and first-pass decision | Missing or ambiguous evidence |
| --- | --- | --- | --- |
| `system/hostname` | Selected endpoint's reported hostname. | Verify selected Device; preserve its existing name/alias. | Identity unavailable; do not fabricate a name. |
| `system/model`, `family`, `vm-mode` | Reported product and deployment kind. | Verify selected DeviceType; report conflict without replacing it. PA-VM/KVM evidence separates guest adapters from physical ports. | No hardware/default profile inferred from a name prefix alone. |
| `system/serial` | Selected firewall instance's serial, not its HA peer's serial. | Candidate fill for blank `Device.serial` after identity/Platform validation. | No manufactured serial. |
| `system/sw-version` | Exact running release token including hotfix suffix. | Candidate native SoftwareVersion fill after PAN-OS Platform validation; preserve existing relationship. | No version/image inference; Cisco normalization does not apply. |
| `hw/entry/name`, `id` | Row identity in this instance's hardware view. | Keep all rows and exact names. Potential `Interface.name` after a reviewed native type contract. | Missing/duplicate names or reused IDs fail collection; missing/disagreeing IDs defer hardware/logical joins. |
| `hw/entry/type` | Numeric PAN-OS internal code; universal meaning is not established. | Observation; it does not choose `Interface.type`. | No numeric-code capability mapping. |
| `hw/entry/state`, `mode`, `st` | Operational link state/behavior. | Observations; do not map to administrative `enabled` or lifecycle `status`. | No Boolean default or failure-state inference. |
| `hw/entry/mtu` | Runtime interface MTU observation. | Report-only; this increment writes MTU solely from explicit applied `layer3/mtu`. | Never substitutes for missing applied MTU or supplies a default. |
| `hw/entry/mac` | PAN-OS dataplane MAC, possibly virtual/shared in HA or distinct from a guest vNIC MAC. | Observation pending exact model/HA/source meaning; no assumption of chassis-port MAC. | Sentinel/invalid MAC omitted; no chassis-MAC substitution. |
| `hw/entry/speed` | Runtime speed token; live/release source units must be corroborated. | Observation. A reviewed Mbps rate would convert to native operational `speed` in Kbps by multiplying by 1000; virtual types prohibit this field. | Unknown, auto, zero and down-link placeholders do not establish a rate. |
| `hw/entry/duplex` | Operational/negotiated duplex. | Observation; native `duplex` is a configured copper setting. | Never supplies configured duplex or physical media. |
| Applied Ethernet `entry/@name`, `comment` | Exact configured identity and description. | Fill blank `Interface.description` after an exact unambiguous join and provenance validation. | Missing description stays blank. |
| Applied Ethernet `layer3/mtu` | Explicit applied Layer 3 MTU in bytes. | Fill blank `Interface.mtu` from a strictly validated whole decimal token within native bounds 1–65536 and with applied-source provenance. | Omitted/invalid value stays unresolved; no operational-MTU or 1500 substitution. |
| Applied Ethernet `link-state` | Configured up, down or auto behavior. | Explicit `up` proposes `enabled=True`; `down` proposes `False`. `auto` requires a reviewed administrative contract. | Omission supplies no default; runtime state cannot replace it. |
| Applied Ethernet `link-duplex` | Configured auto/full/half. | Future `Interface.duplex` only with independently verified copper capability. | No write for virtual/unknown/optical media or an absent leaf. |
| Applied Ethernet `link-speed` | Configured fixed Mbps rate or auto. | Future configuration observation, separate from operational rate and maximum capability. | No rate/capability inference. |
| Physical type/connector | Independent applicable model/port evidence. | Future `Interface.type`/`port_type` mapping; `Other` also needs proven physical classification. | Defer creation rather than rely on ORM defaults. |
| Guest adapter classification | Explicit PA-VM deployment evidence. | Classification remains report-only; this increment never supplies an implicit physical/Other/virtual type. An exact DeviceType template may supply a native type through the shared template contract. | No automatic VM inventory conversion or guessed capability. |
| Dedicated management purpose | Documented MGT purpose plus exact structured identity. | Separate future `mgmt_only=True` contract. | Reachability or a data-port management profile is insufficient. |
| `ifnet/entry` IPs, addresses, zone, vsys, forwarding context, tag | Logical addressing, security and forwarding observations. | Retain; no first-pass IPAM, VLAN, VRF, Namespace, LAG or parent writes. | No zone-to-VRF, vsys-to-Namespace or name-derived relationship. |

The [PAN-OS 11.2 Layer 3 Interface reference](https://docs.paloaltonetworks.com/ngfw/help/11-2/network/network-interfaces/layer-3-interface)
defines comment, configured Mbps speed, duplex, link-state choices and MTU bytes.
These definitions do not establish omitted defaults or a runtime response's
schema/units. Palo Alto's [official Python SDK Ethernet model](https://github.com/PaloAltoNetworks/pan-os-python/blob/develop/panos/network.py)
corroborates configuration paths `network/interface/ethernet`, `comment`,
`link-state`, `link-duplex`, `link-speed` and mode-specific `layer3/mtu`.
The SDK is reference evidence, not a runtime dependency or omitted-default rule.

## Physical, virtual and MAC identity

PANW's [VM-Series hardware-view example](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cm2fCAC)
shows `show interface hardware` returning Ethernet rows on VM-Series and warns
that PAN-OS dataplane MACs need not equal VMware-assigned vNIC MACs. The
[ESXi troubleshooting reference](https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-a-vm-series-firewall-on-an-esxi-server/troubleshoot-esxi-deployments)
maps Ethernet names to VM network adapters. Therefore `hw`, an Ethernet name
and `type=0` do not prove a physical connector. A physical unknown-capability
`Other` contract must be established independently of the VM lab.

The [interface MAC reference](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000CluMCAS)
states that L3 MACs shown by `show interface all` in an HA cluster are virtual
MACs. Keep HA applicability and the selected instance's identity explicit.

Join hardware and logical rows only when their exact identity is unambiguous.
Keep hardware-only rows independently; logical-only rows do not prove ordinary
adapters. Repeated addresses must not produce multiple interface objects.

## Applied configuration and remaining evidence

The live PA-VM verified these exact scoped operational reads:

```text
show config running xpath devices/entry/network/interface
show config effective-running xpath devices/entry/network/interface
```

The CLI XPath is relative to the configuration root. Prefixing it with
`/config/` returned an unstructured `Server error : No such node`; that failed
probe is not a configuration fact. The successful relative-path reads both
returned `response/result/interface/ethernet` with no entries. The collection
uses `effective-running` to request applied configuration; the two views were
identical on this direct, initially empty lab. Effective merged Panorama
configuration remains unvalidated on a managed firewall.

Scope reads to interfaces rather than full configuration. Even an Ethernet
entry may contain PPPoE credentials: reports retain only reviewed applied fields
and address observations, never the complete applied subtree. Operational rows
retain repeated and nested fields. Parse and validate actual complete structured XML, rather than
assuming the session output toggle guarantees every command's body. Candidate
configuration cannot replace applied configuration. Palo Alto's
[Configuration API reference](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api)
also distinguishes candidate retrieval.

The licensing [activation reference](https://docs.paloaltonetworks.com/vm-series/activation-and-onboarding/vm-series-models/activate-the-license)
states that unactivated VM-Series instances have no serial and non-unique
dataplane MACs. Unknown/none/unavailable serial values cannot fill Device.serial.
The live `vm-license=none` and empty interface views are separate observations;
their causal relationship is not established by this capture.

Creation requires a proven native type and administrative Boolean. Missing state
or classification defers the object while retaining every observation. Existing
populated False, zero, Other, UUIDs, names, Module ownership, cables, LAGs, IP
assignments and other relationships remain preserved; disagreements are reported.
The Cisco guessing checkbox grants no PAN-OS defaults.

## Attribution and validation

Selected transport/parser patterns and the two XML captures originate in
[nautobot-testsuite](https://github.com/bforejt/nautobot-testsuite) commit
`7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9`, under Apache-2.0. Relevant sources are
`jobs/transport_ssh.py`, `jobs/panos_xml.py`, identity/interface collectors in
`jobs/checks_panos.py` and corresponding tests/fixtures. Adapted files identify
their modifications, retain applicable notices and use the repository's
[Apache-2.0 LICENSE](../LICENSE). Runtime discovery remains self-contained.

The testsuite's zone/IP normalization omits hardware-only down `ethernet1/7`
and logical rows with absent/N/A addresses. It cannot be used as inventory.
Permissive integer extraction and XML extraction without response validation
also cannot supply inventory proof.

Offline coverage must include all hardware rows, down/unaddressed ports,
logical-only rows, repeated addresses, exact joins, unknown codes/tokens,
duplicate identities, missing state/capability, empty-versus-missing containers,
malformed/truncated XML and explicit errors. Preserve Cisco regressions. Before
live apply, verify zero-write preview, populated-value/UUID/cable preservation,
late-failure rollback and repeat-run idempotence in native Nautobot.

The durable rollback-only harness `tests/nautobot_panos_integration.py` passed
11 native checks using synthetic PAN-OS identity and scoped fixtures. It proves
zero-DML preview, native validation, populated field/UUID/cable preservation,
exact-template creation, idempotence and rollback after related writes. The outer
rollback leaves zero persistent changes. These checks do not establish a live
serial or successful live firewall inventory apply. The full offline check totals are recorded with delivery validation below.

At the first-pass checkpoint, remaining live evidence included usable selected
firewall identity, non-empty dataplane inventory, complete configured and
unconfigured port enumeration, applicable explicit administrative state and
reviewed physical capability. Licensing and adapter attachment are separate
facts. The [VM-Series increment](panos-vm-validation.md) defines a UUID binding
when a serial is absent and reviewed templates for virtual adapters. Without a
reviewed native type, PA-VM rows remain report-only; configured fields
may enrich an eligible existing interface without replacing its native type.
A DeviceType template can supply a native type only through the existing
unambiguous template contract, never through a negotiated-rate inference.
Capture sanitized fixtures with exact commands. Extend models/releases through reviewed evidence or data
profiles, preserving unknown facts without new release/name heuristics.


## First-pass delivery validation, 2026-10-05

The branch starts from merged `main` at `b1a2904` and reports Job version
`0.18.0-dev`. Required checks passed: 745 offline tests, Ruff 0.11.13 lint and
formatting, compileall and Git whitespace validation. Native Nautobot 3.2.5
passed 11 PAN-OS rollback-only checks and all 150 Cisco regression checks.
No persistent test inventory remains.

The user approved creation of `panos-lab` at the Cisco lab's `lab` Location.
The baseline is Palo Alto Networks / PA-VM / PAN-OS (`paloalto_panos`), with a
Firewall role and SSH Secrets Group. Device UUID is
`ed010564-cfd9-4039-bfad-a40ea4487157`. Serial, software and interfaces remain
blank at this checkpoint. Native primary IP requires an actual interface
assignment, so validation uses an explicit process-only endpoint override
rather than inventing an interface. The new source ran in an isolated Nautobot
directory; installed Job `0.17.0-dev` remained unchanged at the first-pass
checkpoint and the worker was not restarted.

Live collection through the actual Job source succeeded using the three fenced
reads. Native preview then blocked exactly on the missing serial and verified
zero inventory DML and an unchanged snapshot. Hostname `PA-VM` conflicts with
the selected alias `panos-lab` and is preserved as expected. The local complete
report is `artifacts/panos-first-pass/live-preview.json` (ignored by Git).
This lab preview explicitly disabled SSH host-key checking; the Job default
remains enabled and requires worker known-host keys.

For an explicit repeat of this blocked lab preview in the configured Django
process with this repository source on the import path:

```python
import runpy

preview = runpy.run_path("/path/to/repository/tools/lab_preview.py")
preview["run"](
    device_id="ed010564-cfd9-4039-bfad-a40ea4487157",
    expected_adapter="panos",
    endpoint_host="10.40.3.232",
    allow_blocked=True,
    ssh_strict=False,
    report_path="/path/to/private/live-preview.json",
)
```

`allow_blocked` retains an expected failed validation report and asserts zero
writes; it does not turn a blocked plan into an applicable one. At this
checkpoint, live serial fill, successful apply/repeat and complete physical/guest
port inventory remained unvalidated. The [current VM-Series contract](panos-vm-validation.md)
allows independently verified UUID binding with native serial left blank; it
does not require licensing to enumerate attached adapters. Physical firewalls
still require their serial and independent capability evidence.
