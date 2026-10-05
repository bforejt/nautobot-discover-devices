# PAN-OS discovery handoff

Use this document to start a new task for Palo Alto PAN-OS discovery. Begin with
the existing testsuite collection work, propose the native Nautobot mappings,
and implement one reviewed increment at a time. The first increment should
verify device identity and discover physical interfaces on an existing Device.

## Project and baseline

Repository/PR state checked on **2026-10-05**; source and lab observations below
were checked on **2026-10-04**. Recheck repository, PR and installed-job state
before branching or deploying; these values are a starting reference.

| Item | Checked state |
| --- | --- |
| Discovery workspace | `/opt/stacks/nautobot-device-discovery` |
| Discovery remote | `https://github.com/bforejt/nautobot-discover-devices.git` |
| Handoff branch | `codex/panos-discovery-handoff` |
| Implementation baseline | `f780de00f379539720fb16d9c1fba1d9a952a3a9` on `codex/ipv6-vrf-discovery`, including the merged hardware-library and reported-hardware increments |
| Testsuite workspace | `/opt/stacks/nautobot-testsuite` |
| Testsuite source commit | `7a2bc1638fe23c5ac23fb9d718f5dc9b79eb4fb9` |
| Nautobot target / verified lab | Target 3.2; lab 3.2.5. Older versions are eligible only where the same code works or explicitly detects unsupported fields. |
| Installed lab job | `0.17.0-dev` |
| Installed package | `nautobot:/opt/nautobot/jobs/nautobot_discover_devices/` |
| Host jobs directory | `/opt/stacks/nautobot-composer/jobs/nautobot_discover_devices/` |
| Cisco regression target | `9300-lab`, UUID `eb46c008-e579-4207-8def-f9b6dfbdc525`, C9300-48UXM / IOS XE 17.18.4 |

At this checkpoint, [PR #11](https://github.com/bforejt/nautobot-discover-devices/pull/11)
is open against `main`. Hardware-library
[PR #12](https://github.com/bforejt/nautobot-discover-devices/pull/12) and reported-hardware
[PR #13](https://github.com/bforejt/nautobot-discover-devices/pull/13) were merged into
`codex/ipv6-vrf-discovery`, not yet into `main`. The PR #13 merge commit is
`f780de00f379539720fb16d9c1fba1d9a952a3a9`.

Fetch and inspect the actual merge state. Create a `codex/` branch from the
baseline containing those changes; if PR #11 remains open, deliberately stack
on its branch or wait for its merge. Do not start from an older `main` and
accidentally omit the IPAM or generic-hardware work. Merged feature branches can
be removed during cleanup; use the retained baseline rather than depending on
their old branch names. Keep unrelated user changes.

The Cisco baseline passed 684 offline tests, 150 rollback-only native Nautobot
checks, CI on Python 3.10/3.11/3.12, and queued lab dry-run/repeat apply with
inventory preserved. These are checkpoint results, not a permanent test count.

## Rules to carry forward

- Discover into an **existing selected Device**. Do not silently create a base
  firewall, replace its DeviceType, rename it, or overwrite populated identity.
- Obtain structured data on every discovery query. JSON, XML and documented
  model/schema fields are acceptable. Do not scrape human-readable tables.
- **No guessing.** Retain missing or ambiguous facts as blank/unresolved with
  evidence. Documented defaults require explicit applicability and source
  evidence; missing data alone does not establish a default.
- Use native Nautobot objects and intended field meanings. **No custom fields.**
- Preserve populated values, including `False`, zero and `Other`; preserve UUIDs,
  aliases, Module ownership, cables, IP assignments and occupied inventory.
  Report conflicts rather than relocating, deleting or replacing assets.
- Keep planning pure and deterministic. Preview validates without inventory
  writes; apply validates and saves the related inventory in one transaction.
  A repeat of the same discovery must produce no inventory changes.
- Device operations are read-only. Session presentation settings are permitted
  where they only select structured output. Never enter configuration mode or
  initiate probes, commits, changes, HA actions or session clearing.
- Credentials come from Nautobot Secrets Groups; never from ordinary job fields,
  fixtures, logs or this handoff. Preserve the discovery project's sanitized
  exception behavior when reusing testsuite credential code.
- Software image maintenance belongs to a separate job. Running PAN-OS release
  may fill the existing native SoftwareVersion relationship after identity and
  Platform validation. Content packages and signatures remain observations
  until a suitable native mapping is reviewed.
- Preserve the existing guessing checkbox's narrow Cisco behavior. It grants
  no new PAN-OS defaults; strict mode remains the baseline.

Cisco's RESTCONF/JSON restriction applies to its adapter. The testsuite's
[structured-data decision](/opt/stacks/nautobot-testsuite/docs/plans/structured-data-queries.md)
explicitly accepts **SSH returning XML** for PAN-OS and sets aside the proposed
XML API migration. Start with that established transport. An HTTPS XML API
adapter would be a separate future decision, not a launch prerequisite.

## Reuse these testsuite sources

The discovery repository must remain self-contained at runtime. Adapt selected
transport/parser code and fixtures with source commit and license attribution;
do not import the other project's installed Jobs package or run its entire
diagnostic catalog to perform inventory discovery.

| Source | Useful starting point |
| --- | --- |
| [checks_panos.py](/opt/stacks/nautobot-testsuite/jobs/checks_panos.py) | `_normalize_system_info()` / `_collect_system_info()`; `_parse_interfaces()` / `_collect_interfaces()`; exact existing reads `show system info` and `show interface all` |
| [panos_xml.py](/opt/stacks/nautobot-testsuite/jobs/panos_xml.py) | Pure XML extraction and element helpers: `extract_xml()`, `result_of()`, `text()` |
| [transport_ssh.py](/opt/stacks/nautobot-testsuite/jobs/transport_ssh.py) | `SshRunner`, Netmiko `paloalto_panos`, command fencing and session presentation setup |
| [creds.py](/opt/stacks/nautobot-testsuite/jobs/creds.py) | Transport-aware SSH then Generic Username/Password lookup |
| [snapshot_job.py](/opt/stacks/nautobot-testsuite/jobs/snapshot_job.py) | `_open_host()` transport/credential setup |
| [test_checks_panos.py](/opt/stacks/nautobot-testsuite/tests/test_checks_panos.py) | `TestSystemInfo`, `TestInterfacesParser` and parser/error cases |
| [test_panos_xml.py](/opt/stacks/nautobot-testsuite/tests/test_panos_xml.py) | Structured payload extraction tests |
| [panos_system_info.txt](/opt/stacks/nautobot-testsuite/tests/fixtures/panos_system_info.txt) | Sanitized identity XML fixture |
| [panos_interfaces.txt](/opt/stacks/nautobot-testsuite/tests/fixtures/panos_interfaces.txt) | Hardware and logical interface XML fixture |

The `.txt` fixture extension does not make its XML payload unstructured. Session
setup uses `set cli pager off` and `set cli op-command-xml-output on`. Keep an
explicit small read set for discovery; inspect each added operation rather than
assuming every existing testsuite check supplies structured inventory facts.

**Do not reuse the existing interface normalized view as inventory.** It keys
interfaces by zone/IP for change comparisons, keeps actual names in raw metadata,
and omits rows without an IP or with `N/A`. The fixture's down `ethernet1/7` is
hardware-only and is omitted from that view. Discovery needs a new view keyed
by actual interface identity, joining `hw/entry` and `ifnet/entry` only when the
relationship is unambiguous. Retain down, unaddressed and unconfigured ports.
Multiple addresses must not create multiple copies of an interface.

XML extraction alone does not prove a successful device response. Validate
response success/error status, complete payloads and expected structure before
accepting facts. Use strict numeric conversion for typed inventory fields;
the testsuite's permissive `to_int()` can extract a number from arbitrary text
and should not be copied as a universal inventory validator.

## Lab information needed

A read-only lab inventory check found no Device matching a PAN-OS driver or a
Palo Alto manufacturer at this checkpoint. This does not prove that no firewall
is available; **a discovery target has not been selected**. Source review and
offline parser design can proceed while the following are resolved.

| Input | What to establish |
| --- | --- |
| Target | Existing Nautobot Device name/UUID, matching DeviceType, Platform, Location and reachable primary IP or DNS name |
| Product and release | Physical appliance versus VM-Series; exact model and installed PAN-OS release. The current collector describes 11.x; do not assume a universal minimum or identical schemas. |
| Endpoint scope | Direct firewall management endpoint initially; establish whether Panorama-managed and which effective running configuration is authoritative. Panorama-wide discovery is outside the first increment. |
| Credentials | Device or override Secrets Group with SSH/Generic Username and Password; verify privileges for selected structured operational and configuration reads |
| SSH environment | Reachability from the worker, port and host-key policy, session XML support, and installed `netmiko`/`paramiko` dependencies |
| Routing/context | Legacy virtual routers versus Advanced Routing logical routers; configured vsys scope and permissions to see the interfaces being inventoried |
| HA | Standalone versus HA, selected member's serial, and whether virtual/shared operational values could be mistaken for physical identity |
| Configuration evidence | Complete structured applied/running interface configuration. A candidate or pending configuration must not silently become discovered applied state. |

Select one model/release and a small initial scope. A down/unaddressed port is
especially valuable for validating completeness. Record what is actually
observed; fixtures alone do not establish live support or lab credentials.

## First increment and interpretation decisions

Propose a field/source table before widening writes. Cite Palo Alto's official
documentation for the observed release and Nautobot/Network to Code's installed
model semantics. For each fact, state its XML field, scope, units, meaning,
missing-data behavior and native destination, or why it remains report-only.

| Area | Starting contract / question to resolve |
| --- | --- |
| Device identity | Reported hostname, model, chassis serial and running PAN-OS version; verify the selected Device and preserve populated aliases/conflicts |
| Physical interfaces | Enumerate every observed port by its real name; retain MAC, MTU, link state and other validated facts even without an address |
| Administrative state | Obtain explicit structured applied configuration. Operational `down` does not mean administratively disabled. If required creation fields are unknown, defer creation rather than use an ORM default. |
| Physical capability | Numeric hardware `type` values need documented meanings. Negotiated speed and an `ethernet` name do not establish maximum capability, cage or connector. Native `Other` requires verified physical classification and a reviewed PAN-OS evidence contract. |
| Speed / duplex | Distinguish operational readings from configured settings and hardware limits; verify units and native field meanings before assigning |
| Description / management purpose | Use applied configuration and documented dedicated-management evidence; reachability or a management-like name alone is insufficient |
| Logical / aggregate interfaces | Preserve raw observations initially. Define eligible native virtual/LAG types and exact membership evidence separately; do not infer relationships from names. |
| Tags / VLANs | A Layer 3 subinterface tag is encapsulation, not proof of Nautobot Access/Tagged switchport mode or a VLAN domain |
| Routing / security contexts | Zone, vsys, virtual router and logical router are distinct concepts. Do not automatically map zone to VRF, vsys to Namespace, or a router name to a globally shared routing domain. |
| Addresses | Retain observed configuration for review. IPAM writes follow a later increment using the existing explicit Namespace/override policy and reviewed routing-domain mapping. |

Do not broaden the first increment to Panorama inventory, HA peer creation,
zones/policy objects, guest/virtual system inventory, topology, optics/modules,
or full IPAM merely because the testsuite can collect related evidence.

## Small framework changes required

The current collection/plan boundary is still Cisco-specific. Preserve its
proof rules while extracting only the shared contract needed by PAN-OS:

- `jobs/discovery_job.py`: `_adapter()` currently selects only Cisco, constructs
  `RestconfClient` directly and handles its transport errors. Add explicit
  platform dispatch and adapter-appropriate transport; keep one Job experience.
- `jobs/credentials.py`: current lookup prefers RESTCONF/HTTP/REST/Generic.
  Add a transport-aware SSH/Generic path without weakening sanitized errors or
  existing Cisco precedence.
- `jobs/reconcile.py`: currently accepts only `cisco_iosxe` and validates Cisco
  physical Ethernet provenance. Introduce a versioned PAN-OS fact contract and
  its own validated evidence, rather than fabricating Cisco/YANG sources.
- Interface canonicalization and component manufacturer provenance in nominally
  shared planners also depend on Cisco. Isolate applicable naming/provenance
  rules; do not pass PAN-OS names through Cisco alias rewriting or remove source
  validation globally.
- Keep the pure planner, inventory snapshots, native ORM validation, atomic
  application, reports and fill-only behavior. Avoid a framework rewrite before
  the second adapter demonstrates what is needed.

## Validation and delivery

Start with the project's normal offline checks:

```sh
python3 -m unittest discover -s tests -t . -v
ruff check .
ruff format --check .
python3 -m compileall -q jobs tests tools __init__.py
git diff --check
```

Use sanitized structured fixtures covering identity, down/unaddressed ports,
physical versus logical rows, multiple addresses, duplicate/ambiguous identities,
missing admin/capability data, XML error replies, malformed/truncated responses,
and operational/configuration disagreements. Preserve field and relationship
semantics when sanitizing captures. Test every proposed write's no-guessing rule.

Add rollback-only native Nautobot checks for new-interface validation, zero-DML
preview, preservation of existing populated values/UUIDs/cables, repeat-run
idempotence and rollback on a late failure. The existing harness is
`tests/nautobot_integration.py`; execute it in a configured Nautobot Django
environment via `nbshell` and `runpy.run_path(...)`.

`tools/lab_preview.py` currently targets Cisco through the actual Job. Adapt its
platform selection before using it as PAN-OS proof; never rely on its default
Cisco UUID. Select the PAN-OS Device explicitly. Then review a live preview,
validate apply on the selected lab target, and repeat with guessing disabled.
Retain reports with source evidence and unresolved reasons; distinguish expected
unresolved observations from collection, validation or apply failures.

For an authorized lab install, use the flat installed package directory above,
verify it matches the intended branch/version, and restart only the worker that
loads these Jobs. Wait for the restarted worker's actual ready message before
queueing validation. Do not queue during startup, purge unrelated work, or use
ephemeral `/tmp` scripts as the durable implementation or handoff.

Deliver a focused commit/PR with the mapping documentation and validation
results. Do not merge automatically. Keep Cisco regressions passing and identify
the exact PAN-OS models/releases validated; partial support is acceptable when
unsupported facts are honestly blank or unresolved.

## New-task opening prompt

> Read `/opt/stacks/nautobot-device-discovery/docs/panos-discovery-handoff.md` and
> the referenced project code. Start PAN-OS discovery using the structured XML
> collection work in `/opt/stacks/nautobot-testsuite`. Recheck the branch/merge
> baseline and preserve Cisco support. Begin with a source audit and a proposed
> native mapping for device identity and complete physical interface inventory,
> including down and unaddressed ports. Use the established SSH/XML transport;
> preserve no-guessing, no-custom-fields, fill-only, atomic validation and
> idempotence rules. Identify the missing lab information and any genuinely
> unresolved modeling decisions while continuing independent source/fixture
> analysis. Present the first increment for review before implementing new
> discovery behavior. Keep advanced routing contexts, IPAM and component
> relationships scoped to subsequent reviewed increments.
