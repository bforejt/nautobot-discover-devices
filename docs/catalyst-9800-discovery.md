# Catalyst 9800 managed AP discovery

Job version: `0.26.0-dev`. Controller-release coverage is provisional pending
field feedback.

`Discover Device` accepts an existing 9800 controller Device, a configured WAP,
or an existing native Controller UUID. A WAP resolves through
`Device.controller_managed_device_group → ControllerManagedDeviceGroup.controller`.
It selects the **complete current controller roster**, including APs at other
sites. AP endpoints, DNS names and credentials are never used for collection.
A missing or ambiguous native association fails before any device connection.

This increment creates eligible new AP Devices and replaces proven AP Location
and running SoftwareVersion values, including downgrades. These replacement
rules apply only to controller-managed APs. Existing aliases, serials, DeviceTypes,
configured primary controller bindings, lifecycle status, role, tenant, racks,
cables and IPAM relationships remain administrative intent. An absent AP is never
deleted, retired or removed from its group. A positively read empty roster causes
no inventory writes; a failed or malformed roster blocks the controller run.

## Validation boundary

The wireless fixtures originate in `nautobot-testsuite` (Apache-2.0) and are
**synthetic**, shaped after published IOS XE 17.12.1 YANG. They are not a live
9800 capture. Published schemas inform parsing; they do not prove what an actual
controller image returns. See the [field feedback procedure](#field-feedback)
before relying on a new release or deployment. Direct controller lab results are
not available for this increment.

The [Cisco-published AP operational YANG](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17121/Cisco-IOS-XE-wireless-access-point-oper.yang)
defines distinct MAC identities, numeric Ethernet duplex and Mbps link speed.
The original synthetic fixtures retain differences from these definitions;
parsing reports uncertain values rather than rewriting the examples as live
proof. CDP update timestamps are retained when present. Ethernet speed remains
report-only until its native operational mapping is reviewed against field data.

Native behavior is targeted at Nautobot 3.2, with rollback-only verification on
3.2.6. Model fields are checked at runtime; older compatibility is not claimed.
Native Controller/group records and target catalogs must be configured by the
operator. Discovery creates no custom fields or Controller/group definitions.

## Source setup

For a physical controller, link an existing native Controller to its Cisco 9800
Device. Configure that Device's management IP or DNS name, IOS XE Platform,
Secrets Group, exact DeviceType model and reported chassis serial. RESTCONF GETs
must be available; TLS verification defaults to enabled. A Secrets Group override
applies to the controller connection, never to an AP.

For C9800-CL, configure the native Controller's endpoint Device, or its approved
HTTPS ExternalIntegration and Secrets Group. Supply an explicit source policy:

```json
{"expected_hostname": "configured-wlc"}
```

The collector verifies the structured native hostname and advertised wireless
operational module against this logical binding. It retains reported host
hardware separately and never fabricates a virtual chassis serial. An external
endpoint must be an HTTPS authority without userinfo, query or arbitrary paths.
Its configured port is used. Source identity and native source associations are
checked separately from each AP's physical identity.

Device Redundancy Group sources currently stop with specific setup guidance.
Member priority, member names and CLI `show redundancy` do not prove an active
endpoint. HA collection requires field evidence and a reviewed shared-endpoint
or structured active-member contract before enabling that source path.

## AP admission and placement

The `9800 AP admission and placement policy` is a JSON object. All identifiers
refer to existing native UUIDs. New APs require explicit manufacturer, Platform,
applicable role/status, target managed group, naming policy and a proven Location.
The group must belong to the collecting Controller. AP DeviceTypes are matched
by exact reported model within the chosen manufacturer; missing types leave the
candidate unresolved rather than fabricating dimensions or templates.

```json
{
  "manufacturer": "11111111-1111-4111-8111-111111111111",
  "platform": "22222222-2222-4222-8222-222222222222",
  "role": "33333333-3333-4333-8333-333333333333",
  "status": "44444444-4444-4444-8444-444444444444",
  "managed_group": "55555555-5555-4555-8555-555555555555",
  "naming": "reported",
  "locations": [
    {
      "match": {"serial": "REPORTED-AP-SERIAL"},
      "location": "66666666-6666-4666-8666-666666666666"
    },
    {
      "match": {"site_tag": "ST-HQ", "floor_label": "3"},
      "location": "77777777-7777-4777-8777-777777777777"
    }
  ]
}
```

Replace example UUIDs with actual catalog objects. Placement match fields are
`serial`, `site_tag`, `location_label` and `floor_label`. Conditions within a rule
all need to match. Multiple matching rules must identify the same Location;
conflicting mappings leave placement unresolved. Tag names and neighbor switch
Locations never become AP geography by themselves. Port/service-area placement
is retained as attachment evidence until its own mapping contract is reviewed.

A partial or blank policy can still update independently identified existing APs.
Missing placement preserves their Location and does not prevent an independent
software update. It defers new AP admission. Native validation enforces Location
Type and rack/hierarchy constraints; discovery does not clear a rack or cable to
force a move. Location replacement records before/after values and mapping proof.

Existing APs match unique reported serial and compatible manufacturer/model.
Names, IPs and controller indexes are labels, not asset identifiers. Duplicate
claims and naming collisions remain unresolved. Replacement hardware with the
same name never updates the old asset's serial. A blank-serial Device can be
bound explicitly using `identity_bindings`, with a reported serial, Device UUID
and reported `wtp_mac` or `ethernet_mac`; a matching independently recorded native
interface MAC is required. MACs are never derived arithmetically.

Software uses the AP's own Platform catalog and preserves exact reviewed build
strings such as `17.12.4.42`. It never borrows the controller release or the
switch version truncation rule. Unknown software preserves the existing value.

## Interfaces and observation domains

The controller supplies separate AP administration, operational connection,
radio administration and Ethernet operational state. Registered and downloading
CAPWAP entries are eligible current candidates in the provisional contract.
Other states are retained as unresolved pending field feedback. Historical join
rows never create APs.

Ethernet observations retain explicit MAC joins, names, negotiated speed and
source evidence. Negotiated speed is not maximum capability, and link state is
not administrative state. New native Ethernet interfaces require the explicit
policy Boolean `ethernet_enabled`; without it, AP creation/software/location can
proceed while interface creation remains unresolved. Unknown Ethernet capability
uses native `Other` only for verified physical Ethernet. Existing interface
intent is preserved and reviewed blank fields can be filled.

Radio state and policy/site/RF assignments are observations until native meanings
are reviewed. CDP/LLDP observations describe attachments; they do not create
neighbor switches or cables. Available age/update facts are retained, with
unknown freshness labeled explicitly. Wireless clients, mobility peers, WLAN
credentials and client identifiers are outside the collected inventory scope.

## Collection and application

The collector uses JSON RESTCONF GETs, sharing one read per inventory resource.
A rejected `fields` parameter gets one unfiltered retry only when a structured
HTTP 400 error explicitly identifies that filter. Generic failures never trigger
an unfiltered retry. Required resources need recognized structures; malformed or
missing data is never converted into a complete empty fleet.

The Job bounds each response at 32 MiB and the roster at at most 10,000 APs.
Exceeding a budget fails completeness. It never truncates the roster and applies
the remaining rows. Optional-source failures retain their status and leave
dependent fields unresolved; independent serial/software observations remain
eligible. Contradictory MAC mappings defer the affected identities.

Preview stages native objects and calls native validation without saving them.
Apply locks and rechecks the source, catalog and asset scope, rebuilds the plan,
and saves each AP graph in its own transaction. A late failure rolls back that
AP's catalog/Device/interface graph while other eligible APs continue. DeviceType
automatic component creation is suppressed so templates do not bypass the source
contract. Mixed outcomes are explicit in Advanced and the JSON report. Repeating
an unchanged full roster produces zero inventory DML.

Committed per-AP outcomes are retained during apply. A handled interruption,
including a soft worker time limit, marks the batch incomplete and reports
committed and pending graphs separately. Source
bindings are rechecked under native locks; changed shared-source facts stop the
remaining controller scope rather than applying observations from a stale source.

## Field feedback

Use an operator-configured production or field controller and start with **Dry
run enabled**. Selecting one WAP intentionally previews other APs across sites.
Provide this evidence for each supported image/deployment:

1. Controller deployment (physical, CL, or HA), actual IOS XE release and
   advertised wireless module names/revisions; include the source binding policy.
2. The complete preview JSON from Advanced/report download, including request
   paths, optional-source outcomes, exact AP builds and unresolved reasons.
3. Sanitized raw RESTCONF replies for CAPWAP, AP name/MAC mapping, Ethernet,
   CDP/LLDP and relevant radio/tag/join resources from Test Suite Shakedown/debug
   capture. Keep explicit empty lists, wrapper names, scalar types, distinct MAC
   identities, state enums and timestamps intact; remove credentials/client data.
4. Examples of a registered AP, an AP downloading software, historical unjoined
   records, duplicate labels, a real new AP and an existing AP with a known
   software/location change. Explain whether neighbors are cached and which age
   or update leaves the image returns.
5. Verify serial/model matching and AP-wide preview scope against known inventory.
   Verify Location UUID rules independently of switch placement and wireless tags.
6. After reviewing the preview and source contract, run an operator-controlled
   apply and an unchanged repeat. Retain per-AP before/after outcomes and evidence
   that failed APs rolled back and the repeat proposed no further changes.

Source fixtures remain labeled synthetic until actual feedback has been reviewed
and sanitized release-specific fixtures are added. Do not advertise an IOS XE
release, HA deployment, native radio mapping or live preview/apply/repeat result
as verified without that evidence.

## Implementation boundaries

Recorded development validation on 2026-10-07:

- 1,436 offline regression tests passed, including the existing platform suites.
- Ruff 0.11.13 lint/format, Python compilation and diff checks passed.
- 13 native acceptance checks passed on Nautobot 3.2.6, using synthetic facts
  and mocked GET transport inside an unconditional outer database rollback.
  They cover both entry paths, AP admission, exact software downgrades, Location
  moves, templates, rack constraints, configured-primary preservation, stale
  sources, late failure isolation and soft-limit progress.
- The actual Job parsed the copied fixtures for a full-roster preview, apply
  and repeat. Preview and repeat issued zero inventory DML; all temporary native
  catalogs and inventory returned to their original counts after rollback.

Run `python3 -m unittest discover -s tests -t . -v` for offline coverage. In a
configured Nautobot process with this checkout on `PYTHONPATH`, run
`tests.nautobot_wireless_integration.run()` for native rollback acceptance.
This harness contacts no controller and reports its native version, evidence
type and zero persistent changes. Real release and deployment acceptance uses
the field procedure above.

`controller_sources.py` resolves native sources before general vendor dispatch.
`adapters/cisco_9800.py` collects the controller snapshot. `wireless_policy.py`
resolves explicit operator intent. `reconcile_wireless.py` builds deterministic
per-AP plans. `nautobot_wireless.py` stages and applies native objects. The shared
Job manages the complete roster's report and connection lifecycle.

The [implementation handoff](catalyst-9800-discovery-handoff.md) contains the
full authorized behavior and acceptance requirements. Its historical lab setup
checkpoint does not describe a configured live controller.
