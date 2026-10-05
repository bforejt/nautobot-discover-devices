# Native PAN-OS VPN inventory

The discovery Job can populate compatible native Nautobot VPN models from the
applied PAN-OS network XML response over the existing SSH transport. Native
capability detection uses installed model fields, algorithm choices and
relationship types. It does not select behavior from a Nautobot version string.
If the optional VPN models are absent, as in Nautobot 2.4, the same PAN-OS
configuration and runtime facts remain available in the discovery report and no
native VPN records are written.

## Select the native scope deliberately

`panos_vpn_mappings` accepts a JSON list. Each entry selects one exact applied
PAN-OS tunnel and supplies explicit native object names. Namespace and Status
selections resolve existing objects by an unambiguous name or UUID:

```json
[
  {
    "tunnel": "lab-ipsec",
    "vpn_name": "PAN lab VPN",
    "tunnel_name": "PAN lab IPsec tunnel",
    "profile_name": "PAN lab existing VPN profile",
    "status": "Active",
    "local_namespace": "Lab public",
    "remote_namespace": "Lab public",
    "local_protected_namespace": "Lab private",
    "remote_protected_namespace": "Remote lab private"
  }
]
```

The source tunnel and each native object name must be distinct across mapping
entries. An empty mapping keeps VPN processing report-only. Status must be
applicable to `VPNTunnel`; it is deliberate native inventory intent, rather than
an inference from an active SA or an omitted PAN-OS disable flag. Without that
selection, the tunnel remains unresolved while independent valid catalogs may
still be planned.

Namespaces do not fall back to another matching address or prefix. Local and
remote address namespaces and protected-prefix namespaces are separate explicit
selections. Omitted scope selections leave their relationships unresolved.

## Profiles and crypto policies

`profile_name` currently targets an **existing native VPNProfile**. PAN-OS facts
do not yet establish an exact meaning for the native profile's required
`keepalive_enabled` and `nat_traversal` booleans. Discovery therefore defers
creating a missing profile and reports the reason. It preserves existing
profile values, including booleans, Roles, Tenants and Secrets Groups. There is
no policy option that turns an unknown PAN-OS behavior into `False`.

Missing profiles do not prevent independently reviewed Phase 1/Phase 2 policy,
VPN, tunnel or endpoint facts from being populated. Their nullable profile
relationships remain unset and policy assignments remain unresolved. Selecting
an existing profile later allows blank relationships and empty policy
assignment sets to be filled on a subsequent discovery.

Referenced crypto policies have names scoped to the selected Device UUID and
the exact applied crypto profile and IKE version. The planner:

- Preserves the applied algorithm order and maps only exact installed native
  algorithm choices. Scalar native fields accept a single explicit algorithm;
  an ordered list that cannot be represented remains unresolved.
- Converts one explicitly supplied lifetime unit to seconds without guessing
  device defaults. An unsupported IPsec lifesize remains a reported observation.
- Maps explicit `no-pfs` to the native empty group array and preserves populated
  group arrays, including an intentional empty array.
- Records `aggressive_mode=False` for an explicit IKEv2 policy because the native
  field is documented as applicable only to IKEv1. IKEv1 requires an explicit
  reviewed main or aggressive exchange mode; unknown/automatic mode is deferred.
- Adds the single reviewed policy to an empty profile phase assignment set with
  native default weight `100`. That weight is inventory ordering, rather than a
  PAN-OS preference observation. Existing assignments and weights are preserved.

Authentication methods and private authentication materials are not inferred.
The native writer never stores pre-shared keys, private keys or authentication
payloads. Runtime SA names, including colon-separated text, are not used to
derive gateway, tunnel, peer or Device identity.

## Exact local and remote endpoint bindings

A local endpoint requires an existing source Interface and tunnel Interface on
the selected Device, a real IPAddress in the explicitly selected Namespace,
the exact configured host/mask, and an actual assignment of that IP to the
observed source Interface. These prerequisites are independently checked again
by the native boundary before normal native model validation and save.

Several PAN-OS tunnels can share a WAN Interface. Nautobot's native endpoint
`source_interface` is a OneToOne relation, so it cannot represent that WAN
Interface on every local endpoint. Each local endpoint instead has an identity
of **selected Device + real source IP + exact tunnel Interface**. When the WAN
is shared, new endpoints keep their verified Device, source IP and tunnel
Interface, while `source_interface` remains unset. The plan retains the exact
observed WAN Interface and binding provenance. The native boundary still
requires the real IP assignment to that WAN Interface and both Interface
ownership checks. Existing populated source Interface bindings are preserved;
an occupied or foreign tunnel Interface is not reassigned.

A configured literal remote IP uses an existing real IPAddress from its
explicit remote Namespace. A configured peer FQDN uses the native text FQDN
field literally; discovery performs no DNS resolution. Literal IPs are never
converted into FQDN text to bypass IPAM requirements. The remote endpoint does
not acquire a Device or source Interface from a tunnel name, runtime SA or
matching IP. Separate explicitly selected existing profile contexts can use
separate remote endpoint records without overwriting another populated profile.

Protected selectors become native `protected_prefixes` relationships only when
their protocol is explicitly `any` and the exact Prefix already exists in the
selected side's protected Namespace. Protocol/port-restricted selectors cannot
be represented by a whole Prefix association. Populated protected-prefix sets
are preserved.

Native generated endpoint names are read-only. For a source-IP-only endpoint,
the installed native model generates an empty name. Validation excludes that
generated field, as a native form does, and runs the model's complete `clean()`
with its real relationships. It does not fabricate an Interface, Device or
FQDN to generate a label.

If a source Interface, tunnel Interface or required IP assignment is being
created by the same discovery, its endpoint is deferred until those native
prerequisites exist. Other valid inventory can be populated first; the next
preview/apply then validates and attaches the endpoint. No global manager or
model behavior is patched to make preview succeed.

## Atomic behavior and proof

Native catalog and association writes occur inside the discovery apply
transaction after preview has run native validation. Only blank scalar/FK
fields and empty assignment sets are filled. Populated values, algorithm order,
zero lifetimes, booleans and weights are preserved, with conflicts reported.
An unchanged repeat produces no inventory DML. A late native save failure rolls
back the entire pending inventory graph.

`tests/test_panos_vpn_reconcile.py` tests the pure planner. The rollback-only
`tests/nautobot_panos_vpn_integration.py` verifies native relationships against
Nautobot 3.2.6 without contacting a firewall or preserving fixture records. Its
11 checks cover zero-DML preview and repeat, atomic apply, multiple tunnels on
one WAN, independent assignment validation, populated-field preservation,
missing native capabilities, namespace isolation, missing-profile deferral,
applied-source provenance and late-failure rollback. The private proof artifact
also records exact runtime/workspace source hashes.

The field semantics were checked against the installed native model source and
the official [Nautobot VPN Profile documentation](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/vpn/vpnprofile/)
and [Palo Alto IKE Gateway advanced options](https://docs.paloaltonetworks.com/ngfw/help/10-2/network/network-network-profiles/network-network-profiles-ike-gateways/ike-gateway-advanced-options-tab).
