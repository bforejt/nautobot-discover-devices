"""Discover and enrich an existing device using structured device facts."""

import json
from uuid import UUID

from nautobot.apps.jobs import BooleanVar, DryRunVar, IntegerVar, Job, ObjectVar, TextVar
from nautobot.dcim.models import Device, Location
from nautobot.extras.models import SecretsGroup, Status
from nautobot.ipam.models import Namespace, VLANGroup

from .adapters import cisco_iosxe, panos
from .adapters.panos_management import normalize_management_policy
from .credentials import CredentialsError, resolve_credentials
from .ipam_policy import normalize_ipam_policy
from .nautobot_inventory import InventoryError, apply_discovery, snapshot_inventory, validate_plan
from .panos_ha_policy import normalize_panos_ha_policy
from .panos_ipam_policy import normalize_panos_ipam_policy
from .panos_vpn_policy import normalize_panos_vpn_policy
from .reconcile import build_plan
from .transport_restconf import RestconfClient, RestconfError
from .transport_ssh import PanosSshClient, SshError

name = "Device Discovery"
JOB_VERSION = "0.23.0-dev"


def _resolve_panos_ipam_target(kind, identifier, namespace_id):
    """Read one explicitly selected native object, with no creation or fallback."""
    from nautobot.ipam.models import VRF

    model = Namespace if kind == "namespace" else VRF
    try:
        lookup = {"pk": str(UUID(identifier))}
    except ValueError:
        lookup = {"name": identifier}
    if kind == "vrf":
        lookup["namespace_id"] = namespace_id
    try:
        obj = model.objects.get(**lookup)
    except (model.DoesNotExist, model.MultipleObjectsReturned):
        raise ValueError(
            "PAN-OS mapping target is missing or ambiguous in its selected scope"
        ) from None
    result = {"id": str(obj.pk), "name": obj.name}
    if kind == "vrf":
        result["namespace_id"] = str(obj.namespace_id)
    return result


def _host(device):
    primary_ip = getattr(device, "primary_ip", None)
    if primary_ip is not None:
        host = getattr(primary_ip, "host", None)
        if host:
            return str(host)
        return str(primary_ip.address.ip)
    if device.name:
        return device.name
    raise ValueError("Assign a primary IP or DNS-resolvable name to the Device")


def _resolve_panos_ha_target(kind, identifier):
    from nautobot.dcim import models as dcim_models

    model = Device if kind == "device" else getattr(dcim_models, "DeviceRedundancyGroup", None)
    if model is None:
        raise ValueError("Installed Nautobot lacks native DeviceRedundancyGroup support")
    try:
        obj = model.objects.get(pk=identifier)
    except model.DoesNotExist:
        raise ValueError("An explicitly selected PAN-OS HA object does not exist") from None
    if kind == "device":
        if _adapter(obj) is not panos:
            raise ValueError("The explicitly selected HA peer must have a PAN-OS platform")
        return {"id": str(obj.pk), "name": obj.name, "model": obj.device_type.model}
    return {"id": str(obj.pk), "name": obj.name, "failover_strategy": obj.failover_strategy}


def _resolve_panos_vpn_target(kind, identifier):
    if kind == "namespace":
        return _resolve_panos_ipam_target(kind, identifier, None)
    from django.contrib.contenttypes.models import ContentType

    try:
        lookup = {"pk": str(UUID(identifier))}
    except ValueError:
        lookup = {"name": identifier}
    applicable = Status.objects.filter(**lookup)
    content_type = ContentType.objects.filter(app_label="vpn", model="vpntunnel").first()
    if content_type is not None:
        applicable = applicable.filter(content_types=content_type)
    try:
        obj = applicable.get()
    except (Status.DoesNotExist, Status.MultipleObjectsReturned):
        raise ValueError("Select an unambiguous applicable native VPNTunnel Status") from None
    return {"id": str(obj.pk), "name": obj.name}


def _adapter(device):
    """Select only reviewed platform/manufacturer pairs before resolving secrets."""
    platform = device.platform
    driver = str(getattr(platform, "network_driver", "") or "").lower()
    platform_name = str(getattr(platform, "name", "") or "").lower()
    normalized_name = platform_name.replace("-", "").replace("_", "").replace(" ", "")
    manufacturer = device.device_type.manufacturer.name.lower()
    if driver in ("paloalto_panos", "panos") or (
        not driver and normalized_name in ("panos", "paloaltopanos")
    ):
        if manufacturer.replace(" ", "").replace("-", "") not in ("paloalto", "paloaltonetworks"):
            raise ValueError("The selected Device must have a Palo Alto DeviceType")
        return panos
    if driver not in ("cisco_ios", "cisco_iosxe") and "iosxe" not in normalized_name:
        raise ValueError(
            "The selected Device must have a supported Cisco IOS XE or PAN-OS platform"
        )
    if "cisco" not in manufacturer:
        raise ValueError("The selected Device must have a Cisco DeviceType")
    return cisco_iosxe


def _prefix_location(device, selected):
    """Resolve an explicit Location or an applicable Site in the Device hierarchy."""
    locations = list(device.location.ancestors(include_self=True))
    if selected is not None:
        selected = Location.objects.get(pk=selected.pk)
        if selected.pk not in {location.pk for location in locations}:
            raise ValueError("The Prefix Location must be in the Device's location hierarchy")
    else:
        # An explicit Site ancestor is preferable to a room or rack location.
        sites = [
            location for location in locations if location.location_type.name.lower() == "site"
        ]
        selected = max(sites, key=lambda item: item.tree_depth) if sites else device.location
    if not selected.location_type.content_types.filter(app_label="ipam", model="prefix").exists():
        return None, "The selected Location Type does not permit Prefix associations"
    return {"id": str(selected.pk), "name": selected.name}, None


class DiscoverDevice(Job):
    device = ObjectVar(model=Device, description="Existing Device to verify and enrich.")
    dryrun = DryRunVar(description="Preview changes without updating device inventory.")
    use_ntc_defaults = BooleanVar(
        label="Use NTC defaults when guessing",
        default=False,
        description=(
            "Disabled: leave uncertain values blank. Enabled: use the reviewed Network to Code "
            "Device Onboarding fallback for down dynamic switchports that allow all VLANs: "
            "Tagged all and their known native VLAN. Also permits Nautobot's 0.95 power-factor "
            "default for identified PSU inlets when no verified factor is available. Strict "
            "mode defers new inlets that lack this required value. Guessed values are identified "
            "in the report; other unresolved data stays blank. Populated values are preserved."
        ),
    )
    verify_tls = BooleanVar(default=True, description="Verify the device HTTPS certificate.")
    restconf_port = IntegerVar(default=443, min_value=1, max_value=65535)
    ssh_port = IntegerVar(default=22, min_value=1, max_value=65535)
    ssh_strict = BooleanVar(
        default=True,
        label="Verify SSH host key",
        description="Verify the PAN-OS SSH host key against the worker's known hosts.",
    )
    expected_vm_uuid = TextVar(
        required=False,
        default="",
        label="Expected PAN-OS VM UUID",
        description=(
            "Explicit identity for the selected PAN-OS PA-VM on KVM. Requires an exact match "
            "with the firewall's reported VM UUID. A blank Device serial may remain blank "
            "when this identity is verified; populated serials remain protected."
        ),
    )
    max_vpn_flow_details = IntegerVar(
        default=256,
        min_value=1,
        max_value=65535,
        label="Maximum VPN flow details",
        description=(
            "PAN-OS: maximum IPsec flows to read in detail. Increase for larger firewalls. "
            "Exceeding the limit stops discovery rather than returning partial VPN evidence."
        ),
    )
    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=False,
        description="Optional override; otherwise use the Device's Secrets Group.",
    )
    interface_status = ObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "dcim.interface"},
        description="Status for new interfaces; defaults to an applicable Active status.",
    )
    software_version_status = ObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "dcim.softwareversion"},
        description="Status for new software versions; defaults to an applicable Active status.",
    )
    module_status = ObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "dcim.module"},
        description="Status for new serialized modules; defaults to an applicable Active status.",
    )
    vlan_group = ObjectVar(
        model=VLANGroup,
        required=False,
        description=(
            "VLAN domain for 802.1Q assignments. Without a selection, VLAN changes are deferred."
        ),
    )
    vlan_status = ObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "ipam.vlan"},
        description="Status for new VLAN records; defaults to an applicable Active status.",
    )
    ipam_namespace = ObjectVar(
        model=Namespace,
        required=False,
        label="Default IPAM namespace",
        description=(
            "Cisco IOS XE: select an existing Namespace for static addressing and named VRFs. "
            "PAN-OS uses the explicit routing-domain mappings below."
        ),
    )
    panos_routing_domains = TextVar(
        required=False,
        default="",
        label="PAN-OS routing-domain mappings",
        description=(
            "JSON list with exact vsys, virtual_router, namespace and vrf fields. "
            "Select existing Namespace/VRF names or UUIDs; vrf:null explicitly selects global "
            'routing. Example: [{"vsys":"vsys1","virtual_router":"lab-vpn-vr",'
            '"namespace":"Lab","vrf":null}]. Blank: report-only PAN-OS IPAM.'
        ),
    )
    panos_management_policy = TextVar(
        required=False,
        default="",
        label="PAN-OS management inventory policy",
        description=(
            "JSON object selecting an existing Namespace. Example: "
            '{"namespace":"Management","include_dhcp":false,"fill_primary":true}. '
            "DHCP leases require an explicit opt-in. Populated primary IPs are preserved."
        ),
    )
    panos_ha_peer = TextVar(
        required=False,
        default="",
        label="PAN-OS HA peer selection",
        description=(
            "JSON object with existing peer_device UUID, peer_vm_uuid and existing "
            "redundancy_group UUID. Peer identity and reciprocal HA evidence are read "
            "directly over SSH. Blank: HA addresses remain report-only."
        ),
    )
    panos_vpn_mappings = TextVar(
        required=False,
        default="",
        label="PAN-OS native VPN mappings",
        description=(
            "JSON list with exact tunnel, vpn_name, tunnel_name and profile_name "
            "selecting an existing VPNProfile. Missing profiles remain unresolved. "
            "optional applicable status and existing local_namespace, remote_namespace, "
            "local_protected_namespace and remote_protected_namespace names or UUIDs. "
            "Blank or unavailable native models: VPN collection stays report-only."
        ),
    )
    ipam_override_namespace = ObjectVar(
        model=Namespace,
        required=False,
        label="Override IPAM namespace",
        description="Optional destination for RFC1918 and manually entered override networks.",
    )
    ipam_override_rfc1918 = BooleanVar(
        default=True,
        label="Use override for RFC1918",
        description=(
            "With an override Namespace selected, place 10.0.0.0/8, 172.16.0.0/12 "
            "and 192.168.0.0/16 there. This applies only to IPv4; use manual IPv6 CIDRs "
            "for IPv6 overrides, including ULA."
        ),
    )
    ipam_override_networks = TextVar(
        required=False,
        default="",
        label="Additional override networks",
        description=(
            "IPv4 or IPv6 network CIDRs, one per line, such as 100.64.0.0/10 or fd00::/8. "
            "Requires an override Namespace. Both address families in one named VRF must "
            "resolve to the same Namespace."
        ),
    )
    ipam_create_missing_prefixes = BooleanVar(
        default=True,
        label="Create missing networks",
        description=(
            "Create exact connected Prefixes from configured addresses and masks, attached "
            "to the Prefix Location. Disabled: defer addresses requiring a missing network."
        ),
    )
    ipam_group_user_vrfs = BooleanVar(
        default=False,
        label="Group matching user VRF names across devices",
        description=(
            "Enabled: matching names within one Namespace represent a shared domain. "
            "Disabled: new VRFs are device-local. Existing Device assignments take precedence."
        ),
    )
    ipam_local_vrf_names = TextVar(
        required=False,
        default="Mgmt-vrf",
        label="Keep these VRF names device-local",
        description=(
            "Exact, case-sensitive names, one per line. These remain device-local when "
            "grouping is enabled. The actual switch name is retained on its Device assignment."
        ),
    )
    ipam_location = ObjectVar(
        model=Location,
        required=False,
        label="Prefix Location",
        description=(
            "Optional Device ancestor override. Defaults to its closest Site ancestor, "
            "otherwise the Device Location. Its Location Type must permit Prefixes."
        ),
    )
    ipam_prefix_status = ObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "ipam.prefix"},
        label="New Prefix status",
        description="Defaults to an applicable Active status; existing statuses are preserved.",
    )
    ipam_ip_address_status = ObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "ipam.ipaddress"},
        label="New IP Address status",
        description="Defaults to an applicable Active status; existing statuses are preserved.",
    )

    class Meta:
        name = "Discover Device"
        description = (
            "Verify Cisco IOS XE or PAN-OS identity and fill supported interfaces. "
            "PAN-OS supports logical and management inventory, explicitly selected HA "
            "ownership and native VPN processing where compatible models exist. "
            "Cisco IOS XE also supports console ports, VLANs, "
            "serialized hardware, static IPv4/IPv6 addressing and named VRFs with "
            "supported import/export route targets."
        )
        dryrun_default = True
        read_only = False
        is_singleton = True
        soft_time_limit = 600
        time_limit = 660
        field_order = (
            "device",
            "dryrun",
            "use_ntc_defaults",
            "verify_tls",
            "restconf_port",
            "ssh_port",
            "ssh_strict",
            "expected_vm_uuid",
            "max_vpn_flow_details",
            "secrets_group",
            "interface_status",
            "software_version_status",
            "module_status",
            "vlan_group",
            "vlan_status",
            "ipam_namespace",
            "panos_routing_domains",
            "panos_management_policy",
            "panos_ha_peer",
            "panos_vpn_mappings",
            "ipam_override_namespace",
            "ipam_override_rfc1918",
            "ipam_override_networks",
            "ipam_create_missing_prefixes",
            "ipam_group_user_vrfs",
            "ipam_local_vrf_names",
            "ipam_location",
            "ipam_prefix_status",
            "ipam_ip_address_status",
        )

    def run(
        self,
        device,
        dryrun=True,
        verify_tls=True,
        restconf_port=443,
        secrets_group=None,
        interface_status=None,
        software_version_status=None,
        module_status=None,
        vlan_group=None,
        vlan_status=None,
        use_ntc_defaults=False,
        ipam_namespace=None,
        ipam_override_namespace=None,
        ipam_override_rfc1918=True,
        ipam_override_networks="",
        ipam_create_missing_prefixes=True,
        ipam_group_user_vrfs=False,
        ipam_local_vrf_names="Mgmt-vrf",
        ipam_location=None,
        ipam_prefix_status=None,
        ipam_ip_address_status=None,
        ssh_port=22,
        ssh_strict=True,
        expected_vm_uuid="",
        max_vpn_flow_details=256,
        panos_routing_domains="",
        panos_management_policy="",
        panos_ha_peer="",
        panos_vpn_mappings="",
    ):
        device = Device.objects.get(pk=device.pk)
        report = {
            "schema_version": 1,
            "job_version": JOB_VERSION,
            "device_id": str(device.pk),
            "dry_run": dryrun,
            "use_ntc_defaults": use_ntc_defaults,
            "verify_tls": verify_tls,
            "restconf_port": restconf_port,
            "ssh_port": ssh_port,
            "ssh_strict": ssh_strict,
            "expected_vm_uuid": expected_vm_uuid,
            "applied": False,
            "vlan_group_id": str(vlan_group.pk) if vlan_group else None,
            "vlan_group_name": vlan_group.name if vlan_group else None,
        }
        self.logger.info(
            "Starting %s for %s.", "discovery preview" if dryrun else "discovery", device.name
        )
        try:
            adapter = _adapter(device)
            if adapter is not panos and any(
                (panos_routing_domains, panos_management_policy, panos_ha_peer, panos_vpn_mappings)
            ):
                raise ValueError("PAN-OS inventory policies are supported only for PAN-OS")
            panos_policy = (
                normalize_panos_ipam_policy(
                    panos_routing_domains,
                    _resolve_panos_ipam_target,
                    create_missing_prefixes=ipam_create_missing_prefixes,
                )
                if adapter is panos
                else None
            )
            management_policy = (
                normalize_management_policy(
                    panos_management_policy,
                    _resolve_panos_ipam_target,
                    create_missing_prefixes=ipam_create_missing_prefixes,
                )
                if adapter is panos
                else None
            )
            ha_policy = (
                normalize_panos_ha_policy(
                    panos_ha_peer, _resolve_panos_ha_target, selected_device_id=str(device.pk)
                )
                if adapter is panos
                else None
            )
            vpn_policy = (
                normalize_panos_vpn_policy(panos_vpn_mappings, _resolve_panos_vpn_target)
                if adapter is panos
                else None
            )
            location, location_reason = (
                _prefix_location(device, ipam_location)
                if (adapter is not panos and ipam_namespace is not None)
                or panos_policy is not None
                or management_policy is not None
                else (None, None)
            )
            ipam_policy = (
                panos_policy
                if adapter is panos
                else normalize_ipam_policy(
                    ipam_namespace,
                    ipam_override_namespace,
                    override_rfc1918=ipam_override_rfc1918,
                    override_networks=ipam_override_networks,
                    create_missing_prefixes=ipam_create_missing_prefixes,
                    group_user_vrfs=ipam_group_user_vrfs,
                    local_vrf_names=ipam_local_vrf_names,
                    location=location,
                    location_reason=location_reason,
                )
            )
            if adapter is panos and ipam_policy is not None:
                ipam_policy.update(location=location, location_reason=location_reason)
            if management_policy is not None:
                management_policy.update(location=location, location_reason=location_reason)
                if ipam_policy is None:
                    ipam_policy = {
                        "contract": "panos-ipam-policy-v1",
                        "panos_routing_domains": [],
                        "default_namespace": management_policy["namespace"],
                        "create_missing_prefixes": ipam_create_missing_prefixes,
                        "location": location,
                        "location_reason": location_reason,
                    }
                ipam_policy["panos_management"] = management_policy
            report["ipam_policy"] = ipam_policy
            if type(use_ntc_defaults) is not bool:
                raise ValueError("Use NTC defaults when guessing must be true or false")
            if expected_vm_uuid is None or (
                isinstance(expected_vm_uuid, str) and not expected_vm_uuid.strip()
            ):
                expected_vm_uuid = None
            else:
                if adapter is not panos:
                    raise ValueError("Expected VM UUID is supported only for PAN-OS discovery")
                expected_vm_uuid = panos.canonical_vm_uuid(expected_vm_uuid)
                if expected_vm_uuid is None:
                    raise ValueError("Expected PAN-OS VM UUID must be a nonzero canonical UUID")
            report["expected_vm_uuid"] = expected_vm_uuid
            report["transport"] = "ssh" if adapter is panos else "restconf"
            if use_ntc_defaults:
                self.logger.info(
                    "PAN-OS discovery retains strict evidence rules; the NTC defaults option "
                    "applies only to Cisco IOS XE."
                    if adapter is panos
                    else "NTC default guessing is enabled. Any inferred assignments are identified "
                    "as guesses in the discovery report."
                )
            if adapter is panos:
                if type(ssh_strict) is not bool:
                    raise ValueError("Verify SSH host key must be true or false")
                if type(max_vpn_flow_details) is not int or not 1 <= max_vpn_flow_details <= 65535:
                    raise ValueError(
                        "Maximum VPN flow details must be an integer between 1 and 65535"
                    )
                report["max_vpn_flow_details"] = max_vpn_flow_details
                username, password = resolve_credentials(
                    device, override_group=secrets_group, transport="ssh"
                )
                client = PanosSshClient(
                    _host(device), username, password, port=ssh_port, ssh_strict=ssh_strict
                )
            else:
                username, password = resolve_credentials(device, override_group=secrets_group)
                client = RestconfClient(
                    _host(device), username, password, port=restconf_port, verify=verify_tls
                )
            try:
                collect_options = {"use_ntc_defaults": use_ntc_defaults}
                if adapter is panos:
                    collect_options["expected_vm_uuid"] = expected_vm_uuid
                    collect_options["max_vpn_flow_details"] = max_vpn_flow_details
                report["discovery"] = adapter.collect(client, **collect_options)
            finally:
                client.close()
                report["requests"] = client.trace
            discovery = report["discovery"]
            if adapter is panos:
                discovery["vpn_policy"] = vpn_policy
                if ha_policy is not None:
                    peer = Device.objects.get(pk=ha_policy["peer_device"]["id"])
                    username, password = resolve_credentials(
                        peer, override_group=secrets_group, transport="ssh"
                    )
                    peer_client = PanosSshClient(
                        _host(peer), username, password, port=ssh_port, ssh_strict=ssh_strict
                    )
                    try:
                        peer_discovery = panos.collect(
                            peer_client,
                            expected_vm_uuid=ha_policy["peer_vm_uuid"],
                            max_vpn_flow_details=max_vpn_flow_details,
                        )
                    finally:
                        peer_client.close()
                        report["peer_requests"] = peer_client.trace
                    discovery["ha_pair"] = {
                        "contract": "panos-ha-pair-v1",
                        "policy": ha_policy,
                        "peer_discovery": peer_discovery,
                    }
            if adapter is panos:
                observations = discovery.get("observations", {})
                vpn = observations.get("vpn", {})
                configuration = vpn.get("configuration", {})
                runtime = vpn.get("runtime", {})
                self.logger.info(
                    "Collected HA state and %s configured IPsec tunnels with %s flow details. "
                    "HA/VPN evidence and explicitly selected native processing are available "
                    "under Advanced and in the report.",
                    len(configuration.get("ipsec_tunnels", [])),
                    len(runtime.get("flow_details", [])),
                )
            management = discovery.get("management", {})
            if (
                ipam_policy is None
                and (management.get("interfaces") or management.get("observations"))
                and management.get("writes_deferred_reason")
            ):
                self.logger.info(
                    "Management VRF and address evidence is available under Advanced. "
                    "VRF/IP assignments are deferred until their Namespace mapping is selected."
                )
            if management.get("unresolved"):
                self.logger.warning(
                    "Could not establish %s management configuration observations. "
                    "Available hardware and configuration evidence remains under Advanced.",
                    len(management["unresolved"]),
                )
            self.logger.info(
                "Read %s interfaces and %s identified hardware modules from %s.",
                len(discovery.get("interfaces", [])),
                len(discovery.get("components", {}).get("items", [])),
                device.name,
            )
            self.logger.info("Comparing discovered details with Nautobot inventory.")
            report["plan"] = build_plan(
                report["discovery"],
                snapshot_inventory(
                    device,
                    discovery=report["discovery"],
                    vlan_group=vlan_group,
                    ipam_policy=ipam_policy,
                ),
            )
            plan = report["plan"]
            validate_plan(
                plan,
                device,
                interface_status=interface_status,
                software_version_status=software_version_status,
                module_status=module_status,
                vlan_status=vlan_status,
                ipam_prefix_status=ipam_prefix_status,
                ipam_ip_address_status=ipam_ip_address_status,
            )
            if not dryrun:
                self.logger.info("Validation passed. Saving missing inventory details.")
                report["plan"] = apply_discovery(
                    report["discovery"],
                    device,
                    interface_status=interface_status,
                    software_version_status=software_version_status,
                    module_status=module_status,
                    vlan_group=vlan_group,
                    vlan_status=vlan_status,
                    ipam_policy=ipam_policy,
                    ipam_prefix_status=ipam_prefix_status,
                    ipam_ip_address_status=ipam_ip_address_status,
                )
                report["applied"] = True
            self._log_plan(report["plan"], dryrun=dryrun)
            self.logger.info(
                "Preview complete. No inventory changes were saved."
                if dryrun
                else "Discovery complete."
            )
            self.logger.info(
                "Full discovery results are available under Advanced and in the report download."
            )
        except Exception as exc:
            report["error"] = str(exc)
            if isinstance(
                exc,
                (
                    RestconfError,
                    SshError,
                    CredentialsError,
                    cisco_iosxe.DiscoveryError,
                    panos.DiscoveryError,
                    InventoryError,
                ),
            ):
                self.logger.error("Discovery failed: %s", exc)
                # Jobs are dynamically imported in the child process. The
                # Celery parent may not be able to import their exception
                # classes while unpickling a failed task's result.
                raise RuntimeError(str(exc)) from None
            raise
        finally:
            # Nautobot shares this request with its Celery runner. The result
            # backend persists request.meta on success and failure, and the
            # JobResult UI displays it on Advanced rather than the main tab.
            self.request.meta = {
                **(getattr(self.request, "meta", None) or {}),
                "discovery_report": report,
            }
            self._attach_report(report)

    def _log_plan(self, plan, dryrun):
        summary = plan["summary"]
        changes = (
            (
                "device_fields_updated",
                "fill",
                "Filled",
                "empty device field",
                "empty device fields",
            ),
            (
                "capacity_fields_updated",
                "fill",
                "Filled",
                "empty VM capacity field",
                "empty VM capacity fields",
            ),
            ("interfaces_created", "add", "Added", "interface", "interfaces"),
            ("virtual_chassis_created", "add", "Added", "virtual chassis", "virtual chassis"),
            ("virtual_chassis_updated", "update", "Updated", "virtual chassis", "virtual chassis"),
            ("stack_members_created", "add", "Added", "stack member", "stack members"),
            ("stack_members_updated", "update", "Updated", "stack member", "stack members"),
            (
                "stack_member_software_assigned",
                "assign",
                "Assigned",
                "stack member software version",
                "stack member software versions",
            ),
            ("device_types_created", "add", "Added", "device type", "device types"),
            ("console_ports_created", "add", "Added", "console port", "console ports"),
            ("console_ports_updated", "update", "Updated", "console port", "console ports"),
            (
                "management_interfaces_updated",
                "mark",
                "Marked",
                "dedicated management interface",
                "dedicated management interfaces",
            ),
            (
                "interfaces_updated",
                "update",
                "Updated",
                "existing interface",
                "existing interfaces",
            ),
            (
                "lag_memberships_updated",
                "link",
                "Linked",
                "port-channel member",
                "port-channel members",
            ),
            ("manufacturers_created", "add", "Added", "manufacturer", "manufacturers"),
            ("module_types_created", "add", "Added", "hardware type", "hardware types"),
            ("module_types_updated", "update", "Updated", "hardware type", "hardware types"),
            ("module_bays_created", "add", "Added", "module bay", "module bays"),
            ("module_bays_updated", "update", "Updated", "module bay", "module bays"),
            ("modules_created", "add", "Added", "hardware module", "hardware modules"),
            ("modules_updated", "update", "Updated", "hardware module", "hardware modules"),
            ("power_ports_created", "add", "Added", "power inlet", "power inlets"),
            ("power_ports_updated", "update", "Updated", "power inlet", "power inlets"),
            (
                "interface_modules_updated",
                "link",
                "Linked",
                "interface to its hardware module",
                "interfaces to their hardware modules",
            ),
            ("vlans_created", "add", "Added", "VLAN", "VLANs"),
            ("vlans_updated", "update", "Updated", "VLAN", "VLANs"),
            (
                "interface_vlan_assignments_updated",
                "update",
                "Updated",
                "interface VLAN assignment",
                "interface VLAN assignments",
            ),
            ("prefixes_created", "add", "Added", "network Prefix", "network Prefixes"),
            ("ip_addresses_created", "add", "Added", "IP address", "IP addresses"),
            (
                "ip_assignments_created",
                "link",
                "Linked",
                "IP address assignment",
                "IP address assignments",
            ),
            ("vrfs_created", "add", "Added", "VRF", "VRFs"),
            ("route_targets_created", "add", "Added", "route target", "route targets"),
            (
                "vrf_import_targets_added",
                "link",
                "Linked",
                "VRF import route target",
                "VRF import route targets",
            ),
            (
                "vrf_export_targets_added",
                "link",
                "Linked",
                "VRF export route target",
                "VRF export route targets",
            ),
            (
                "vrf_device_assignments_created",
                "add",
                "Added",
                "Device VRF assignment",
                "Device VRF assignments",
            ),
            (
                "vrf_device_assignments_updated",
                "fill",
                "Filled",
                "Device VRF assignment",
                "Device VRF assignments",
            ),
            (
                "interface_vrfs_updated",
                "update",
                "Updated",
                "interface VRF assignment",
                "interface VRF assignments",
            ),
            (
                "prefix_vrf_associations_created",
                "link",
                "Linked",
                "Prefix VRF assignment",
                "Prefix VRF assignments",
            ),
            ("panos_primary_ips_updated", "fill", "Filled", "primary IP", "primary IPs"),
            (
                "interface_parents_assigned",
                "link",
                "Linked",
                "logical interface parent",
                "logical interface parents",
            ),
            (
                "panos_lag_assignments",
                "link",
                "Linked",
                "PAN-OS aggregate membership",
                "PAN-OS aggregate memberships",
            ),
            ("ha_groups_updated", "fill", "Filled", "HA group", "HA groups"),
            ("ha_devices_updated", "fill", "Filled", "HA membership", "HA memberships"),
            ("vpn_objects_created", "add", "Added", "VPN object", "VPN objects"),
            ("vpn_objects_updated", "fill", "Filled", "VPN object", "VPN objects"),
            (
                "vpn_policy_assignments_created",
                "link",
                "Linked",
                "VPN policy assignment",
                "VPN policy assignments",
            ),
            (
                "vpn_prefix_assignments_created",
                "link",
                "Linked",
                "VPN Prefix assignment",
                "VPN Prefix assignments",
            ),
        )
        if not any(summary.get(key, 0) for key, *_ in changes):
            self.logger.info("No inventory changes are needed.")
        for key, preview_verb, applied_verb, singular, plural in changes:
            count = summary.get(key, 0)
            if count:
                self.logger.info(
                    "%s %s %s.",
                    "Would " + preview_verb if dryrun else applied_verb,
                    count,
                    singular if count == 1 else plural,
                )
        ipam = plan.get("ipam", {})
        capacity = plan.get("capacity", {})
        for domain, label in (
            ("panos_interfaces", "PAN-OS logical interface"),
            ("management", "PAN-OS management"),
            ("ha", "PAN-OS HA"),
            ("vpn", "PAN-OS VPN"),
        ):
            unresolved = plan.get(domain, {}).get("unresolved", [])
            if unresolved:
                self.logger.info(
                    "Left %s %s observations unresolved; review their evidence under Advanced.",
                    len(unresolved),
                    label,
                )
        if capacity.get("unresolved"):
            self.logger.info(
                "Left %s VM capacity observations unresolved. Review source evidence and "
                "custom-field requirements under Advanced.",
                len(capacity["unresolved"]),
            )
        if ipam.get("unresolved"):
            self.logger.info(
                "Left %s IPAM observations unresolved. The report explains missing evidence, "
                "Namespace policy and routing conflicts; existing IPAM is preserved.",
                len(ipam["unresolved"]),
            )
        if summary.get("unknown_interface_capabilities"):
            self.logger.info(
                "Physical capability remains unknown for %s observed Ethernet interfaces. "
                "New interfaces use Other; populated types are preserved. Reported facts remain "
                "eligible without inferring connector, duplex or maximum speed.",
                summary["unknown_interface_capabilities"],
            )
        if plan["warnings"]:
            count = len(plan["warnings"])
            self.logger.warning(
                "Found %s discovery %s. Review the details under Advanced.",
                count,
                "warning" if count == 1 else "warnings",
            )
        if summary["conflicts"]:
            self.logger.warning(
                "Kept existing inventory values for %s %s. Review the differences under Advanced.",
                summary["conflicts"],
                "conflict" if summary["conflicts"] == 1 else "conflicts",
            )
            # Only reviewed choice labels belong in the main log. Arbitrary
            # before/observed values and complete evidence stay in the report.
            type_labels = {"other": "Other", "virtual": "Virtual", "lag": "Link aggregation"}
            for conflict in plan.get("conflicts", []):
                before = (
                    type_labels.get(conflict.get("before"))
                    if isinstance(conflict.get("before"), str)
                    else None
                )
                observed = (
                    type_labels.get(conflict.get("observed"))
                    if isinstance(conflict.get("observed"), str)
                    else None
                )
                if (
                    conflict.get("scope") == "interface"
                    and conflict.get("field") == "type"
                    and before
                    and observed
                ):
                    self.logger.warning(
                        "Interface %s: kept type %s; discovery identifies it as %s. "
                        "This is an inventory difference; the existing interface was preserved.",
                        conflict["name"],
                        before,
                        observed,
                    )
        if summary["unresolved_components"]:
            missing_identity_reasons = {
                "Serialized component model or serial number is unavailable",
                "Component identity is unavailable; presence or occupancy "
                "is not inferred from operational state",
                "PSU serialized identity is unavailable; occupancy is retained from empty "
                "and asset identity is not inferred from operational power state",
            }
            missing_identity = sum(
                row.get("reason") in missing_identity_reasons
                for row in plan.get("components", {}).get("unresolved", [])
            )
            if missing_identity:
                self.logger.warning(
                    "Could not create %s serialized hardware %s: the device did not provide "
                    "model or serial identity. Existing hardware was preserved; "
                    "review the observations under Advanced.",
                    missing_identity,
                    "record" if missing_identity == 1 else "records",
                )
            unknown_power_factor = sum(
                row.get("reason") == "New PowerPort requires a power factor; "
                "no documented value or enabled NtC default is available"
                for row in plan.get("components", {}).get("unresolved", [])
            )
            if unknown_power_factor:
                self.logger.info(
                    "Deferred %s new PSU power %s because Nautobot requires a power factor "
                    "and the device did not provide a verified value. Bays and identified assets "
                    "remain eligible; the NTC defaults option permits the inferred 0.95 default.",
                    unknown_power_factor,
                    "inlet" if unknown_power_factor == 1 else "inlets",
                )
            remaining = summary["unresolved_components"] - missing_identity - unknown_power_factor
            if remaining:
                self.logger.warning(
                    "Left %s hardware %s unresolved because identity or placement "
                    "could not be established safely. Existing hardware was preserved; "
                    "review the details under Advanced.",
                    remaining,
                    "observation" if remaining == 1 else "observations",
                )
        if summary.get("deferred_interface_ownership"):
            self.logger.info(
                "Deferred %s interface-to-module links across stack member Devices. "
                "Physical modules remain eligible on their confirmed members; existing "
                "network interface ownership is preserved. Details are in the report.",
                summary["deferred_interface_ownership"],
            )
        if summary.get("power_ports_inferred"):
            self.logger.info(
                "%s Nautobot's power-factor default of 0.95 for %s PSU "
                "inlet observations. This is an inferred value, not a measurement; "
                "the NTC defaults option explicitly permits it and its provenance is in "
                "the report.",
                "Would use" if dryrun else "Used",
                summary["power_ports_inferred"],
            )
        if summary.get("switching_not_applicable"):
            self.logger.info(
                "Switchport VLAN mapping does not apply to %s management, routed, or "
                "logical interfaces. This is expected.",
                summary["switching_not_applicable"],
            )
        if summary.get("switching_defaults"):
            self.logger.info(
                "Established documented switchport defaults for %s interfaces from complete "
                "configuration reads; their source evidence is under Advanced.",
                summary["switching_defaults"],
            )
        operational_source = plan.get("layer2", {}).get("operational_source") or {}
        if operational_source.get("status") in (
            "not-advertised",
            "unsupported",
            "capability-unknown",
        ):
            self.logger.info(
                "Operational switchport mode source is %s. Negotiated mode stays blank "
                "without supported evidence; configured assignments remain available.",
                operational_source["status"],
            )
        if operational_source.get("status") in ("unavailable", "invalid"):
            self.logger.warning(
                "Optional operational switchport source is %s. Discovery continues with "
                "independently verified configuration; source details are under Advanced.",
                operational_source["status"],
            )
            if operational_source["status"] == "invalid":
                self.logger.warning(
                    "Rejected operational switchport data cannot be used for assignments "
                    "or NTC mode guessing. Existing inventory is preserved."
                )
        if operational_source.get("status") == "available" and operational_source.get(
            "probed_without_advertisement"
        ):
            self.logger.info(
                "Operational switchport source was validated by a direct RESTCONF probe "
                "because module-library evidence was unavailable. Its revision remains unknown."
            )
        if summary.get("switching_operational"):
            self.logger.info(
                "Observed actual negotiated access/trunk mode on %s interfaces; %s dynamic "
                "switchports also have complete, supported configured VLAN assignments. "
                "The operational source and administrative mode are separate in the report.",
                summary["switching_operational"],
                summary["switching_dynamic_resolved"],
            )
        if summary.get("switching_dynamic"):
            if summary.get("switching_inferred"):
                self.logger.info(
                    "%s interfaces have dynamic switchport configuration; %s match the "
                    "opt-in NTC guessing policy. These guesses do not establish a negotiated "
                    "access/trunk mode. Configuration and inference evidence are under Advanced.",
                    summary["switching_dynamic"],
                    summary["switching_inferred"],
                )
            else:
                self.logger.info(
                    "%s interfaces have dynamic switchport configuration. Available configuration "
                    "is retained separately; %s have complete assignments established from their "
                    "reported negotiated mode. Any unknown negotiated 802.1Q mode remains blank.",
                    summary["switching_dynamic"],
                    summary.get("switching_dynamic_resolved", 0),
                )
        if summary.get("interface_vlan_assignments_inferred"):
            self.logger.info(
                "%s NTC-inferred VLAN assignments on %s interfaces. "
                "The assumed mode and its source are identified in the report.",
                "Would use" if dryrun else "Used",
                summary["interface_vlan_assignments_inferred"],
            )
        if summary.get("unresolved_switching"):
            self.logger.warning(
                "Left %s interface VLAN observations unresolved because required evidence "
                "is missing or has no reviewed mapping. Available configuration remains "
                "in the discovery report; review the details under Advanced.",
                summary["unresolved_switching"],
            )
        if summary.get("unresolved_console_ports"):
            self.logger.warning(
                "Left %s console-port observations unresolved because required evidence "
                "is unavailable or ambiguous. Review the details under Advanced.",
                summary["unresolved_console_ports"],
            )
        if summary["missing_interfaces"]:
            self.logger.warning(
                "%s existing %s %s not found on the device and kept in Nautobot. "
                "Review the details under Advanced.",
                summary["missing_interfaces"],
                "interface" if summary["missing_interfaces"] == 1 else "interfaces",
                "was" if summary["missing_interfaces"] == 1 else "were",
            )
        if summary["excluded_interfaces"]:
            self.logger.info(
                "Skipped %s interface %s outside the supported discovery scope.",
                summary["excluded_interfaces"],
                "observation" if summary["excluded_interfaces"] == 1 else "observations",
            )

    def _attach_report(self, report):
        try:
            self.create_file(
                "discovery_%s.json" % report["device_id"],
                json.dumps(report, indent=2, sort_keys=True),
            )
        except Exception:
            self.logger.warning(
                "Could not attach the report download. Full discovery results are under Advanced."
            )
