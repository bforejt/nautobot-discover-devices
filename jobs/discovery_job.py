"""Discover and enrich an existing device using structured device facts."""

import json
from uuid import UUID

from nautobot.apps.jobs import BooleanVar, ChoiceVar, DryRunVar, IntegerVar, Job, ObjectVar, TextVar
from nautobot.dcim.models import Device, Location
from nautobot.extras.models import SecretsGroup, Status
from nautobot.ipam.models import Namespace, VLANGroup

from .adapters import cisco_9800, cisco_iosxe, esxi, panos, proxmox
from .adapters.panos_management import normalize_management_policy
from .credentials import CredentialsError, resolve_credentials
from .esxi_guest_policy import normalize_esxi_guest_policy
from .ipam_policy import normalize_ipam_policy
from .nautobot_inventory import InventoryError, apply_discovery, snapshot_inventory, validate_plan
from .panos_ha_policy import normalize_panos_ha_policy
from .panos_ipam_policy import normalize_panos_ipam_policy
from .panos_vpn_policy import normalize_panos_vpn_policy
from .proxmox_guest_policy import normalize_proxmox_guest_policy
from .reconcile import build_plan
from .transport_esxi import EsxiClient, EsxiError
from .transport_proxmox import ProxmoxClient, ProxmoxError
from .transport_restconf import RestconfClient, RestconfError
from .transport_ssh import PanosSshClient, SshError

name = "Device Discovery"
JOB_VERSION = "0.26.0-dev"


def _controller_source(device, *, controller_id=None, source_policy=None):
    from .controller_sources import resolve_controller_source

    return resolve_controller_source(
        device, controller_id=controller_id, source_policy=source_policy
    )


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


def _resolve_hosted_guest_target(kind, identifier, label):
    """Resolve the existing Hosted On relationship and explicitly selected Devices."""
    if kind == "device":
        try:
            obj = Device.objects.get(pk=identifier)
        except Device.DoesNotExist:
            raise ValueError(
                "An explicitly selected %s guest Device does not exist" % label
            ) from None
        return {"id": str(obj.pk), "name": obj.name}
    if kind != "relationship" or identifier != "hosted_on":
        raise ValueError("Unsupported %s guest mapping target" % label)
    try:
        from nautobot.extras.models import Relationship
    except ImportError:
        raise ValueError("Installed Nautobot lacks native Relationship support") from None
    try:
        obj = Relationship.objects.get(key="hosted_on")
    except (Relationship.DoesNotExist, Relationship.MultipleObjectsReturned):
        raise ValueError("The existing Hosted On relationship is missing or ambiguous") from None
    return {
        "id": str(obj.pk),
        "key": obj.key,
        "type": obj.type,
        "source_type": "%s.%s" % (obj.source_type.app_label, obj.source_type.model),
        "destination_type": "%s.%s" % (obj.destination_type.app_label, obj.destination_type.model),
    }


def _resolve_esxi_guest_target(kind, identifier):
    return _resolve_hosted_guest_target(kind, identifier, "ESXi")


def _resolve_proxmox_guest_target(kind, identifier):
    return _resolve_hosted_guest_target(kind, identifier, "Proxmox")


def _adapter(device):
    """Select only reviewed platform/manufacturer pairs before resolving secrets."""
    platform = device.platform
    driver = str(getattr(platform, "network_driver", "") or "").lower()
    platform_name = str(getattr(platform, "name", "") or "").lower()
    normalized_name = platform_name.replace("-", "").replace("_", "").replace(" ", "")
    if driver in ("esxi", "vmware_esxi") or (
        not driver and normalized_name in ("esxi", "vmwareesxi")
    ):
        return esxi
    if driver in ("proxmox", "proxmox_ve") or (
        not driver and normalized_name in ("proxmox", "proxmoxve")
    ):
        return proxmox
    manufacturer = device.device_type.manufacturer.name.lower()
    if driver in ("paloalto_panos", "panos") or (
        not driver and normalized_name in ("panos", "paloaltopanos")
    ):
        if manufacturer.replace(" ", "").replace("-", "") not in ("paloalto", "paloaltonetworks"):
            raise ValueError("The selected Device must have a Palo Alto DeviceType")
        return panos
    if driver not in ("cisco_ios", "cisco_iosxe") and "iosxe" not in normalized_name:
        raise ValueError(
            "Select a Device with a supported Cisco IOS XE, PAN-OS, ESXi or Proxmox platform"
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
    device = ObjectVar(
        model=Device,
        required=False,
        description=(
            "Existing Device, controller or WAP. A WAP selects its configured controller's "
            "entire current AP roster, including other sites. Select a Device or logical "
            "9800 Controller UUID."
        ),
    )
    wireless_controller = TextVar(
        required=False,
        default="",
        label="9800 logical Controller UUID",
        description=(
            "Existing native Controller UUID. Optional for an unambiguously linked controller "
            "Device or WAP. A WAP and explicit Controller must resolve to the same source."
        ),
    )
    wireless_source_policy = TextVar(
        required=False,
        default="",
        label="9800 endpoint identity policy",
        description=(
            'JSON source binding; C9800-CL requires {"expected_hostname":"configured-wlc"}. '
            "Physical sources require their controller Device's exact model and serial."
        ),
    )
    wireless_policy = TextVar(
        required=False,
        default="",
        label="9800 AP admission and placement policy",
        description=(
            "Explicit JSON catalog selections and Location UUID mappings for the full roster. "
            "Eligible APs can be created and proven locations/software replaced. Missing "
            "admission values defer new APs; see the 9800 discovery contract."
        ),
    )
    wireless_max_aps = IntegerVar(
        default=10000,
        min_value=1,
        max_value=10000,
        label="9800 AP roster limit",
        description="Exceeding this limit fails collection; partial rosters are never applied.",
    )
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
    esxi_port = IntegerVar(default=443, min_value=1, max_value=65535, label="ESXi HTTPS port")
    expected_esxi_host_uuid = TextVar(
        required=False,
        default="",
        label="Expected ESXi host UUID",
        description=(
            "Explicit hardware UUID for the selected standalone ESXi host. Requires an exact "
            "match with HostSystem.hardware.systemInfo.uuid. A missing chassis serial remains "
            "blank; the UUID is never stored as a serial."
        ),
    )
    esxi_guest_mappings = TextVar(
        required=False,
        default="",
        label="ESXi Hosted On guest mappings",
        description=(
            "JSON list selecting an observed VM BIOS UUID and an existing guest Device UUID: "
            '[{"vm_uuid":"00000000-0000-4000-8000-000000000001",'
            '"device":"00000000-0000-4000-8000-000000000002"}]. '
            "Uses the existing Hosted On relationship. Blank retains guest evidence in the report."
        ),
    )
    esxi_new_interface_state = ChoiceVar(
        choices=(
            ("report-only", "Report only"),
            ("enabled", "Enabled"),
            ("disabled", "Disabled"),
        ),
        default="report-only",
        label="ESXi new interface administrative state",
        description=(
            "ESXi does not report NIC administrative state. Report only defers new interfaces. "
            "Enabled or Disabled explicitly supplies intent for newly created host interfaces; "
            "existing administrative state is preserved."
        ),
    )
    proxmox_port = IntegerVar(
        default=8006, min_value=1, max_value=65535, label="Proxmox HTTPS port"
    )
    expected_proxmox_node = TextVar(
        required=False,
        default="",
        label="Expected Proxmox node",
        description="Pin the API-local node name. It must match the Linux SSH hostname.",
    )
    expected_proxmox_host_uuid = TextVar(
        required=False,
        default="",
        label="Expected Proxmox host UUID",
        description=(
            "Explicit BIOS UUID binding for the selected host. Requires an exact DMI "
            "match; a missing chassis serial remains blank."
        ),
    )
    proxmox_ssh_host_key = TextVar(
        required=False,
        default="",
        label="Proxmox SSH host key SHA256",
        description=(
            "Pin the Linux host key as SHA256:base64. Blank uses worker known hosts. "
            "Proxmox always verifies the SSH host key."
        ),
    )
    proxmox_guest_mappings = TextVar(
        required=False,
        default="",
        label="Proxmox Hosted On guest mappings",
        description=(
            "JSON list selecting QEMU SMBIOS UUIDs and existing Device UUIDs: "
            '[{"vm_uuid":"00000000-0000-4000-8000-000000000001",'
            '"device":"00000000-0000-4000-8000-000000000002"}]. '
            "Blank retains QEMU/LXC guest observations in the report."
        ),
    )
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
            "9800 controller or WAP inputs discover the entire configured controller AP "
            "roster across sites, creating eligible APs and updating proven AP locations "
            "and running software. WAPs are never contacted directly. "
            "Verify Cisco IOS XE, PAN-OS, standalone ESXi or Proxmox identity and fill supported "
            "interfaces. "
            "ESXi and Proxmox can link explicitly selected existing NFV Devices through Hosted On; "
            "guest sizing, storage and virtual networking remain report-only evidence. "
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
            "wireless_controller",
            "wireless_source_policy",
            "wireless_policy",
            "wireless_max_aps",
            "dryrun",
            "use_ntc_defaults",
            "verify_tls",
            "restconf_port",
            "esxi_port",
            "expected_esxi_host_uuid",
            "esxi_new_interface_state",
            "esxi_guest_mappings",
            "proxmox_port",
            "expected_proxmox_node",
            "expected_proxmox_host_uuid",
            "proxmox_ssh_host_key",
            "proxmox_guest_mappings",
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
        device=None,
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
        esxi_port=443,
        expected_esxi_host_uuid="",
        esxi_new_interface_state="report-only",
        esxi_guest_mappings="",
        proxmox_port=8006,
        expected_proxmox_node="",
        expected_proxmox_host_uuid="",
        proxmox_ssh_host_key="",
        proxmox_guest_mappings="",
        wireless_controller="",
        wireless_source_policy="",
        wireless_policy="",
        wireless_max_aps=10000,
    ):
        device = Device.objects.get(pk=device.pk) if device is not None else None
        report = {
            "schema_version": 1,
            "job_version": JOB_VERSION,
            "device_id": str(device.pk) if device is not None else None,
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
            "Starting %s for %s.",
            "discovery preview" if dryrun else "discovery",
            device.name if device is not None else wireless_controller,
        )
        try:
            source = _controller_source(
                device,
                controller_id=wireless_controller or None,
                source_policy=wireless_source_policy or None,
            )
            if source is not None:
                self._run_wireless(
                    source,
                    report,
                    wireless_policy,
                    dryrun=dryrun,
                    verify_tls=verify_tls,
                    restconf_port=restconf_port,
                    secrets_group=secrets_group,
                    interface_status=interface_status,
                    software_version_status=software_version_status,
                    max_aps=wireless_max_aps,
                )
                return
            if device is None:
                raise ValueError("Select an existing Device or native 9800 Controller UUID")
            if wireless_policy or wireless_source_policy or wireless_controller:
                raise ValueError("9800 policies require a configured native wireless Controller")
            adapter = _adapter(device)
            if adapter in (esxi, proxmox):
                if any(
                    (
                        vlan_group is not None,
                        vlan_status is not None,
                        module_status is not None,
                        ipam_namespace is not None,
                        ipam_override_namespace is not None,
                        ipam_override_networks,
                        ipam_group_user_vrfs,
                        ipam_local_vrf_names != "Mgmt-vrf",
                        ipam_location is not None,
                        ipam_prefix_status is not None,
                        ipam_ip_address_status is not None,
                        ipam_override_rfc1918 is not True,
                        ipam_create_missing_prefixes is not True,
                    )
                ):
                    raise ValueError(
                        "Hypervisor host discovery does not support IPAM, VLAN or module writes"
                    )
                if type(verify_tls) is not bool:
                    raise ValueError("Verify HTTPS certificate must be true or false")
                if adapter is esxi:
                    if type(esxi_port) is not int or not 1 <= esxi_port <= 65535:
                        raise ValueError("ESXi HTTPS port must be an integer between 1 and 65535")
                    report.update(esxi_port=esxi_port)
                    for field in ("restconf_port", "ssh_port", "ssh_strict"):
                        report.pop(field, None)
                else:
                    report.pop("restconf_port", None)
            if adapter is proxmox:
                if type(proxmox_port) is not int or not 1 <= proxmox_port <= 65535:
                    raise ValueError("Proxmox HTTPS port must be an integer between 1 and 65535")
                if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
                    raise ValueError("Proxmox SSH port must be an integer between 1 and 65535")
                if ssh_strict is not True:
                    raise ValueError("Proxmox requires SSH host key verification")
                report.update(proxmox_port=proxmox_port, ssh_port=ssh_port, ssh_strict=True)
                report.pop("esxi_port", None)
            elif any(
                (
                    expected_proxmox_node,
                    expected_proxmox_host_uuid,
                    proxmox_ssh_host_key,
                    proxmox_guest_mappings,
                )
            ):
                raise ValueError("Proxmox identity and guest settings require a Proxmox platform")
            if adapter is proxmox:
                if not isinstance(expected_proxmox_node, str):
                    raise ValueError("Expected Proxmox node must be text")
                expected_proxmox_node = expected_proxmox_node.strip() or None
                if expected_proxmox_host_uuid:
                    expected_proxmox_host_uuid = proxmox.canonical_host_uuid(
                        expected_proxmox_host_uuid
                    )
                    if expected_proxmox_host_uuid is None:
                        raise ValueError("Expected Proxmox UUID must be a nonzero canonical UUID")
                else:
                    expected_proxmox_host_uuid = None
                report.update(
                    expected_proxmox_node=expected_proxmox_node,
                    expected_proxmox_host_uuid=expected_proxmox_host_uuid,
                )
            if esxi_new_interface_state not in ("report-only", "enabled", "disabled"):
                raise ValueError(
                    "ESXi new interface state must be report-only, enabled or disabled"
                )
            if adapter is not esxi and esxi_new_interface_state != "report-only":
                raise ValueError("ESXi new interface state is supported only for ESXi discovery")
            interface_enabled_policy = (
                {
                    "contract": "esxi-interface-policy-v1",
                    "new_enabled": esxi_new_interface_state == "enabled",
                }
                if adapter is esxi and esxi_new_interface_state != "report-only"
                else None
            )
            if expected_esxi_host_uuid is None or (
                isinstance(expected_esxi_host_uuid, str) and not expected_esxi_host_uuid.strip()
            ):
                expected_esxi_host_uuid = None
            else:
                if adapter is not esxi:
                    raise ValueError("Expected ESXi host UUID is supported only for ESXi discovery")
                expected_esxi_host_uuid = esxi.canonical_host_uuid(expected_esxi_host_uuid)
                if expected_esxi_host_uuid is None:
                    raise ValueError("Expected ESXi host UUID must be a nonzero canonical UUID")
            if adapter is not esxi and esxi_guest_mappings:
                raise ValueError(
                    "ESXi Hosted On guest mappings are supported only for ESXi discovery"
                )
            guest_policy = (
                normalize_esxi_guest_policy(
                    esxi_guest_mappings,
                    _resolve_esxi_guest_target,
                    selected_device_id=str(device.pk),
                )
                if adapter is esxi
                else None
            )
            if adapter is proxmox:
                guest_policy = normalize_proxmox_guest_policy(
                    proxmox_guest_mappings,
                    _resolve_proxmox_guest_target,
                    selected_device_id=str(device.pk),
                )
                report["proxmox_guest_policy"] = guest_policy
            report["expected_esxi_host_uuid"] = expected_esxi_host_uuid
            if adapter is esxi:
                report["esxi_guest_policy"] = guest_policy
                report["esxi_new_interface_state"] = esxi_new_interface_state
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
                if (adapter is cisco_iosxe and ipam_namespace is not None)
                or panos_policy is not None
                or management_policy is not None
                else (None, None)
            )
            ipam_policy = (
                panos_policy
                if adapter is panos
                else None
                if adapter in (esxi, proxmox)
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
            report["transport"] = (
                "ssh"
                if adapter is panos
                else "esxi-soap"
                if adapter is esxi
                else "proxmox-json-ssh"
                if adapter is proxmox
                else "restconf"
            )
            if use_ntc_defaults:
                self.logger.info(
                    "%s discovery retains strict evidence rules; the NTC defaults option "
                    "applies only to Cisco IOS XE."
                    % (
                        "PAN-OS"
                        if adapter is panos
                        else "Proxmox"
                        if adapter is proxmox
                        else "ESXi"
                    )
                    if adapter is not cisco_iosxe
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
            elif adapter is esxi:
                username, password = resolve_credentials(
                    device, override_group=secrets_group, transport="esxi"
                )
                client = EsxiClient(
                    _host(device), username, password, port=esxi_port, verify=verify_tls
                )
            elif adapter is proxmox:
                token_id, token_secret = resolve_credentials(
                    device, override_group=secrets_group, transport="proxmox"
                )
                ssh_username, ssh_password = resolve_credentials(
                    device, override_group=secrets_group, transport="proxmox_ssh"
                )
                client = ProxmoxClient(
                    _host(device),
                    token_id,
                    token_secret,
                    ssh_username,
                    ssh_password,
                    port=proxmox_port,
                    ssh_port=ssh_port,
                    verify=verify_tls,
                    host_key_sha256=proxmox_ssh_host_key or None,
                )
            else:
                username, password = resolve_credentials(device, override_group=secrets_group)
                client = RestconfClient(
                    _host(device), username, password, port=restconf_port, verify=verify_tls
                )
            try:
                collect_options = {
                    "use_ntc_defaults": use_ntc_defaults
                    if adapter not in (esxi, proxmox)
                    else False
                }
                if adapter is panos:
                    collect_options["expected_vm_uuid"] = expected_vm_uuid
                    collect_options["max_vpn_flow_details"] = max_vpn_flow_details
                elif adapter is esxi:
                    collect_options["expected_host_uuid"] = expected_esxi_host_uuid
                    collect_options["interface_enabled_policy"] = interface_enabled_policy
                elif adapter is proxmox:
                    collect_options["expected_node"] = expected_proxmox_node
                    collect_options["expected_host_uuid"] = expected_proxmox_host_uuid
                report["discovery"] = adapter.collect(client, **collect_options)
            finally:
                try:
                    client.close()
                finally:
                    report["requests"] = client.trace
            discovery = report["discovery"]
            if adapter in (esxi, proxmox):
                discovery["guest_policy"] = guest_policy
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
            if adapter in (esxi, proxmox):
                observations = discovery.get("observations", {})
                self.logger.info(
                    "Collected %s host interfaces, %s VM observations and %s datastore "
                    "observations from %s. Full network and storage evidence is available "
                    "under Advanced.",
                    len(discovery.get("interfaces", [])),
                    len(observations.get("guests", [])),
                    len(observations.get("datastores", observations.get("storage", []))),
                    device.name,
                )
            else:
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
                    EsxiError,
                    ProxmoxError,
                    proxmox.DiscoveryError,
                    esxi.DiscoveryError,
                    SshError,
                    CredentialsError,
                    cisco_iosxe.DiscoveryError,
                    cisco_9800.DiscoveryError,
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

    def _run_wireless(
        self,
        source,
        report,
        policy_value,
        *,
        dryrun,
        verify_tls,
        restconf_port,
        secrets_group,
        interface_status,
        software_version_status,
        max_aps,
    ):
        from .nautobot_wireless import (
            apply_wireless_discovery,
            resolve_wireless_target,
            snapshot_wireless_inventory,
            validate_wireless_plan,
        )
        from .reconcile_wireless import build_wireless_plan
        from .wireless_policy import normalize_wireless_policy

        if type(dryrun) is not bool:
            raise ValueError("Dry run must be true or false")
        if type(verify_tls) is not bool:
            raise ValueError("Verify HTTPS certificate must be true or false")
        if type(restconf_port) is not int or not 1 <= restconf_port <= 65535:
            raise ValueError("RESTCONF port must be between 1 and 65535")
        if type(max_aps) is not int or not 1 <= max_aps <= 10000:
            raise ValueError("9800 AP roster limit must be between 1 and 10000")
        policy = normalize_wireless_policy(
            policy_value, resolve_wireless_target, controller_id=source["controller_id"]
        )
        report.update(
            controller_id=source["controller_id"],
            transport="restconf",
            wireless_policy=policy,
            source_binding=source["source_snapshot"],
            wireless_max_aps=max_aps,
            max_response_bytes=32 * 1024 * 1024,
            field_validation="pending-controller-feedback",
        )
        self.logger.info(
            "Discovering the complete AP roster of controller %s, including other sites. "
            "The selected WAP, group and controller Location do not restrict the roster.",
            source["controller_id"],
        )
        username, password = resolve_credentials(
            source["credential_device"],
            override_group=secrets_group or source.get("secrets_group"),
        )
        client = RestconfClient(
            source["host"],
            username,
            password,
            port=source.get("port") or restconf_port,
            verify=verify_tls,
            max_response_bytes=32 * 1024 * 1024,
        )
        try:
            discovery = cisco_9800.collect(
                client,
                controller_id=source["controller_id"],
                source_policy=source["source_policy"],
                max_aps=max_aps,
            )
            discovery["source_binding"] = source["source_snapshot"]
            report["discovery"] = discovery
        finally:
            try:
                client.close()
            finally:
                report["requests"] = client.trace
        plan = build_wireless_plan(
            discovery, snapshot_wireless_inventory(discovery, policy), policy
        )
        report["plan"] = plan
        validate_wireless_plan(
            plan,
            interface_status=interface_status,
            software_version_status=software_version_status,
        )
        if not dryrun:

            def record_progress(progress):
                report["plan"] = progress
                report["batch_outcome"] = "incomplete"
                report["applied"] = bool(
                    progress["summary"].get("created") or progress["summary"].get("updated")
                )

            report["plan"] = apply_wireless_discovery(
                discovery,
                policy,
                interface_status=interface_status,
                software_version_status=software_version_status,
                progress_callback=record_progress,
            )
            report["applied"] = True
        report["batch_outcome"] = (
            "preview"
            if dryrun
            else "mixed"
            if report["plan"].get("partial")
            or any(row.get("outcome") in {"failed", "unresolved"} for row in report["plan"]["aps"])
            else "applied"
        )
        self._log_wireless_plan(report["plan"], dryrun=dryrun)
        self.logger.info(
            "Full-controller %s complete. Per-AP proposals, evidence and outcomes are "
            "available under Advanced and in the report download.",
            "preview" if dryrun else "discovery",
        )

    def _log_wireless_plan(self, plan, *, dryrun):
        summary = plan.get("summary", {})
        counters = (
            ("created", "AP Devices"),
            ("location_updates", "AP locations"),
            ("software_updates", "AP software assignments"),
            ("interface_creates", "AP interfaces"),
            ("interface_updates", "AP interfaces"),
        )
        for key, noun in counters:
            if summary.get(key):
                self.logger.info(
                    "%s %s %s.", "Would change" if dryrun else "Changed", summary[key], noun
                )
        unresolved = sum(bool(row.get("errors") or row.get("unresolved")) for row in plan["aps"])
        if unresolved:
            self.logger.warning(
                "%s AP candidates have unresolved proposals; independent eligible APs remain "
                "eligible. Review reasons under Advanced.",
                unresolved,
            )
        failed = sum(row.get("outcome") == "failed" for row in plan["aps"])
        if failed:
            self.logger.warning(
                "%s AP proposals failed; review per-AP reasons and %s outcomes.",
                failed,
                "preview" if dryrun else "mixed batch",
            )
        if not any(summary.get(key, 0) for key, _ in counters):
            self.logger.info("No eligible AP inventory changes are needed.")

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
            ("hosted_on_created", "link", "Linked", "Hosted On guest", "Hosted On guests"),
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
                "discovery_%s.json"
                % (report["device_id"] or report.get("controller_id", "source")),
                json.dumps(report, indent=2, sort_keys=True),
            )
        except Exception:
            self.logger.warning(
                "Could not attach the report download. Full discovery results are under Advanced."
            )
