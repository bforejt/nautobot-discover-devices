"""Discover and enrich an existing device using structured device facts."""

import json

from nautobot.apps.jobs import BooleanVar, DryRunVar, IntegerVar, Job, ObjectVar, TextVar
from nautobot.dcim.models import Device, Location
from nautobot.extras.models import SecretsGroup, Status
from nautobot.ipam.models import Namespace, VLANGroup

from .adapters import cisco_iosxe
from .credentials import CredentialsError, resolve_credentials
from .ipam_policy import normalize_ipam_policy
from .nautobot_inventory import InventoryError, apply_discovery, snapshot_inventory, validate_plan
from .reconcile import build_plan
from .transport_restconf import RestconfClient, RestconfError

name = "Device Discovery"
JOB_VERSION = "0.14.0-dev"


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


def _adapter(device):
    platform = device.platform
    driver = str(getattr(platform, "network_driver", "") or "").lower()
    platform_name = str(getattr(platform, "name", "") or "").lower()
    if driver not in ("cisco_ios", "cisco_iosxe") and "iosxe" not in platform_name.replace(
        "-", ""
    ).replace("_", ""):
        raise ValueError("The selected Device must have a Cisco IOS XE platform")
    manufacturer = device.device_type.manufacturer.name.lower()
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
            "Select an existing Namespace to enable static IPv4 and named VRF discovery. "
            "Unmatched addresses use this Namespace. Leave blank for report-only IPAM."
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
            "and 192.168.0.0/16 there. Additional networks are combined with these ranges."
        ),
    )
    ipam_override_networks = TextVar(
        required=False,
        default="",
        label="Additional override networks",
        description="IPv4 network CIDRs, one per line. Requires an override Namespace.",
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
            "Verify Cisco IOS XE identity and fill interfaces, console ports, VLANs, "
            "serialized hardware, static IPv4 addressing and named VRFs."
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
            "secrets_group",
            "interface_status",
            "software_version_status",
            "module_status",
            "vlan_group",
            "vlan_status",
            "ipam_namespace",
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
            "applied": False,
            "vlan_group_id": str(vlan_group.pk) if vlan_group else None,
            "vlan_group_name": vlan_group.name if vlan_group else None,
        }
        self.logger.info(
            "Starting %s for %s.", "discovery preview" if dryrun else "discovery", device.name
        )
        try:
            location, location_reason = (
                _prefix_location(device, ipam_location)
                if ipam_namespace is not None
                else (None, None)
            )
            ipam_policy = normalize_ipam_policy(
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
            report["ipam_policy"] = ipam_policy
            if type(use_ntc_defaults) is not bool:
                raise ValueError("Use NTC defaults when guessing must be true or false")
            if use_ntc_defaults:
                self.logger.info(
                    "NTC default guessing is enabled. Any inferred assignments are identified "
                    "as guesses in the discovery report."
                )
            adapter = _adapter(device)
            username, password = resolve_credentials(device, override_group=secrets_group)
            client = RestconfClient(
                _host(device), username, password, port=restconf_port, verify=verify_tls
            )
            try:
                report["discovery"] = adapter.collect(client, use_ntc_defaults=use_ntc_defaults)
            finally:
                client.close()
                report["requests"] = client.trace
            discovery = report["discovery"]
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
                exc, (RestconfError, CredentialsError, cisco_iosxe.DiscoveryError, InventoryError)
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
        if ipam.get("unresolved"):
            self.logger.info(
                "Left %s IPAM observations unresolved. The report explains missing evidence, "
                "Namespace policy and routing conflicts; existing IPAM is preserved.",
                len(ipam["unresolved"]),
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
