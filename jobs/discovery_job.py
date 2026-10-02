"""Discover and enrich an existing device using structured device facts."""

import json

from nautobot.apps.jobs import BooleanVar, DryRunVar, IntegerVar, Job, ObjectVar
from nautobot.dcim.models import Device
from nautobot.extras.models import SecretsGroup, Status
from nautobot.ipam.models import VLANGroup

from .adapters import cisco_iosxe
from .credentials import CredentialsError, resolve_credentials
from .nautobot_inventory import InventoryError, apply_discovery, snapshot_inventory, validate_plan
from .reconcile import build_plan
from .transport_restconf import RestconfClient, RestconfError

name = "Device Discovery"
JOB_VERSION = "0.11.1-dev"


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


class DiscoverDevice(Job):
    device = ObjectVar(model=Device, description="Existing Device to verify and enrich.")
    dryrun = DryRunVar(description="Preview changes without updating device inventory.")
    use_ntc_defaults = BooleanVar(
        label="Use NTC defaults when guessing",
        default=False,
        description=(
            "Disabled: leave uncertain values blank. Enabled: use the reviewed Network to Code "
            "Device Onboarding fallback for down dynamic switchports that allow all VLANs: "
            "Tagged all and their known native VLAN. Guessed values are identified in the report; "
            "other unresolved data stays blank. Existing populated values are preserved."
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

    class Meta:
        name = "Discover Device"
        description = (
            "Verify Cisco IOS XE identity and fill interfaces, console ports, VLANs, "
            "and serialized hardware."
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
            if (management.get("interfaces") or management.get("observations")) and management.get(
                "writes_deferred_reason"
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
                snapshot_inventory(device, discovery=report["discovery"], vlan_group=vlan_group),
            )
            plan = report["plan"]
            validate_plan(
                plan,
                device,
                interface_status=interface_status,
                software_version_status=software_version_status,
                module_status=module_status,
                vlan_status=vlan_status,
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
            remaining = summary["unresolved_components"] - missing_identity
            if remaining:
                self.logger.warning(
                    "Left %s hardware %s unresolved because identity or placement "
                    "could not be established safely. Existing hardware was preserved; "
                    "review the details under Advanced.",
                    remaining,
                    "observation" if remaining == 1 else "observations",
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
