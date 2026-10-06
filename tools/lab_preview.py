"""Run live read-only discovery through the actual Job without saving inventory.

Execute in the lab Nautobot Django environment with ``runpy.run_path``. Job
reports are captured in memory; optional ``NAUTOBOT_DISCOVERY_REPORT_PATH``
saves the complete JSON report to a local file rather than a FileProxy row.
Select a Device explicitly with ``NAUTOBOT_DISCOVERY_DEVICE_ID`` or ``device_id``.
Optional ``NAUTOBOT_DISCOVERY_EXPECTED_ADAPTER`` verifies platform dispatch
before opening a device connection. An explicit ``endpoint_host`` or
``NAUTOBOT_DISCOVERY_ENDPOINT_HOST`` selects a literal IP only for this process
when native primary-IP validation requires an unobserved Interface. Credentials
are resolved by the normal
Device Secrets Group code and are never printed. An optional explicit
``expected_vm_uuid`` or ``NAUTOBOT_DISCOVERY_EXPECTED_VM_UUID`` enables the
reviewed PA-VM KVM identity binding without inventing a serial. The default verifies TLS; set
``NAUTOBOT_DISCOVERY_VERIFY_TLS=false`` for a lab self-signed certificate.
"""

import json
import logging
import os
import re
import sys
from contextlib import nullcontext
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _boolean(value):
    if value.lower() not in ("true", "false"):
        raise ValueError("Preview Boolean options must be true or false")
    return value.lower() == "true"


def run(
    device_id=None,
    verify_tls=None,
    report_path=None,
    vlan_group_id=None,
    use_ntc_defaults=None,
    ipam_namespace_id=None,
    ipam_override_namespace_id=None,
    ipam_override_rfc1918=True,
    ipam_override_networks="",
    ipam_group_user_vrfs=False,
    ipam_local_vrf_names="Mgmt-vrf",
    expected_adapter=None,
    ssh_strict=None,
    allow_blocked=None,
    endpoint_host=None,
    expected_vm_uuid=None,
):
    """Collect structured live data and verify a zero-write Job preview."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device
    from nautobot.ipam.models import Namespace, VLANGroup

    from jobs.discovery_job import DiscoverDevice, _adapter
    from jobs.nautobot_inventory import snapshot_inventory

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not device_id:
        raise ValueError("Select the lab Device explicitly with NAUTOBOT_DISCOVERY_DEVICE_ID")
    if verify_tls is None:
        verify_tls = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_VERIFY_TLS", "true"))
    report_path = report_path or os.environ.get("NAUTOBOT_DISCOVERY_REPORT_PATH")
    if use_ntc_defaults is None:
        use_ntc_defaults = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_USE_NTC_DEFAULTS", "false"))
    if ssh_strict is None:
        ssh_strict = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_SSH_STRICT", "true"))
    if allow_blocked is None:
        allow_blocked = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_ALLOW_BLOCKED", "false"))
    endpoint_host = endpoint_host or os.environ.get("NAUTOBOT_DISCOVERY_ENDPOINT_HOST")
    if endpoint_host:
        endpoint_host = str(ip_address(endpoint_host))
    expected_vm_uuid = expected_vm_uuid or os.environ.get("NAUTOBOT_DISCOVERY_EXPECTED_VM_UUID")
    if expected_vm_uuid:
        parsed_uuid = UUID(str(expected_vm_uuid))
        if parsed_uuid.int in (0, (1 << 128) - 1):
            raise ValueError("Expected PAN-OS VM UUID cannot be a sentinel UUID")
        expected_vm_uuid = str(parsed_uuid)
    device = Device.objects.get(pk=device_id)
    expected_adapter = expected_adapter or os.environ.get("NAUTOBOT_DISCOVERY_EXPECTED_ADAPTER")
    adapter_name = _adapter(device).__name__.rsplit(".", 1)[-1]
    if expected_adapter and adapter_name != expected_adapter:
        raise ValueError("Selected Device uses %s; expected %s" % (adapter_name, expected_adapter))
    vlan_group_id = vlan_group_id or os.environ.get("NAUTOBOT_DISCOVERY_VLAN_GROUP_ID")
    vlan_group = VLANGroup.objects.get(pk=vlan_group_id) if vlan_group_id else None
    ipam_namespace_id = ipam_namespace_id or os.environ.get("NAUTOBOT_DISCOVERY_IPAM_NAMESPACE_ID")
    ipam_namespace = Namespace.objects.get(pk=ipam_namespace_id) if ipam_namespace_id else None
    ipam_override_namespace = (
        Namespace.objects.get(pk=ipam_override_namespace_id) if ipam_override_namespace_id else None
    )
    baseline = snapshot_inventory(device, vlan_group=vlan_group)
    captured_files = []

    class PreviewJob(DiscoverDevice):
        def __init__(self):
            super().__init__()
            self.logger = logging.getLogger("nautobot_discovery.lab_preview")
            self.request = SimpleNamespace(meta={})

        def create_file(self, filename, data):
            captured_files.append((filename, data))

    transport_host = (
        patch("jobs.discovery_job._host", return_value=endpoint_host)
        if endpoint_host
        else nullcontext()
    )
    with transaction.atomic(), transport_host:
        try:
            with CaptureQueriesContext(connection) as captured:
                job = PreviewJob()
                result = None
                try:
                    result = job.run(
                        device=device,
                        dryrun=True,
                        verify_tls=verify_tls,
                        ssh_strict=ssh_strict,
                        vlan_group=vlan_group,
                        use_ntc_defaults=use_ntc_defaults,
                        ipam_namespace=ipam_namespace,
                        ipam_override_namespace=ipam_override_namespace,
                        ipam_override_rfc1918=ipam_override_rfc1918,
                        ipam_override_networks=ipam_override_networks,
                        ipam_group_user_vrfs=ipam_group_user_vrfs,
                        ipam_local_vrf_names=ipam_local_vrf_names,
                        expected_vm_uuid=expected_vm_uuid,
                    )
                except RuntimeError:
                    failure_report = job.request.meta.get("discovery_report", {})
                    if not allow_blocked or not failure_report.get("plan", {}).get("errors"):
                        raise
                    assert not failure_report["applied"]
            assert result is None, "Detailed discovery data must not appear in the main result"
            report = job.request.meta["discovery_report"]
            writes = [query for query in captured.captured_queries if WRITE_SQL.match(query["sql"])]
            assert not writes, "Job preview issued %d database mutation statements" % len(writes)
            assert report["dry_run"] and not report["applied"]
            assert len(captured_files) == 1, "Job preview did not produce exactly one report"
            assert json.loads(captured_files[0][1]) == report, (
                "Captured report differs from Advanced discovery data"
            )
            assert (
                snapshot_inventory(Device.objects.get(pk=device.pk), vlan_group=vlan_group)
                == baseline
            )
        finally:
            transaction.set_rollback(True)

    assert snapshot_inventory(Device.objects.get(pk=device.pk), vlan_group=vlan_group) == baseline
    if report_path:
        Path(report_path).write_text(captured_files[0][1] + "\n", encoding="utf-8")
    return {
        "device_id": str(device.pk),
        "adapter": adapter_name,
        "endpoint_host": endpoint_host,
        "expected_vm_uuid": expected_vm_uuid,
        "dry_run": True,
        "use_ntc_defaults": use_ntc_defaults,
        "applied": False,
        "blocked": bool(report["plan"]["errors"]),
        "database_write_statements": 0,
        "identity": report["discovery"]["identity"],
        "observations": report["discovery"].get("observations", {}),
        "sources": report["discovery"].get("sources", {}),
        "stack": report["discovery"].get("stack", {}),
        "stack_plan": report["plan"].get("stack", {}),
        "summary": report["plan"]["summary"],
        "lag_memberships": report["discovery"].get("lag_memberships", []),
        "components": report["discovery"].get("components", {}),
        "component_plan": report["plan"].get("components", {}),
        "console_ports": report["discovery"].get("console_ports", {}),
        "console_port_plan": report["plan"].get("console_ports", {}),
        "management": report["discovery"].get("management", {}),
        "ipam": report["discovery"].get("ipam", {}),
        "ipam_policy": report.get("ipam_policy"),
        "ipam_plan": report["plan"].get("ipam", {}),
        "layer2": report["discovery"].get("layer2", {}),
        "layer2_plan": report["plan"].get("layer2", {}),
        "required_identity_errors": report["plan"]["errors"],
        "interface_creates_by_type": {
            interface_type: sum(
                row["type"] == interface_type for row in report["plan"]["interface_creates"]
            )
            for interface_type in sorted(
                {row["type"] for row in report["plan"]["interface_creates"]}
            )
        },
        "excluded_interfaces": report["plan"]["excluded_interfaces"],
        "warnings": report["plan"]["warnings"],
        "requests": report.get("requests", []),
        "report_path": report_path,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
