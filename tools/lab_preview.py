"""Run live GET-only discovery through the actual Job without saving inventory.

Execute in the lab Nautobot Django environment with ``runpy.run_path``. Job
reports are captured in memory; optional ``NAUTOBOT_DISCOVERY_REPORT_PATH``
saves the complete JSON report to a local file rather than a FileProxy row.
Credentials are resolved by the normal Device Secrets Group code and are
never printed. The default verifies TLS; explicitly set
``NAUTOBOT_DISCOVERY_VERIFY_TLS=false`` for a lab self-signed certificate.
"""

import json
import logging
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

DEFAULT_DEVICE_ID = "eb46c008-e579-4207-8def-f9b6dfbdc525"
WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _boolean(value):
    if value.lower() not in ("true", "false"):
        raise ValueError("NAUTOBOT_DISCOVERY_VERIFY_TLS must be true or false")
    return value.lower() == "true"


def run(
    device_id=None, verify_tls=None, report_path=None, vlan_group_id=None, use_ntc_defaults=None
):
    """Collect live JSON and validate the Job preview without database mutation."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device
    from nautobot.ipam.models import VLANGroup

    from jobs.discovery_job import DiscoverDevice
    from jobs.nautobot_inventory import snapshot_inventory

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID", DEFAULT_DEVICE_ID)
    if verify_tls is None:
        verify_tls = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_VERIFY_TLS", "true"))
    report_path = report_path or os.environ.get("NAUTOBOT_DISCOVERY_REPORT_PATH")
    if use_ntc_defaults is None:
        use_ntc_defaults = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_USE_NTC_DEFAULTS", "false"))
    device = Device.objects.get(pk=device_id)
    vlan_group_id = vlan_group_id or os.environ.get("NAUTOBOT_DISCOVERY_VLAN_GROUP_ID")
    vlan_group = VLANGroup.objects.get(pk=vlan_group_id) if vlan_group_id else None
    baseline = snapshot_inventory(device, vlan_group=vlan_group)
    captured_files = []

    class PreviewJob(DiscoverDevice):
        def __init__(self):
            super().__init__()
            self.logger = logging.getLogger("nautobot_discovery.lab_preview")
            self.request = SimpleNamespace(meta={})

        def create_file(self, filename, data):
            captured_files.append((filename, data))

    with transaction.atomic():
        try:
            with CaptureQueriesContext(connection) as captured:
                job = PreviewJob()
                result = job.run(
                    device=device,
                    dryrun=True,
                    verify_tls=verify_tls,
                    vlan_group=vlan_group,
                    use_ntc_defaults=use_ntc_defaults,
                )
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
        "dry_run": True,
        "use_ntc_defaults": use_ntc_defaults,
        "applied": False,
        "database_write_statements": 0,
        "identity": report["discovery"]["identity"],
        "summary": report["plan"]["summary"],
        "lag_memberships": report["discovery"].get("lag_memberships", []),
        "components": report["discovery"].get("components", {}),
        "component_plan": report["plan"].get("components", {}),
        "console_ports": report["discovery"].get("console_ports", {}),
        "console_port_plan": report["plan"].get("console_ports", {}),
        "management": report["discovery"].get("management", {}),
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
