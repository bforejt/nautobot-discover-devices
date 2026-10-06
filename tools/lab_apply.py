"""Validate an authorized PAN-OS lab preview, apply and repeat through the real Job.

Run in a configured Nautobot Django process via runpy. Select the existing lab
Device, expected VM UUID and expected interface names explicitly. Normal Secrets
Group lookup supplies credentials. An optional literal endpoint override applies
only to this process. Reports are captured locally without FileProxy writes.
The first apply persists inventory; an unexpected preservation change rolls its
transaction back. The repeat must issue zero inventory DML.
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
    if not isinstance(value, str) or value.lower() not in ("true", "false"):
        raise ValueError("Lab Boolean options must be true or false")
    return value.lower() == "true"


def _uuid(value):
    try:
        parsed = UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Select an explicit valid expected PAN-OS VM UUID") from None
    if parsed.int in (0, (1 << 128) - 1):
        raise ValueError("Expected PAN-OS VM UUID cannot be a sentinel UUID")
    return str(parsed)


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _preserved_rows(before, after, allowed_fields):
    """Check native rows by UUID, including every populated value and relationship."""
    after_by_id = {str(row["id"]): row for row in after}
    for original in before:
        key = str(original["id"])
        if key not in after_by_id:
            raise AssertionError("Lab apply removed an existing native inventory row")
        current = after_by_id[key]
        changed_fields = allowed_fields.get(key, set())
        for field, value in original.items():
            if field in changed_fields:
                if not _blank(value) and current[field] != value:
                    raise AssertionError("Lab apply changed a populated native field: %s" % field)
                continue
            if field == "last_updated" and changed_fields:
                continue
            if current[field] != value:
                raise AssertionError("Lab apply changed preserved native field: %s" % field)


def _relation_rows(relation, interface_model, interface_ids):
    fields = [
        field.name
        for field in relation._meta.fields
        if field.is_relation and field.related_model is interface_model
    ]
    if len(fields) != 1:
        raise AssertionError("Native interface assignment relation is not unambiguous")
    return list(
        relation.objects.filter(**{fields[0] + "_id__in": interface_ids}).order_by("pk").values()
    )


def run(
    device_id=None,
    expected_vm_uuid=None,
    expected_interface_names=None,
    endpoint_host=None,
    ssh_strict=None,
    report_directory=None,
):
    """Persist a reviewed lab apply and prove preservation plus zero-DML repeat."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Cable, Device, Interface
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import CustomField

    from jobs.discovery_job import DiscoverDevice, _adapter
    from jobs.nautobot_inventory import snapshot_inventory

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not device_id:
        raise ValueError("Select the existing lab Device explicitly")
    device_id = _uuid(device_id)
    expected_vm_uuid = _uuid(
        expected_vm_uuid or os.environ.get("NAUTOBOT_DISCOVERY_EXPECTED_VM_UUID")
    )
    if expected_interface_names is None:
        encoded = os.environ.get("NAUTOBOT_DISCOVERY_EXPECTED_INTERFACE_NAMES")
        if encoded:
            try:
                expected_interface_names = json.loads(encoded)
            except json.JSONDecodeError:
                raise ValueError("Expected lab interface names must be a JSON list") from None
    if (
        not isinstance(expected_interface_names, (list, tuple))
        or not expected_interface_names
        or any(not isinstance(name, str) or not name.strip() for name in expected_interface_names)
        or len(set(expected_interface_names)) != len(expected_interface_names)
    ):
        raise ValueError("Select distinct explicit expected lab interface names")
    expected_interface_names = set(expected_interface_names)
    endpoint_host = endpoint_host or os.environ.get("NAUTOBOT_DISCOVERY_ENDPOINT_HOST")
    if endpoint_host:
        endpoint_host = str(ip_address(endpoint_host))
    if ssh_strict is None:
        ssh_strict = _boolean(os.environ.get("NAUTOBOT_DISCOVERY_SSH_STRICT", "true"))
    if type(ssh_strict) is not bool:
        raise ValueError("SSH host-key checking must be a Boolean")
    report_directory = report_directory or os.environ.get("NAUTOBOT_DISCOVERY_REPORT_DIRECTORY")

    def selected():
        return Device.objects.get(pk=device_id)

    device = selected()
    if _adapter(device).__name__.rsplit(".", 1)[-1] != "panos":
        raise ValueError("The lab apply helper requires the selected PAN-OS Device")
    if not _blank(device.serial):
        raise ValueError("Explicit VM UUID lab binding requires a blank selected Device serial")
    original_interfaces = (
        device.all_interfaces if hasattr(device, "all_interfaces") else device.interfaces
    )
    original_interface_ids = list(original_interfaces.values_list("pk", flat=True))
    original_custom_fields = CustomField.objects.count()

    def native_snapshot():
        target = selected()
        interfaces = (
            target.all_interfaces if hasattr(target, "all_interfaces") else target.interfaces
        )
        cable_terms = list(
            CableToCableTermination.objects.filter(interface_id__in=original_interface_ids)
            .order_by("pk")
            .values()
        )
        cable_ids = {row["cable_id"] for row in cable_terms}
        return {
            "device": [Device.objects.filter(pk=target.pk).values().get()],
            "interfaces": list(interfaces.order_by("pk").values()),
            "cable_terminations": cable_terms,
            "cables": list(Cable.objects.filter(pk__in=cable_ids).order_by("pk").values()),
            "ip_assignments": _relation_rows(
                Interface.ip_addresses.through, Interface, original_interface_ids
            ),
            "tagged_vlan_assignments": _relation_rows(
                Interface.tagged_vlans.through, Interface, original_interface_ids
            ),
        }

    original_native = native_snapshot()
    original_inventory = snapshot_inventory(device)
    phase_files = []
    approved_device_fields = set()
    approved_interface_fields = {}

    class LabJob(DiscoverDevice):
        def __init__(self):
            super().__init__()
            self.logger = logging.getLogger("nautobot_discovery.lab_apply")
            self.request = SimpleNamespace(meta={})

        def create_file(self, filename, data):
            phase_files.append((filename, data))

    def run_phase(phase, *, dryrun):
        phase_files.clear()
        job = LabJob()
        before = snapshot_inventory(selected())
        transport_host = (
            patch("jobs.discovery_job._host", return_value=endpoint_host)
            if endpoint_host
            else nullcontext()
        )
        with transaction.atomic(), transport_host:
            with CaptureQueriesContext(connection) as captured:
                result = job.run(
                    device=selected(),
                    dryrun=dryrun,
                    ssh_strict=ssh_strict,
                    use_ntc_defaults=False,
                    expected_vm_uuid=expected_vm_uuid,
                )
            if result is not None:
                raise AssertionError("Detailed lab evidence appeared in the main Job result")
            report = job.request.meta["discovery_report"]
            if report["plan"]["errors"] or report["plan"]["summary"]["blocked"]:
                raise AssertionError("The reviewed PAN-OS lab plan is blocked")
            if report["dry_run"] is not dryrun or report["applied"] is dryrun:
                raise AssertionError("The lab Job reported an inconsistent apply state")
            if len(phase_files) != 1 or json.loads(phase_files[0][1]) != report:
                raise AssertionError("Lab report attachment and Advanced evidence differ")
            observed = {row["name"] for row in report["discovery"]["interfaces"]}
            if not expected_interface_names.issubset(observed):
                raise AssertionError("Live discovery omitted an expected lab interface")
            writes = sum(
                WRITE_SQL.match(row["sql"]) is not None for row in captured.captured_queries
            )
            after = snapshot_inventory(selected())
            if dryrun or phase == "repeat":
                if writes or after != before:
                    raise AssertionError("Preview or repeated apply changed native inventory")
            if not dryrun:
                native = native_snapshot()
                allowed_interface = {
                    str(row["id"]): {change["field"] for change in row["changes"]}
                    for row in report["plan"]["interface_updates"]
                }
                device_fields = {
                    change["field"] + ("_id" if change["field"] == "software_version" else "")
                    for change in report["plan"]["device_updates"]
                }
                approved_device_fields.update(device_fields)
                for key, fields in allowed_interface.items():
                    approved_interface_fields.setdefault(key, set()).update(fields)
                _preserved_rows(
                    original_native["device"], native["device"], {device_id: approved_device_fields}
                )
                _preserved_rows(
                    original_native["interfaces"], native["interfaces"], approved_interface_fields
                )
                for relation in (
                    "cable_terminations",
                    "cables",
                    "ip_assignments",
                    "tagged_vlan_assignments",
                ):
                    if native[relation] != original_native[relation]:
                        raise AssertionError("Lab apply changed preserved %s" % relation)
                if CustomField.objects.count() != original_custom_fields:
                    raise AssertionError("Lab apply changed the custom-field catalog")
                if not _blank(selected().serial):
                    raise AssertionError("VM UUID identity was written into the chassis serial")
        if report_directory:
            directory = Path(report_directory)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / ("panos-" + phase + ".json")).write_text(
                phase_files[0][1] + "\n", encoding="utf-8"
            )
        return {
            "dry_run": dryrun,
            "applied": report["applied"],
            "inventory_dml": writes,
            "summary": report["plan"]["summary"],
            "observed_interfaces": sorted(observed),
            "identity": report["discovery"]["identity"],
            "identity_binding": report["discovery"].get("identity_binding"),
        }

    preview = run_phase("preview", dryrun=True)
    if snapshot_inventory(selected()) != original_inventory:
        raise AssertionError("Live preview did not preserve the baseline inventory")
    apply = run_phase("apply", dryrun=False)
    after_apply = snapshot_inventory(selected())
    repeat = run_phase("repeat", dryrun=False)
    if snapshot_inventory(selected()) != after_apply:
        raise AssertionError("Fresh repeated discovery did not preserve the applied inventory")
    return {
        "device_id": device_id,
        "expected_vm_uuid": expected_vm_uuid,
        "endpoint_host": endpoint_host,
        "use_ntc_defaults": False,
        "preview": preview,
        "apply": apply,
        "repeat": repeat,
        "existing_rows_and_relationships_preserved": True,
        "serial_preserved_blank": True,
        "report_directory": str(report_directory) if report_directory else None,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
