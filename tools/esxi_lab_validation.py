"""Verify the real standalone ESXi Job inside an unconditional lab rollback.

Run in configured Nautobot with explicitly supplied anchor, endpoint, credentials,
expected BIOS UUID and an already collected transport capture. Credentials stay
in temporary process environment; no password is stored in a Secret or report.
This is a lab harness, not a production discovery path or a provisioning Job.
"""

import json
import os
import re
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def run(
    *, anchor_device_id, host, username, password, expected_host_uuid, source_path, report_path=None
):
    """Exercise normal Secrets resolution, actual HTTPS collection and native apply."""
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Interface,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.extras.choices import (
        SecretsGroupAccessTypeChoices,
        SecretsGroupSecretTypeChoices,
    )
    from nautobot.extras.models import (
        Relationship,
        RelationshipAssociation,
        Secret,
        SecretsGroup,
        SecretsGroupAssociation,
    )

    from jobs.adapters import esxi
    from jobs.discovery_job import JOB_VERSION
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory
    from tools.lab_preview import run as preview

    models = (
        Device,
        DeviceType,
        Interface,
        Manufacturer,
        Platform,
        SoftwareVersion,
        Relationship,
        RelationshipAssociation,
        Secret,
        SecretsGroup,
        SecretsGroupAssociation,
    )
    before_counts = {model._meta.label: model.objects.count() for model in models}
    anchor = Device.objects.get(pk=anchor_device_id)
    raw = json.loads(Path(source_path).read_text())
    if raw.get("adapter") == "esxi":
        raw = raw["source"]["inventory"]
    source = esxi.collect(
        SimpleNamespace(discovery=lambda: raw), expected_host_uuid=expected_host_uuid
    )
    identity = source["identity"]
    token = uuid4().hex[:12]
    variables = {"ESXI_LAB_USER_" + token: username, "ESXI_LAB_PASSWORD_" + token: password}
    previous = {key: os.environ.get(key) for key in variables}
    os.environ.update(variables)
    result = None
    try:
        with transaction.atomic():
            try:
                manufacturer, _ = Manufacturer.objects.get_or_create(name=identity["vendor"])
                device_type, _ = DeviceType.objects.get_or_create(
                    manufacturer=manufacturer, model=identity["model"]
                )
                platform, _ = Platform.objects.get_or_create(
                    name="ESXi", defaults={"network_driver": "esxi"}
                )
                if platform.network_driver not in ("esxi", "vmware_esxi", ""):
                    raise ValueError("Existing ESXi Platform has an incompatible driver")
                group = SecretsGroup(name="esxi-live-validation-" + token)
                group.validated_save()
                for index, secret_type in enumerate(
                    (
                        SecretsGroupSecretTypeChoices.TYPE_USERNAME,
                        SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
                    )
                ):
                    secret = Secret(
                        name="esxi-live-validation-" + token + str(index),
                        provider="environment-variable",
                        parameters={"variable": list(variables)[index]},
                    )
                    secret.validated_save()
                    association = SecretsGroupAssociation(
                        secrets_group=group,
                        secret=secret,
                        access_type=SecretsGroupAccessTypeChoices.TYPE_HTTP,
                        secret_type=secret_type,
                    )
                    association.validated_save()
                device = Device(
                    name="esxi-live-validation-" + token,
                    device_type=device_type,
                    platform=platform,
                    location=anchor.location,
                    role=anchor.role,
                    status=anchor.status,
                    secrets_group=group,
                    serial="",
                )
                device.validated_save()
                preview_path = Path("/tmp/esxi-live-preview-" + token + ".json")
                brief = preview(
                    device_id=str(device.pk),
                    verify_tls=False,
                    expected_adapter="esxi",
                    endpoint_host=host,
                    expected_esxi_host_uuid=expected_host_uuid,
                    esxi_new_interface_state="enabled",
                    report_path=str(preview_path),
                )
                preview_path.chmod(0o600)
                initial = json.loads(preview_path.read_text())
                preview_path.unlink()
                if brief["database_write_statements"] != 0:
                    raise AssertionError("Live Job preview issued database writes")
                if initial["job_version"] != JOB_VERSION or initial["plan"]["errors"]:
                    raise AssertionError("Live ESXi Job preview did not validate")
                if password in json.dumps(initial):
                    raise AssertionError("Credential value entered the live report")
                applied = apply_discovery(initial["discovery"], device)
                device.refresh_from_db()
                with CaptureQueriesContext(connection) as captured:
                    repeated = apply_discovery(initial["discovery"], device)
                if any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries):
                    raise AssertionError("Unchanged live ESXi apply issued database writes")
                snapshot = snapshot_inventory(device, discovery=initial["discovery"])
                result = {
                    "passed": True,
                    "persistent_changes": 0,
                    "job_version": initial["job_version"],
                    "endpoint": host,
                    "host_uuid": identity["host_uuid"],
                    "software_version": snapshot["device"]["software_version"],
                    "interfaces": [row["name"] for row in snapshot["interfaces"]],
                    "visible_guests": len(initial["discovery"]["observations"]["guests"]),
                    "preview_inventory_dml": 0,
                    "repeat_inventory_dml": 0,
                    "apply_summary": applied["summary"],
                    "repeat_summary": repeated["summary"],
                    "requests": initial["requests"],
                }
                if report_path:
                    p = Path(report_path)
                    p.write_text(json.dumps({"proof": result, "report": initial}, indent=2))
                    p.chmod(0o600)
            finally:
                transaction.set_rollback(True)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    if before_counts != {model._meta.label: model.objects.count() for model in models}:
        raise AssertionError("Live lab validation left persistent inventory or Secret records")
    return result
