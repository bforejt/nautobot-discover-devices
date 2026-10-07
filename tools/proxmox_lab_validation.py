"""Run actual Proxmox collection and the normal Job inside a native lab rollback.

The anchor only supplies existing role, location and status. Temporary Devices,
catalogs and HTTP/SSH environment-variable Secret references are rolled back;
API token and Linux password values never enter Secret records or reports.
No Proxmox host configuration changes are made by this harness.

In configured Nautobot, call ``run()`` with explicit function arguments, or set
NAUTOBOT_DISCOVERY_DEVICE_ID and NAUTOBOT_PROXMOX_HOST, TOKEN_ID, TOKEN_SECRET,
SSH_USERNAME, SSH_PASSWORD and NODE (each with the NAUTOBOT_PROXMOX_ prefix).
Optional EXPECTED_HOST_UUID, HOST_KEY_SHA256, SOURCE_PATH and REPORT_PATH share
that prefix. VERIFY_TLS defaults to true; false is an explicit lab exception.
Keep credentials out of shell command arguments and captured terminal output.
"""

import copy
import json
import os
import re
import tempfile
from pathlib import Path
from uuid import uuid4

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _assert_credentials_absent(payload, token_id, token_secret, ssh_username, ssh_password):
    serialized = json.dumps(payload, ensure_ascii=True, allow_nan=False)
    if any(value in serialized for value in (token_id, token_secret, ssh_password)):
        raise AssertionError("Credential data entered a Proxmox validation artifact")
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
        elif isinstance(value, str):
            if value == ssh_username or any(
                secret in value for secret in (token_id, token_secret, ssh_password)
            ):
                raise AssertionError("Credential data entered a Proxmox validation artifact")


def _write_private(path, payload):
    """Create private JSON, including when replacing an existing regular artifact."""
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(payload, stream, indent=2, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def run(
    *,
    anchor_device_id,
    host,
    token_id,
    token_secret,
    ssh_username,
    ssh_password,
    expected_node,
    expected_host_uuid=None,
    host_key_sha256=None,
    verify_tls=True,
    port=8006,
    source_path=None,
    report_path=None,
):
    """Collect live data, preview the real Job, apply/repeat, then roll back all DML."""
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

    from jobs.adapters import proxmox
    from jobs.discovery_job import JOB_VERSION
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory
    from jobs.transport_proxmox import ProxmoxClient
    from tools.lab_preview import run as preview

    if type(verify_tls) is not bool:
        raise ValueError("Lab Job TLS verification must be an explicit boolean")
    if not isinstance(expected_node, str) or not expected_node:
        raise ValueError("Select the expected Proxmox API-local node explicitly")
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
    anchor = Device.objects.select_related("location", "role", "status").get(pk=anchor_device_id)
    anchor_before = snapshot_inventory(anchor)
    anchor_custom = copy.deepcopy(anchor._custom_field_data)
    relationships_before = list(RelationshipAssociation.objects.order_by("pk").values())
    with ProxmoxClient(
        host,
        token_id,
        token_secret,
        ssh_username,
        ssh_password,
        port=port,
        verify=verify_tls,
        host_key_sha256=host_key_sha256,
    ) as client:
        source = proxmox.collect(
            client, expected_node=expected_node, expected_host_uuid=expected_host_uuid
        )
        source_trace = copy.deepcopy(client.trace)
    _assert_credentials_absent(source, token_id, token_secret, ssh_username, ssh_password)
    _assert_credentials_absent(source_trace, token_id, token_secret, ssh_username, ssh_password)
    identity = source["identity"]
    if not identity.get("vendor") or not identity.get("model"):
        raise AssertionError("Live host must supply corroborated manufacturer and model")
    if not identity.get("serial") and not expected_host_uuid:
        raise AssertionError("A host without chassis serial requires an explicit DMI UUID binding")
    if source_path:
        _write_private(source_path, source)
    token = uuid4().hex[:12]
    variables = {
        "PROXMOX_LAB_TOKEN_ID_" + token: token_id,
        "PROXMOX_LAB_TOKEN_SECRET_" + token: token_secret,
        "PROXMOX_LAB_SSH_USERNAME_" + token: ssh_username,
        "PROXMOX_LAB_SSH_PASSWORD_" + token: ssh_password,
    }
    previous = {key: os.environ.get(key) for key in variables}
    os.environ.update(variables)
    result = initial = None
    try:
        with transaction.atomic():
            try:
                manufacturer = Manufacturer.objects.filter(name=identity["vendor"]).first()
                if manufacturer is None:
                    manufacturer = Manufacturer(name=identity["vendor"])
                    manufacturer.validated_save()
                device_type = DeviceType.objects.filter(
                    manufacturer=manufacturer, model=identity["model"]
                ).first()
                if device_type is None:
                    device_type = DeviceType(manufacturer=manufacturer, model=identity["model"])
                    device_type.validated_save()
                platform = Platform(name="Proxmox live proof " + token, network_driver="proxmox")
                platform.validated_save()
                group = SecretsGroup(name="proxmox-live-validation-" + token)
                group.validated_save()
                username_type = SecretsGroupSecretTypeChoices.TYPE_USERNAME
                password_type = SecretsGroupSecretTypeChoices.TYPE_PASSWORD
                http_type = SecretsGroupAccessTypeChoices.TYPE_HTTP
                ssh_type = SecretsGroupAccessTypeChoices.TYPE_SSH
                specs = (
                    (http_type, username_type),
                    (http_type, password_type),
                    (ssh_type, username_type),
                    (ssh_type, password_type),
                )
                for index, ((access_type, secret_type), variable) in enumerate(
                    zip(specs, variables)
                ):
                    secret = Secret(
                        name="proxmox-live-validation-" + token + str(index),
                        provider="environment-variable",
                        parameters={"variable": variable},
                    )
                    secret.validated_save()
                    SecretsGroupAssociation(
                        secrets_group=group,
                        secret=secret,
                        access_type=access_type,
                        secret_type=secret_type,
                    ).validated_save()
                device = Device(
                    name="proxmox-live-validation-" + token,
                    device_type=device_type,
                    platform=platform,
                    location=anchor.location,
                    role=anchor.role,
                    status=anchor.status,
                    secrets_group=group,
                    serial="",
                )
                device.validated_save()
                device_before = snapshot_inventory(device)
                with tempfile.NamedTemporaryFile(
                    prefix="proxmox-live-preview-", suffix=".json", delete=False
                ) as temporary:
                    preview_path = Path(temporary.name)
                try:
                    brief = preview(
                        device_id=str(device.pk),
                        verify_tls=verify_tls,
                        expected_adapter="proxmox",
                        endpoint_host=host,
                        proxmox_port=port,
                        expected_proxmox_node=expected_node,
                        expected_proxmox_host_uuid=expected_host_uuid,
                        proxmox_ssh_host_key=host_key_sha256,
                        report_path=str(preview_path),
                    )
                    initial = json.loads(preview_path.read_text(encoding="utf-8"))
                finally:
                    preview_path.unlink(missing_ok=True)
                if brief["database_write_statements"] != 0:
                    raise AssertionError("Live Proxmox Job preview issued database writes")
                if initial["job_version"] != JOB_VERSION or initial["plan"]["errors"]:
                    raise AssertionError(
                        "Live Proxmox Job preview failed current native validation"
                    )
                if initial["discovery"]["identity"] != identity:
                    raise AssertionError("API/SSH host identity changed between collection and Job")
                if snapshot_inventory(Device.objects.get(pk=device.pk)) != device_before:
                    raise AssertionError("Live Job preview changed native inventory")
                _assert_credentials_absent(
                    initial, token_id, token_secret, ssh_username, ssh_password
                )
                applied = apply_discovery(initial["discovery"], device)
                device.refresh_from_db()
                after = snapshot_inventory(device, discovery=initial["discovery"])
                with CaptureQueriesContext(connection) as captured:
                    repeated = apply_discovery(initial["discovery"], device)
                if any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries):
                    raise AssertionError("Unchanged live Proxmox apply issued database writes")
                if (
                    snapshot_inventory(
                        Device.objects.get(pk=device.pk), discovery=initial["discovery"]
                    )
                    != after
                ):
                    raise AssertionError("Unchanged Proxmox repeat changed native inventory")
                if (
                    device.name != "proxmox-live-validation-" + token
                    or device.platform_id != platform.pk
                    or device.device_type_id != device_type.pk
                ):
                    raise AssertionError("Proxmox apply changed selected native identity or intent")
                result = {
                    "passed": True,
                    "persistent_changes": 0,
                    "job_version": JOB_VERSION,
                    "endpoint": host,
                    "node": identity["hostname"],
                    "host_uuid": identity["host_uuid"],
                    "software_version": after["device"]["software_version"],
                    "interfaces": [row["name"] for row in after["interfaces"]],
                    "visible_guests": len(initial["discovery"]["observations"]["guests"]),
                    "preview_inventory_dml": 0,
                    "repeat_inventory_dml": 0,
                    "apply_summary": applied["summary"],
                    "repeat_summary": repeated["summary"],
                    "collection_requests": source_trace,
                    "requests": initial["requests"],
                }
                _assert_credentials_absent(
                    result, token_id, token_secret, ssh_username, ssh_password
                )
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
    restored_anchor = Device.objects.get(pk=anchor.pk)
    if (
        snapshot_inventory(restored_anchor) != anchor_before
        or restored_anchor._custom_field_data != anchor_custom
        or list(RelationshipAssociation.objects.order_by("pk").values()) != relationships_before
    ):
        raise AssertionError("Live validation changed the anchor or existing native relationships")
    if report_path:
        _write_private(report_path, {"proof": result, "report": initial, "source": source})
    return result


if __name__ == "__main__":

    def required(name):
        value = os.environ.get(name)
        if not value:
            raise ValueError("Missing required lab validation environment variable: " + name)
        return value

    tls_setting = os.environ.get("NAUTOBOT_PROXMOX_VERIFY_TLS", "true").lower()
    if tls_setting not in {"true", "false"}:
        raise ValueError("NAUTOBOT_PROXMOX_VERIFY_TLS must be true or false")
    print(
        json.dumps(
            run(
                anchor_device_id=required("NAUTOBOT_DISCOVERY_DEVICE_ID"),
                host=required("NAUTOBOT_PROXMOX_HOST"),
                token_id=required("NAUTOBOT_PROXMOX_TOKEN_ID"),
                token_secret=required("NAUTOBOT_PROXMOX_TOKEN_SECRET"),
                ssh_username=required("NAUTOBOT_PROXMOX_SSH_USERNAME"),
                ssh_password=required("NAUTOBOT_PROXMOX_SSH_PASSWORD"),
                expected_node=required("NAUTOBOT_PROXMOX_NODE"),
                expected_host_uuid=os.environ.get("NAUTOBOT_PROXMOX_EXPECTED_HOST_UUID"),
                host_key_sha256=os.environ.get("NAUTOBOT_PROXMOX_HOST_KEY_SHA256"),
                source_path=os.environ.get("NAUTOBOT_PROXMOX_SOURCE_PATH"),
                report_path=os.environ.get("NAUTOBOT_PROXMOX_REPORT_PATH"),
                verify_tls=tls_setting == "true",
                port=int(os.environ.get("NAUTOBOT_PROXMOX_PORT", "8006")),
            ),
            indent=2,
            sort_keys=True,
        )
    )
