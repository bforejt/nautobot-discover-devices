"""Validate a normal queued Proxmox preview with explicitly temporary lab inventory.

Call ``start()`` in configured Nautobot after deploying the reviewed package. Pass
four worker-readable text-file Secret paths, an existing anchor, a validated live
source file and explicit QEMU BIOS UUIDs. Credential values are never read here.
The literal endpoint becomes the temporary host's name; no IPAM is created.

``status()`` returns immediately. Call ``finish()`` after the worker completes;
it verifies Advanced/attachment evidence and unchanged inventory, then removes
only this proof's temporary objects even when validation fails. JobResult and
FileProxy audit records remain. Pending/running jobs keep their fixtures until
completion; this module neither sleeps nor cancels worker tasks.
"""

import copy
import json
import os
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid4

from tools.proxmox_lab_validation import _write_private

CONTRACT = "proxmox-worker-proof-v1"
SECRET_KEYS = ("http_username", "http_password", "ssh_username", "ssh_password")


def _models():
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Interface,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.extras.models import (
        CustomField,
        Job,
        Relationship,
        RelationshipAssociation,
        Secret,
        SecretsGroup,
        SecretsGroupAssociation,
    )

    return {
        model._meta.label: model
        for model in (
            Device,
            DeviceType,
            Interface,
            Manufacturer,
            Platform,
            SoftwareVersion,
            CustomField,
            Relationship,
            RelationshipAssociation,
            Secret,
            SecretsGroup,
            SecretsGroupAssociation,
            Job,
        )
    }


def _records(models):
    """Hash exact native rows so private baselines contain no arbitrary field values."""
    result = {}
    for label, model in models.items():
        result[label] = []
        for row in model.objects.order_by("pk").values():
            encoded = json.dumps(row, default=str, sort_keys=True, allow_nan=False).encode("utf-8")
            result[label].append({"id": str(row["id"]), "sha256": sha256(encoded).hexdigest()})
    return result


def _manifest(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("contract") != CONTRACT
        or not isinstance(value.get("created"), dict)
        or set(value["created"]) != set(_models())
    ):
        raise ValueError("The queued Proxmox proof manifest has an invalid contract")
    for label, identifiers in value["created"].items():
        if not isinstance(identifiers, list) or any(
            not isinstance(identifier, str) or str(UUID(identifier)) != identifier
            for identifier in identifiers
        ):
            raise ValueError("The queued proof manifest has invalid fixture UUIDs")
        existing_ids = {str(row["id"]) for row in value["baseline"][label]}
        if existing_ids.intersection(identifiers):
            raise ValueError("Queued proof cleanup cannot select pre-existing objects")
    return value


def _job_result(manifest):
    from nautobot.extras.models import JobResult

    return JobResult.objects.get(pk=manifest["job_result_id"])


def _completed(job_result):
    return job_result.date_done is not None and job_result.status in {
        "SUCCESS",
        "FAILURE",
        "REVOKED",
        "REJECTED",
        "IGNORED",
    }


def start(
    *,
    anchor_device_id,
    source_path,
    endpoint_host,
    secret_paths,
    manifest_path,
    host_key_sha256,
    guest_vm_uuids=(),
    guest_anchor_device_id=None,
    job_model_id=None,
    user_id=None,
    verify_tls=True,
    port=8006,
    ssh_port=22,
    expected_request_count=None,
):
    """Commit private temporary fixtures and enqueue the existing registered Job."""
    from django.contrib.auth import get_user_model
    from django.db import transaction
    from nautobot.dcim.models import Device, DeviceType, Manufacturer, Platform
    from nautobot.extras.choices import (
        SecretsGroupAccessTypeChoices,
        SecretsGroupSecretTypeChoices,
    )
    from nautobot.extras.models import (
        Job,
        JobResult,
        Secret,
        SecretsGroup,
        SecretsGroupAssociation,
    )

    from jobs.adapters import proxmox
    from jobs.discovery_job import JOB_VERSION
    from jobs.proxmox_guest_policy import canonical_uuid

    if Path(manifest_path).exists():
        raise ValueError("Select a new manifest path for each queued Proxmox proof")
    endpoint_host = str(ip_address(endpoint_host))
    if type(verify_tls) is not bool:
        raise ValueError("Queued proof TLS verification must be an explicit boolean")
    if any(type(value) is not int or not 1 <= value <= 65535 for value in (port, ssh_port)):
        raise ValueError("Queued proof transport ports must be integers from 1 to 65535")
    if (
        not isinstance(host_key_sha256, str)
        or not host_key_sha256.startswith("SHA256:")
        or len(host_key_sha256) > 128
    ):
        raise ValueError("Pin the independently verified Proxmox SSH SHA256 host key")
    if expected_request_count is not None and (
        type(expected_request_count) is not int or expected_request_count < 1
    ):
        raise ValueError("Expected queued proof request count must be a positive integer")
    if (
        not isinstance(secret_paths, dict)
        or set(secret_paths) != set(SECRET_KEYS)
        or any(
            not isinstance(path, str) or not Path(path).is_absolute()
            for path in secret_paths.values()
        )
        or len(set(secret_paths.values())) != len(SECRET_KEYS)
    ):
        raise ValueError("Supply four distinct absolute worker-readable text-file Secret paths")
    if any(
        not Path(path).is_file() or not os.access(path, os.R_OK) for path in secret_paths.values()
    ):
        raise ValueError("Every queued proof Secret path must reference an existing readable file")
    if not isinstance(guest_vm_uuids, (list, tuple)) or len(guest_vm_uuids) > 4096:
        raise ValueError("Explicit worker proof guest UUIDs must be a list of at most 4096 UUIDs")
    guest_vm_uuids = tuple(canonical_uuid(value) for value in guest_vm_uuids)
    if None in guest_vm_uuids or len(set(guest_vm_uuids)) != len(guest_vm_uuids):
        raise ValueError("Explicit worker proof guest UUIDs must be unique non-sentinel UUIDs")
    source = json.loads(Path(source_path).read_text(encoding="utf-8"))
    proxmox.reconstruct(source)
    identity = source["identity"]
    if not identity.get("vendor") or not identity.get("model"):
        raise ValueError("The live source must establish the physical host vendor and model")
    for vm_uuid in guest_vm_uuids:
        observed = [
            row
            for row in source["observations"]["guests"]
            if row.get("identity", {}).get("guest_uuid") == vm_uuid
        ]
        if (
            len(observed) != 1
            or observed[0].get("kind") != "qemu"
            or observed[0].get("identity", {}).get("unique") is not True
        ):
            raise ValueError("Explicit worker proof guest UUID lacks unique observed QEMU identity")
    if Device.objects.filter(name=endpoint_host).exists():
        raise ValueError("The temporary endpoint-named Device collides with existing inventory")
    anchor = Device.objects.select_related("location", "role", "status").get(pk=anchor_device_id)
    guest_anchor = (
        Device.objects.select_related("device_type", "platform", "location", "role", "status").get(
            pk=guest_anchor_device_id
        )
        if guest_anchor_device_id
        else anchor
    )
    User = get_user_model()
    user = (
        User.objects.get(pk=user_id, is_active=True)
        if user_id
        else User.objects.filter(is_active=True, is_superuser=True).order_by("pk").first()
    )
    if user is None:
        raise ValueError("Select an existing active Nautobot user for the queued proof")
    jobs = Job.objects.filter(installed=True, enabled=True, job_class_name="DiscoverDevice")
    if job_model_id:
        jobs = jobs.filter(pk=job_model_id)
    else:
        jobs = jobs.filter(module_name__endswith=".discovery_job")
    if jobs.count() != 1:
        raise ValueError("Select exactly one enabled installed Device Discovery Job")
    job_model = jobs.get()
    if job_model.default_job_queue_id is None:
        raise ValueError("The registered Device Discovery Job needs its existing default queue")
    models = _models()
    baseline = _records(models)
    manifest = {
        "contract": CONTRACT,
        "token": uuid4().hex[:12],
        "endpoint": endpoint_host,
        "source_identity": identity,
        "expected_job_version": JOB_VERSION,
        "expected_request_count": expected_request_count,
        "guest_vm_uuids": list(guest_vm_uuids),
        "job_model_id": str(job_model.pk),
        "baseline": baseline,
        "created": {label: [] for label in models},
        "cleaned": False,
        "baseline_restored": False,
    }

    def created(obj):
        obj.validated_save()
        manifest["created"][obj._meta.label].append(str(obj.pk))
        return obj

    token = manifest["token"]
    with transaction.atomic():
        manufacturer = Manufacturer.objects.filter(name=identity["vendor"]).first()
        if manufacturer is None:
            manufacturer = created(Manufacturer(name=identity["vendor"]))
        device_type = DeviceType.objects.filter(
            manufacturer=manufacturer, model=identity["model"]
        ).first()
        if device_type is None:
            device_type = created(DeviceType(manufacturer=manufacturer, model=identity["model"]))
        platform = created(Platform(name="Proxmox worker proof " + token, network_driver="proxmox"))
        group = created(SecretsGroup(name="proxmox-worker-proof-" + token))
        http_type = SecretsGroupAccessTypeChoices.TYPE_HTTP
        ssh_type = SecretsGroupAccessTypeChoices.TYPE_SSH
        username_type = SecretsGroupSecretTypeChoices.TYPE_USERNAME
        password_type = SecretsGroupSecretTypeChoices.TYPE_PASSWORD
        specs = (
            (http_type, username_type),
            (http_type, password_type),
            (ssh_type, username_type),
            (ssh_type, password_type),
        )
        for key, (access_type, secret_type) in zip(SECRET_KEYS, specs):
            secret = created(
                Secret(
                    name="proxmox-worker-proof-" + token + "-" + key,
                    provider="text-file",
                    parameters={"path": secret_paths[key]},
                )
            )
            created(
                SecretsGroupAssociation(
                    secrets_group=group,
                    secret=secret,
                    access_type=access_type,
                    secret_type=secret_type,
                )
            )
        host = created(
            Device(
                name=endpoint_host,
                device_type=device_type,
                platform=platform,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
                secrets_group=group,
                serial="",
            )
        )
        mappings = []
        for index, vm_uuid in enumerate(guest_vm_uuids):
            guest = Device(
                name="proxmox-worker-guest-" + token + "-" + str(index),
                device_type=guest_anchor.device_type,
                platform=guest_anchor.platform,
                location=guest_anchor.location,
                role=guest_anchor.role,
                status=guest_anchor.status,
                serial="",
            )
            guest._custom_field_data = copy.deepcopy(guest_anchor._custom_field_data)
            created(guest)
            mappings.append({"vm_uuid": vm_uuid, "device": str(guest.pk)})
        manifest["host_device_id"] = str(host.pk)
        manifest["guest_mappings"] = mappings
        manifest["preview_baseline"] = _records(models)
        job_result = JobResult.enqueue_job(
            job_model,
            user,
            job_queue=job_model.default_job_queue,
            job_kwargs={
                "device": str(host.pk),
                "dryrun": True,
                "verify_tls": verify_tls,
                "ssh_port": ssh_port,
                "proxmox_port": port,
                "expected_proxmox_node": identity["hostname"],
                "expected_proxmox_host_uuid": identity["host_uuid"],
                "proxmox_ssh_host_key": host_key_sha256,
                "proxmox_guest_mappings": json.dumps(mappings) if mappings else "",
            },
        )
        manifest["job_result_id"] = str(job_result.pk)
        _write_private(manifest_path, manifest)
    return status(manifest_path)


def status(manifest_path):
    """Return a compact immediate snapshot, with no polling or task mutation."""
    manifest = _manifest(manifest_path)
    job_result = _job_result(manifest)
    return {
        "job_result_id": str(job_result.pk),
        "status": job_result.status,
        "ready": _completed(job_result),
        "cleaned": manifest["cleaned"],
    }


def _cleanup(manifest):
    """Delete only proof-created inventory and dependencies inside one transaction."""
    from django.db import transaction
    from django.db.models import Q
    from nautobot.dcim.models import Device, Platform, SoftwareVersion
    from nautobot.extras.models import RelationshipAssociation

    models = _models()
    created = manifest["created"]
    device_ids = created[Device._meta.label]
    platform_ids = created[Platform._meta.label]
    order = (
        "dcim.Device",
        "extras.SecretsGroupAssociation",
        "extras.Secret",
        "extras.SecretsGroup",
        "dcim.Platform",
        "dcim.DeviceType",
        "dcim.Manufacturer",
    )
    with transaction.atomic():
        # Generic relationship IDs need explicit cleanup; fixture Interfaces cascade.
        RelationshipAssociation.objects.filter(
            Q(source_id__in=device_ids) | Q(destination_id__in=device_ids)
        ).delete()
        models["dcim.Device"].objects.filter(pk__in=device_ids).delete()
        # A broken preview may have created a version under its private Platform.
        SoftwareVersion.objects.filter(platform_id__in=platform_ids).delete()
        for label in order[1:]:
            models[label].objects.filter(pk__in=created[label]).delete()
    manifest["cleaned"] = True
    manifest["baseline_restored"] = _records(models) == manifest["baseline"]
    if not manifest["baseline_restored"]:
        raise AssertionError("Queued proof cleanup found changed pre-existing inventory or counts")


def finish(manifest_path, *, proof_path=None):
    """Validate a completed preview and always clean its temporary inventory."""
    from jobs.adapters import proxmox

    manifest = _manifest(manifest_path)
    job_result = _job_result(manifest)
    if not _completed(job_result):
        return status(manifest_path)
    if manifest["cleaned"]:
        return manifest["proof"]
    proof = {
        "job_result_id": str(job_result.pk),
        "status": job_result.status,
        "ready": True,
        "passed": False,
    }
    try:
        if job_result.status != "SUCCESS":
            raise AssertionError("The queued Proxmox preview did not complete successfully")
        report = job_result.meta.get("discovery_report")
        if (
            not isinstance(report, dict)
            or report.get("job_version") != manifest["expected_job_version"]
            or report.get("device_id") != manifest["host_device_id"]
            or report.get("dry_run") is not True
            or report.get("applied") is not False
            or report.get("plan", {}).get("errors")
            or report.get("discovery", {}).get("identity") != manifest["source_identity"]
        ):
            raise AssertionError(
                "The queued Proxmox preview failed expected identity or plan checks"
            )
        discovery = report["discovery"]
        proxmox.reconstruct(discovery)
        inventory = discovery["source"]["inventory"]
        if inventory["completeness"]["guests"] is not True:
            raise AssertionError("The queued preview lacks complete guest registry evidence")
        local_registry = {
            (row["type"], int(vmid))
            for vmid, row in inventory["ssh"]["host"]["guest_registry"].get("ids", {}).items()
            if row["node"] == discovery["identity"]["hostname"]
        }
        local_api = {
            (kind, row["vmid"]) for kind in ("qemu", "lxc") for row in inventory["api"][kind]
        }
        if local_registry != local_api:
            raise AssertionError("The queued preview API guests disagree with the host registry")
        expected_count = manifest["expected_request_count"]
        if expected_count is not None and len(report["requests"]) != expected_count:
            raise AssertionError("The queued preview did not complete its expected read set")
        mappings = manifest["guest_mappings"]
        guest_plan = report["plan"]["proxmox_guests"]
        if (
            guest_plan.get("errors")
            or guest_plan["summary"]["hosted_on_created"] != len(mappings)
            or {
                (row["vm_uuid"], row["destination_id"], row["source_id"])
                for row in guest_plan["creates"]
            }
            != {(row["vm_uuid"], row["device"], manifest["host_device_id"]) for row in mappings}
        ):
            raise AssertionError("The queued preview did not plan exactly the explicit guest links")
        files = list(job_result.files.all())
        if len(files) != 1:
            raise AssertionError("The queued preview did not produce exactly one JSON attachment")
        with files[0].file.open("rb") as stream:
            contents = stream.read(64 * 1024 * 1024 + 1)
        if len(contents) > 64 * 1024 * 1024 or json.loads(contents) != report:
            raise AssertionError("The queued preview attachment differs from Advanced evidence")
        if _records(_models()) != manifest["preview_baseline"]:
            raise AssertionError("The queued preview changed fixture or pre-existing inventory")
        proof.update(
            {
                "passed": True,
                "job_version": report["job_version"],
                "identity": discovery["identity"],
                "requests": len(report["requests"]),
                "registered_guests": len(local_registry),
                "guest_vm_uuids": manifest["guest_vm_uuids"],
                "hosted_on_planned": len(mappings),
                "preview_inventory_changes": 0,
                "file_proxy_id": str(files[0].pk),
            }
        )
    except Exception as error:
        proof["validation_error"] = (
            str(error) if isinstance(error, AssertionError) else type(error).__name__
        )
        raise
    finally:
        try:
            _cleanup(manifest)
        except Exception as error:
            proof["passed"] = False
            proof["cleanup_error"] = (
                str(error) if isinstance(error, AssertionError) else type(error).__name__
            )
            raise
        finally:
            proof["cleaned"] = manifest["cleaned"]
            proof["baseline_restored"] = manifest["baseline_restored"]
            proof["persistent_inventory_changes"] = 0 if manifest["baseline_restored"] else None
            manifest["proof"] = proof
            _write_private(manifest_path, manifest)
            if proof_path:
                _write_private(proof_path, proof)
    return proof
