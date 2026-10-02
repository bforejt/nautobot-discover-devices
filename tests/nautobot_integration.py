"""Exercise the real Nautobot ORM while rolling every inventory change back.

Run inside a configured Nautobot Django process, for example with ``nbshell``
and ``runpy.run_path(..., run_name="__main__")``. The target is an existing
lab Device; no test runner, migrations, JobResult, or persistent test records
are required. Every mutation is enclosed in an outer transaction that is
marked for rollback even when an assertion fails.
"""

import copy
import json
import os
import pickle
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

DEFAULT_DEVICE_ID = "eb46c008-e579-4207-8def-f9b6dfbdc525"
WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def write_queries(queries):
    """Return database mutation statements without displaying their values."""
    return [query for query in queries if WRITE_SQL.match(query["sql"])]


def _fact(name, **values):
    return {
        "name": name,
        "type": "virtual",
        "enabled": True,
        "description": "Discovery ORM integration verification",
        "mtu": 1500,
        "mac_address": "02:00:00:00:00:01",
        "type_source": "synthetic integration input",
        **values,
    }


def _unused_version(platform_id):
    from nautobot.dcim.models import SoftwareVersion

    for patch_number in range(1, 100):
        version = "17.99.%02d" % patch_number
        if not SoftwareVersion.objects.filter(platform_id=platform_id, version=version).exists():
            return version
    raise AssertionError("No unused synthetic software release is available for integration")


def _verify_job_error_serialization(device):
    """A Job failure must survive the actual Billiard prefork result wrapper.

    The parent process does not necessarily import Git datasource packages.
    Unpickle in an isolated interpreter that cannot import either Jobs package
    name, rather than allowing this process's imports to hide that failure.
    """
    from billiard.einfo import ExceptionInfo
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    import jobs.discovery_job as job_module
    from jobs.nautobot_inventory import snapshot_inventory
    from jobs.transport_restconf import RestconfError

    captured_files = []
    logger = Mock()
    message = "GET /data/example:leaf: TLS handshake failed"
    client = SimpleNamespace(
        trace=[{"path": "/data/example:leaf", "status": None, "error": "TLS handshake failed"}],
        close=Mock(),
    )

    class FailureJob(job_module.DiscoverDevice):
        def __init__(self):
            super().__init__()
            self.logger = logger
            self.request = SimpleNamespace(meta={})

        def create_file(self, filename, data):
            captured_files.append((filename, data))

    before = snapshot_inventory(device)
    serialized = None
    with (
        patch.object(
            job_module, "resolve_credentials", return_value=("example-user", "example-password")
        ),
        patch.object(job_module, "RestconfClient", return_value=client),
        patch.object(job_module.cisco_iosxe, "collect", side_effect=RestconfError(message)),
        CaptureQueriesContext(connection) as captured,
    ):
        try:
            # Exercise the apply input: failure must stop before any inventory
            # changes even when the caller did not request a preview.
            job = FailureJob()
            job.run(device=device, dryrun=False)
        except Exception as exc:
            assert type(exc) is RuntimeError, (
                "Job-defined exceptions must be converted to built-in RuntimeError"
            )
            assert str(exc) == message
            assert exc.__suppress_context__, "Failure must suppress the original custom exception"
            serialized = pickle.dumps(ExceptionInfo(), protocol=pickle.HIGHEST_PROTOCOL)
        else:
            raise AssertionError("Injected RESTCONF failure unexpectedly succeeded")

    assert serialized is not None
    assert not write_queries(captured.captured_queries), "Failed apply issued database writes"
    assert snapshot_inventory(device) == before
    client.close.assert_called_once()
    assert any(message in str(call) for call in logger.error.call_args_list), (
        "The operator-facing error must be logged"
    )
    assert len(captured_files) == 1, "Failed Job must still attach its discovery report"
    filename, data = captured_files[0]
    assert filename == "discovery_%s.json" % device.pk
    report = json.loads(data)
    assert job.request.meta["discovery_report"] == report
    assert report["error"] == message
    assert report["requests"] == client.trace
    assert report["dry_run"] is False and report["applied"] is False

    child_script = """
import importlib.util
import json
import pickle
import sys

for name in ("jobs", "nautobot_discover_devices"):
    assert importlib.util.find_spec(name) is None, "Fresh parent can import a Jobs package"
info = pickle.loads(sys.stdin.buffer.read())
assert info.type is RuntimeError
assert type(info.exception) is RuntimeError
assert str(info.exception) == "GET /data/example:leaf: TLS handshake failed"
print(json.dumps({"exception_type": "builtins.RuntimeError", "jobs_package_imported": False}))
"""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "JOBS_ROOT", "NAUTOBOT_JOBS_ROOT")
    }
    with tempfile.TemporaryDirectory(prefix="discovery-celery-error-") as directory:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", child_script],
            input=serialized,
            capture_output=True,
            cwd=directory,
            env=environment,
            timeout=20,
            check=False,
        )
    assert completed.returncode == 0, (
        "Billiard ExceptionInfo failed to unpickle without Jobs imports: "
        + completed.stderr.decode("utf-8", errors="replace")
    )
    result = json.loads(completed.stdout)
    assert result["exception_type"] == "builtins.RuntimeError"
    assert result["jobs_package_imported"] is False


def _verify_lag_relationships(device, interface_status, checks):
    """Exercise real physical-member foreign keys inside the caller's rollback."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, Interface, SoftwareVersion

    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "LAG integration requires outer rollback"
    device.refresh_from_db()
    prefix = str(uuid.uuid4().int)[:12]
    parent_name = "Port-channel" + prefix + "1"
    physical_prefix = "GigabitEthernet" + prefix + "/0/"
    member_name = physical_prefix + "1"
    identity = {
        "hostname": device.name or "discovery-integration",
        "serial": device.serial or "CODEX-LAG-INTEGRATION",
        "model": device.device_type.model,
        "software_version": (
            device.software_version.version
            if device.software_version_id
            else _unused_version(device.platform_id)
        ),
    }

    def observed(facts, members):
        return {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": copy.deepcopy(identity),
            "interfaces": facts,
            "lag_memberships": [
                {
                    "member": member,
                    "lag": parent,
                    "source": {
                        "path": "/data/Cisco-IOS-XE-native:native/interface",
                        "field": "channel-group/number",
                    },
                }
                for member, parent in members
            ],
            "warnings": [],
            "excluded_interfaces": [],
        }

    def lag_fact(name):
        return _fact(name, type="lag", mac_address=None)

    def physical_fact(name):
        return _fact(name, type="1000base-t")

    discovery = observed(
        [lag_fact(parent_name), physical_fact(member_name)], [(member_name, parent_name)]
    )
    before_preview = snapshot_inventory(device)
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(discovery, snapshot_inventory(device))
        validate_plan(preview, device, interface_status=interface_status)
    assert not write_queries(captured.captured_queries), "LAG preview issued database writes"
    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_preview
    assert preview["summary"]["interfaces_created"] == 2
    assert preview["summary"]["lag_memberships_updated"] == 1
    assert len(preview["lag_assignments"]) == 1
    checks.append("LAG preview validates an unsaved parent and physical member without DML")

    first = apply_discovery(discovery, device, interface_status=interface_status)
    device.refresh_from_db()
    parent = Interface.objects.get(device=device, name=parent_name)
    member = Interface.objects.get(device=device, name=member_name)
    assert parent.type == "lag"
    assert member.type == "1000base-t"
    assert member.lag_id == parent.pk
    assert first["summary"]["lag_memberships_updated"] == 1
    checks.append("apply creates the LAG and physical member before assigning the member FK")

    before_repeat = snapshot_inventory(device)
    with CaptureQueriesContext(connection) as captured:
        repeat = apply_discovery(discovery, device, interface_status=interface_status)
    assert not write_queries(captured.captured_queries), "Repeated LAG apply issued inventory DML"
    assert repeat["summary"]["interfaces_created"] == 0
    assert repeat["summary"]["interfaces_updated"] == 0
    assert repeat["summary"]["lag_memberships_updated"] == 0
    assert repeat["lag_assignments"] == []
    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_repeat
    checks.append("repeated LAG discovery preserves membership and issues zero inventory DML")

    # An existing physical interface with a short alias must receive the FK
    # without a replacement row, rename, or type change.
    alias_name = "Gi" + prefix + "/0/2"
    alias_canonical = physical_prefix + "2"
    existing_fact = physical_fact(alias_canonical)
    attributes = {
        field: existing_fact[field]
        for field in ("type", "enabled", "description", "mtu", "mac_address")
    }
    seeded = Interface(device=device, name=alias_name, status=interface_status, **attributes)
    seeded.validated_save()
    seeded_id = seeded.pk
    blank_lag = observed([lag_fact(parent_name), existing_fact], [(alias_canonical, parent_name)])
    before_preview = snapshot_inventory(device)
    with CaptureQueriesContext(connection) as captured:
        plan = build_plan(blank_lag, snapshot_inventory(device))
        validate_plan(plan, device, interface_status=interface_status)
    assert not write_queries(captured.captured_queries), "Existing-member LAG preview issued DML"
    assert snapshot_inventory(device) == before_preview
    assert plan["summary"]["interfaces_created"] == 0
    assert plan["summary"]["lag_memberships_updated"] == 1
    apply_discovery(blank_lag, device, interface_status=interface_status)
    seeded.refresh_from_db()
    assert seeded.pk == seeded_id and seeded.name == alias_name
    assert seeded.lag_id == parent.pk
    assert seeded.type == "1000base-t"
    assert not Interface.objects.filter(device=device, name=alias_canonical).exists()
    checks.append(
        "existing physical member receives a blank LAG FK while preserving alias and UUID"
    )

    # A populated relationship is an operator-owned value under fill-only
    # reconciliation, even when fresh structured observations differ.
    other_parent_name = "Port-channel" + prefix + "2"
    other_parent = Interface(
        device=device, name=other_parent_name, type="lag", status=interface_status
    )
    other_parent.validated_save()
    seeded.lag = other_parent
    seeded.validated_save()
    before_conflict = snapshot_inventory(device)
    with CaptureQueriesContext(connection) as captured:
        conflict = apply_discovery(blank_lag, device, interface_status=interface_status)
    assert not write_queries(captured.captured_queries), (
        "Conflicting LAG membership was overwritten"
    )
    seeded.refresh_from_db()
    assert seeded.lag_id == other_parent.pk
    assert conflict["summary"]["lag_memberships_updated"] == 0
    assert conflict["lag_assignments"] == []
    assert any(row["field"] == "lag" for row in conflict["conflicts"])
    assert snapshot_inventory(device) == before_conflict
    checks.append(
        "conflicting populated LAG FK is reported, preserved, and causes no inventory DML"
    )

    # Fail on the final relationship save, after preceding interface, catalog,
    # device, and first member-link writes have actually occurred.
    Device.objects.filter(pk=device.pk).update(serial="", software_version=None)
    device.refresh_from_db()
    rollback_parent_name = "Port-channel" + prefix + "3"
    first_member_name = physical_prefix + "3"
    failing_member_name = physical_prefix + "4"
    rollback_discovery = observed(
        [
            lag_fact(rollback_parent_name),
            physical_fact(first_member_name),
            physical_fact(failing_member_name),
        ],
        [(first_member_name, rollback_parent_name), (failing_member_name, rollback_parent_name)],
    )
    rollback_discovery["identity"]["software_version"] = _unused_version(device.platform_id)
    before_failure = snapshot_inventory(device)
    interface_count = Interface.objects.count()
    version_count = SoftwareVersion.objects.count()
    original_save = Interface.validated_save
    writes_seen = []

    def fail_final_link(interface, *args, **kwargs):
        if interface.name == failing_member_name and interface.lag_id is not None:
            saved_parent = Interface.objects.get(device=device, name=rollback_parent_name)
            saved_first = Interface.objects.get(device=device, name=first_member_name)
            saved_final = Interface.objects.get(device=device, name=failing_member_name)
            assert saved_first.lag_id == saved_parent.pk, "Earlier member link was not saved"
            assert saved_final.lag_id is None, (
                "Failure was not injected before the final link write"
            )
            saved_device = Device.objects.get(pk=device.pk)
            assert saved_device.serial == rollback_discovery["identity"]["serial"]
            assert (
                saved_device.software_version.version
                == rollback_discovery["identity"]["software_version"]
            )
            writes_seen.append("earlier device, software, interfaces, and link written")
            raise ValidationError({"lag": "Intentional final membership-save failure"})
        return original_save(interface, *args, **kwargs)

    with patch.object(Interface, "validated_save", fail_final_link):
        try:
            apply_discovery(rollback_discovery, device, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("The injected final LAG link failure did not occur")
    assert writes_seen, "The LAG rollback scenario never saved preceding rows and membership"
    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_failure
    assert Interface.objects.count() == interface_count
    assert SoftwareVersion.objects.count() == version_count
    assert not Interface.objects.filter(
        device=device, name__in=(rollback_parent_name, first_member_name, failing_member_name)
    ).exists()
    checks.append(
        "final LAG link failure rolls back preceding device, software, interface, and link writes"
    )


def run(device_id=None):
    """Verify preview, enrichment, idempotence, and transaction rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, Interface, SoftwareVersion
    from nautobot.extras.models import Status

    from jobs.discovery_job import DiscoverDevice
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan
    from tests.nautobot_access_integration import catalog_counts as access_catalog_counts
    from tests.nautobot_access_integration import run as verify_access_inventory
    from tests.nautobot_components_integration import (
        catalog_counts,
    )
    from tests.nautobot_components_integration import (
        run as verify_component_inventory,
    )
    from tests.nautobot_vlan_integration import catalog_counts as vlan_catalog_counts
    from tests.nautobot_vlan_integration import run as verify_vlan_inventory

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID", DEFAULT_DEVICE_ID)
    device = Device.objects.get(pk=device_id)
    assert device.platform_id, "The integration target must have a Platform"
    baseline = snapshot_inventory(device)
    initial_interface_count = Interface.objects.count()
    initial_version_count = SoftwareVersion.objects.count()
    initial_component_catalog_counts = catalog_counts()
    initial_vlan_catalog_counts = vlan_catalog_counts()
    initial_access_catalog_counts = access_catalog_counts()
    interface_status = Status.objects.filter(
        name="Active", content_types=ContentType.objects.get_for_model(Interface)
    ).first()
    assert interface_status is not None, "An applicable Active interface status is required"
    checks = []
    form = DiscoverDevice.as_form()
    assert DiscoverDevice.supports_dryrun, "Nautobot must recognize the dryrun input"
    assert form["dryrun"].value() is True, "The rendered Job must default to a preview"
    checks.append("Nautobot recognizes the dryrun field and renders it enabled by default")
    assert form["use_ntc_defaults"].value() is False
    assert form.fields["use_ntc_defaults"].label == "Use NTC defaults when guessing"
    assert "uncertain values blank" in form.fields["use_ntc_defaults"].help_text
    checks.append(
        "NTC guessing renders as a separate checkbox disabled by default with scoped help"
    )
    _verify_job_error_serialization(device)
    checks.append(
        "failed apply logs and attaches its report without writes, and Billiard ExceptionInfo "
        "unpickles in a fresh parent without Jobs package imports"
    )
    synthetic_prefix = str(uuid.uuid4().int)[:12]
    alias_name = "Lo" + synthetic_prefix + "1"
    canonical_alias = "Loopback" + synthetic_prefix + "1"
    created_name = "Loopback" + synthetic_prefix + "2"
    assert not device.interfaces.filter(
        name__in=(alias_name, canonical_alias, created_name)
    ).exists()

    with transaction.atomic():
        try:
            # This seed deliberately stores the short Cisco alias and False,
            # both of which reconciliation must preserve without duplication.
            seed = Interface(
                device=device,
                name=alias_name,
                type="virtual",
                enabled=False,
                description="",
                mtu=None,
                mac_address=None,
                status=interface_status,
            )
            seed.validated_save()
            Device.objects.filter(pk=device.pk).update(serial="", software_version=None)
            device.refresh_from_db()
            version = _unused_version(device.platform_id)
            serial = baseline["device"]["serial"] or "CODEX-INTEGRATION"
            discovery = {
                "schema_version": 1,
                "adapter": "cisco_iosxe",
                "identity": {
                    "hostname": device.name or "discovery-integration",
                    "serial": serial,
                    "model": device.device_type.model,
                    "software_version": version,
                },
                "interfaces": [_fact(canonical_alias), _fact(created_name)],
                "warnings": [],
                "excluded_interfaces": [],
            }
            before_preview = snapshot_inventory(device)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(discovery, snapshot_inventory(device))
                validate_plan(plan, device, interface_status=interface_status)
            assert not write_queries(captured.captured_queries), "Preview validation issued writes"
            assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_preview
            assert plan["software_version"]["create"], "Expected a new software catalog record"
            assert plan["summary"]["device_fields_updated"] == 2
            assert plan["summary"]["interfaces_created"] == 1
            assert plan["summary"]["interfaces_updated"] == 1
            checks.append(
                "preview validates a new software FK and interfaces without database writes"
            )

            applied = apply_discovery(discovery, device, interface_status=interface_status)
            device.refresh_from_db()
            seed.refresh_from_db()
            assert device.serial == serial
            assert device.software_version.version == version
            assert seed.name == alias_name, "An existing short interface name must remain unchanged"
            assert seed.enabled is False, "Populated False must not be treated as blank"
            assert seed.description == discovery["interfaces"][0]["description"]
            assert seed.mtu == 1500
            assert str(seed.mac_address).replace(":", "").lower() == "020000000001"
            assert device.interfaces.filter(name=created_name).count() == 1
            assert not device.interfaces.filter(name=canonical_alias).exists()
            assert applied["summary"]["interfaces_created"] == 1
            checks.append(
                "apply fills blanks, creates software and interfaces, "
                "and preserves aliases and False"
            )

            before_second_apply = snapshot_inventory(device)
            with CaptureQueriesContext(connection) as captured:
                second = apply_discovery(discovery, device, interface_status=interface_status)
            assert not write_queries(captured.captured_queries), (
                "Idempotent apply issued inventory writes"
            )
            assert second["summary"]["device_fields_updated"] == 0
            assert second["summary"]["interfaces_created"] == 0
            assert second["summary"]["interfaces_updated"] == 0
            assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_second_apply
            checks.append("second apply is idempotent and issues no inventory writes")

            # A real model validator must reject the complete proposed set
            # before a valid earlier interface can be committed.
            invalid = copy.deepcopy(discovery)
            invalid["interfaces"] = [
                _fact("Loopback" + synthetic_prefix + "3"),
                _fact("Loopback" + synthetic_prefix + "4", mtu=-1),
            ]
            before_failure = snapshot_inventory(Device.objects.get(pk=device.pk))
            try:
                apply_discovery(invalid, device, interface_status=interface_status)
            except ValidationError:
                pass
            else:
                raise AssertionError("Negative MTU unexpectedly passed real Interface validation")
            assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_failure
            checks.append("real Interface validation rejects all proposed changes atomically")

            # Also exercise the transaction after preceding rows have been
            # written: a later validated_save can fail because validation or
            # concurrent database conditions changed after initial validation.
            Device.objects.filter(pk=device.pk).update(serial="", software_version=None)
            device.refresh_from_db()
            late_failure = copy.deepcopy(discovery)
            late_failure["identity"]["software_version"] = _unused_version(device.platform_id)
            first_name = "Loopback" + synthetic_prefix + "5"
            failure_name = "Loopback" + synthetic_prefix + "6"
            late_failure["interfaces"] = [_fact(first_name), _fact(failure_name)]
            before_failure = snapshot_inventory(device)
            interface_count = Interface.objects.count()
            version_count = SoftwareVersion.objects.count()
            original_save = Interface.validated_save
            writes_seen = []

            def late_validation_failure(interface, *args, **kwargs):
                if interface.name == failure_name:
                    assert Interface.objects.filter(device=device, name=first_name).exists()
                    assert SoftwareVersion.objects.filter(
                        platform=device.platform,
                        version=late_failure["identity"]["software_version"],
                    ).exists()
                    writes_seen.append("earlier rows written")
                    raise ValidationError({"name": "Intentional final-row validation failure"})
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", late_validation_failure):
                try:
                    apply_discovery(late_failure, device, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("The injected final-row validation failure did not occur")
            assert writes_seen, "Rollback scenario did not write any earlier rows"
            assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_failure
            assert Interface.objects.count() == interface_count
            assert SoftwareVersion.objects.count() == version_count
            checks.append(
                "late validation failure rolls back earlier device, software, and interface writes"
            )
            _verify_lag_relationships(device, interface_status, checks)
            verify_component_inventory(device, interface_status, checks)
            verify_vlan_inventory(device, interface_status, checks)
            verify_access_inventory(device, interface_status, checks)
        finally:
            transaction.set_rollback(True)

    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == baseline
    assert Interface.objects.count() == initial_interface_count
    assert SoftwareVersion.objects.count() == initial_version_count
    assert catalog_counts() == initial_component_catalog_counts
    assert vlan_catalog_counts() == initial_vlan_catalog_counts
    assert access_catalog_counts() == initial_access_catalog_counts
    checks.append("outer rollback restores original lab inventory and catalog counts")
    return {"device_id": str(device.pk), "passed": True, "checks": checks, "persistent_changes": 0}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
