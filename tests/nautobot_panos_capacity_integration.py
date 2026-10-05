"""Prove PAN-OS capacity custom-field writes inside an unconditional rollback.

Run in a configured Nautobot Django process via ``nbshell`` and ``runpy`` with
``NAUTOBOT_DISCOVERY_DEVICE_ID`` identifying an existing Location/Role/Status
anchor. The three capacity custom fields must already exist. These fixtures
exercise the actual installed ORM and model validation, without contacting a
firewall. Catalog metadata, targets and all writes roll back.
"""

import copy
import importlib.util
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

FIELDS = ("vcpus", "memory_mb", "disk_gb")
EXPECTED = {"vcpus": 4}
WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _discovery(name, vm_uuid, *, ports=(), version="99.99.7-h1"):
    """Use production XML collection with sanitized PAN-OS system evidence."""
    from jobs.transport_ssh import SYSTEM_INFO

    module_path = Path(__file__).with_name("nautobot_panos_integration.py")
    spec = importlib.util.spec_from_file_location("panos_native_capacity_fixture", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    response = ET.fromstring(
        (Path(__file__).with_name("fixtures") / "panos_vm_system_info.xml").read_text()
    )
    system = response.find("result/system")
    for field, value in {"hostname": name, "vm-uuid": vm_uuid, "sw-version": version}.items():
        system.find(field).text = value
    discovery = module._vm_discovery(
        name,
        vm_uuid,
        expected_vm_uuid=vm_uuid,
        ports=ports,
        version=version,
        report_payloads={SYSTEM_INFO: ET.tostring(response, encoding="unicode")},
    )
    assert {
        key: value["value"] for key, value in discovery["capacity"]["fields"].items()
    } == EXPECTED
    assert {row["field"] for row in discovery["capacity"]["unresolved"]} == {
        "memory_mb",
        "disk_gb",
    }
    return discovery


def run(device_id=None):
    """Verify preview, blank fill, preservation, schema guards and late rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Interface,
        InterfaceTemplate,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.extras.models import CustomField, Status

    from jobs.nautobot_inventory import (
        InventoryError,
        apply_discovery,
        snapshot_inventory,
        validate_plan,
    )
    from jobs.reconcile import build_plan

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not device_id:
        raise ValueError("Select an existing anchor with NAUTOBOT_DISCOVERY_DEVICE_ID")
    anchor = Device.objects.select_related("location", "role", "status").get(pk=device_id)
    device_ct = ContentType.objects.get_for_model(Device)
    definitions = {field.key: field for field in CustomField.objects.filter(key__in=FIELDS)}
    assert set(definitions) == set(FIELDS), "Install the existing Device capacity schema first"
    assert all(
        field.type == "integer" and field.content_types.filter(pk=device_ct.pk).exists()
        for field in definitions.values()
    ), "The baseline capacity schema must be integer fields attached to Device"
    anchor_before = copy.deepcopy(anchor._custom_field_data)
    tracked = (
        Device,
        DeviceType,
        Interface,
        InterfaceTemplate,
        Manufacturer,
        Platform,
        SoftwareVersion,
        CustomField,
    )
    through = CustomField.content_types.through
    counts_before = {model._meta.label: model.objects.count() for model in (*tracked, through)}
    metadata_fields = ["id", "key", "type", "default", "validation_minimum", "validation_maximum"]
    scope_supported = "scope_filter" in {field.name for field in CustomField._meta.fields}
    if scope_supported:
        metadata_fields.append("scope_filter")
    metadata_before = list(
        CustomField.objects.filter(key__in=FIELDS).order_by("key").values(*metadata_fields)
    )
    joins_before = list(through.objects.filter(customfield__key__in=FIELDS).order_by("pk").values())
    interface_status = Status.objects.get_for_model(Interface).get(name="Active")
    checks = []

    def uncached_fields(manager, model, exclude_filter_disabled=False, get_queryset=True):
        """Read actual ORM definitions without caching rolled-back fixture metadata."""
        content_type = ContentType.objects.get_for_model(model._meta.concrete_model)
        queryset = manager.get_queryset().filter(content_types=content_type)
        if exclude_filter_disabled:
            queryset = queryset.exclude(filter_logic="disabled")
        return queryset if get_queryset else list(queryset)

    with (
        transaction.atomic(),
        patch.object(type(CustomField.objects), "get_for_model", uncached_fields),
    ):
        try:
            token = uuid.uuid4().hex[:12]
            manufacturer = Manufacturer.objects.get(name="Palo Alto Networks")
            device_type = DeviceType.objects.get(manufacturer=manufacturer, model="PA-VM")
            platform = Platform(
                name="PAN-capacity-native-" + token,
                manufacturer=manufacturer,
                network_driver="paloalto_panos",
            )
            platform.validated_save()
            version = SoftwareVersion(
                platform=platform,
                version="99.99.7-h1",
                status=Status.objects.get_for_model(SoftwareVersion).get(name="Active"),
            )
            version.validated_save()
            target = Device(
                name="panos-capacity-native-" + token,
                serial="",
                platform=platform,
                device_type=device_type,
                software_version=version,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            target.validated_save()
            # Synthetic ports need exact virtual templates; PAN-OS discovery
            # intentionally leaves unknown capabilities unresolved.
            for number in (104, 105):
                name = "ethernet1/%d" % number
                assert not device_type.interface_templates.filter(name=name).exists()
                InterfaceTemplate(
                    device_type=device_type, name=name, type="virtual"
                ).validated_save()
            vm_uuid = str(uuid.uuid4())
            discovery = _discovery(target.name, vm_uuid)
            raw = copy.deepcopy(target._custom_field_data)
            raw.update({"vcpus": None, "memory_mb": None, "disk_gb": None})
            # This existing deployment field proves capacity does not replace
            # the complete JSON object with only the three discovered keys.
            if CustomField.objects.filter(key="vmid", content_types=device_ct).exists():
                raw["vmid"] = 918273
            Device.objects.filter(pk=target.pk).update(_custom_field_data=raw)
            target.refresh_from_db()
            blank_before = copy.deepcopy(target._custom_field_data)

            with CaptureQueriesContext(connection) as captured:
                preview = build_plan(discovery, snapshot_inventory(target, discovery=discovery))
                validate_plan(preview, target, interface_status=interface_status)
            _no_dml(captured, "Capacity preview issued inventory DML")
            assert not preview["errors"] and not preview["summary"]["blocked"]
            assert preview["summary"]["capacity_fields_updated"] == 1
            assert {
                row["field"]: row["after"] for row in preview["capacity"]["updates"]
            } == EXPECTED
            assert Device.objects.get(pk=target.pk)._custom_field_data == blank_before
            checks.append("native CPU capacity preview validates the fill without inventory DML")

            applied = apply_discovery(discovery, target, interface_status=interface_status)
            target.refresh_from_db()
            assert applied["summary"]["capacity_fields_updated"] == 1
            assert {key: target.cf[key] for key in EXPECTED} == EXPECTED
            assert target._custom_field_data == {**blank_before, **EXPECTED}
            assert target.cf["memory_mb"] is None and target.cf["disk_gb"] is None
            checks.append(
                "apply fills the existing CPU field and preserves unresolved memory/storage"
            )

            after = copy.deepcopy(target._custom_field_data)
            with CaptureQueriesContext(connection) as captured:
                repeated = apply_discovery(discovery, target, interface_status=interface_status)
            _no_dml(captured, "Repeated capacity apply issued inventory DML")
            assert repeated["summary"]["capacity_fields_updated"] == 0
            assert Device.objects.get(pk=target.pk)._custom_field_data == after
            checks.append("repeated capacity discovery issues zero inventory DML")

            # Zero and False are stored values, not empty capacity intent. The
            # unavailable memory/storage facts must preserve blank or populated
            # values, without borrowing deployment sizes from another source.
            for preserved in (0, False, 8):
                values = {**blank_before, "vcpus": preserved, "memory_mb": None, "disk_gb": 120}
                Device.objects.filter(pk=target.pk).update(_custom_field_data=values)
                target.refresh_from_db()
                with CaptureQueriesContext(connection) as captured:
                    preserved_plan = apply_discovery(
                        discovery, target, interface_status=interface_status
                    )
                _no_dml(captured, "Populated capacity intent issued inventory DML")
                saved = Device.objects.get(pk=target.pk)._custom_field_data
                assert saved == values
                assert type(saved["vcpus"]) is type(preserved)
                assert preserved_plan["summary"]["capacity_fields_updated"] == 0
                assert preserved_plan["capacity"]["conflicts"]
            checks.append("populated CPU intent, zero and Boolean values remain exact without DML")

            all_populated = {
                **blank_before,
                "vcpus": False,
                "memory_mb": 8192,
                "disk_gb": 60,
            }
            Device.objects.filter(pk=target.pk).update(
                _custom_field_data=all_populated, software_version=None
            )
            target.refresh_from_db()
            software_fill = _discovery(target.name, vm_uuid, version="99.99.9-h1")
            software_plan = apply_discovery(
                software_fill, target, interface_status=interface_status
            )
            saved = Device.objects.get(pk=target.pk)
            assert software_plan["summary"]["capacity_fields_updated"] == 0
            assert saved.software_version.version == "99.99.9-h1"
            assert saved._custom_field_data == all_populated
            assert saved.cf["vcpus"] is False
            checks.append("ordinary Device software fill preserves every populated capacity value")
            Device.objects.filter(pk=target.pk).update(software_version=version)

            def reset_blank():
                Device.objects.filter(pk=target.pk).update(_custom_field_data=blank_before)
                target.refresh_from_db()

            def schema_case(key, mutate, label):
                reset_blank()
                with transaction.atomic():
                    try:
                        mutate(definitions[key])
                        before = copy.deepcopy(Device.objects.get(pk=target.pk)._custom_field_data)
                        with CaptureQueriesContext(connection) as captured:
                            guarded = build_plan(
                                discovery, snapshot_inventory(target, discovery=discovery)
                            )
                            validate_plan(guarded, target, interface_status=interface_status)
                            guarded = apply_discovery(
                                discovery, target, interface_status=interface_status
                            )
                        assert key not in {row["field"] for row in guarded["capacity"]["updates"]}
                        saved = Device.objects.get(pk=target.pk)._custom_field_data
                        assert saved.get(key) == before.get(key)
                        assert guarded["capacity"]["unresolved"]
                        _no_dml(captured, "An ineligible CPU capacity field issued inventory DML")
                        assert not any(
                            WRITE_SQL.match(row["sql"])
                            and "extras_customfield" in row["sql"].lower()
                            for row in captured.captured_queries
                        ), "Discovery mutated the custom-field schema"
                        checks.append(label)
                    finally:
                        transaction.set_rollback(True)

            schema_case(
                "vcpus",
                lambda field: CustomField.objects.filter(pk=field.pk).update(
                    key="capacity-missing-" + token
                ),
                "missing capacity definition is unresolved without schema creation",
            )
            schema_case(
                "vcpus",
                lambda field: CustomField.objects.filter(pk=field.pk).update(type="text"),
                "non-integer capacity definition remains unresolved",
            )
            schema_case(
                "vcpus",
                lambda field: through.objects.filter(
                    customfield_id=field.pk, contenttype_id=device_ct.pk
                ).delete(),
                "capacity definition outside Device scope remains unresolved",
            )
            if scope_supported:
                schema_case(
                    "vcpus",
                    lambda field: CustomField.objects.filter(pk=field.pk).update(
                        scope_filter={"name": [target.name]}
                    ),
                    "filtered capacity definition is rejected conservatively",
                )

            schema_case(
                "vcpus",
                lambda field: CustomField.objects.filter(pk=field.pk).update(
                    validation_maximum=EXPECTED["vcpus"] - 1
                ),
                "capacity outside existing numeric bounds remains unresolved",
            )

            reset_blank()
            with transaction.atomic():
                try:
                    for key in EXPECTED:
                        definition = definitions[key]
                        CustomField.objects.filter(pk=definition.pk).update(
                            validation_maximum=EXPECTED[key] - 1
                        )
                    with CaptureQueriesContext(connection) as captured:
                        guarded = apply_discovery(
                            discovery, target, interface_status=interface_status
                        )
                    _no_dml(captured, "Capacity outside every numeric bound issued DML")
                    assert guarded["summary"]["capacity_fields_updated"] == 0
                    assert guarded["summary"]["unresolved_capacity"] >= 3
                    assert Device.objects.get(pk=target.pk)._custom_field_data == blank_before
                    checks.append("an entirely ineligible capacity plan issues zero inventory DML")
                finally:
                    transaction.set_rollback(True)

            reset_blank()
            original_validate = CustomField.validate
            native_validation_seen = []

            def native_rejection(field, value, *args, **kwargs):
                if field.key == "vcpus" and value == EXPECTED["vcpus"]:
                    native_validation_seen.append(True)
                    raise ValidationError("Intentional native capacity field validator rejection")
                return original_validate(field, value, *args, **kwargs)

            with patch.object(CustomField, "validate", native_rejection):
                with CaptureQueriesContext(connection) as captured:
                    try:
                        apply_discovery(discovery, target, interface_status=interface_status)
                    except ValidationError:
                        pass
                    else:
                        raise AssertionError("Native capacity field validator was bypassed")
            _no_dml(captured, "Native custom-field rejection occurred after inventory DML")
            assert native_validation_seen
            assert Device.objects.get(pk=target.pk)._custom_field_data == blank_before
            checks.append("native custom-field validator rejection blocks all writes before DML")

            invalid_source = copy.deepcopy(discovery)
            invalid_source["capacity"]["fields"]["vcpus"]["value"] += 1
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(invalid_source, target, interface_status=interface_status)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("Tampered capacity provenance was accepted")
            _no_dml(captured, "Tampered capacity provenance issued inventory DML")
            assert Device.objects.get(pk=target.pk)._custom_field_data == blank_before
            checks.append("tampered allocation provenance blocks the complete plan before DML")

            reset_blank()
            Device.objects.filter(pk=target.pk).update(software_version=None)
            target.refresh_from_db()
            failing = _discovery(target.name, vm_uuid, ports=(104, 105), version="99.99.8-h1")
            before_failure = snapshot_inventory(target, discovery=failing)
            software_count = SoftwareVersion.objects.count()
            interface_count = Interface.objects.count()
            original_save = Interface.validated_save
            writes_seen = []

            def fail_late(interface, *args, **kwargs):
                if interface.name == "ethernet1/105":
                    saved = Device.objects.get(pk=target.pk)
                    assert {key: saved.cf[key] for key in EXPECTED} == EXPECTED
                    assert saved.cf["memory_mb"] is None and saved.cf["disk_gb"] is None
                    assert saved.software_version.version == "99.99.8-h1"
                    assert target.interfaces.filter(name="ethernet1/104").exists()
                    writes_seen.append(True)
                    raise ValidationError({"name": "Intentional late capacity rollback failure"})
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", fail_late):
                try:
                    apply_discovery(failing, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("Late capacity rollback failure did not occur")
            assert writes_seen, "Capacity rollback fixture did not first write inventory"
            assert (
                snapshot_inventory(Device.objects.get(pk=target.pk), discovery=failing)
                == before_failure
            )
            assert Device.objects.get(pk=target.pk)._custom_field_data == blank_before
            assert SoftwareVersion.objects.count() == software_count
            assert Interface.objects.count() == interface_count
            checks.append("late failure rolls capacity, software and preceding interfaces back")
        finally:
            transaction.set_rollback(True)

    assert Device.objects.get(pk=anchor.pk)._custom_field_data == anchor_before
    assert {
        model._meta.label: model.objects.count() for model in (*tracked, through)
    } == counts_before
    assert (
        list(CustomField.objects.filter(key__in=FIELDS).order_by("key").values(*metadata_fields))
        == metadata_before
    )
    assert (
        list(through.objects.filter(customfield__key__in=FIELDS).order_by("pk").values())
        == joins_before
    )
    checks.append("outer rollback restores anchor, native catalogs and field metadata")
    return {
        "anchor_device_id": str(anchor.pk),
        "passed": True,
        "checks": checks,
        "persistent_changes": 0,
        "scope_filter_available": scope_supported,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
