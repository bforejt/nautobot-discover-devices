"""Prove ESXi native host reconciliation inside unconditional outer rollback.

Run in a configured Nautobot nbshell process with NAUTOBOT_DISCOVERY_DEVICE_ID
selecting an existing anchor. Synthetic sources exercise the production adapter
and actual installed ORM. An optional already-collected live source may be
provided without credentials or host connections. Every temporary catalog,
custom-field definition, Device, Interface and Cable is rolled back.
"""

import copy
import json
import os
import re
import runpy
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)
HOST_UUID = "dce10001-0002-0003-0004-000000000005"


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _source(name, vendor, model, serial, *, ports=(0, 1, 2), build="24677879"):
    """Independent fixture builder, safe inside configured Django imports."""
    product = {
        "apiType": "HostAgent",
        "apiVersion": "8.0.3.0",
        "productLineId": "embeddedEsx",
        "vendor": "VMware, Inc.",
        "version": "8.0.3",
        "build": build,
    }
    pnics = []
    for index, port in enumerate(ports):
        row = {
            "device": "vmnic%d" % port,
            "key": "key-vim.host.PhysicalNic-vmnic%d" % port,
            "pci": "0000:00:%02x.0" % (0x12 + index),
            "driver": "ixgben",
            "mac": "02:ac:00:00:01:%02x" % (index + 1),
        }
        if index != 1:
            row["linkSpeed"] = {"speedMb": 10000, "duplex": True}
        pnics.append(row)
    return {
        "service": dict(product),
        "host": {
            "ref": "ha-host",
            "properties": {
                "name": name,
                "config.product": dict(product),
                "hardware.systemInfo": {
                    "vendor": vendor,
                    "model": model,
                    "uuid": HOST_UUID,
                    "serialNumber": serial,
                },
                "summary": {
                    "hardware": {
                        "vendor": vendor,
                        "model": model,
                        "uuid": HOST_UUID,
                        "numCpuPkgs": 1,
                        "numCpuCores": 8,
                        "numCpuThreads": 16,
                        "memorySize": 68719476736,
                    },
                    "config": {"name": name},
                },
                "config.network.pnic": pnics,
                "config.network.vnic": [
                    {
                        "device": "vmk0",
                        "key": "vmk0",
                        "portgroup": "Management",
                        "spec": {
                            "ip": {
                                "ipAddress": "192.0.2.1",
                                "subnetMask": "255.255.255.0",
                                "dhcp": False,
                            }
                        },
                    }
                ],
                "vm": [],
                "datastore": [],
            },
        },
        "guests": [],
        "datastores": [],
        "completeness": {
            "host": True,
            "guests": "permission-scoped",
            "datastores": "permission-scoped",
        },
    }


def _collect(raw, *, enabled=False, bound=True):
    from jobs.adapters import esxi

    expected = raw["host"]["properties"]["hardware.systemInfo"]["uuid"] if bound else None
    policy = (
        None
        if enabled is None
        else {
            "contract": "esxi-interface-policy-v1",
            "new_enabled": enabled,
        }
    )
    return esxi.collect(
        SimpleNamespace(discovery=lambda: copy.deepcopy(raw)),
        expected_host_uuid=expected,
        interface_enabled_policy=policy,
    )


def _live_source(path):
    from jobs.adapters import esxi

    payload = json.loads(Path(path).read_text())
    if payload.get("adapter") == "esxi":
        return esxi.reconstruct(payload)["source"]["inventory"]
    return payload


def run(device_id=None, *, live_source_path=None, include_guest_checks=False):
    """Verify previews, apply, preserved intent, repeat and late native-save rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import nautobot
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Cable,
        Device,
        DeviceType,
        Interface,
        InterfaceTemplate,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import CustomField, RelationshipAssociation, Status

    from jobs.discovery_job import _adapter
    from jobs.nautobot_inventory import (
        InventoryError,
        apply_discovery,
        snapshot_inventory,
        validate_plan,
    )
    from jobs.reconcile import _mac, build_plan

    selected = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not selected:
        raise ValueError("Select an existing anchor with NAUTOBOT_DISCOVERY_DEVICE_ID")
    anchor = Device.objects.select_related("location", "role", "status").get(pk=selected)
    anchor_before = snapshot_inventory(anchor)
    anchor_custom = copy.deepcopy(anchor._custom_field_data)
    tracked = (
        Manufacturer,
        Platform,
        DeviceType,
        Device,
        InterfaceTemplate,
        Interface,
        SoftwareVersion,
        Cable,
        CableToCableTermination,
        CustomField,
        CustomField.content_types.through,
        RelationshipAssociation,
    )
    counts_before = {model._meta.label: model.objects.count() for model in tracked}
    relationships_before = list(RelationshipAssociation.objects.order_by("pk").values())
    custom_metadata_before = list(CustomField.objects.order_by("pk").values("id", "key", "type"))
    interface_status = Status.objects.get_for_model(Interface).get(name="Active")
    cable_status = Status.objects.get_for_model(Cable).get(name="Connected")
    checks = []
    token = uuid.uuid4().hex[:12]

    def uncached_fields(manager, model, exclude_filter_disabled=False, get_queryset=True):
        """Avoid retaining rolled-back custom-field fixture metadata in process caches."""
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
            manufacturer = Manufacturer(name="ESXi synthetic " + token)
            manufacturer.validated_save()
            platform = Platform(
                name="ESXi synthetic " + token, network_driver="esxi", manufacturer=manufacturer
            )
            platform.validated_save()
            device_type = DeviceType(manufacturer=manufacturer, model="ESXI-SYNTHETIC-" + token)
            device_type.validated_save()
            target = Device(
                name="esxi-native-" + token,
                serial="",
                device_type=device_type,
                platform=platform,
                role=anchor.role,
                location=anchor.location,
                status=anchor.status,
            )
            target.validated_save()
            assert _adapter(target).__name__.endswith(".esxi")
            checks.append("native ESXi Platform dispatch selects the standalone adapter")

            definitions = []
            for kind, value in (("boolean", False), ("integer", 0), ("text", "Other")):
                field = CustomField(
                    key="esxi_%s_%s" % (kind, token),
                    label="ESXi synthetic %s %s" % (kind, token),
                    type=kind,
                )
                field.validated_save()
                field.content_types.add(
                    ContentType.objects.get_for_model(Device),
                    ContentType.objects.get_for_model(Interface),
                )
                definitions.append((field.key, value))
            default_field = CustomField(
                key="esxi_default_" + token,
                label="ESXi synthetic default " + token,
                type="text",
                default="UNREQUESTED-DEFAULT",
            )
            default_field.validated_save()
            default_field.content_types.add(ContentType.objects.get_for_model(Interface))
            preserved_custom = {key: value for key, value in definitions}
            preserved_custom["unrelated_esxi_" + token] = {
                "zero": 0,
                "false": False,
                "text": "Other",
            }
            Device.objects.filter(pk=target.pk).update(_custom_field_data=preserved_custom)
            target.refresh_from_db()
            InterfaceTemplate(
                device_type=device_type, name="vmnic1", type="10gbase-t"
            ).validated_save()
            port = Interface(
                device=target,
                name="vmnic0",
                type="other",
                enabled=False,
                description="Operator description",
                mtu=9000,
                speed=0,
                mac_address="02:00:00:00:00:01",
                status=interface_status,
                _custom_field_data={key: value for key, value in definitions},
            )
            port.validated_save()
            updater = Interface(
                device=target,
                name="vmnic4",
                type="other",
                enabled=False,
                speed=0,
                status=interface_status,
                _custom_field_data={key: value for key, value in definitions},
            )
            updater.validated_save()
            updater_custom = {key: value for key, value in definitions}
            integer_key = next(key for key, value in definitions if type(value) is int)
            updater_custom[integer_key] = "0"
            Interface.objects.filter(pk=updater.pk).update(_custom_field_data=updater_custom)
            updater.refresh_from_db()
            assert default_field.key not in updater._custom_field_data
            assert updater._custom_field_data[integer_key] == "0"
            peer = Interface(
                device=target,
                name="vmnic99",
                type="1000base-t",
                enabled=False,
                status=interface_status,
            )
            peer.validated_save()
            cable = Cable(status=cable_status)
            cable.validated_save()
            for end, interface in (("A", port), ("B", peer)):
                CableToCableTermination(
                    cable=cable, cable_end=end, connector=1, interface=interface
                ).validated_save()
            port.refresh_from_db()
            port_id, port_custom = port.pk, copy.deepcopy(port._custom_field_data)
            cable_joins = list(cable.terminations.order_by("pk").values())
            serial = "ESXI-" + token
            raw = _source(
                target.name, manufacturer.name, device_type.model, serial, ports=(0, 1, 2, 4)
            )
            observed = _collect(raw, enabled=False)
            before = snapshot_inventory(target, discovery=observed)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(observed, snapshot_inventory(target, discovery=observed))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "ESXi preview issued inventory DML")
            assert not plan["summary"]["blocked"] and not plan["errors"]
            assert len(plan["interface_creates"]) == 2
            assert {row["name"]: row["type"] for row in plan["interface_creates"]} == {
                "vmnic1": "10gbase-t",
                "vmnic2": "other",
            }
            assert all(row["enabled"] is False for row in plan["interface_creates"])
            assert all(
                row["enabled_source"]["new_enabled"] is False for row in plan["interface_creates"]
            )
            assert snapshot_inventory(target, discovery=observed) == before
            checks.append(
                "native preview validates software and template/Other interfaces with zero DML"
            )

            applied = apply_discovery(observed, target, interface_status=interface_status)
            target.refresh_from_db()
            port.refresh_from_db()
            assert applied["summary"]["interfaces_created"] == 2
            assert (
                target.serial == serial
                and target.software_version.version == "8.0.3 build-24677879"
            )
            assert target.platform_id == platform.pk and target.device_type_id == device_type.pk
            assert target._custom_field_data == preserved_custom
            assert port.pk == port_id and port.type == "other" and port.enabled is False
            assert (
                port.speed == 0 and port.mtu == 9000 and port.description == "Operator description"
            )
            assert str(port.mac_address) == "02:00:00:00:00:01" and port.cable_id == cable.pk
            assert port._custom_field_data == port_custom
            updater.refresh_from_db()
            assert _mac(updater.mac_address) == "02:ac:00:00:01:04"
            assert updater._custom_field_data == updater_custom
            assert updater._custom_field_data[integer_key] == "0"
            assert default_field.key not in updater._custom_field_data
            checks.append(
                "existing Interface MAC fill preserves raw integer text and missing CF default"
            )
            assert list(cable.terminations.order_by("pk").values()) == cable_joins
            assert target.interfaces.get(name="vmnic1").enabled is False
            assert target.interfaces.get(name="vmnic2").speed == 10000000
            checks.append(
                "apply fills serial/exact build and preserves False, zero, Other and exact CF data"
            )
            checks.append(
                "native interface UUIDs, populated intent, owners and cable joins are preserved"
            )
            assert (
                list(RelationshipAssociation.objects.order_by("pk").values())
                == relationships_before
            )
            checks.append("host-only discovery leaves every existing native relationship unchanged")

            after = snapshot_inventory(target, discovery=observed)
            with CaptureQueriesContext(connection) as captured:
                repeated = apply_discovery(observed, target, interface_status=interface_status)
            _no_dml(captured, "Unchanged ESXi repeat issued inventory DML")
            assert repeated["summary"]["interfaces_created"] == 0
            assert repeated["summary"]["interfaces_updated"] == 0
            assert repeated["summary"]["device_fields_updated"] == 0
            assert snapshot_inventory(target, discovery=observed) == after
            checks.append("unchanged repeat has zero native inventory DML")

            unresolved = _collect(
                _source(target.name, manufacturer.name, device_type.model, serial, ports=(3,)),
                enabled=None,
            )
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(unresolved, snapshot_inventory(target, discovery=unresolved))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "Missing creation policy preview issued DML")
            assert not plan["errors"] and plan["interface_creates"] == []
            checks.append(
                "new-interface creation is deferred when admin state and operator policy are absent"
            )

            enabled = _collect(
                _source(target.name, manufacturer.name, device_type.model, serial, ports=(3,)),
                enabled=True,
            )
            applied = apply_discovery(enabled, target, interface_status=interface_status)
            assert applied["summary"]["interfaces_created"] == 1
            assert target.interfaces.get(name="vmnic3").enabled is True
            checks.append(
                "explicit True creation policy is separate from unavailable source admin state"
            )

            for reason in ("model", "serial", "vendor", "uuid-binding", "source", "missing-serial"):
                bad_raw = copy.deepcopy(raw)
                properties = bad_raw["host"]["properties"]
                if reason in {"model", "vendor"}:
                    for hardware in (
                        properties["hardware.systemInfo"],
                        properties["summary"]["hardware"],
                    ):
                        hardware[reason] = "WRONG"
                elif reason == "serial":
                    properties["hardware.systemInfo"]["serialNumber"] = "WRONG"
                elif reason == "missing-serial":
                    properties["hardware.systemInfo"].pop("serialNumber")
                bad = _collect(bad_raw, bound=reason != "missing-serial")
                if reason == "uuid-binding":
                    bad["identity_binding"]["expected_uuid"] = str(uuid.uuid4())
                elif reason == "source":
                    bad["source"]["inventory"]["service"]["build"] = "1"
                before_bad = snapshot_inventory(target, discovery=bad)
                with CaptureQueriesContext(connection) as captured:
                    try:
                        apply_discovery(bad, target, interface_status=interface_status)
                    except InventoryError:
                        pass
                    else:
                        raise AssertionError("ESXi native apply accepted invalid " + reason)
                _no_dml(captured, "Invalid ESXi identity/source guard issued DML")
                assert snapshot_inventory(target, discovery=bad) == before_bad
                checks.append("native apply blocks %s without inventory DML" % reason)

            too_long = Interface._meta.get_field("name").max_length
            invalid_raw = _source(
                target.name, manufacturer.name, device_type.model, serial, ports=(10,)
            )
            invalid_raw["host"]["properties"]["config.network.pnic"][0]["device"] = (
                "vmnic" + "9" * too_long
            )
            invalid = _collect(invalid_raw)
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(invalid, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("ESXi oversized interface name passed native validation")
            _no_dml(
                captured, "Whole-plan ESXi validation issued DML before rejecting an invalid row"
            )
            checks.append(
                "full native model validation rejects an invalid source-backed row before writes"
            )

            missing_serial = _source(
                target.name, manufacturer.name, device_type.model, "unknown", ports=()
            )
            bound = _collect(missing_serial)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(bound, snapshot_inventory(target, discovery=bound))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "UUID-bound missing serial preview issued DML")
            assert not plan["errors"]
            assert not any(change["field"] == "serial" for change in plan["device_updates"])
            checks.append(
                "explicit matching BIOS UUID permits missing serial without a fabricated serial"
            )

            Device.objects.filter(pk=target.pk).update(software_version=None)
            target.refresh_from_db()
            failing = _collect(
                _source(
                    target.name,
                    manufacturer.name,
                    device_type.model,
                    serial,
                    ports=(90, 91),
                    build="24677880",
                )
            )
            before_failure = snapshot_inventory(target, discovery=failing)
            version_count, port_count = SoftwareVersion.objects.count(), Interface.objects.count()
            original_save, writes_seen = Interface.validated_save, []

            def fail_late(interface, *args, **kwargs):
                if interface.name == "vmnic91":
                    assert target.interfaces.filter(name="vmnic90").exists()
                    saved = Device.objects.get(pk=target.pk)
                    assert saved.software_version.version == "8.0.3 build-24677880"
                    assert saved._custom_field_data == preserved_custom
                    writes_seen.append(True)
                    raise ValidationError({"name": "Intentional final ESXi interface save failure"})
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", fail_late):
                try:
                    apply_discovery(failing, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("ESXi late native interface failure did not occur")
            assert writes_seen, "ESXi late rollback did not first save software and an interface"
            assert (
                snapshot_inventory(Device.objects.get(pk=target.pk), discovery=failing)
                == before_failure
            )
            assert (
                SoftwareVersion.objects.count() == version_count
                and Interface.objects.count() == port_count
            )
            checks.append(
                "late interface failure rolls back preceding software, Device and interface writes"
            )

            if live_source_path is not None:
                live = copy.deepcopy(_live_source(live_source_path))
                observed_live = _collect(live, enabled=True)
                live_identity = observed_live["identity"]
                live_vendor = Manufacturer.objects.filter(name=live_identity["vendor"]).first()
                if live_vendor is None:
                    live_vendor = Manufacturer(name=live_identity["vendor"])
                    live_vendor.validated_save()
                live_type = DeviceType(manufacturer=live_vendor, model=live_identity["model"])
                existing_type = DeviceType.objects.filter(
                    manufacturer=live_vendor, model=live_identity["model"]
                ).first()
                if existing_type is None:
                    live_type.validated_save()
                else:
                    live_type = existing_type
                live_platform = Platform(
                    name="ESXi source proof " + token,
                    network_driver="esxi",
                    manufacturer=live_vendor,
                )
                live_platform.validated_save()
                live_target = Device(
                    name="esxi-source-proof-" + token,
                    serial="",
                    device_type=live_type,
                    platform=live_platform,
                    role=anchor.role,
                    location=anchor.location,
                    status=anchor.status,
                )
                live_target.validated_save()
                with CaptureQueriesContext(connection) as captured:
                    plan = build_plan(
                        observed_live, snapshot_inventory(live_target, discovery=observed_live)
                    )
                    validate_plan(plan, live_target, interface_status=interface_status)
                _no_dml(captured, "Already-collected live ESXi native preview issued DML")
                assert not plan["errors"]
                applied = apply_discovery(
                    observed_live, live_target, interface_status=interface_status
                )
                live_target.refresh_from_db()
                assert live_target.name == "esxi-source-proof-" + token
                assert live_target.software_version.version == live_identity["software_version"]
                assert applied["summary"]["interfaces_created"] == len(observed_live["interfaces"])
                checks.append(
                    "collected live ESXi source validates and applies in an ephemeral native copy"
                )

        finally:
            transaction.set_rollback(True)

    restored_anchor = Device.objects.get(pk=anchor.pk)
    assert snapshot_inventory(restored_anchor) == anchor_before
    assert restored_anchor._custom_field_data == anchor_custom
    assert {model._meta.label: model.objects.count() for model in tracked} == counts_before
    assert list(RelationshipAssociation.objects.order_by("pk").values()) == relationships_before
    assert (
        list(CustomField.objects.order_by("pk").values("id", "key", "type"))
        == custom_metadata_before
    )
    checks.append(
        "outer rollback restores anchor, catalogs, custom-field definitions and relationships"
    )
    result = {
        "anchor_device_id": str(anchor.pk),
        "passed": True,
        "native_version": nautobot.__version__,
        "checks": checks,
        "checks_passed": len(checks),
        "persistent_changes": 0,
    }
    if include_guest_checks:
        guest_module = runpy.run_path(
            str(Path(__file__).with_name("nautobot_esxi_guests_integration.py"))
        )
        result["hosted_on"] = guest_module["run"](device_id=str(anchor.pk))
    return result


if __name__ == "__main__":
    print(
        json.dumps(
            run(live_source_path=os.environ.get("NAUTOBOT_ESXI_SOURCE_PATH")),
            indent=2,
            sort_keys=True,
        )
    )
