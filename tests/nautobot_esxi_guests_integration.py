"""Prove existing Hosted On ESXi guest links inside unconditional outer rollback.

Run in a configured Nautobot Django process with an explicit anchor Device UUID.
No ESXi endpoint is contacted. All temporary Devices and associations roll back;
no Relationship or custom-field schema is created or modified.
"""

import copy
import json
import os
import re
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)
HOST_UUID = "00000011-0000-4000-8000-000000000011"
VM_UUIDS = tuple("0000002%d-0000-4000-8000-00000000002%d" % (n, n) for n in range(1, 5))


def _inventory(host, guest_uuids, *, nic=False, build="24677879"):
    """Independent SDK fixture factory; never import the offline synthetic loader."""
    product = {
        "apiType": "HostAgent",
        "apiVersion": "8.0.3.0",
        "productLineId": "embeddedEsx",
        "vendor": "VMware, Inc.",
        "version": "8.0.3",
        "build": build,
    }
    host_properties = {
        "name": host.name,
        "config.product": dict(product),
        "hardware.systemInfo": {
            "uuid": HOST_UUID,
            "vendor": host.device_type.manufacturer.name,
            "model": host.device_type.model,
            "serialNumber": host.serial,
        },
        "summary.hardware": {
            "uuid": HOST_UUID,
            "vendor": host.device_type.manufacturer.name,
            "model": host.device_type.model,
        },
        "config.network.pnic": [],
        "hardware.pciDevice": [],
        "vm": [{"type": "VirtualMachine", "ref": str(n)} for n in range(1, len(guest_uuids) + 1)],
    }
    if nic:
        host_properties["config.network.pnic"] = [
            {
                "device": "vmnic999",
                "key": "key-vim.host.PhysicalNic-vmnic999",
                "pci": "0000:00:12.0",
                "mac": "02:ac:00:00:09:99",
                "driver": "ixgben",
            }
        ]
        host_properties["hardware.pciDevice"] = [
            {
                "id": "0000:00:12.0",
                "vendorId": "32902",
                "deviceId": "4110",
            }
        ]
    return {
        "service": dict(product),
        "host": {"ref": "ha-host", "properties": host_properties},
        "guests": [
            {
                "ref": str(n),
                "properties": {
                    "name": "reported-vnf-%d" % n,
                    "config.uuid": identifier,
                    "config.template": False,
                    "runtime.host": {"type": "HostSystem", "ref": "ha-host"},
                    "runtime.connectionState": "connected",
                    "runtime.powerState": "poweredOff",
                    "config.hardware.numCPU": "8",
                    "config.hardware.memoryMB": "8192",
                },
            }
            for n, identifier in enumerate(guest_uuids, 1)
        ],
        "datastores": [],
        "completeness": {
            "host": True,
            "guests": "permission-scoped",
            "datastores": "permission-scoped",
        },
    }


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def run(device_id=None):
    """Validate explicit identity, ownership preservation, repeats and late rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, Interface, Platform, SoftwareVersion
    from nautobot.extras.models import CustomField, Relationship, RelationshipAssociation

    from jobs.adapters import esxi
    from jobs.discovery_job import _resolve_esxi_guest_target
    from jobs.esxi_guest_policy import normalize_esxi_guest_policy
    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    selected_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not selected_id:
        raise ValueError("Select an existing anchor Device UUID for native ESXi guest checks")
    anchor = Device.objects.select_related(
        "device_type__manufacturer", "location", "role", "status"
    ).get(pk=selected_id)
    relationship = Relationship.objects.get(key="hosted_on")
    assert relationship.type == "one-to-many"
    assert relationship.source_type.app_label == relationship.destination_type.app_label == "dcim"
    assert relationship.source_type.model == relationship.destination_type.model == "device"
    assert relationship.source_filter is None and relationship.destination_filter is None
    relationship_before = Relationship.objects.filter(pk=relationship.pk).values().get()
    anchor_before = {
        "name": anchor.name,
        "serial": anchor.serial,
        "custom_fields": copy.deepcopy(anchor._custom_field_data),
        "software_version_id": anchor.software_version_id,
        "platform_id": anchor.platform_id,
    }
    tracked = (
        Device,
        Interface,
        Platform,
        SoftwareVersion,
        Relationship,
        RelationshipAssociation,
        CustomField,
    )
    counts = {model._meta.label: model.objects.count() for model in tracked}
    checks = []

    with transaction.atomic():
        try:
            token = uuid.uuid4().hex[:12]
            platform = Platform(name="ESXi-guest-native-" + token, network_driver="esxi")
            platform.validated_save()

            def device(name):
                obj = Device(
                    name=name + "-" + token,
                    serial="ESXG-" + name + "-" + token,
                    device_type=anchor.device_type,
                    location=anchor.location,
                    role=anchor.role,
                    status=anchor.status,
                    platform=platform,
                )
                obj.validated_save()
                return obj

            host, other = device("host"), device("other-host")
            guests = [device("native-vnf-%d" % n) for n in range(1, 5)]
            for guest in guests:
                values = copy.deepcopy(guest._custom_field_data)
                values.update(vcpus=0, memory_mb=False)
                Device.objects.filter(pk=guest.pk).update(_custom_field_data=values)
                guest.refresh_from_db()
            guest_before = {
                str(guest.pk): {
                    "name": guest.name,
                    "serial": guest.serial,
                    "platform_id": guest.platform_id,
                    "custom_fields": copy.deepcopy(guest._custom_field_data),
                }
                for guest in guests
            }
            device_type = ContentType.objects.get(app_label="dcim", model="device")

            def observed(indices=(0,), **options):
                identifiers = [VM_UUIDS[n] for n in indices]
                raw = _inventory(host, identifiers, **options)
                discovery = esxi.collect(
                    SimpleNamespace(discovery=lambda: raw),
                    expected_host_uuid=HOST_UUID,
                    interface_enabled_policy=(
                        {"contract": "esxi-interface-policy-v1", "new_enabled": True}
                        if options.get("nic")
                        else None
                    ),
                )
                discovery["guest_policy"] = normalize_esxi_guest_policy(
                    json.dumps(
                        [{"vm_uuid": VM_UUIDS[n], "device": str(guests[n].pk)} for n in indices]
                    ),
                    _resolve_esxi_guest_target,
                    selected_device_id=str(host.pk),
                )
                return discovery

            def preview(discovery):
                planned = build_plan(discovery, snapshot_inventory(host, discovery=discovery))
                validate_plan(planned, host)
                return planned

            data = observed()
            with CaptureQueriesContext(connection) as captured:
                planned = preview(data)
            _no_dml(captured, "Hosted On preview issued DML")
            assert not planned["errors"], planned["errors"]
            assert planned["esxi_guests"]["summary"]["hosted_on_created"] == 1
            assert Relationship.objects.count() == counts[Relationship._meta.label]
            assert CustomField.objects.count() == counts[CustomField._meta.label]
            checks.append("preview uses the exact existing Hosted On schema with zero DML")

            applied = apply_discovery(data, host)
            assert applied["summary"]["hosted_on_created"] == 1
            linked = RelationshipAssociation.objects.get(
                relationship=relationship, destination_type=device_type, destination_id=guests[0].pk
            )
            assert linked.source_type_id == device_type.pk and linked.source_id == host.pk
            linked_id = linked.pk
            host.refresh_from_db()
            assert host.software_version.version == "8.0.3 build-24677879"
            checks.append("positive host-local BIOS UUID evidence fills one native guest link")
            before_repeat = snapshot_inventory(host, discovery=data)
            with CaptureQueriesContext(connection) as captured:
                repeated = apply_discovery(data, host)
            _no_dml(captured, "Unchanged Hosted On apply issued DML")
            assert repeated["summary"]["hosted_on_created"] == 0
            assert RelationshipAssociation.objects.get(pk=linked_id).source_id == host.pk
            assert snapshot_inventory(host, discovery=data) == before_repeat
            checks.append("unchanged apply keeps the existing association UUID and issues no DML")

            foreign = RelationshipAssociation(
                relationship=relationship,
                source_type=device_type,
                source_id=other.pk,
                destination_type=device_type,
                destination_id=guests[1].pk,
            )
            foreign.validated_save()
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(observed((1,)), host)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("Conflicting Hosted On source unexpectedly passed")
            _no_dml(captured, "Conflicting Hosted On source issued DML")
            assert RelationshipAssociation.objects.get(pk=foreign.pk).source_id == other.pk
            checks.append("existing foreign host ownership blocks reparenting without DML")

            cases = []
            missing = observed((2,))
            missing["guest_policy"]["mappings"][0]["device"]["id"] = str(uuid.uuid4())
            cases.append(("missing existing guest Device", missing))
            duplicate = observed((2, 3))
            duplicate["guest_policy"]["mappings"][1]["vm_uuid"] = VM_UUIDS[2]
            cases.append(("duplicate guest UUID mapping", duplicate))
            foreign_host = observed((2,))
            foreign_host["source"]["inventory"]["guests"][0]["properties"]["runtime.host"] = {
                "type": "HostSystem",
                "ref": "another-host",
            }
            cases.append(("foreign host source evidence", foreign_host))
            template = observed((2,))
            template["source"]["inventory"]["guests"][0]["properties"]["config.template"] = True
            cases.append(("template source evidence", template))
            for label, invalid in cases:
                with CaptureQueriesContext(connection) as captured:
                    try:
                        apply_discovery(invalid, host)
                    except (InventoryError, ValueError):
                        pass
                    else:
                        raise AssertionError(label + " unexpectedly passed")
                _no_dml(captured, label + " issued DML")
                checks.append(label + " blocks all proposed links with zero DML")

            Device.objects.filter(pk=host.pk).update(software_version=None)
            host.refresh_from_db()
            late = observed((2, 3), nic=True, build="24677880")
            before_failure = snapshot_inventory(host, discovery=late)
            failure_counts = {model._meta.label: model.objects.count() for model in tracked}
            rollback_rows = build_plan(late, snapshot_inventory(host, discovery=late))[
                "esxi_guests"
            ]["creates"]
            assert len(rollback_rows) == 2
            first_guest_id = rollback_rows[0]["destination_id"]
            failing_guest_id = rollback_rows[-1]["destination_id"]
            original_save = RelationshipAssociation.validated_save
            writes_seen = []

            def fail_after_earlier_writes(association, *args, **kwargs):
                if str(association.destination_id) == failing_guest_id:
                    assert RelationshipAssociation.objects.filter(
                        relationship=relationship,
                        source_id=host.pk,
                        destination_id=first_guest_id,
                    ).exists()
                    assert Interface.objects.filter(device=host, name="vmnic999").exists()
                    assert SoftwareVersion.objects.filter(
                        platform=platform, version="8.0.3 build-24677880"
                    ).exists()
                    writes_seen.append("software, interface and first association written")
                    raise ValidationError("Intentional later guest association failure")
                return original_save(association, *args, **kwargs)

            with patch.object(RelationshipAssociation, "validated_save", fail_after_earlier_writes):
                try:
                    apply_discovery(late, host)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("Injected later guest association failure did not occur")
            assert writes_seen, "Late guest rollback proof did not write preceding rows"
            assert (
                snapshot_inventory(Device.objects.get(pk=host.pk), discovery=late) == before_failure
            )
            assert {model._meta.label: model.objects.count() for model in tracked} == failure_counts
            checks.append(
                "late guest failure rolls back earlier software, interface and guest writes"
            )

            for guest in guests:
                guest.refresh_from_db()
                assert {
                    "name": guest.name,
                    "serial": guest.serial,
                    "platform_id": guest.platform_id,
                    "custom_fields": guest._custom_field_data,
                } == guest_before[str(guest.pk)]
            assert (
                Relationship.objects.filter(pk=relationship.pk).values().get()
                == relationship_before
            )
            checks.append(
                "guest sizing intent, unrelated data and relationship definition stay exact"
            )
        finally:
            transaction.set_rollback(True)

    anchor.refresh_from_db()
    assert {
        "name": anchor.name,
        "serial": anchor.serial,
        "custom_fields": anchor._custom_field_data,
        "software_version_id": anchor.software_version_id,
        "platform_id": anchor.platform_id,
    } == anchor_before
    assert {model._meta.label: model.objects.count() for model in tracked} == counts
    assert Relationship.objects.filter(pk=relationship.pk).values().get() == relationship_before
    checks.append("outer rollback restores the anchor and every tracked native catalog count")
    return {
        "device_id": str(anchor.pk),
        "relationship_id": str(relationship.pk),
        "passed": True,
        "persistent_changes": 0,
        "checks": checks,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
