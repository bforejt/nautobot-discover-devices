"""Prove existing Hosted On Proxmox guest links inside unconditional outer rollback.

Run in a configured Nautobot Django process with an explicit anchor Device UUID.
No Proxmox endpoint is contacted. All temporary Devices and associations roll back;
no Relationship or custom-field schema is created or modified.
"""

import copy
import json
import os
import re
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)
HOST_UUID = "00000011-0000-4000-8000-000000000011"
VM_UUIDS = tuple("0000002%d-0000-4000-8000-00000000002%d" % (n, n) for n in range(1, 5))


def _inventory(host, guest_uuids, *, nic=False, build="8.4.1"):
    """Independent API/Linux fixture factory; no offline synthetic loader import."""
    node = host.name
    version = {"version": build, "release": ".".join(build.split(".")[:2]), "repoid": "a1b2c3d4"}
    system = {
        "id": node,
        "class": "system",
        "vendor": host.device_type.manufacturer.name,
        "product": host.device_type.model,
        "serial": host.serial,
        "configuration": {"uuid": HOST_UUID},
        "children": [],
    }
    host_source = {
        "hostname": node,
        "dmi": {
            "sys_vendor": host.device_type.manufacturer.name,
            "product_name": host.device_type.model,
            "product_serial": host.serial,
            "chassis_serial": host.serial,
            "product_uuid": HOST_UUID,
        },
        "net": [],
        "pci": [],
        "errors": [],
        "unavailable": [],
    }
    links = []
    if nic:
        pci = "0000:00:12.0"
        driver = "/sys/bus/pci/drivers/igb"
        host_source["pci"] = [
            {
                "id": pci,
                "driver": driver,
                "physical_function": None,
                "virtual_functions": [],
                "vendor": "0x8086",
                "device": "0x1521",
                "class": "0x020000",
            }
        ]
        host_source["net"] = [
            {
                "name": "en999",
                "device": "/sys/devices/pci0000:00/" + pci,
                "driver": driver,
                "physical_function": None,
                "virtual_functions": [],
                "wireless": False,
                "type": "1",
                "carrier": "0",
                "speed": "-1",
            }
        ]
        system["children"] = [
            {
                "id": "network",
                "class": "network",
                "logicalname": "en999",
                "businfo": "pci@" + pci,
                "capabilities": {"ethernet": True},
                "configuration": {"driver": "igb"},
            }
        ]
        links = [
            {
                "ifindex": 999,
                "ifname": "en999",
                "link_type": "ether",
                "flags": ["BROADCAST", "MULTICAST", "UP"],
                "mtu": 1500,
                "address": "02:ac:00:00:09:99",
                "operstate": "DOWN",
            }
        ]
    guests = []
    permissions = {"/nodes/" + node: {"Sys.Audit": 1}, "/vms": {"VM.Audit": 1}}
    for n, identifier in enumerate(guest_uuids, 1):
        vmid = 100 + n
        summary = {"vmid": vmid, "name": "reported-vnf-%d" % n, "status": "stopped", "template": 0}
        config = {"smbios1": "uuid=" + identifier, "cores": 8, "memory": 8192, "template": 0}
        guests.append(
            {
                "kind": "qemu",
                "vmid": vmid,
                "node": node,
                "summary": summary,
                "config": dict(config),
                "current_config": dict(config),
                "pending": [],
                "status": {"vmid": vmid, "status": "stopped"},
            }
        )
        permissions["/vms/%s" % vmid] = {"VM.Audit": 1}
    host_source["guest_registry"] = {
        "version": 1,
        "ids": {
            str(row["vmid"]): {"node": node, "type": row["kind"], "version": 1} for row in guests
        },
    }
    return {
        "node": node,
        "api": {
            "version": dict(version),
            "node_version": dict(version),
            "cluster_status": [
                {"type": "node", "name": node, "local": 1, "id": "node/" + node, "online": 1}
            ],
            "node_status": {"memory": {"total": 17179869184, "used": 1073741824}},
            "permissions": permissions,
            "node_network": [],
            "node_network_changes": False,
            "storage": [],
            "qemu": [copy.deepcopy(row["summary"]) for row in guests],
            "lxc": [],
        },
        "ssh": {
            "host": host_source,
            "hardware": system,
            "links": links,
            "addresses": [],
            "bridge_vlans": [],
        },
        "guests": guests,
        "completeness": {
            "host": True,
            "interfaces": True,
            "network": True,
            "guests": True,
            "storage": "permission-scoped",
            "permission_scoped": True,
        },
    }


class _Client:
    """Serve bounded native JSON fixture endpoints without contacting any device."""

    def __init__(self, raw):
        self.raw = raw

    def get(self, path, params=None):
        api, node = self.raw["api"], self.raw["node"]
        base = "/nodes/" + node
        if path == "/access/permissions":
            scope = params["path"]
            return copy.deepcopy({scope: api["permissions"][scope]})
        endpoint = {
            "/version": "version",
            "/cluster/status": "cluster_status",
            base + "/version": "node_version",
            base + "/status": "node_status",
            base + "/storage": "storage",
            base + "/qemu": "qemu",
            base + "/lxc": "lxc",
        }.get(path)
        if endpoint is not None:
            return copy.deepcopy(api[endpoint])
        for guest in self.raw["guests"]:
            prefix = base + "/%s/%s" % (guest["kind"], guest["vmid"])
            if path == prefix + "/config":
                return copy.deepcopy(
                    guest["current_config" if params == {"current": 1} else "config"]
                )
            if path == prefix + "/pending":
                return copy.deepcopy(guest["pending"])
            if path == prefix + "/status/current":
                return copy.deepcopy(guest["status"])
        raise AssertionError("Unexpected fixture endpoint: " + path)

    def get_envelope(self, path):
        assert path == "/nodes/" + self.raw["node"] + "/network"
        return {"data": copy.deepcopy(self.raw["api"]["node_network"])}

    def ssh_json(self, source):
        return copy.deepcopy(self.raw["ssh"][source])


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

    from jobs.adapters import proxmox
    from jobs.discovery_job import _resolve_proxmox_guest_target
    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.proxmox_guest_policy import normalize_proxmox_guest_policy
    from jobs.reconcile import build_plan

    selected_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not selected_id:
        raise ValueError("Select an existing anchor Device UUID for native Proxmox guest checks")
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
            platform = Platform(name="Proxmox-guest-native-" + token, network_driver="proxmox")
            platform.validated_save()

            def device(name):
                obj = Device(
                    name=name + "-" + token,
                    serial="PVG-" + name + "-" + token,
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
                discovery = proxmox.collect(
                    _Client(raw),
                    expected_node=host.name,
                    expected_host_uuid=HOST_UUID,
                )
                discovery["guest_policy"] = normalize_proxmox_guest_policy(
                    json.dumps(
                        [{"vm_uuid": VM_UUIDS[n], "device": str(guests[n].pk)} for n in indices]
                    ),
                    _resolve_proxmox_guest_target,
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
            assert planned["proxmox_guests"]["summary"]["hosted_on_created"] == 1
            assert Relationship.objects.count() == counts[Relationship._meta.label]
            assert CustomField.objects.count() == counts[CustomField._meta.label]
            checks.append("preview uses the exact existing Hosted On schema with zero DML")

            for field, value in (
                ("kind", "lxc"),
                ("node", "foreign-node"),
                ("vmid", 99),
                ("vmid", True),
                ("vm_uuid", HOST_UUID),
                ("destination_id", str(other.pk)),
                ("unexpected", "unreviewed"),
            ):
                forged = copy.deepcopy(planned)
                forged["proxmox_guests"]["creates"][0][field] = value
                with CaptureQueriesContext(connection) as captured:
                    try:
                        validate_plan(forged, host)
                    except InventoryError:
                        pass
                    else:
                        raise AssertionError("Altered native guest %s unexpectedly passed" % field)
                _no_dml(captured, "Altered native guest %s issued DML" % field)
            duplicate_plan = copy.deepcopy(planned)
            duplicate_plan["proxmox_guests"]["creates"].append(
                copy.deepcopy(duplicate_plan["proxmox_guests"]["creates"][0])
            )
            with CaptureQueriesContext(connection) as captured:
                try:
                    validate_plan(duplicate_plan, host)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("Duplicate native guest destination unexpectedly passed")
            _no_dml(captured, "Duplicate native guest destination issued DML")
            checks.append(
                "altered QEMU kind, node, VMID, UUID and duplicate targets fail before DML"
            )

            applied = apply_discovery(data, host)
            assert applied["summary"]["hosted_on_created"] == 1
            linked = RelationshipAssociation.objects.get(
                relationship=relationship, destination_type=device_type, destination_id=guests[0].pk
            )
            assert linked.source_type_id == device_type.pk and linked.source_id == host.pk
            linked_id = linked.pk
            host.refresh_from_db()
            assert host.software_version.version == "8.4.1"
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
            hidden_guest = observed((2,))
            hidden_guest["source"]["inventory"]["ssh"]["host"]["guest_registry"]["ids"]["999"] = {
                "node": host.name,
                "type": "qemu",
                "version": 1,
            }
            cases.append(("registered guest hidden from API source", hidden_guest))
            absent_registration = observed((2,))
            absent_registration["source"]["inventory"]["ssh"]["host"]["guest_registry"]["ids"].pop(
                "101"
            )
            cases.append(("visible guest absent from host registry", absent_registration))
            wrong_registry_kind = observed((2,))
            wrong_registry_kind["source"]["inventory"]["ssh"]["host"]["guest_registry"]["ids"][
                "101"
            ]["type"] = "lxc"
            cases.append(("registry guest kind disagrees with API source", wrong_registry_kind))
            missing = observed((2,))
            missing["guest_policy"]["mappings"][0]["device"]["id"] = str(uuid.uuid4())
            cases.append(("missing existing guest Device", missing))
            duplicate = observed((2, 3))
            duplicate["guest_policy"]["mappings"][1]["vm_uuid"] = VM_UUIDS[2]
            cases.append(("duplicate guest UUID mapping", duplicate))
            foreign_host = observed((2,))
            foreign_host["source"]["inventory"]["guests"][0]["node"] = "another-host"
            cases.append(("foreign host source evidence", foreign_host))
            template = observed((2,))
            template["source"]["inventory"]["guests"][0]["current_config"]["template"] = 1
            cases.append(("template source evidence", template))
            pending_current_uuid = observed((2,))
            pending_current_uuid["source"]["inventory"]["guests"][0]["pending"] = [
                {"key": "smbios1", "value": "uuid=" + HOST_UUID}
            ]
            cases.append(("conflicting current UUID in pending source", pending_current_uuid))
            pending_current_template = observed((2,))
            pending_current_template["source"]["inventory"]["guests"][0]["pending"] = [
                {"key": "template", "value": 1}
            ]
            cases.append(("template current value in pending source", pending_current_template))
            pending_current_lock = observed((2,))
            pending_current_lock["source"]["inventory"]["guests"][0]["pending"] = [
                {"key": "lock", "value": "migrate"}
            ]
            cases.append(("migration lock in pending source", pending_current_lock))
            config_lock = observed((2,))
            config_lock["source"]["inventory"]["guests"][0]["config"]["lock"] = "migrate"
            cases.append(("migration lock in merged config source", config_lock))
            opaque_args = observed((2,))
            opaque_args["source"]["inventory"]["guests"][0]["current_config"]["args"] = True
            cases.append(("opaque custom QEMU identity arguments", opaque_args))
            pending_args = observed((2,))
            pending_args["source"]["inventory"]["guests"][0]["pending"] = [
                {"key": "args", "pending": True}
            ]
            cases.append(("opaque pending QEMU identity arguments", pending_args))
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
            late = observed((2, 3), nic=True, build="8.4.2")
            before_failure = snapshot_inventory(host, discovery=late)
            failure_counts = {model._meta.label: model.objects.count() for model in tracked}
            rollback_rows = build_plan(late, snapshot_inventory(host, discovery=late))[
                "proxmox_guests"
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
                    assert Interface.objects.filter(device=host, name="en999").exists()
                    assert SoftwareVersion.objects.filter(
                        platform=platform, version="8.4.2"
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
