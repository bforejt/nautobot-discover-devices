"""Prove Proxmox native host reconciliation inside unconditional outer rollback.

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
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)
HOST_UUID = "dce10001-0002-0003-0004-000000000005"


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _source(name, vendor, model, serial, *, ports=(0, 1, 2), version="9.2.2"):
    """Independent Linux/API fixture; native checks do not reuse adapter output."""
    version_data = {"version": version, "release": "9.2", "repoid": "fixture-build"}
    net, pci, hardware, links = [], [], [], []
    for index, port in enumerate(ports):
        name_port = "eno%d" % port
        pci_id = "0000:03:%02x.0" % index
        mac = "02:ac:00:00:01:%02x" % (index + 1)
        driver = "/sys/bus/pci/drivers/igb"
        net.append(
            {
                "name": name_port,
                "device": "/sys/devices/pci0000:00/" + pci_id,
                "driver": driver,
                "physical_function": None,
                "virtual_functions": [],
                "wireless": False,
                "speed": "1000",
                "carrier": "1",
                "type": "1",
                "duplex": "full",
                "mtu": "1500",
                "address": mac,
            }
        )
        pci.append(
            {
                "id": pci_id,
                "driver": driver,
                "physical_function": None,
                "virtual_functions": [],
                "vendor": "0x8086",
                "device": "0x1521",
                "class": "0x020000",
            }
        )
        hardware.append(
            {
                "id": "network%d" % port,
                "class": "network",
                "logicalname": name_port,
                "businfo": "pci@" + pci_id,
                "serial": mac,
                "configuration": {"driver": "igb"},
                "capabilities": {"ethernet": True, "physical": True},
            }
        )
        links.append(
            {
                "ifindex": index + 2,
                "ifname": name_port,
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "mtu": 1500,
                "link_type": "ether",
                "address": mac,
            }
        )
    return {
        "node": name,
        "api": {
            "version": dict(version_data),
            "node_version": dict(version_data),
            "cluster_status": [{"type": "node", "name": name, "local": 1}],
            "node_status": {
                "cpuinfo": {"cores": 8, "cpus": 16, "sockets": 1},
                "memory": {"total": 68719476736},
            },
            "permissions": {"/nodes/" + name: {"Sys.Audit": 0}, "/vms": {"VM.Audit": 1}},
            "node_network": [{"iface": row["name"], "type": "eth", "autostart": 1} for row in net],
            "node_network_changes": False,
            "storage": [],
            "qemu": [],
            "lxc": [],
        },
        "ssh": {
            "host": {
                "hostname": name,
                "guest_registry": {"version": 1, "ids": {}},
                "dmi": {
                    "sys_vendor": vendor,
                    "product_name": model,
                    "product_serial": serial,
                    "chassis_serial": serial,
                    "product_uuid": HOST_UUID,
                    "board_serial": "NOT-CHASSIS",
                },
                "net": net,
                "pci": pci,
                "errors": [],
                "unavailable": [],
            },
            "hardware": {
                "id": "computer",
                "class": "system",
                "vendor": vendor,
                "product": model,
                "serial": serial,
                "configuration": {"uuid": HOST_UUID},
                "children": hardware,
            },
            "links": links,
            "addresses": [],
            "bridge_vlans": [],
        },
        "guests": [],
        "completeness": {
            "host": True,
            "interfaces": True,
            "network": True,
            "guests": True,
            "storage": "permission-scoped",
            "permission_scoped": True,
        },
    }


def _collect(raw, *, enabled=True, bound=True):
    from jobs.adapters import proxmox

    raw = copy.deepcopy(raw)
    for link in raw["ssh"]["links"]:
        if enabled is None:
            link.pop("flags", None)
        elif enabled is False:
            link["flags"] = ["BROADCAST", "MULTICAST"]
    node = raw["node"]
    api = raw["api"]
    endpoints = {
        "version": "node_version",
        "status": "node_status",
        "qemu": "qemu",
        "lxc": "lxc",
        "storage": "storage",
    }

    def get(path, params=None):
        if path == "/version":
            return copy.deepcopy(api["version"])
        if path == "/cluster/status":
            return copy.deepcopy(api["cluster_status"])
        if path == "/access/permissions":
            scope = params["path"]
            return {scope: copy.deepcopy(api["permissions"].get(scope, {}))}
        suffix = path.removeprefix("/nodes/" + node + "/")
        if suffix in endpoints:
            return copy.deepcopy(api[endpoints[suffix]])
        kind, vmid, endpoint, *_tail = suffix.split("/")
        row = next(
            item for item in raw["guests"] if item["kind"] == kind and str(item["vmid"]) == vmid
        )
        key = (
            "current_config"
            if endpoint == "config" and params == {"current": 1}
            else (
                "config"
                if endpoint == "config"
                else "pending"
                if endpoint == "pending"
                else "status"
            )
        )
        return copy.deepcopy(row[key])

    client = SimpleNamespace(
        get=get,
        get_envelope=lambda *_args, **_kwargs: {
            "data": copy.deepcopy(api["node_network"]),
            "changes": "pending" if api["node_network_changes"] else "",
        },
        ssh_json=lambda source: copy.deepcopy(raw["ssh"][source]),
    )
    expected = raw["ssh"]["host"]["dmi"]["product_uuid"] if bound else None
    return proxmox.collect(client, expected_node=node, expected_host_uuid=expected)


def _live_source(path):
    from jobs.adapters import proxmox

    payload = json.loads(Path(path).read_text())
    if payload.get("adapter") == "proxmox":
        return proxmox.reconstruct(payload)["source"]["inventory"]
    return payload


def run(device_id=None, *, live_source_path=None):
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
            manufacturer = Manufacturer(name="Proxmox synthetic " + token)
            manufacturer.validated_save()
            platform = Platform(
                name="Proxmox synthetic " + token,
                network_driver="proxmox",
                manufacturer=manufacturer,
            )
            platform.validated_save()
            device_type = DeviceType(manufacturer=manufacturer, model="PROXMOX-SYNTHETIC-" + token)
            device_type.validated_save()
            target = Device(
                name="proxmox-native-" + token,
                serial="",
                device_type=device_type,
                platform=platform,
                role=anchor.role,
                location=anchor.location,
                status=anchor.status,
            )
            target.validated_save()
            assert _adapter(target).__name__.endswith(".proxmox")
            checks.append("native Proxmox Platform dispatch selects the standalone adapter")

            definitions = []
            for kind, value in (("boolean", False), ("integer", 0), ("text", "Other")):
                field = CustomField(
                    key="proxmox_%s_%s" % (kind, token),
                    label="Proxmox synthetic %s %s" % (kind, token),
                    type=kind,
                )
                field.validated_save()
                field.content_types.add(
                    ContentType.objects.get_for_model(Device),
                    ContentType.objects.get_for_model(Interface),
                )
                definitions.append((field.key, value))
            default_field = CustomField(
                key="proxmox_default_" + token,
                label="Proxmox synthetic default " + token,
                type="text",
                default="UNREQUESTED-DEFAULT",
            )
            default_field.validated_save()
            default_field.content_types.add(ContentType.objects.get_for_model(Interface))
            preserved_custom = {key: value for key, value in definitions}
            preserved_custom["unrelated_proxmox_" + token] = {
                "zero": 0,
                "false": False,
                "text": "Other",
            }
            Device.objects.filter(pk=target.pk).update(_custom_field_data=preserved_custom)
            target.refresh_from_db()
            InterfaceTemplate(
                device_type=device_type, name="eno1", type="10gbase-t"
            ).validated_save()
            port = Interface(
                device=target,
                name="eno0",
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
                name="eno4",
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
                name="eno99",
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
            serial = "PROXMOX-" + token
            raw = _source(
                target.name, manufacturer.name, device_type.model, serial, ports=(0, 1, 2, 4)
            )
            observed = _collect(raw)
            before = snapshot_inventory(target, discovery=observed)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(observed, snapshot_inventory(target, discovery=observed))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "Proxmox preview issued inventory DML")
            assert not plan["summary"]["blocked"] and not plan["errors"]
            assert len(plan["interface_creates"]) == 2
            assert {row["name"]: row["type"] for row in plan["interface_creates"]} == {
                "eno1": "10gbase-t",
                "eno2": "other",
            }
            assert all(row["enabled"] is True for row in plan["interface_creates"])
            assert snapshot_inventory(target, discovery=observed) == before
            checks.append(
                "native preview validates software and template/Other interfaces with zero DML"
            )

            applied = apply_discovery(observed, target, interface_status=interface_status)
            target.refresh_from_db()
            port.refresh_from_db()
            assert applied["summary"]["interfaces_created"] == 2
            assert target.serial == serial and target.software_version.version == "9.2.2"
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
            assert target.interfaces.get(name="eno1").enabled is True
            assert target.interfaces.get(name="eno2").speed == 1000000
            checks.append(
                "apply fills serial/exact release and preserves "
                "False, zero, Other and exact CF data"
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
            _no_dml(captured, "Unchanged Proxmox repeat issued inventory DML")
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
            _no_dml(captured, "Missing live admin flags preview issued DML")
            assert not plan["errors"] and plan["interface_creates"] == []
            checks.append(
                "new-interface creation is deferred when complete live admin flags are absent"
            )

            enabled = _collect(
                _source(target.name, manufacturer.name, device_type.model, serial, ports=(3,)),
                enabled=True,
            )
            applied = apply_discovery(enabled, target, interface_status=interface_status)
            assert applied["summary"]["interfaces_created"] == 1
            assert target.interfaces.get(name="eno3").enabled is True
            checks.append("complete live UP flags create an enabled native physical interface")

            for reason in (
                "model",
                "serial",
                "vendor",
                "uuid-binding",
                "source",
                "missing-serial",
                "hidden-registration",
                "missing-guest-registry",
            ):
                bad_raw = copy.deepcopy(raw)
                hardware, dmi = bad_raw["ssh"]["hardware"], bad_raw["ssh"]["host"]["dmi"]
                if reason == "model":
                    hardware["product"] = dmi["product_name"] = "WRONG"
                elif reason == "vendor":
                    hardware["vendor"] = dmi["sys_vendor"] = "WRONG"
                elif reason == "serial":
                    hardware["serial"] = dmi["product_serial"] = dmi["chassis_serial"] = "WRONG"
                elif reason == "missing-serial":
                    hardware["serial"] = dmi["product_serial"] = dmi["chassis_serial"] = "unknown"
                bad = _collect(bad_raw, bound=reason != "missing-serial")
                if reason == "uuid-binding":
                    bad["identity_binding"]["expected_uuid"] = str(uuid.uuid4())
                elif reason == "source":
                    bad["source"]["inventory"]["api"]["version"]["version"] = "9.2.3"
                elif reason == "hidden-registration":
                    bad["source"]["inventory"]["ssh"]["host"]["guest_registry"]["ids"]["999"] = {
                        "node": target.name,
                        "type": "qemu",
                        "version": 1,
                    }
                elif reason == "missing-guest-registry":
                    bad["source"]["inventory"]["ssh"]["host"].pop("guest_registry")
                before_bad = snapshot_inventory(target, discovery=bad)
                with CaptureQueriesContext(connection) as captured:
                    try:
                        apply_discovery(bad, target, interface_status=interface_status)
                    except InventoryError:
                        pass
                    else:
                        raise AssertionError("Proxmox native apply accepted invalid " + reason)
                _no_dml(captured, "Invalid Proxmox identity/source guard issued DML")
                assert snapshot_inventory(target, discovery=bad) == before_bad
                checks.append("native apply blocks %s without inventory DML" % reason)

            missing_serial = _source(
                target.name, manufacturer.name, device_type.model, "unknown", ports=()
            )
            bound = _collect(missing_serial)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(bound, snapshot_inventory(target, discovery=bound))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "DMI UUID-bound missing serial preview issued DML")
            assert not plan["errors"]
            assert not any(change["field"] == "serial" for change in plan["device_updates"])
            checks.append("explicit matching DMI UUID permits missing serial without inventing one")

            Device.objects.filter(pk=target.pk).update(software_version=None)
            target.refresh_from_db()
            failing = _collect(
                _source(
                    target.name,
                    manufacturer.name,
                    device_type.model,
                    serial,
                    ports=(90, 91),
                    version="9.2.3",
                )
            )
            before_failure = snapshot_inventory(target, discovery=failing)
            version_count, port_count = SoftwareVersion.objects.count(), Interface.objects.count()
            original_save, writes_seen = Interface.validated_save, []

            def fail_late(interface, *args, **kwargs):
                if interface.name == "eno91":
                    assert target.interfaces.filter(name="eno90").exists()
                    saved = Device.objects.get(pk=target.pk)
                    assert saved.software_version.version == "9.2.3"
                    assert saved._custom_field_data == preserved_custom
                    writes_seen.append(True)
                    raise ValidationError(
                        {"name": "Intentional final Proxmox interface save failure"}
                    )
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", fail_late):
                try:
                    apply_discovery(failing, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("Proxmox late native interface failure did not occur")
            assert writes_seen, "Proxmox late rollback did not first save software and an interface"
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
                    name="Proxmox source proof " + token,
                    network_driver="proxmox",
                    manufacturer=live_vendor,
                )
                live_platform.validated_save()
                live_target = Device(
                    name="proxmox-source-proof-" + token,
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
                _no_dml(captured, "Already-collected live Proxmox native preview issued DML")
                assert not plan["errors"]
                applied = apply_discovery(
                    observed_live, live_target, interface_status=interface_status
                )
                live_target.refresh_from_db()
                assert live_target.name == "proxmox-source-proof-" + token
                assert live_target.software_version.version == live_identity["software_version"]
                assert applied["summary"]["interfaces_created"] == len(observed_live["interfaces"])
                checks.append(
                    "collected live Proxmox source validates and applies "
                    "in an ephemeral native copy"
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
    return result


if __name__ == "__main__":
    print(
        json.dumps(
            run(live_source_path=os.environ.get("NAUTOBOT_PROXMOX_SOURCE_PATH")),
            indent=2,
            sort_keys=True,
        )
    )
