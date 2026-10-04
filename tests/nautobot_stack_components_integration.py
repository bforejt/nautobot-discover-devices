"""Native per-member network modules and nested optics inside outer rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Interface,
        Manufacturer,
        Module,
        ModuleBay,
        ModuleType,
        SoftwareVersion,
        VirtualChassis,
    )

    return {
        model.__name__: model.objects.count()
        for model in (
            Device,
            DeviceType,
            VirtualChassis,
            Manufacturer,
            SoftwareVersion,
            ModuleType,
            ModuleBay,
            Module,
            Interface,
        )
    }


def run(device, interface_status, checks):
    """Verify serial ownership, interface preservation and atomic full-stack saves."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import (
        Cable,
        Device,
        DeviceType,
        Interface,
        Module,
        ModuleBay,
        SoftwareVersion,
    )
    from nautobot.dcim.models.cables import CableToCableTermination
    from nautobot.extras.models import Status
    from nautobot.ipam.models import IPAddressToInterface

    from jobs.adapters.cisco_iosxe import INSTALL_PATH, canonical_software_version
    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, (
        "Stack component checks need outer rollback"
    )
    device.refresh_from_db()
    version = (
        device.software_version or SoftwareVersion.objects.filter(platform=device.platform).first()
    )
    assert version is not None
    release = canonical_software_version(version.version)
    assert release is not None

    def no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    def fixture():
        suffix = uuid.uuid4().hex[:12]
        serial1, serial2 = "STACK-NM-1-" + suffix, "STACK-NM-2-" + suffix
        model2 = "C9300-STACK-NM-CHECK-" + suffix
        with SkipAutoComponentCreation():
            target = Device(
                name="discovery-stack-nm-" + suffix,
                serial=serial1,
                device_type=device.device_type,
                location=device.location,
                role=device.role,
                status=device.status,
                platform=device.platform,
                tenant=device.tenant,
                software_version=version,
                secrets_group=device.secrets_group,
            )
            target.validated_save()
        ports = []
        for position in (1, 2):
            port = Interface(
                device=target,
                name="Gi%d/1/1" % position,
                type="1000base-x-sfp",
                enabled=True,
                description="Operator stack component fixture",
                status=interface_status,
            )
            port.validated_save()
            ports.append(port)
        cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
        cable.validated_save()
        for cable_end, port in zip(("A", "B"), ports):
            join = CableToCableTermination(
                cable=cable, cable_end=cable_end, connector=1, interface=port
            )
            join.full_clean()
            join.save()
        assignment = None
        if device.primary_ip4_id:
            assignment = IPAddressToInterface(
                ip_address_id=device.primary_ip4_id, interface=ports[1]
            )
            assignment.validated_save()

        def member(position, serial, model, role, priority):
            return {
                "position": position,
                "serial": serial,
                "model": model,
                "role": role,
                "priority": priority,
                "state": "state-ready",
                "stack_mode": "mode-stackwise-rear",
                "software_version": release,
                "sources": {
                    "identity": "Synthetic structured stack component fixture",
                    "software_version": {
                        "module": "Cisco-IOS-XE-install-oper",
                        "path": INSTALL_PATH,
                        "chassis": position,
                        "install_rows": [
                            {
                                "chassis": position,
                                "version": release,
                                "release": release,
                                "fru": "fru-rp",
                                "current": "install-version-state-provisioned-committed",
                            }
                        ],
                    },
                },
            }

        members = [
            member(2, serial2, model2, "role-active", 15),
            member(1, serial1, target.device_type.model, "role-standby", 10),
        ]
        items = []
        for owner in members:
            position = owner["position"]
            name = "GigabitEthernet%d/1/1" % position
            context = {
                "device_serial": owner["serial"],
                "member": position,
                "chassis_model": owner["model"],
            }
            parent = {
                "key": "uplink:%d/1" % position,
                "kind": "network-module",
                "manufacturer": target.device_type.manufacturer.name,
                "model": "STACK-UPLINK-CHECK-" + suffix,
                "part_number": "STACK-UPLINK-CHECK-" + suffix,
                "serial": "STACK-UPLINK-%s-%d" % (suffix, position),
                "parent_key": None,
                "bay": {"name": "Uplink Module 1", "position": "1", "label": "Uplink Module 1"},
                "interfaces": [name],
                "source": {"identity": "Synthetic uplink identity", "ownership": dict(context)},
                "observations": {},
                **context,
            }
            child = {
                "key": "transceiver:%d/1/1" % position,
                "kind": "transceiver",
                "manufacturer": parent["manufacturer"],
                "model": "STACK-OPTIC-CHECK-" + suffix,
                "part_number": "STACK-OPTIC-CHECK-" + suffix,
                "serial": "STACK-OPTIC-%s-%d" % (suffix, position),
                "parent_key": parent["key"],
                "bay": {"name": "SFP " + name, "position": "1", "label": name},
                "interfaces": [],
                "source": {
                    "identity": "Synthetic serialized optic identity",
                    "ownership": {
                        "parent_key": parent["key"],
                        "parent_model": parent["model"],
                        "parent_serial": parent["serial"],
                        "interface": name,
                        **context,
                    },
                },
                "observations": {},
                **context,
            }
            items.extend((child, parent))
        observed = {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": {
                "hostname": target.name,
                "serial": serial2,
                "model": model2,
                "software_version": release,
            },
            "stack": {
                "schema_version": 1,
                "name": target.name,
                "is_stack": True,
                "active_position": 2,
                "members": members,
                "absent_members": [],
                "unresolved": [],
                "observations": {},
            },
            "components": {"schema_version": 1, "items": items, "unresolved": [], "excluded": []},
            "interfaces": [
                {
                    "name": "GigabitEthernet%d/1/1" % position,
                    "type": "1000base-x-sfp",
                    "enabled": True,
                    "type_source": "Synthetic observed SFP capability",
                }
                for position in (1, 2)
            ],
            "warnings": [],
            "excluded_interfaces": [],
        }
        preserved = {
            "target": (
                target.pk,
                target.name,
                target.serial,
                target.secrets_group_id,
                copy.deepcopy(target._custom_field_data),
            ),
            "ports": [
                (port.pk, port.device_id, port.name, port.description, port.type) for port in ports
            ],
            "cable_rows": list(cable.terminations.order_by("pk").values()),
            "assignment": assignment.pk if assignment else None,
        }
        return target, observed, ports, cable, preserved

    def assert_preserved(target, ports, cable, preserved, *, first_module=None):
        target.refresh_from_db()
        assert (
            target.pk,
            target.name,
            target.serial,
            target.secrets_group_id,
            target._custom_field_data,
        ) == preserved["target"]
        for port, values in zip(ports, preserved["ports"]):
            port.refresh_from_db()
            assert (port.pk, port.device_id, port.name, port.description, port.type) == values
            assert port.cable_id == cable.pk
        assert ports[0].module_id == first_module
        assert ports[1].module_id is None
        assert list(cable.terminations.order_by("pk").values()) == preserved["cable_rows"]
        if preserved["assignment"]:
            assert (
                IPAddressToInterface.objects.get(pk=preserved["assignment"]).interface_id
                == ports[1].pk
            )

    target, observed, ports, cable, preserved = fixture()
    initial_counts = catalog_counts()
    baseline = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(observed, snapshot_inventory(target, discovery=observed))
        assert not preview["errors"], preview["errors"]
        validate_plan(preview, target, interface_status=interface_status)
    no_dml(captured, "Stack network-module/optic preview issued DML")
    assert catalog_counts() == initial_counts
    assert snapshot_inventory(target, discovery=observed) == baseline
    assert preview["summary"]["modules_created"] == 4
    assert preview["summary"]["module_bays_created"] == 4
    assert preview["summary"]["interface_modules_updated"] == 1
    assert preview["summary"]["deferred_interface_ownership"] == 1
    assert_preserved(target, ports, cable, preserved)
    checks.append("stack uplink/optic preview validates unsaved member hierarchy with zero DML")

    applied = apply_discovery(observed, target, interface_status=interface_status)
    target.refresh_from_db()
    owners = {owner.vc_position: owner for owner in target.virtual_chassis.members.all()}
    assert owners[1].pk == target.pk and target.virtual_chassis.master_id == owners[2].pk
    assert owners[2].software_version_id == version.pk
    parents = {}
    for item in observed["components"]["items"]:
        asset = Module.objects.get(serial=item["serial"])
        owner = owners[item["member"]]
        assert owner.serial == item["device_serial"] and asset.device.pk == owner.pk
        assert asset.parent_module_bay.parent_device_id == owner.pk
        if item["parent_key"] is None:
            assert asset.parent_module_bay.parent_module_id is None
            parents[item["member"]] = asset
        else:
            parent_item = next(
                row for row in observed["components"]["items"] if row["key"] == item["parent_key"]
            )
            assert asset.parent_module_bay.parent_module.serial == parent_item["serial"]
            assert not asset.interfaces.exists()
        assert asset._custom_field_data == {}
    assert applied["summary"]["modules_created"] == 4
    assert_preserved(target, ports, cable, preserved, first_module=parents[1].pk)
    checks.append(
        "uplinks and nested optics save on exact members while "
        "existing interfaces/IPs/cables stay put"
    )

    stable_counts = catalog_counts()
    stable = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured, "Repeated stack uplink/optic discovery issued DML")
    assert catalog_counts() == stable_counts
    assert snapshot_inventory(target, discovery=observed) == stable
    assert repeated["summary"]["deferred_interface_ownership"] == 1
    assert all(
        value == 0
        for key, value in repeated["summary"].items()
        if key != "deferred_interface_ownership"
    )
    assert_preserved(target, ports, cable, preserved, first_module=parents[1].pk)
    checks.append("repeated per-member uplink/optic discovery preserves identities with zero DML")

    # A populated serial may contain operator-entered padding. Source identity
    # matching trims it, while staging must use the same normalized map key
    # without rewriting the existing Device's serial or placement.
    padded_owner = owners[2]
    padded_serial = "  " + padded_owner.serial + "  "
    Device.objects.filter(pk=padded_owner.pk).update(serial=padded_serial)
    padded_owner.refresh_from_db()
    restore_item = next(
        row for row in observed["components"]["items"] if row["key"] == "transceiver:2/1/1"
    )
    removed_optic = Module.objects.get(serial=restore_item["serial"])
    assert removed_optic.device.pk == padded_owner.pk
    removed_optic.delete()
    padded_baseline = snapshot_inventory(target, discovery=observed)
    padded_counts = catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        padded_preview = build_plan(observed, snapshot_inventory(target, discovery=observed))
        assert not padded_preview["errors"], padded_preview["errors"]
        validate_plan(padded_preview, target, interface_status=interface_status)
    no_dml(captured, "Padded existing stack owner preview issued inventory writes")
    assert snapshot_inventory(target, discovery=observed) == padded_baseline
    assert catalog_counts() == padded_counts
    assert padded_preview["summary"]["modules_created"] == 1
    restored = apply_discovery(observed, target, interface_status=interface_status)
    restored_optic = Module.objects.get(serial=restore_item["serial"])
    assert restored["summary"]["stack_members_created"] == 0
    assert restored["summary"]["modules_created"] == 1
    assert restored_optic.device.pk == padded_owner.pk
    assert restored_optic.parent_module_bay.parent_module_id == parents[2].pk
    padded_owner.refresh_from_db()
    assert padded_owner.serial == padded_serial
    padded_stable = snapshot_inventory(target, discovery=observed)
    with CaptureQueriesContext(connection) as captured:
        padded_repeat = apply_discovery(observed, target, interface_status=interface_status)
    no_dml(captured, "Repeated padded stack owner discovery issued inventory writes")
    assert snapshot_inventory(target, discovery=observed) == padded_stable
    assert padded_repeat["summary"]["modules_created"] == 0
    padded_owner.refresh_from_db()
    assert padded_owner.serial == padded_serial
    assert_preserved(target, ports, cable, preserved, first_module=parents[1].pk)
    stable, stable_counts = padded_stable, catalog_counts()
    checks.append(
        "padded existing member identity stages/restores its nested optic and repeats "
        "without serial changes or DML"
    )

    replacement = copy.deepcopy(observed)
    replacement_parent = next(
        row for row in replacement["components"]["items"] if row["key"] == "uplink:2/1"
    )
    replacement_parent["serial"] += "-REPLACEMENT"
    replacement_child = next(
        row for row in replacement["components"]["items"] if row["key"] == "transceiver:2/1/1"
    )
    replacement_child["source"]["ownership"]["parent_serial"] = replacement_parent["serial"]
    with CaptureQueriesContext(connection) as captured:
        occupied = apply_discovery(replacement, target, interface_status=interface_status)
    no_dml(captured, "Occupied stack uplink was replaced or its optic reparented")
    assert occupied["conflicts"] and catalog_counts() == stable_counts
    assert snapshot_inventory(target, discovery=observed) == stable
    assert_preserved(target, ports, cable, preserved, first_module=parents[1].pk)
    checks.append(
        "occupied per-member uplink conflicts preserve the existing module and nested optic"
    )

    invalid = copy.deepcopy(observed)
    invalid["components"]["items"][0]["source"]["ownership"]["parent_serial"] = (
        "WRONG-PARENT-SERIAL"
    )
    with CaptureQueriesContext(connection) as captured:
        try:
            apply_discovery(invalid, target, interface_status=interface_status)
        except InventoryError:
            pass
        else:
            raise AssertionError("Contradictory nested component ownership unexpectedly applied")
    no_dml(captured, "Contradictory nested component source issued DML")
    assert snapshot_inventory(target, discovery=observed) == stable
    checks.append("contradictory optic parent provenance rejects the full plan before writes")

    def rollback_case(fail_stage):
        failing_target, failing, failing_ports, failing_cable, failing_preserved = fixture()
        before_failure = catalog_counts()
        failure_snapshot = snapshot_inventory(failing_target, discovery=failing)
        late_optic = next(
            row for row in failing["components"]["items"] if row["key"] == "transceiver:2/1/1"
        )
        new_model = failing["identity"]["model"]
        preceding_writes = []
        original_module_save, original_interface_save = (
            Module.validated_save,
            Interface.validated_save,
        )

        def fail_optic(asset, *args, **kwargs):
            if fail_stage == "optic" and asset.serial == late_optic["serial"]:
                assert DeviceType.objects.filter(model=new_model).exists()
                assert Device.objects.filter(serial=late_optic["device_serial"]).exists()
                assert (
                    Module.objects.filter(parent_module_bay__parent_device=failing_target).count()
                    == 2
                )
                assert ModuleBay.objects.filter(
                    parent_module=asset.parent_module_bay.parent_module
                ).exists()
                preceding_writes.append(True)
                raise ValidationError({"serial": "Intentional late stack optic failure"})
            return original_module_save(asset, *args, **kwargs)

        def fail_assignment(port, *args, **kwargs):
            if fail_stage == "interface" and port.pk == failing_ports[0].pk and port.module_id:
                assert Module.objects.filter(serial=late_optic["serial"]).exists()
                assert DeviceType.objects.filter(model=new_model).exists()
                assert Device.objects.get(pk=failing_target.pk).virtual_chassis_id is not None
                preceding_writes.append(True)
                raise ValidationError(
                    {"module": "Intentional late stack interface assignment failure"}
                )
            return original_interface_save(port, *args, **kwargs)

        try:
            with (
                patch.object(Module, "validated_save", fail_optic),
                patch.object(Interface, "validated_save", fail_assignment),
            ):
                apply_discovery(failing, failing_target, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("Intentional late stack component failure did not occur")
        assert preceding_writes
        assert catalog_counts() == before_failure
        assert snapshot_inventory(failing_target, discovery=failing) == failure_snapshot
        failing_target.refresh_from_db()
        assert failing_target.virtual_chassis_id is None
        assert not DeviceType.objects.filter(model=new_model).exists()
        assert not Module.objects.filter(serial=late_optic["serial"]).exists()
        assert_preserved(failing_target, failing_ports, failing_cable, failing_preserved)

    for fail_stage in ("optic", "interface"):
        rollback_case(fail_stage)
    checks.append(
        "late optic or interface assignment failures roll back the entire new stack/component graph"
    )
