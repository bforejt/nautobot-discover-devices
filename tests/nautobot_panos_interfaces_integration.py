"""Actual native PAN interface proof; every fixture and mutation rolls back.

Run in a configured Nautobot nbshell process with an existing Device anchor.
No firewall is contacted. This validates the installed native model rather than
claiming that another Nautobot release has been exercised.
"""

import copy
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _no_dml(captured):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)


def run(device_id=None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, DeviceType, Interface
    from nautobot.extras.models import Status

    from jobs.adapters.panos_logical import parse_logical_interfaces
    from jobs.exceptions import InventoryError
    from jobs.nautobot_panos_interfaces import (
        panos_interface_objects,
        save_panos_interfaces,
        snapshot_panos_interfaces,
        validate_panos_interfaces,
    )
    from jobs.reconcile_panos_interfaces import FIELDS, plan_panos_interfaces

    anchor = Device.objects.select_related(
        "location", "role", "status", "device_type", "platform"
    ).get(pk=device_id or os.environ["NAUTOBOT_DISCOVERY_DEVICE_ID"])
    status = Status.objects.get_for_model(Interface).get(name="Active")
    before_counts = {
        "devices": Device.objects.count(),
        "interfaces": Interface.objects.count(),
        "device_types": DeviceType.objects.count(),
    }
    checks = []
    source = ET.fromstring(
        (Path(__file__).with_name("fixtures") / "panos_ipam_network.xml").read_text()
    )
    entry = source.find(
        'result/network/interface/ethernet/entry/layer3/units/entry[@name="ethernet1/1.100"]'
    )
    for name, value in (("comment", "Explicit transit"), ("mtu", "1600"), ("tag", "100")):
        ET.SubElement(entry, name).text = value
    discovery = {
        "adapter": "panos",
        "logical_interfaces": parse_logical_interfaces(ET.tostring(source, encoding="unicode")),
    }

    with transaction.atomic():
        try:
            token = uuid.uuid4().hex[:12]
            fixture_type = DeviceType(
                manufacturer=anchor.device_type.manufacturer, model="PAN logical fixture " + token
            )
            fixture_type.validated_save()
            target = Device(
                name="pan-logical-native-" + token,
                device_type=fixture_type,
                platform=anchor.platform,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            target.validated_save()
            for name, interface_type in (
                ("ethernet1/1", "virtual"),
                ("ethernet1/2", "virtual"),
                ("ethernet1/5", "1000base-t"),
            ):
                Interface(
                    device=target, name=name, type=interface_type, enabled=True, status=status
                ).validated_save()

            def snapshot():
                return {
                    "device": {"id": str(target.pk), "name": target.name},
                    "interfaces": [
                        {
                            "id": str(row.pk),
                            "name": row.name,
                            "device_id": str(row.device_id),
                            "module_id": str(row.module_id) if row.module_id else None,
                            **{field: getattr(row, field, None) for field in FIELDS},
                        }
                        for row in target.interfaces.all()
                    ],
                    "unsupported_interface_fields": [
                        field
                        for field in FIELDS
                        if field not in {field.name for field in Interface._meta.fields}
                    ],
                    "panos_interface_inventory": snapshot_panos_interfaces(
                        target, discovery=discovery
                    ),
                }

            def plan(existing=None):
                return plan_panos_interfaces(
                    discovery, existing or snapshot(), identity_verified=True
                )

            def objects(planned):
                bound = {row.name: row for row in target.interfaces.all()}
                creates, updates = [], []
                for row in planned["creates"]:
                    interface = Interface(
                        device=target,
                        name=row["name"],
                        status=status,
                        **{field: row[field] for field in FIELDS if row[field] is not None},
                    )
                    creates.append(interface)
                    bound[row["name"]] = interface
                for row in planned["updates"]:
                    interface = bound[row["name"]]
                    for change in row["changes"]:
                        setattr(interface, change["field"], change["after"])
                    updates.append(interface)
                for interface in creates + updates:
                    interface.full_clean()
                relations = panos_interface_objects(planned, bound, target)
                validate_panos_interfaces(relations, target)
                return creates, updates, relations, bound

            def apply(planned):
                with transaction.atomic():
                    creates, updates, relations, bound = objects(planned)
                    for interface in creates + updates:
                        interface.full_clean()
                        interface.save()
                    save_panos_interfaces(relations, target)
                return bound

            with CaptureQueriesContext(connection) as captured:
                preview = plan()
                created, updated, relations, bound = objects(preview)
            _no_dml(captured)
            assert len(created) == 6 and len(relations) == 4 and not updated
            assert all(interface.parent_interface_id is None for interface in created)
            assert target.interfaces.count() == 3
            checks.append("preview_native_full_clean_and_relationship_validation_zero_dml")

            apply(preview)
            assert target.interfaces.count() == 9
            assert (
                target.interfaces.get(name="ethernet1/1.100").parent_interface.name == "ethernet1/1"
            )
            assert (
                target.interfaces.get(name="ethernet1/2.101").parent_interface.name == "ethernet1/2"
            )
            assert target.interfaces.get(name="ae1.200").parent_interface.name == "ae1"
            assert target.interfaces.get(name="ethernet1/5").lag.name == "ae1"
            assert target.interfaces.get(name="tunnel.1").type == "tunnel"
            checks.append("create_six_logical_interfaces_three_direct_parents_and_physical_lag")

            child = target.interfaces.get(name="ethernet1/1.100")
            assert child.description == "Explicit transit" and child.mtu == 1600
            assert (
                child.mode != "tagged"
                and child.untagged_vlan_id is None
                and not child.tagged_vlans.exists()
            )
            checks.append("explicit_comment_mtu_and_report_only_encapsulation_tag")

            with CaptureQueriesContext(connection) as captured:
                repeat = plan()
                objects(repeat)
                apply(repeat)
            _no_dml(captured)
            assert not any(
                repeat[key] for key in ("creates", "updates", "parents", "lag_assignments")
            )
            checks.append("repeat_has_zero_native_changes_and_zero_dml")

            child.enabled, child.description, child.mtu = False, "Deployment intent", 1700
            child.validated_save()
            preserved = plan()
            assert not preserved["updates"]
            assert {row["field"] for row in preserved["conflicts"]} == {
                "enabled",
                "description",
                "mtu",
            }
            with CaptureQueriesContext(connection) as captured:
                objects(preserved)
                apply(preserved)
            _no_dml(captured)
            child.refresh_from_db()
            assert (
                child.enabled is False
                and child.description == "Deployment intent"
                and child.mtu == 1700
            )
            checks.append("populated_admin_description_and_mtu_intent_preserved")

            child.description, child.mtu = "", None
            child.validated_save()
            filled = plan()
            assert {change["field"] for change in filled["updates"][0]["changes"]} == {
                "description",
                "mtu",
            }
            apply(filled)
            child.refresh_from_db()
            assert (
                child.enabled is False
                and child.description == "Explicit transit"
                and child.mtu == 1600
            )
            checks.append("blank_optional_fields_fill_while_false_admin_intent_remains")

            member = target.interfaces.get(name="ethernet1/5")
            member.lag, member.type = None, "virtual"
            member.validated_save()
            virtual = plan()
            assert not virtual["lag_assignments"]
            assert any("virtual vNICs" in row["reason"] for row in virtual["unresolved"])
            with CaptureQueriesContext(connection) as captured:
                objects(virtual)
                apply(virtual)
            _no_dml(captured)
            member.refresh_from_db()
            assert (
                member.type == "virtual"
                and member.lag_id is None
                and member.breakout_position is None
            )
            checks.append("virtual_vnic_lag_conflict_reported_without_retype_or_fake_breakout")

            existing = snapshot()
            existing["panos_interface_inventory"]["capabilities"]["parent_interface"] = False
            child.parent_interface = None
            child.validated_save()
            existing = snapshot()
            existing["panos_interface_inventory"]["capabilities"]["parent_interface"] = False
            absent = plan(existing)
            assert not absent["parents"] and any(
                "parent-interface field" in row["reason"] for row in absent["unresolved"]
            )
            checks.append("feature_detected_missing_parent_capability_is_report_only")

            missing = snapshot()
            missing["interfaces"] = [
                row for row in missing["interfaces"] if row["name"] != "ethernet1/1"
            ]
            deferred = plan(missing)
            assert not deferred["parents"]
            checks.append("missing_exact_parent_is_report_only")

            root = target.interfaces.get(name="ethernet1/1")
            root.parent_interface = target.interfaces.get(name="loopback.1")
            root.validated_save()
            # Planner conflicts are verified against actual populated child FK.
            child.parent_interface = target.interfaces.get(name="loopback.1")
            child.validated_save()
            preserved_parent = plan()
            assert not preserved_parent["parents"]
            assert any(row["field"] == "parent_interface" for row in preserved_parent["conflicts"])
            checks.append("populated_parent_assignment_preserved")
            child.parent_interface = None
            child.validated_save()

            pending = plan()
            bound = {row.name: row for row in target.interfaces.all()}
            bound["ethernet1/1"].parent_interface = bound["ethernet1/1.100"]
            with CaptureQueriesContext(connection) as captured:
                try:
                    panos_interface_objects(pending, bound, target)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("A parent cycle was accepted")
            _no_dml(captured)
            checks.append("native_direct_parent_cycle_guard_zero_dml")

            root.parent_interface = None
            root.validated_save()
            pending = plan()
            tampered = copy.deepcopy(pending)
            tampered["parents"][0]["parent_name"] = "ethernet1/2"
            with CaptureQueriesContext(connection) as captured:
                try:
                    panos_interface_objects(
                        tampered, {row.name: row for row in target.interfaces.all()}, target
                    )
                except InventoryError:
                    pass
                else:
                    raise AssertionError("Tampered direct-parent provenance was accepted")
            _no_dml(captured)
            checks.append("native_relationship_provenance_rechecked_zero_dml")

            rollback_source = ET.fromstring(ET.tostring(source, encoding="unicode"))
            ET.SubElement(
                rollback_source.find("result/network/interface/loopback/units"),
                "entry",
                name="loopback.77",
            )
            discovery["logical_interfaces"] = parse_logical_interfaces(
                ET.tostring(rollback_source, encoding="unicode")
            )
            child.description, child.mtu = "", None
            child.validated_save()
            pending = plan()
            assert len(pending["creates"]) == 1 and len(pending["updates"]) == 1
            before = list(
                target.interfaces.order_by("pk").values(
                    "id", "name", "parent_interface_id", "lag_id", "description", "mtu"
                )
            )
            original_save = Interface.save

            def late_failure(interface, *args, **kwargs):
                result = original_save(interface, *args, **kwargs)
                if interface.name == "ethernet1/1.100" and "parent_interface" in kwargs.get(
                    "update_fields", []
                ):
                    raise RuntimeError("Synthetic late native relationship failure")
                return result

            try:
                with patch.object(Interface, "save", late_failure):
                    apply(pending)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Synthetic late failure was not reached")
            after = list(
                target.interfaces.order_by("pk").values(
                    "id", "name", "parent_interface_id", "lag_id", "description", "mtu"
                )
            )
            assert before == after
            checks.append("late_relationship_save_failure_rolls_back_all_interface_changes")
        finally:
            transaction.set_rollback(True)

    assert before_counts == {
        "devices": Device.objects.count(),
        "interfaces": Interface.objects.count(),
        "device_types": DeviceType.objects.count(),
    }
    return {"passed": True, "checks": checks, "persistent_changes": 0}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
