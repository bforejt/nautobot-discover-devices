"""Native physical interface checks for the documented Catalyst hardware library."""

import re
import uuid

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def run(device, interface_status, checks):
    """Validate new physical choices, zero-write previews, preservation and repeats."""
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, DeviceType, Interface
    from nautobot.extras.models import CustomField

    from jobs.adapters.cisco_hardware_profiles import CHASSIS_PROFILES, NETWORK_MODULE_PROFILES
    from jobs.adapters.cisco_iosxe import _interfaces
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Hardware checks require outer rollback"
    known_choices = {choice[0] for choice in Interface._meta.get_field("type").flatchoices}
    for profile in CHASSIS_PROFILES.values():
        regions = [*profile.get("fixed_ports", ())]
        if profile.get("management"):
            regions.append(profile["management"])
        for regions_override in profile.get("network_module_ports", {}).values():
            regions.extend(regions_override)
        assert all(region["type"] in known_choices for region in regions)
    for profile in NETWORK_MODULE_PROFILES.values():
        assert all(region["type"] in known_choices for region in profile["ports"])
    checks.append("every documented physical type is a native Nautobot Interface choice")
    initial_custom_fields = CustomField.objects.count()
    token = uuid.uuid4().hex[:10]
    for pid, names, types, module_pid in (
        ("C9300-48UN", ("FiveGigabitEthernet1/0/1",), ("5gbase-t",), None),
        (
            "C9500-48Y4C",
            ("TwentyFiveGigE1/0/1", "HundredGigE1/0/49"),
            ("25gbase-x-sfp28", "100gbase-x-qsfp28"),
            None,
        ),
        (
            "C9500X-60L4D",
            ("FiftyGigE1/0/1", "FourHundredGigE1/0/31"),
            ("50gbase-x-sfp56", "400gbase-x-qsfpdd"),
            None,
        ),
        (
            "C9500-16X",
            ("TenGigabitEthernet1/0/1", "TenGigabitEthernet1/1/8"),
            ("10gbase-x-sfpp", "10gbase-x-sfpp"),
            "C9500-NM-8X",
        ),
    ):
        device_type = DeviceType.objects.filter(
            manufacturer=device.device_type.manufacturer, model=pid
        ).first()
        if device_type is None:
            device_type = DeviceType(manufacturer=device.device_type.manufacturer, model=pid)
            device_type.validated_save()
        target = Device(
            name="CODEX-HARDWARE-" + pid + "-" + token,
            serial="SYNTHETIC-" + pid + "-" + token,
            device_type=device_type,
            role=device.role,
            location=device.location,
            status=device.status,
            platform=device.platform,
            software_version=device.software_version,
        )
        target.validated_save()
        raw = {
            "Cisco-IOS-XE-interfaces-oper:interfaces": {
                "interface": [
                    {
                        "name": name,
                        "interface-type": "iana-iftype-ethernet-csmacd",
                        "admin-status": "if-state-up",
                        "oper-status": "if-oper-state-down",
                        "speed": 1_000_000_000,
                    }
                    for name in names
                ]
            }
        }
        inventory = [{"hw-type": "hw-type-pim", "part-number": module_pid}] if module_pid else []
        interfaces, excluded = _interfaces(raw, pid, 1, inventory, [])
        assert [row["type"] for row in interfaces] == [
            expected for _, expected in sorted(zip(names, types, strict=True))
        ]
        source = {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": {
                "hostname": target.name,
                "serial": target.serial,
                "model": pid,
                "software_version": device.software_version.version,
            },
            "interfaces": interfaces,
            "excluded_interfaces": excluded,
            "warnings": [],
            "lag_memberships": [],
        }
        before = snapshot_inventory(target)
        plan = build_plan(source, before)
        assert not plan["errors"] and not plan["summary"]["blocked"]
        with CaptureQueriesContext(connection) as captured:
            validate_plan(plan, target, interface_status=interface_status)
        assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
        assert snapshot_inventory(target) == before
        saved = apply_discovery(source, target, interface_status=interface_status)
        assert saved["summary"]["interfaces_created"] == len(names)
        observed = dict(target.interfaces.values_list("name", "type"))
        assert observed == {row["name"]: row["type"] for row in interfaces}
        after = snapshot_inventory(target)
        with CaptureQueriesContext(connection) as captured:
            repeated = apply_discovery(source, target, interface_status=interface_status)
        assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
        assert repeated["summary"]["interfaces_created"] == 0
        assert snapshot_inventory(target) == after
        checks.append(
            pid + " physical profile preview/apply/repeat uses native models without DML on repeats"
        )

    # A documented capability cannot overwrite a populated operator choice.
    existing = target.interfaces.get(name="TenGigabitEthernet1/0/1")
    existing.type = "other"
    existing.validated_save()
    before = snapshot_inventory(target)
    conflict = build_plan(source, before)
    assert any(row.get("field") == "type" for row in conflict["conflicts"])
    with CaptureQueriesContext(connection) as captured:
        apply_discovery(source, target, interface_status=interface_status)
    assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries)
    assert snapshot_inventory(target) == before
    assert CustomField.objects.count() == initial_custom_fields
    checks.append(
        "new physical profiles preserve existing interface types and create no custom fields"
    )
