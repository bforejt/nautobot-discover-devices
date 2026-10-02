"""Real module ownership regressions, called only inside an outer rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    """Track catalog rows as well as component inventory across outer rollback."""
    from nautobot.dcim.models import InterfaceTemplate, Manufacturer, Module, ModuleBay, ModuleType

    return {
        model.__name__: model.objects.count()
        for model in (Manufacturer, ModuleType, ModuleBay, Module, InterfaceTemplate)
    }


def run(device, interface_status, checks):
    """Verify module previews, adoption, conflicts, and complete transaction rollback."""
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Device,
        Interface,
        InterfaceTemplate,
        Module,
        ModuleBay,
        ModuleType,
        SoftwareVersion,
    )

    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, "Component tests require outer rollback"
    device.refresh_from_db()
    prefix = str(uuid.uuid4().int)[:12]
    manufacturer = device.device_type.manufacturer

    def physical_name(number, short=False):
        return ("Gi" if short else "GigabitEthernet") + prefix + "/1/" + str(number)

    def fact(name, type_="1000base-t", description="Component ORM verification"):
        return {
            "name": name,
            "type": type_,
            "enabled": True,
            "description": description,
            "mtu": 1500,
            "mac_address": None,
            "type_source": "synthetic component fixture",
            "observations": {},
        }

    def component(number, names, model=None, serial=None):
        pid = model or "CODEX-NM-" + prefix + "-" + str(number)
        return {
            "key": "uplink:1/" + str(number),
            "kind": "network-module",
            "manufacturer": manufacturer.name,
            "model": pid,
            "part_number": pid,
            "serial": serial or "CODEX-SERIAL-" + prefix + "-" + str(number),
            "parent_key": None,
            "bay": {
                "name": "Integration uplink " + prefix + "/" + str(number),
                "position": str(number),
                "label": "Synthetic integration bay",
            },
            "interfaces": names,
            "source": {},
            "observations": {},
        }

    def observed(items, facts):
        return {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": copy.deepcopy(identity),
            "interfaces": facts,
            "lag_memberships": [],
            "warnings": [],
            "excluded_interfaces": [],
            "components": {"schema_version": 1, "items": items, "unresolved": [], "excluded": []},
        }

    def unused_version():
        for patch_number in range(1, 100):
            version = "17.98.%02d" % patch_number
            if not SoftwareVersion.objects.filter(
                platform=device.platform, version=version
            ).exists():
                return version
        raise AssertionError("No unused synthetic component-test software version")

    identity = {
        "hostname": device.name or "discovery-integration",
        "serial": device.serial or "CODEX-COMPONENT-INTEGRATION",
        "model": device.device_type.model,
        "software_version": (
            device.software_version.version if device.software_version_id else unused_version()
        ),
    }

    def assert_no_dml(captured, message):
        assert not any(WRITE_SQL.match(query["sql"]) for query in captured.captured_queries), (
            message
        )

    def seed_interface(
        name, type_="1000base-t", lag=None, description="Component ORM verification"
    ):
        row = Interface(
            device=device,
            name=name,
            type=type_,
            enabled=True,
            description=description,
            mtu=1500,
            status=interface_status,
            lag=lag,
        )
        row.validated_save()
        return row

    # Preserve an existing short alias, UUID, and LAG while adopting the port
    # into a newly discovered module. All three module parents are unsaved in preview.
    lag_name = "Port-channel" + prefix
    lag = seed_interface(lag_name, type_="lag")
    member = seed_interface(physical_name(1, short=True), lag=lag)
    member_id = member.pk
    first_item = component(1, [physical_name(1)])
    discovery = observed([first_item], [fact(physical_name(1)), fact(lag_name, type_="lag")])
    before_preview = snapshot_inventory(device)
    before_counts = catalog_counts()
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(discovery, snapshot_inventory(device))
        validate_plan(preview, device, interface_status=interface_status)
    assert_no_dml(captured, "Component preview wrote unsaved module parents to the database")
    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_preview
    assert catalog_counts() == before_counts
    assert preview["summary"]["module_types_created"] == 1
    assert preview["summary"]["module_bays_created"] == 1
    assert preview["summary"]["modules_created"] == 1
    assert preview["summary"]["interface_modules_updated"] == 1
    checks.append(
        "component preview validates unsaved ModuleType, ModuleBay, Module, "
        "and adoption without DML"
    )

    apply_discovery(discovery, device, interface_status=interface_status)
    device.refresh_from_db()
    member.refresh_from_db()
    first_module = Module.objects.get(serial=first_item["serial"])
    assert first_module.module_type.model == first_item["model"]
    assert first_module.parent_module_bay.name == first_item["bay"]["name"]
    assert member.module_id == first_module.pk
    assert member.pk == member_id and member.name == physical_name(1, short=True)
    assert member.lag_id == lag.pk and member.device_id == device.pk
    assert not Interface.objects.filter(device=device, name=physical_name(1)).exists()
    checks.append(
        "component apply creates native module inventory and adopts an existing alias "
        "preserving UUID and LAG"
    )

    before_repeat = snapshot_inventory(device)
    with CaptureQueriesContext(connection) as captured:
        repeated = apply_discovery(discovery, device, interface_status=interface_status)
    assert_no_dml(captured, "Repeated component apply issued inventory DML")
    for field in (
        "module_types_created",
        "module_types_updated",
        "module_bays_created",
        "module_bays_updated",
        "modules_created",
        "modules_updated",
        "interface_modules_updated",
    ):
        assert repeated["summary"][field] == 0, "Repeated component apply changed " + field
    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_repeat
    checks.append("repeated component discovery preserves ownership and issues zero inventory DML")

    # A ModuleType template would instantiate a duplicate of this existing
    # physical port unless the job suppresses Nautobot's auto component creation.
    template_member = seed_interface(physical_name(2, short=True))
    template_member_id = template_member.pk
    template_item = component(2, [physical_name(2)])
    template_type = ModuleType(
        manufacturer=manufacturer,
        model=template_item["model"],
        part_number=template_item["part_number"],
    )
    template_type.validated_save()
    template = InterfaceTemplate(
        module_type=template_type, name=physical_name(2, short=True), type="1000base-t"
    )
    template.validated_save()
    before_interface_count = Interface.objects.count()
    template_discovery = observed([template_item], [fact(physical_name(2))])
    apply_discovery(template_discovery, device, interface_status=interface_status)
    template_member.refresh_from_db()
    assert template_member.pk == template_member_id
    assert template_member.module_id == Module.objects.get(serial=template_item["serial"]).pk
    assert Interface.objects.count() == before_interface_count, (
        "Module templates duplicated an existing port"
    )
    assert Interface.objects.filter(device=device, name=physical_name(2, short=True)).count() == 1
    checks.append(
        "existing ModuleType interface templates are suppressed so adoption cannot duplicate ports"
    )

    # A port can acquire both module ownership and LAG membership in one plan.
    # Preview must skip both unsaved FKs, while still checking cached relations.
    for number, existing_lag in ((7, True), (8, False)):
        combined_member = seed_interface(physical_name(number, short=True))
        combined_lag_name = "Port-channel" + prefix + str(number)
        if existing_lag:
            seed_interface(combined_lag_name, type_="lag")
        combined_item = component(number, [physical_name(number)])
        combined = observed(
            [combined_item],
            [fact(physical_name(number)), fact(combined_lag_name, type_="lag")],
        )
        combined["lag_memberships"] = [
            {"member": physical_name(number), "lag": combined_lag_name, "source": {}}
        ]
        with CaptureQueriesContext(connection) as captured:
            plan = build_plan(combined, snapshot_inventory(device, discovery=combined))
            validate_plan(plan, device, interface_status=interface_status)
        assert_no_dml(captured, "Combined Module/LAG preview issued DML")
        assert plan["summary"]["interface_modules_updated"] == 1
        assert plan["summary"]["lag_memberships_updated"] == 1
        apply_discovery(combined, device, interface_status=interface_status)
        combined_member.refresh_from_db()
        assert combined_member.module_id == Module.objects.get(serial=combined_item["serial"]).pk
        assert (
            combined_member.lag_id
            == Interface.objects.get(device=device, name=combined_lag_name).pk
        )
        with CaptureQueriesContext(connection) as captured:
            apply_discovery(combined, device, interface_status=interface_status)
        assert_no_dml(captured, "Repeated combined Module/LAG apply issued DML")
    checks.append("module adoption and new or existing LAG assignment validate and apply together")

    # Catalog matching trims device PIDs even when an existing catalog uses a
    # friendly model and padded part number. The filtered snapshot must include it.
    padded_item = component(9, [])
    padded_type = ModuleType(
        manufacturer=manufacturer,
        model="Integration friendly module " + prefix,
        part_number="  " + padded_item["part_number"] + "  ",
    )
    padded_type.validated_save()
    padded = observed([padded_item], [])
    padded_plan = build_plan(padded, snapshot_inventory(device, discovery=padded))
    assert not padded_plan["errors"]
    assert padded_plan["summary"]["module_types_created"] == 0
    apply_discovery(padded, device, interface_status=interface_status)
    assert Module.objects.get(serial=padded_item["serial"]).module_type_id == padded_type.pk
    assert not ModuleType.objects.filter(
        manufacturer=manufacturer, model=padded_item["model"]
    ).exists()
    checks.append("filtered catalogs retain friendly models with whitespace-padded PIDs")

    parent_item = component(10, [])
    child_item = component(11, [])
    child_item["parent_key"] = parent_item["key"]
    nested = observed([child_item, parent_item], [])
    with CaptureQueriesContext(connection) as captured:
        nested_plan = build_plan(nested, snapshot_inventory(device, discovery=nested))
        validate_plan(nested_plan, device, interface_status=interface_status)
    assert_no_dml(captured, "Nested module preview issued DML")
    apply_discovery(nested, device, interface_status=interface_status)
    nested_parent = Module.objects.get(serial=parent_item["serial"])
    nested_child = Module.objects.get(serial=child_item["serial"])
    assert nested_child.parent_module_bay.parent_module_id == nested_parent.pk
    assert nested_child.parent_module_bay.parent_device_id == device.pk
    assert nested_child.device.pk == device.pk
    with CaptureQueriesContext(connection) as captured:
        apply_discovery(nested, device, interface_status=interface_status)
    assert_no_dml(captured, "Repeated nested module apply issued DML")
    checks.append(
        "nested bays retain the root Device and immediate parent Module without repeat DML"
    )

    Module.objects.filter(pk=first_module.pk).update(serial=None)
    blank_serial = apply_discovery(discovery, device, interface_status=interface_status)
    first_module.refresh_from_db()
    assert first_module.serial == first_item["serial"]
    assert blank_serial["summary"]["modules_updated"] == 1
    checks.append("an existing module's blank serial is enriched without replacing its record")

    replacement_item = copy.deepcopy(first_item)
    replacement_item["serial"] = "CODEX-REPLACEMENT-" + prefix
    replacement = observed([replacement_item], [fact(physical_name(1))])
    before_conflict = snapshot_inventory(device)
    with CaptureQueriesContext(connection) as captured:
        conflict = apply_discovery(replacement, device, interface_status=interface_status)
    assert_no_dml(captured, "An occupied bay was changed by a replacement observation")
    first_module.refresh_from_db()
    member.refresh_from_db()
    assert first_module.serial == first_item["serial"] and member.module_id == first_module.pk
    assert conflict["conflicts"] and snapshot_inventory(device) == before_conflict

    relocation_item = component(
        3, [physical_name(1)], model=first_item["model"], serial=first_item["serial"]
    )
    relocation = observed([relocation_item], [fact(physical_name(1))])
    with CaptureQueriesContext(connection) as captured:
        conflict = apply_discovery(relocation, device, interface_status=interface_status)
    assert_no_dml(captured, "A populated module was silently relocated")
    first_module.refresh_from_db()
    assert first_module.parent_module_bay.name == first_item["bay"]["name"]
    assert conflict["conflicts"] and snapshot_inventory(device) == before_conflict
    assert not ModuleBay.objects.filter(
        parent_device=device, name=relocation_item["bay"]["name"]
    ).exists()
    checks.append(
        "occupied-bay replacement and same-serial relocation conflicts preserve all inventory"
    )

    # Corrupt source relationships must fail before catalog or component writes.
    ambiguous = observed(
        [copy.deepcopy(first_item), component(4, [physical_name(1)])], [fact(physical_name(1))]
    )
    self_parent = copy.deepcopy(discovery)
    self_parent["components"]["items"][0]["parent_key"] = first_item["key"]
    bad_schema = copy.deepcopy(discovery)
    bad_schema["components"]["schema_version"] = 99
    for invalid in (ambiguous, self_parent, bad_schema):
        before_failure = snapshot_inventory(device)
        with CaptureQueriesContext(connection) as captured:
            try:
                apply_discovery(invalid, device, interface_status=interface_status)
            except (ValueError, ValidationError):
                pass
            else:
                raise AssertionError("Ambiguous or invalid component source unexpectedly applied")
        assert_no_dml(captured, "Invalid component source issued DML before rejection")
        assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_failure
    checks.append(
        "ambiguous interface ownership, self-parent relationships, "
        "and invalid schema block before writes"
    )

    # Inject the final ownership-save failure after preceding module catalog,
    # bay, module, device, software, and interface changes have actually occurred.
    final_member = seed_interface(physical_name(6), description="")
    Device.objects.filter(pk=device.pk).update(serial="", software_version=None)
    device.refresh_from_db()
    failure_item = component(5, [physical_name(5), physical_name(6)])
    failure_discovery = observed([failure_item], [fact(physical_name(5)), fact(physical_name(6))])
    failure_discovery["identity"]["software_version"] = unused_version()
    before_failure = snapshot_inventory(device)
    before_catalog_counts = catalog_counts()
    before_interface_count = Interface.objects.count()
    before_version_count = SoftwareVersion.objects.count()
    original_save = Interface.validated_save
    writes_seen = []

    def fail_final_owner(interface, *args, **kwargs):
        if interface.pk == final_member.pk and interface.module_id is not None:
            installed = Module.objects.get(serial=failure_item["serial"])
            assert installed.module_type.model == failure_item["model"]
            assert installed.parent_module_bay.name == failure_item["bay"]["name"]
            assert (
                Interface.objects.get(device=device, name=physical_name(5)).module_id
                == installed.pk
            )
            saved_final = Interface.objects.get(pk=final_member.pk)
            assert saved_final.module_id is None
            saved_device = Device.objects.get(pk=device.pk)
            assert saved_device.serial == failure_discovery["identity"]["serial"]
            assert (
                saved_device.software_version.version
                == failure_discovery["identity"]["software_version"]
            )
            writes_seen.append(
                "catalog, bay, module, device, software, interface, and ownership saved"
            )
            raise ValidationError({"module": "Intentional final interface ownership-save failure"})
        return original_save(interface, *args, **kwargs)

    with patch.object(Interface, "validated_save", fail_final_owner):
        try:
            apply_discovery(failure_discovery, device, interface_status=interface_status)
        except ValidationError:
            pass
        else:
            raise AssertionError("The injected final module ownership-save failure did not occur")
    assert writes_seen, "Rollback scenario did not save preceding module and ownership rows"
    assert snapshot_inventory(Device.objects.get(pk=device.pk)) == before_failure
    assert catalog_counts() == before_catalog_counts
    assert Interface.objects.count() == before_interface_count
    assert SoftwareVersion.objects.count() == before_version_count
    assert not Module.objects.filter(serial=failure_item["serial"]).exists()
    assert not Interface.objects.filter(device=device, name=physical_name(5)).exists()
    checks.append(
        "final interface ownership failure rolls back preceding catalogs, bays, modules, "
        "device, and interfaces"
    )
