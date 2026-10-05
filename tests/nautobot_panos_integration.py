"""Prove PAN-OS native inventory behavior inside an unconditional outer rollback.

Run in a configured Nautobot Django process via ``nbshell`` and ``runpy``. Select
an existing Device explicitly with ``NAUTOBOT_DISCOVERY_DEVICE_ID``; it supplies
only the temporary synthetic target's Location, Role and Status. These checks
are synthetic ORM proof, not evidence for a particular firewall's capabilities.
No credentials or live device connections are used, and all records roll back.
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


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _fact(name, **values):
    from jobs.transport_ssh import INTERFACES, RUNNING_INTERFACES

    fact = {
        "name": name,
        "type": None,
        "enabled": True,
        "description": "Synthetic PAN-OS native ORM verification",
        "mtu": 1500,
        "mac_address": None,
        "type_source": "Synthetic capability unknown; exact DeviceType template required",
        **values,
    }
    fact["source"] = {
        "contract": "panos-interface-v1",
        "operational_command": INTERFACES,
        "hardware_path": "result/hw/entry",
        "name": name,
        "id": "synthetic-" + name,
        "applied_command": RUNNING_INTERFACES,
        "applied_path": "result/interface/ethernet/entry",
        "link_state": {True: "up", False: "down"}.get(fact["enabled"]),
        "comment": fact["description"],
        "mtu": str(fact["mtu"]) if fact["mtu"] is not None else None,
    }
    return fact


def _vm_discovery(
    name,
    vm_uuid,
    *,
    expected_vm_uuid=None,
    ports=(100, 101, 102, 103),
    version="99.99.3-h1",
    report_payloads=None,
):
    """Collect production adapter facts from explicit synthetic structured evidence."""
    import xml.etree.ElementTree as ET
    from types import SimpleNamespace

    from jobs.adapters import panos
    from jobs.transport_ssh import (
        HA_STATE,
        IKE_SAS,
        INTERFACES,
        IPSEC_SAS,
        RUNNING_HA,
        RUNNING_INTERFACES,
        RUNNING_VPN,
        SYSTEM_INFO,
        VM_INTERFACES,
        VPN_FLOWS,
    )

    system_response = ET.Element("response", status="success")
    system = ET.SubElement(ET.SubElement(system_response, "result"), "system")
    for field, value in {
        "hostname": name,
        "model": "PA-VM",
        "serial": "unknown",
        "sw-version": version,
        "family": "vm",
        "vm-mode": "KVM",
        "vm-license": "none",
        "vm-uuid": vm_uuid,
    }.items():
        ET.SubElement(system, field).text = value
    interface_response = ET.Element("response", status="success")
    result = ET.SubElement(interface_response, "result")
    ET.SubElement(result, "hw")
    ET.SubElement(result, "ifnet")
    vm_response = ET.Element("response", status="success")
    vm_result = ET.SubElement(vm_response, "result")
    applied_response = ET.Element("response", status="success")
    applied = ET.SubElement(
        ET.SubElement(ET.SubElement(applied_response, "result"), "interface"), "ethernet"
    )
    for index, number in enumerate(ports):
        name = "ethernet1/%d" % number
        row = ET.SubElement(vm_result, "entry")
        for field, value in {
            "Interface_name": "Ethernet1/%d" % number,
            "Base-OS_port": "eth%d" % (index + 1),
            "Base-OS_BUS": "0000:00:%02x.0" % (0x13 + index),
            "Base-OS_MAC": "02:00:00:00:01:%02x" % (index + 1),
        }.items():
            ET.SubElement(row, field).text = value
        config = ET.SubElement(applied, "entry", name=name)
        if index < 3:
            ET.SubElement(config, "link-state").text = ("up", "down", "auto")[index]
        ET.SubElement(config, "comment").text = "Synthetic UUID-bound PAN-OS port"
        ET.SubElement(ET.SubElement(config, "layer3"), "mtu").text = "1500"
    outputs = {
        command: ET.tostring(response, encoding="unicode")
        for command, response in (
            (SYSTEM_INFO, system_response),
            (INTERFACES, interface_response),
            (RUNNING_INTERFACES, applied_response),
            (VM_INTERFACES, vm_response),
        )
    }
    # These successful envelopes assert only synthetic structured absence. Do
    # not import unit-test modules (which replace jobs imports outside Django).
    outputs.update(
        {
            RUNNING_HA: '<response status="success"><result><deviceconfig/></result></response>',
            HA_STATE: '<response status="success"><result><enabled>no</enabled>'
            "<group><peer-info><enabled>no</enabled></peer-info></group></result></response>",
            RUNNING_VPN: '<response status="success"><result><network/></result></response>',
            IKE_SAS: '<response status="success"><result/></response>',
            IPSEC_SAS: '<response status="success"><result><entries/><ntun>0</ntun>'
            "</result></response>",
            VPN_FLOWS: '<response status="success"><result><dp>dp0</dp><num_ipsec>0</num_ipsec>'
            "<num_sslvpn>0</num_sslvpn><IPSec/><total>0</total></result></response>",
        }
    )
    if report_payloads is not None:
        outputs.update(report_payloads)
    return panos.collect(
        SimpleNamespace(run=outputs.__getitem__), expected_vm_uuid=expected_vm_uuid
    )


def run(device_id=None):
    """Verify strict previews, native apply, preservation, repeats and rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.apps import apps
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
    from nautobot.extras.models import CustomField, Status

    from jobs.discovery_job import _adapter
    from jobs.nautobot_inventory import (
        InventoryError,
        apply_discovery,
        snapshot_inventory,
        validate_plan,
    )
    from jobs.reconcile import build_plan
    from jobs.transport_ssh import (
        HA_STATE,
        IKE_SAS,
        IPSEC_SAS,
        RUNNING_HA,
        RUNNING_VPN,
        VPN_FLOWS,
        vpn_flow_detail_command,
    )

    device_id = device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID")
    if not device_id:
        raise ValueError("Select an existing anchor with NAUTOBOT_DISCOVERY_DEVICE_ID")
    anchor = Device.objects.select_related("location", "role", "status").get(pk=device_id)
    baseline = snapshot_inventory(anchor)
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
    )
    # Discover only actual installed models; do not assume VPN exists on 2.4.
    report_only_models = tuple(
        model
        for model in apps.get_models()
        if model._meta.app_label == "vpn"
        or (
            model._meta.app_label == "dcim"
            and model._meta.model_name
            in {
                "deviceredundancygroup",
                "interfaceredundancygroup",
                "interfaceredundancygroupassociation",
            }
        )
    )
    tracked += report_only_models
    before_counts = {model.__name__: model.objects.count() for model in tracked}
    interface_status = Status.objects.get_for_model(Interface).get(name="Active")
    checks = []
    token = uuid.uuid4().hex[:12]
    with transaction.atomic():
        try:
            manufacturer = Manufacturer(name="Palo Alto Networks")
            existing_manufacturer = Manufacturer.objects.filter(name=manufacturer.name).first()
            if existing_manufacturer:
                manufacturer = existing_manufacturer
            else:
                manufacturer.validated_save()
            platform = Platform(
                name="PAN-OS synthetic " + token,
                network_driver="paloalto_panos",
                manufacturer=manufacturer,
            )
            platform.validated_save()
            device_type = DeviceType(manufacturer=manufacturer, model="SYNTHETIC-PANOS-" + token)
            device_type.validated_save()
            target = Device(
                name="panos-native-" + token,
                serial="",
                device_type=device_type,
                platform=platform,
                role=anchor.role,
                location=anchor.location,
                status=anchor.status,
            )
            target.validated_save()
            assert _adapter(target).__name__.endswith(".panos")
            checks.append("PAN-OS Platform dispatch selects the PAN-OS adapter")
            # Create templates after the Device: test planner use of the exact
            # template rather than automatic component creation at Device save.
            for number in range(1, 8):
                InterfaceTemplate(
                    device_type=device_type, name="ethernet1/%d" % number, type="1000base-t"
                ).validated_save()
            port = Interface(
                device=target,
                name="ethernet1/1",
                type="other",
                enabled=False,
                description="Operator description",
                mtu=9000,
                mac_address="02:00:00:00:00:01",
                status=interface_status,
            )
            port.validated_save()
            peer = Interface(
                device=target,
                name="ethernet1/99",
                type="1000base-t",
                enabled=False,
                status=interface_status,
            )
            peer.validated_save()
            cable = Cable(status=Status.objects.get_for_model(Cable).get(name="Connected"))
            cable.validated_save()
            for cable_end, interface in (("A", port), ("B", peer)):
                CableToCableTermination(
                    cable=cable, cable_end=cable_end, connector=1, interface=interface
                ).validated_save()
            port.refresh_from_db()
            preserved_port_id = port.pk
            cable_joins = list(cable.terminations.order_by("pk").values())
            identity = {
                "hostname": target.name,
                "serial": "SYNTHETIC-PANOS-" + token,
                "model": device_type.model,
                "software_version": "99.99.1-h1",
            }
            discovery = {
                "schema_version": 1,
                "adapter": "panos",
                "identity": identity,
                "interfaces": [
                    _fact("ethernet1/1"),
                    _fact("ethernet1/2", enabled=False),
                    _fact("ethernet1/3", enabled=None),
                ],
                "warnings": [],
                "excluded_interfaces": [],
            }
            before = snapshot_inventory(target, discovery=discovery)
            with CaptureQueriesContext(connection) as captured:
                plan = build_plan(discovery, snapshot_inventory(target, discovery=discovery))
                validate_plan(plan, target, interface_status=interface_status)
            _no_dml(captured, "PAN-OS preview issued inventory DML")
            assert not plan["errors"] and not plan["summary"]["blocked"]
            assert plan["summary"]["interfaces_created"] == 1
            assert plan["interface_creates"][0]["name"] == "ethernet1/2"
            assert plan["interface_creates"][0]["enabled"] is False
            assert snapshot_inventory(target, discovery=discovery) == before
            checks.append(
                "PAN-OS preview validates new software and exact-template interfaces without DML"
            )
            checks.append(
                "missing administrative state defers creation despite an exact type template"
            )

            applied = apply_discovery(discovery, target, interface_status=interface_status)
            target.refresh_from_db()
            port.refresh_from_db()
            created = target.interfaces.get(name="ethernet1/2")
            assert applied["summary"]["interfaces_created"] == 1
            assert created.type == "1000base-t" and created.enabled is False
            assert not target.interfaces.filter(name="ethernet1/3").exists()
            assert target.serial == identity["serial"]
            assert target.software_version.version == "99.99.1-h1"
            assert target.platform_id == platform.pk and target.device_type_id == device_type.pk
            checks.append(
                "apply creates disabled interfaces and fills exact PAN-OS software "
                "release and serial"
            )
            assert port.pk == preserved_port_id and port.type == "other" and port.enabled is False
            assert port.description == "Operator description" and port.mtu == 9000
            assert str(port.mac_address) == "02:00:00:00:00:01" and port.cable_id == cable.pk
            assert list(cable.terminations.order_by("pk").values()) == cable_joins
            checks.append(
                "apply preserves populated Other, False, description, MTU, MAC, UUID "
                "and cable joins"
            )

            after = snapshot_inventory(target, discovery=discovery)
            with CaptureQueriesContext(connection) as captured:
                repeated = apply_discovery(discovery, target, interface_status=interface_status)
            _no_dml(captured, "Repeated PAN-OS apply issued inventory DML")
            assert repeated["summary"]["interfaces_created"] == 0
            assert repeated["summary"]["interfaces_updated"] == 0
            assert repeated["summary"]["device_fields_updated"] == 0
            assert snapshot_inventory(target, discovery=discovery) == after
            checks.append("repeat PAN-OS discovery produces zero inventory DML")

            unknown = copy.deepcopy(discovery)
            unknown["interfaces"] = [_fact("ethernet1/98")]
            with CaptureQueriesContext(connection) as captured:
                unknown_plan = build_plan(unknown, snapshot_inventory(target, discovery=unknown))
                validate_plan(unknown_plan, target, interface_status=interface_status)
            _no_dml(captured, "Unknown PAN-OS type preview issued inventory DML")
            assert unknown_plan["interface_creates"] == []
            checks.append(
                "unclassified interface without an exact template is unresolved rather than guessed"
            )

            incomplete = copy.deepcopy(discovery)
            incomplete["identity"]["serial"] = None
            incomplete["interfaces"] = [_fact("ethernet1/4")]
            before_incomplete = snapshot_inventory(target, discovery=incomplete)
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(incomplete, target, interface_status=interface_status)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("PAN-OS apply accepted missing discovered serial identity")
            _no_dml(captured, "PAN-OS missing-serial apply issued inventory DML")
            assert snapshot_inventory(target, discovery=incomplete) == before_incomplete
            checks.append(
                "missing discovered serial blocks all PAN-OS apply writes even with "
                "existing identity"
            )

            invalid = copy.deepcopy(discovery)
            too_long = "X" * (Interface._meta.get_field("description").max_length + 1)
            invalid["interfaces"] = [
                _fact("ethernet1/4"),
                _fact("ethernet1/5", description=too_long),
            ]
            before_failure = snapshot_inventory(target, discovery=invalid)
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(invalid, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError(
                        "PAN-OS oversized description unexpectedly passed real model validation"
                    )
            _no_dml(
                captured,
                "PAN-OS whole-plan validation issued DML before rejecting an oversized description",
            )
            assert snapshot_inventory(target, discovery=invalid) == before_failure
            checks.append("native whole-plan validation rejects invalid PAN-OS rows before any DML")

            Device.objects.filter(pk=target.pk).update(serial="", software_version=None)
            target.refresh_from_db()
            failing = copy.deepcopy(discovery)
            failing["identity"]["software_version"] = "99.99.2-h1"
            failing["interfaces"] = [_fact("ethernet1/6"), _fact("ethernet1/7")]
            before_failure = snapshot_inventory(target, discovery=failing)
            version_count = SoftwareVersion.objects.count()
            interface_count = Interface.objects.count()
            original_save = Interface.validated_save
            writes_seen = []

            def fail_late(interface, *args, **kwargs):
                if interface.name == "ethernet1/7":
                    assert target.interfaces.filter(name="ethernet1/6").exists()
                    assert SoftwareVersion.objects.filter(
                        platform=platform, version="99.99.2-h1"
                    ).exists()
                    saved = Device.objects.get(pk=target.pk)
                    assert saved.serial == identity["serial"]
                    assert saved.software_version_id is not None
                    writes_seen.append(True)
                    raise ValidationError(
                        {"name": "Intentional PAN-OS final interface save failure"}
                    )
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", fail_late):
                try:
                    apply_discovery(failing, target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("PAN-OS late interface failure did not occur")
            assert writes_seen, "PAN-OS rollback scenario did not first save related inventory"
            assert (
                snapshot_inventory(Device.objects.get(pk=target.pk), discovery=failing)
                == before_failure
            )
            assert SoftwareVersion.objects.count() == version_count
            assert Interface.objects.count() == interface_count
            assert list(cable.terminations.order_by("pk").values()) == cable_joins
            checks.append(
                "late PAN-OS save failure rolls back preceding device, software and "
                "interface writes"
            )

            # A deliberately explicit VM UUID contract: the production adapter
            # parses synthetic XML, so the planner is tested against its actual
            # provenance shape. Exact virtual templates supply native type.
            vm_type = DeviceType.objects.filter(manufacturer=manufacturer, model="PA-VM").first()
            if vm_type is None:
                vm_type = DeviceType(manufacturer=manufacturer, model="PA-VM")
                vm_type.validated_save()
            vm_target = Device(
                name="panos-vm-native-" + token,
                serial="",
                device_type=vm_type,
                platform=platform,
                role=anchor.role,
                location=anchor.location,
                status=anchor.status,
            )
            vm_target.validated_save()
            for number in range(100, 106):
                vm_name = "ethernet1/%d" % number
                assert not vm_type.interface_templates.filter(name=vm_name).exists()
                InterfaceTemplate(
                    device_type=vm_type, name=vm_name, type="virtual"
                ).validated_save()
            vm_uuid = str(uuid.uuid4())
            vm_discovery = _vm_discovery(vm_target.name, vm_uuid, expected_vm_uuid=vm_uuid)
            assert vm_discovery["identity"]["serial"] is None
            assert vm_discovery["identity_binding"]["observed_uuid"] == vm_uuid
            assert all(
                row["source"]["contract"] == "panos-vm-interface-v1"
                for row in vm_discovery["interfaces"]
            )
            assert all(row["mac_address"] is None for row in vm_discovery["interfaces"])

            def rejected_vm(discovery, message):
                before_rejected = snapshot_inventory(vm_target, discovery=discovery)
                with CaptureQueriesContext(connection) as captured:
                    try:
                        apply_discovery(discovery, vm_target, interface_status=interface_status)
                    except InventoryError:
                        pass
                    else:
                        raise AssertionError(message)
                _no_dml(captured, message + " issued inventory DML")
                assert snapshot_inventory(vm_target, discovery=discovery) == before_rejected

            unbound = _vm_discovery(vm_target.name, vm_uuid)
            rejected_vm(unbound, "PAN-OS VM missing explicit UUID binding was accepted")
            checks.append(
                "blank-serial VM apply without explicit UUID binding is blocked before DML"
            )
            mismatched = _vm_discovery(vm_target.name, vm_uuid, expected_vm_uuid=str(uuid.uuid4()))
            rejected_vm(mismatched, "PAN-OS VM mismatched explicit UUID was accepted")
            checks.append("mismatched expected and observed VM UUID blocks every native write")
            for mutate in (
                lambda row: row["observations"]["system"].update({"vm-uuid": str(uuid.uuid4())}),
                lambda row: row["sources"]["identity"].update({"command": "show system software"}),
                lambda row: row["identity_binding"].update({"contract": "unreviewed"}),
            ):
                invalid_binding = copy.deepcopy(vm_discovery)
                mutate(invalid_binding)
                rejected_vm(invalid_binding, "PAN-OS VM invalid UUID provenance was accepted")
            checks.append(
                "VM UUID exemption requires matching raw system, command and contract provenance"
            )
            invalid_profile = copy.deepcopy(vm_discovery)
            invalid_profile["observations"]["system"]["vm-mode"] = "ESXi"
            invalid_profile["identity_binding"]["vm_mode"] = "ESXi"
            rejected_vm(invalid_profile, "PAN-OS VM unreviewed platform profile was accepted")
            checks.append(
                "VM UUID serial exemption remains limited to the reviewed PA-VM KVM profile"
            )
            Device.objects.filter(pk=vm_target.pk).update(serial="Operator VM serial")
            vm_target.refresh_from_db()
            rejected_vm(vm_discovery, "PAN-OS VM populated selected serial bypassed identity gate")
            Device.objects.filter(pk=vm_target.pk).update(serial="")
            vm_target.refresh_from_db()
            checks.append("UUID binding never bypasses the populated selected serial requirement")

            for field, value in (
                ("enumeration_command", "debug show vm-series interfaces"),
                ("enumeration_path", "result/hw/entry"),
                ("raw_name", "Ethernet1/999"),
                ("base_os_port", "eth999"),
                ("base_os_bus", "0000:00:12.0"),
            ):
                invalid_vm_source = copy.deepcopy(vm_discovery)
                invalid_vm_source["interfaces"][0]["source"][field] = value
                rejected_vm(
                    invalid_vm_source, "PAN-OS VM tampered enumeration " + field + " was accepted"
                )
            for mutate in (
                lambda row: row["sources"]["vm_interfaces"].update(
                    {"command": "debug show vm-series interfaces"}
                ),
                lambda row: row["observations"]["vm_interfaces"].append(
                    copy.deepcopy(row["observations"]["vm_interfaces"][0])
                ),
                lambda row: row["observations"].update({"vm_interfaces": []}),
            ):
                invalid_vm_source = copy.deepcopy(vm_discovery)
                mutate(invalid_vm_source)
                rejected_vm(
                    invalid_vm_source, "PAN-OS VM invalid enumeration observations were accepted"
                )
            checks.append(
                "VM interface command, path, raw name, base port and bus "
                "must match unique observations before any native DML"
            )

            before_vm = snapshot_inventory(vm_target, discovery=vm_discovery)
            with CaptureQueriesContext(connection) as captured:
                vm_plan = build_plan(vm_discovery, before_vm)
                validate_plan(vm_plan, vm_target, interface_status=interface_status)
            _no_dml(captured, "UUID-bound PAN-OS VM preview issued inventory DML")
            assert not vm_plan["errors"] and not vm_plan["summary"]["blocked"]
            assert vm_plan["identity_binding"]["expected_uuid"] == vm_uuid
            assert {row["name"] for row in vm_plan["interface_creates"]} == {
                "ethernet1/100",
                "ethernet1/101",
            }
            assert all(row["type"] == "virtual" for row in vm_plan["interface_creates"])
            assert snapshot_inventory(vm_target, discovery=vm_discovery) == before_vm
            checks.append(
                "UUID-bound VM preview validates exact virtual templates "
                "and defers auto or absent admin"
            )
            vm_applied = apply_discovery(vm_discovery, vm_target, interface_status=interface_status)
            vm_target.refresh_from_db()
            assert vm_applied["summary"]["interfaces_created"] == 2
            assert vm_target.interfaces.get(name="ethernet1/100").enabled is True
            assert vm_target.interfaces.get(name="ethernet1/101").enabled is False
            assert not vm_target.interfaces.filter(
                name__in=("ethernet1/102", "ethernet1/103")
            ).exists()
            assert vm_target.serial == ""
            assert vm_target.software_version.version == "99.99.3-h1"
            assert vm_target.platform_id == platform.pk and vm_target.device_type_id == vm_type.pk
            checks.append(
                "UUID-bound VM apply creates virtual ports and software "
                "while preserving blank serial"
            )
            after_vm = snapshot_inventory(vm_target, discovery=vm_discovery)
            with CaptureQueriesContext(connection) as captured:
                repeated_vm = apply_discovery(
                    vm_discovery, vm_target, interface_status=interface_status
                )
            _no_dml(captured, "Repeated UUID-bound PAN-OS VM apply issued inventory DML")
            assert repeated_vm["summary"]["interfaces_created"] == 0
            assert repeated_vm["summary"]["interfaces_updated"] == 0
            assert repeated_vm["summary"]["device_fields_updated"] == 0
            assert snapshot_inventory(vm_target, discovery=vm_discovery) == after_vm
            checks.append("fresh UUID-bound VM repeat issues zero inventory DML")

            # Valid collected report facts change independently of inventory.
            # Use sanitized reviewed evidence, then change an actual HA role and
            # VPN counter through XML parsing rather than inventing native data.
            import xml.etree.ElementTree as ET

            fixtures = Path(__file__).parent / "fixtures"
            detail_command = vpn_flow_detail_command(1)
            report_payloads = {
                RUNNING_HA: (fixtures / "panos_ha_configured.xml").read_text(),
                HA_STATE: (fixtures / "panos_ha_active.xml").read_text(),
                RUNNING_VPN: (fixtures / "panos_vpn_applied_network.xml").read_text(),
                IKE_SAS: (fixtures / "panos_vpn_ike_sas.xml").read_text(),
                IPSEC_SAS: (fixtures / "panos_vpn_ipsec_sas.xml").read_text(),
                VPN_FLOWS: (fixtures / "panos_vpn_flows.xml").read_text(),
                detail_command: (fixtures / "panos_vpn_local_flow_detail.xml").read_text(),
            }
            observed_vm = _vm_discovery(
                vm_target.name, vm_uuid, expected_vm_uuid=vm_uuid, report_payloads=report_payloads
            )
            changed_payloads = dict(report_payloads)
            changed_payloads[HA_STATE] = (fixtures / "panos_ha_passive.xml").read_text()
            detail_xml = ET.fromstring(changed_payloads[detail_command])
            counter = detail_xml.find("result/IPSec/entry/pkt-encap")
            counter.text = str(int(counter.text) + 7)
            changed_payloads[detail_command] = ET.tostring(detail_xml, encoding="unicode")
            changed_vm = _vm_discovery(
                vm_target.name, vm_uuid, expected_vm_uuid=vm_uuid, report_payloads=changed_payloads
            )
            assert observed_vm["observations"]["ha"]["runtime"]["local"]["role"] == "active"
            assert changed_vm["observations"]["ha"]["runtime"]["local"]["role"] == "passive"
            observed_counter = observed_vm["observations"]["vpn"]["runtime"]["flow_details"][0][
                "counters"
            ]["pkt_encap"]
            changed_counter = changed_vm["observations"]["vpn"]["runtime"]["flow_details"][0][
                "counters"
            ]["pkt_encap"]
            assert changed_counter == observed_counter + 7
            assert observed_vm["observations"]["vpn"]["native_writes"] is False
            assert changed_vm["observations"]["vpn"]["native_writes"] is False
            observation_counts = {model.__name__: model.objects.count() for model in tracked}
            with CaptureQueriesContext(connection) as captured:
                base_plan = build_plan(
                    vm_discovery, snapshot_inventory(vm_target, discovery=vm_discovery)
                )
                observed_plan = build_plan(
                    observed_vm, snapshot_inventory(vm_target, discovery=observed_vm)
                )
                changed_plan = build_plan(
                    changed_vm, snapshot_inventory(vm_target, discovery=changed_vm)
                )
                assert observed_plan == base_plan == changed_plan
                validate_plan(changed_plan, vm_target, interface_status=interface_status)
                observed_repeat = apply_discovery(
                    changed_vm, vm_target, interface_status=interface_status
                )
            _no_dml(captured, "Changed HA role or VPN counter issued native inventory DML")
            assert observed_repeat["summary"]["interfaces_created"] == 0
            assert observed_repeat["summary"]["interfaces_updated"] == 0
            assert observed_repeat["summary"]["device_fields_updated"] == 0
            assert snapshot_inventory(vm_target, discovery=changed_vm) == after_vm
            assert {
                model.__name__: model.objects.count() for model in tracked
            } == observation_counts
            checks.append(
                "parsed HA role and VPN counter changes preserve the same native plan, "
                "issue zero DML, and leave installed HA/VPN models unchanged"
            )

            Device.objects.filter(pk=vm_target.pk).update(software_version=None)
            vm_target.refresh_from_db()
            vm_failing = _vm_discovery(
                vm_target.name,
                vm_uuid,
                expected_vm_uuid=vm_uuid,
                ports=(104, 105),
                version="99.99.4-h1",
            )
            vm_before_failure = snapshot_inventory(vm_target, discovery=vm_failing)
            vm_version_count = SoftwareVersion.objects.count()
            vm_interface_count = Interface.objects.count()
            vm_writes_seen = []

            def vm_fail_late(interface, *args, **kwargs):
                if interface.name == "ethernet1/105":
                    assert vm_target.interfaces.filter(name="ethernet1/104").exists()
                    saved_vm = Device.objects.get(pk=vm_target.pk)
                    assert saved_vm.serial == "" and saved_vm.software_version_id is not None
                    assert SoftwareVersion.objects.filter(
                        platform=platform, version="99.99.4-h1"
                    ).exists()
                    vm_writes_seen.append(True)
                    raise ValidationError({"name": "Intentional UUID-bound VM final save failure"})
                return original_save(interface, *args, **kwargs)

            with patch.object(Interface, "validated_save", vm_fail_late):
                try:
                    apply_discovery(vm_failing, vm_target, interface_status=interface_status)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("UUID-bound VM late interface failure did not occur")
            assert vm_writes_seen, "VM rollback scenario did not first save related inventory"
            assert (
                snapshot_inventory(Device.objects.get(pk=vm_target.pk), discovery=vm_failing)
                == vm_before_failure
            )
            assert SoftwareVersion.objects.count() == vm_version_count
            assert Interface.objects.count() == vm_interface_count
            checks.append(
                "UUID-bound VM late save failure rolls back software and preceding interface writes"
            )

        finally:
            transaction.set_rollback(True)

    assert snapshot_inventory(Device.objects.get(pk=anchor.pk)) == baseline
    assert {model.__name__: model.objects.count() for model in tracked} == before_counts
    checks.append("outer rollback restores anchor inventory and every tracked native catalog count")
    return {
        "anchor_device_id": str(anchor.pk),
        "passed": True,
        "checks": checks,
        "persistent_changes": 0,
        "observation_only_native_models": sorted(model._meta.label for model in report_only_models),
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
