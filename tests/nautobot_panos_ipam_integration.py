"""Native PAN-OS IPAM proof, with every fixture and mutation rolled back.

Run in a configured Nautobot process using nbshell/runpy. The selected anchor
supplies only Location/Role/Status. All devices, namespaces, mappings and source
XML are explicit synthetic reviewed-schema evidence; no firewall is contacted.
This harness validates the installed ORM, not another Nautobot or PAN-OS release.
"""

import copy
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)
ANCHOR = "ed010564-cfd9-4039-bfad-a40ea4487157"
FIXTURES = Path(__file__).parent / "fixtures"


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _fixture(name):
    return (FIXTURES / name).read_text()


def _extra_loopback(network, vsys, number, ipv4, ipv6=None):
    """Add an explicit reviewed-schema test address and both routing memberships."""
    network_root, vsys_root = ET.fromstring(network), ET.fromstring(vsys)
    name = "loopback.%d" % number
    entry = ET.SubElement(
        network_root.find("result/network/interface/loopback/units"), "entry", name=name
    )
    ET.SubElement(ET.SubElement(entry, "ip"), "entry", name=ipv4)
    if ipv6 is not None:
        family = ET.SubElement(entry, "ipv6")
        ET.SubElement(family, "enabled").text = "yes"
        address = ET.SubElement(ET.SubElement(family, "address"), "entry", name=ipv6)
        ET.SubElement(address, "enable-on-interface").text = "yes"
    router = network_root.find('result/network/virtual-router/entry[@name="vr-public"]/interface')
    ET.SubElement(router, "member").text = name
    imported = vsys_root.find('result/vsys/entry[@name="vsys1"]/import/network/interface')
    ET.SubElement(imported, "member").text = name
    return ET.tostring(network_root, encoding="unicode"), ET.tostring(vsys_root, encoding="unicode")


def _collect(name, vm_uuid, *, network=None, vsys=None, ha_state=None):
    """Exercise the production collector, including independent system UUID proof."""
    from jobs.adapters import panos
    from jobs.transport_ssh import (
        HA_STATE,
        IKE_SAS,
        INTERFACES,
        IPSEC_SAS,
        RUNNING_HA,
        RUNNING_INTERFACES,
        RUNNING_VPN,
        RUNNING_VSYS,
        SYSTEM_INFO,
        VM_INTERFACES,
        VPN_FLOWS,
    )

    network = network if network is not None else _fixture("panos_ipam_network.xml")
    vsys = vsys if vsys is not None else _fixture("panos_ipam_vsys.xml")
    system = ET.fromstring(_fixture("panos_vm_system_info.xml"))
    system.find("result/system/hostname").text = name
    system.find("result/system/vm-uuid").text = vm_uuid
    interface_response = ET.Element("response", status="success")
    interface_result = ET.SubElement(interface_response, "result")
    interface_result.append(copy.deepcopy(ET.fromstring(network).find("result/network/interface")))
    payloads = {
        SYSTEM_INFO: ET.tostring(system, encoding="unicode"),
        INTERFACES: _fixture("panos_vm_empty_interfaces.xml"),
        VM_INTERFACES: _fixture("panos_vm_guest_interfaces.xml"),
        RUNNING_INTERFACES: ET.tostring(interface_response, encoding="unicode"),
        RUNNING_HA: '<response status="success"><result><deviceconfig/></result></response>',
        HA_STATE: ha_state if ha_state is not None else _fixture("panos_ha_disabled.xml"),
        RUNNING_VPN: network,
        RUNNING_VSYS: vsys,
        IKE_SAS: '<response status="success"><result/></response>',
        IPSEC_SAS: '<response status="success"><result><entries/><ntun>0</ntun>'
        "</result></response>",
        VPN_FLOWS: '<response status="success"><result><dp>dp0</dp><num_ipsec>0</num_ipsec>'
        "<num_sslvpn>0</num_sslvpn><IPSec/><total>0</total></result></response>",
    }
    return panos.collect(SimpleNamespace(run=payloads.__getitem__), expected_vm_uuid=vm_uuid)


def run(device_id=None):
    """Verify explicit mappings, static native relations, preservation and rollback."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.apps import apps
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Device,
        DeviceType,
        Interface,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.extras.models import CustomField, Status
    from nautobot.ipam import models as ipam_models
    from nautobot.ipam.models import (
        VRF,
        IPAddress,
        IPAddressToInterface,
        Namespace,
        Prefix,
        PrefixLocationAssignment,
        RouteTarget,
        VRFDeviceAssignment,
        VRFPrefixAssignment,
    )

    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    anchor = Device.objects.select_related("location", "role", "status").get(
        pk=device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID") or ANCHOR
    )
    anchor_before = snapshot_inventory(anchor)
    location_content_types = set(
        anchor.location.location_type.content_types.values_list("pk", flat=True)
    )
    tracked = [
        Manufacturer,
        Platform,
        DeviceType,
        Device,
        SoftwareVersion,
        Interface,
        Namespace,
        VRF,
        VRFDeviceAssignment,
        Prefix,
        PrefixLocationAssignment,
        VRFPrefixAssignment,
        IPAddress,
        IPAddressToInterface,
        RouteTarget,
        CustomField,
    ]
    if hasattr(ipam_models, "IPAddressRange"):
        tracked.append(ipam_models.IPAddressRange)
    tracked.extend(
        model
        for model in apps.get_models()
        if model._meta.app_label == "vpn"
        or (model._meta.app_label == "dcim" and "redundancy" in model._meta.model_name)
    )

    def counts():
        return {model._meta.label: model.objects.count() for model in tracked}

    before_counts, checks = counts(), []
    interface_status = Status.objects.get_for_model(Interface).get(name="Active")
    prefix_status = Status.objects.get_for_model(Prefix).get(name="Active")
    address_status = Status.objects.get_for_model(IPAddress).get(name="Active")
    token = uuid.uuid4().hex[:12]
    with transaction.atomic():
        try:
            anchor.location.location_type.content_types.add(
                ContentType.objects.get_for_model(Prefix)
            )
            manufacturer = Manufacturer.objects.filter(name="Palo Alto Networks").first()
            if manufacturer is None:
                manufacturer = Manufacturer(name="Palo Alto Networks")
                manufacturer.validated_save()
            device_type = DeviceType.objects.filter(
                manufacturer=manufacturer, model="PA-VM"
            ).first()
            if device_type is None:
                device_type = DeviceType(manufacturer=manufacturer, model="PA-VM")
                device_type.validated_save()
            platform = Platform(
                name="PAN-IPAM-native-" + token,
                manufacturer=manufacturer,
                network_driver="paloalto_panos",
            )
            platform.validated_save()
            vm_uuid = str(uuid.uuid4())
            name = "panos-ipam-native-" + token
            discovery = _collect(name, vm_uuid)
            version = SoftwareVersion(
                platform=platform,
                version=discovery["identity"]["software_version"],
                status=Status.objects.get_for_model(SoftwareVersion).get(name="Active"),
            )
            version.validated_save()
            target = Device(
                name=name,
                serial="",
                device_type=device_type,
                platform=platform,
                software_version=version,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            target.validated_save()
            peer = Device(
                name="panos-ipam-peer-" + token,
                device_type=device_type,
                platform=platform,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            peer.validated_save()
            native_interfaces = {}
            for row in discovery["ipam"]["interfaces"]:
                existing = target.interfaces.filter(name=row["name"]).first()
                if existing is None:
                    existing = Interface(
                        device=target,
                        name=row["name"],
                        type="lag" if row["kind"] == "aggregate-ethernet" else "virtual",
                        enabled=False,
                        description="Operator-authored baseline",
                        mtu=9000,
                        status=interface_status,
                    )
                else:
                    existing.enabled = False
                    existing.description = "Operator-authored baseline"
                    existing.mtu = 9000
                existing.validated_save()
                native_interfaces[row["name"]] = existing
            for name, parent in (("ethernet1/1.100", "ethernet1/1"), ("ae1.200", "ae1")):
                native_interfaces[name].parent_interface = native_interfaces[parent]
                native_interfaces[name].validated_save()

            public = Namespace(name="PAN-IPAM-PUBLIC-" + token)
            internal = Namespace(name="PAN-IPAM-INTERNAL-" + token)
            outside = Namespace(name="PAN-IPAM-OUTSIDE-" + token)
            for namespace in (public, internal, outside):
                namespace.validated_save()
            routed = VRF(name="Operator canonical VRF " + token, namespace=public, rd="65000:77")
            routed.validated_save()
            routed_assignment = VRFDeviceAssignment(
                vrf=routed, device=target, name="Operator-local-alias", rd="65000:88"
            )
            routed_assignment.validated_save()
            policy = {
                "contract": "panos-ipam-policy-v1",
                "panos_routing_domains": [
                    {
                        "vsys": "vsys1",
                        "virtual_router": "vr-public",
                        "namespace": {"id": str(public.pk), "name": public.name},
                        "vrf": {
                            "id": str(routed.pk),
                            "name": routed.name,
                            "namespace_id": str(public.pk),
                        },
                    },
                    {
                        "vsys": "vsys2",
                        "virtual_router": "vr-internal",
                        "namespace": {"id": str(internal.pk), "name": internal.name},
                        "vrf": None,
                    },
                ],
                "create_missing_prefixes": True,
                "location": {"id": str(target.location_id), "name": target.location.name},
            }
            # An identical host in an unselected Namespace is a distinct identity.
            outside_prefix = Prefix(
                prefix="192.0.2.0/24", namespace=outside, type="network", status=prefix_status
            )
            outside_prefix.validated_save()
            outside_ip = IPAddress(
                address="192.0.2.1/24", parent=outside_prefix, status=address_status
            )
            outside_ip.validated_save()
            outside_port = Interface(
                device=peer,
                name="loopback.999",
                type="virtual",
                enabled=False,
                status=interface_status,
            )
            outside_port.validated_save()
            outside_join = IPAddressToInterface(
                ip_address=outside_ip, interface=outside_port, is_secondary=True
            )
            outside_join.validated_save()
            outside_identity = (
                outside_ip.pk,
                outside_ip.parent_id,
                outside_join.pk,
                outside_join.interface_id,
                outside_join.is_secondary,
            )

            def snapshot(data=discovery, selected_policy=policy):
                return snapshot_inventory(target, discovery=data, ipam_policy=selected_policy)

            def preview(data=discovery, selected_policy=policy):
                plan = build_plan(data, snapshot(data, selected_policy))
                validate_plan(
                    plan,
                    target,
                    interface_status=interface_status,
                    ipam_prefix_status=prefix_status,
                    ipam_ip_address_status=address_status,
                )
                return plan

            def apply(data=discovery, selected_policy=policy):
                return apply_discovery(
                    data,
                    target,
                    interface_status=interface_status,
                    ipam_policy=selected_policy,
                    ipam_prefix_status=prefix_status,
                    ipam_ip_address_status=address_status,
                )

            def fingerprint():
                return list(
                    target.interfaces.order_by("name").values(
                        "pk",
                        "name",
                        "type",
                        "enabled",
                        "description",
                        "mtu",
                        "mac_address",
                        "parent_interface_id",
                        "lag_id",
                    )
                )

            stable_interfaces = fingerprint()
            initial, initial_counts = snapshot(), counts()
            with CaptureQueriesContext(connection) as captured:
                plan = preview()
            _no_dml(captured, "PAN static IPAM preview issued inventory DML")
            assert not plan["errors"] and not plan["summary"]["blocked"]
            assert plan["summary"]["prefixes_created"] == 12
            assert plan["summary"]["ip_addresses_created"] == 12
            assert plan["summary"]["ip_assignments_created"] == 12
            assert plan["summary"]["interfaces_created"] == 0
            assert snapshot() == initial and counts() == initial_counts
            checks.append(
                "static v4/v6 on six explicit existing L3 interface kinds validates with "
                "zero preview DML"
            )
            assert all(not row["create"] for row in plan["ipam"]["vrfs"])
            assert not plan["ipam"]["vrf_device_assignments"] or all(
                not row["create"] and not row["changes"]
                for row in plan["ipam"]["vrf_device_assignments"]
            )
            assert not plan["ipam"].get("route_targets")
            checks.append(
                "vsys/router mappings select existing VRF UUIDs or explicit global without "
                "VRF/RD/RT naming heuristics"
            )
            with CaptureQueriesContext(connection) as applied_queries:
                apply()
            namespace_locks = [
                row["sql"].replace("-", "").lower()
                for row in applied_queries.captured_queries
                if '"ipam_namespace"' in row["sql"] and "FOR UPDATE" in row["sql"].upper()
            ]
            assert any(
                public.pk.hex in query and internal.pk.hex in query and outside.pk.hex not in query
                for query in namespace_locks
            ), "Apply did not lock both explicitly mapped Namespaces"
            checks.append("apply locks every selected Namespace and omits unselected Namespaces")
            target.refresh_from_db()
            assert (
                target.serial == ""
                and target.primary_ip4_id is None
                and target.primary_ip6_id is None
            )
            assert fingerprint() == stable_interfaces
            assert VRF.objects.count() == initial_counts["ipam.VRF"]
            routed_assignment.refresh_from_db()
            assert (
                routed_assignment.name == "Operator-local-alias"
                and routed_assignment.rd == "65000:88"
            )
            expected = {}
            for row in discovery["ipam"]["interfaces"]:
                namespace, vrf = (public, routed) if row["vsys"] == "vsys1" else (internal, None)
                native = target.interfaces.get(name=row["name"])
                assert native.vrf_id == (vrf.pk if vrf is not None else None)
                for address in row["ipv4"] + row["ipv6"]:
                    join = IPAddressToInterface.objects.select_related("ip_address__parent").get(
                        interface=native, ip_address__host=address["host"]
                    )
                    assert join.ip_address.mask_length == address["prefix_length"]
                    assert join.ip_address.parent.namespace_id == namespace.pk
                    assert set(join.ip_address.parent.vrfs.values_list("pk", flat=True)) == (
                        {vrf.pk} if vrf else set()
                    )
                    assert set(join.ip_address.parent.locations.values_list("pk", flat=True)) == {
                        target.location_id
                    }
                    assert not join.is_primary and not join.is_secondary
                    expected[(row["name"], address["host"])] = join.pk
                native.full_clean()
            checks.append(
                "native static IPs, connected Prefixes and assignments use explicit "
                "namespaces/routing contexts and preserve interface baselines"
            )
            outside_ip.refresh_from_db()
            outside_join.refresh_from_db()
            assert outside_identity == (
                outside_ip.pk,
                outside_ip.parent_id,
                outside_join.pk,
                outside_join.interface_id,
                outside_join.is_secondary,
            )
            assert IPAddress.objects.filter(host="192.0.2.1").count() >= 2
            checks.append(
                "duplicate host and Prefix in an unselected Namespace retain their UUIDs "
                "and assignments"
            )

            primary4 = target.interfaces.get(name="ethernet1/1").ip_addresses.get(ip_version=4)
            primary6 = target.interfaces.get(name="ethernet1/1").ip_addresses.get(ip_version=6)
            target.primary_ip4, target.primary_ip6 = primary4, primary6
            target.validated_save()
            preserved = IPAddressToInterface.objects.get(pk=expected[("ethernet1/1", "192.0.2.1")])
            preserved.is_secondary = True
            preserved.validated_save()
            stable, stable_counts = snapshot(), counts()
            with CaptureQueriesContext(connection) as captured:
                repeated = apply()
            _no_dml(captured, "Repeated PAN static IPAM apply issued inventory DML")
            assert snapshot() == stable and counts() == stable_counts
            assert all(
                repeated["summary"][key] == 0
                for key in (
                    "prefixes_created",
                    "ip_addresses_created",
                    "ip_assignments_created",
                    "interfaces_updated",
                )
            )
            target.refresh_from_db()
            preserved.refresh_from_db()
            assert (target.primary_ip4_id, target.primary_ip6_id) == (primary4.pk, primary6.pk)
            assert preserved.is_secondary is True
            checks.append(
                "repeat preserves assigned UUIDs, operator secondary flags and Device "
                "primary IPs with zero DML"
            )

            def no_write_case(data, message, selected_policy=policy):
                before, before_case_counts = snapshot(data, selected_policy), counts()
                with CaptureQueriesContext(connection) as queries:
                    result = apply(data, selected_policy)
                _no_dml(queries, message)
                assert snapshot(data, selected_policy) == before and counts() == before_case_counts
                return result

            base_network, base_vsys = (
                _fixture("panos_ipam_network.xml"),
                _fixture("panos_ipam_vsys.xml"),
            )
            # An explicit existing catalog VRF need not already be assigned to
            # this Device. Blank planner fields defer to native model defaults;
            # native clean inherits the selected catalog name/RD, not PAN labels.
            selected_vrf = VRF(
                name="Operator newly selected VRF " + token, namespace=public, rd="65000:99"
            )
            selected_vrf.validated_save()
            new_vrf_port = Interface(
                device=target,
                name="loopback.5",
                type="virtual",
                enabled=False,
                status=interface_status,
            )
            new_vrf_port.validated_save()
            new_vrf_policy = copy.deepcopy(policy)
            new_vrf_policy["panos_routing_domains"][0]["vrf"] = {
                "id": str(selected_vrf.pk),
                "name": selected_vrf.name,
                "namespace_id": str(public.pk),
            }
            new_network, new_vsys = _extra_loopback(
                base_network, base_vsys, 5, "10.255.5.1/32", "2001:db8:555::1/128"
            )
            new_vrf_source = _collect(name, vm_uuid, network=new_network, vsys=new_vsys)
            assert not VRFDeviceAssignment.objects.filter(vrf=selected_vrf, device=target).exists()
            before_assignment, before_assignment_counts = (
                snapshot(new_vrf_source, new_vrf_policy),
                counts(),
            )
            with CaptureQueriesContext(connection) as queries:
                assignment_plan = preview(new_vrf_source, new_vrf_policy)
            _no_dml(queries, "New selected-VRF assignment preview issued inventory DML")
            assert snapshot(new_vrf_source, new_vrf_policy) == before_assignment
            assert counts() == before_assignment_counts
            assert not assignment_plan["errors"] and not assignment_plan["summary"]["blocked"]
            assert assignment_plan["summary"]["vrf_device_assignments_created"] == 1
            created_specs = [
                row for row in assignment_plan["ipam"]["vrf_device_assignments"] if row["create"]
            ]
            assert len(created_specs) == 1
            assert created_specs[0]["name"] == "" and created_specs[0]["rd"] is None
            selected_vrf_identity = (
                selected_vrf.pk,
                selected_vrf.namespace_id,
                selected_vrf.name,
                selected_vrf.rd,
            )
            assignment_count = VRFDeviceAssignment.objects.count()
            applied_assignment = apply(new_vrf_source, new_vrf_policy)
            assert applied_assignment["summary"]["vrf_device_assignments_created"] == 1
            assert VRFDeviceAssignment.objects.count() == assignment_count + 1
            created_assignment = VRFDeviceAssignment.objects.get(vrf=selected_vrf, device=target)
            assert created_assignment.name == selected_vrf.name
            assert created_assignment.rd == selected_vrf.rd
            assert created_assignment.vrf_id == selected_vrf.pk
            assert created_assignment.device_id == target.pk
            assert created_assignment.vrf.namespace_id == public.pk
            assert created_assignment.virtual_machine_id is None
            assert getattr(created_assignment, "virtual_device_context_id", None) is None
            selected_vrf.refresh_from_db()
            assert (
                selected_vrf.pk,
                selected_vrf.namespace_id,
                selected_vrf.name,
                selected_vrf.rd,
            ) == selected_vrf_identity
            new_vrf_port.refresh_from_db()
            assert new_vrf_port.vrf_id == selected_vrf.pk
            assert new_vrf_port.ip_addresses.count() == 2
            stable_assignment, stable_assignment_counts = (
                snapshot(new_vrf_source, new_vrf_policy),
                counts(),
            )
            with CaptureQueriesContext(connection) as queries:
                repeated_assignment = apply(new_vrf_source, new_vrf_policy)
            _no_dml(queries, "Repeated new selected-VRF assignment apply issued inventory DML")
            assert repeated_assignment["summary"]["vrf_device_assignments_created"] == 0
            assert snapshot(new_vrf_source, new_vrf_policy) == stable_assignment
            assert counts() == stable_assignment_counts
            repeated_native = VRFDeviceAssignment.objects.get(vrf=selected_vrf, device=target)
            assert (repeated_native.pk, repeated_native.name, repeated_native.rd) == (
                created_assignment.pk,
                selected_vrf.name,
                selected_vrf.rd,
            )
            checks.append(
                "new explicit existing VRF binding previews without DML, creates one "
                "assignment with native catalog inheritance, and repeats without DML"
            )

            extra_network, extra_vsys = _extra_loopback(
                base_network, base_vsys, 404, "10.255.4.4/32"
            )
            absent = _collect(name, vm_uuid, network=extra_network, vsys=extra_vsys)
            absent_plan = no_write_case(absent, "Missing logical Interface apply issued DML")
            assert any(
                row.get("name") == "loopback.404" for row in absent_plan["ipam"]["unresolved"]
            )
            assert not target.interfaces.filter(name="loopback.404").exists()
            assert not IPAddress.objects.filter(
                parent__namespace=public, host="10.255.4.4"
            ).exists()
            checks.append(
                "configured logical address never invents an Interface or administrative "
                "enabled state"
            )

            other_vrf = VRF(name="Operator preserved VRF " + token, namespace=public)
            other_vrf.validated_save()
            VRFDeviceAssignment(vrf=other_vrf, device=target).validated_save()
            conflict_port = Interface(
                device=target,
                name="loopback.2",
                type="virtual",
                enabled=False,
                vrf=other_vrf,
                status=interface_status,
            )
            conflict_port.validated_save()
            extra_network, extra_vsys = _extra_loopback(base_network, base_vsys, 2, "10.255.2.1/32")
            conflict_source = _collect(name, vm_uuid, network=extra_network, vsys=extra_vsys)
            conflict_plan = no_write_case(
                conflict_source, "Populated conflicting Interface VRF apply issued DML"
            )
            conflict_port.refresh_from_db()
            assert conflict_port.vrf_id == other_vrf.pk
            assert any(
                row.get("name") == "loopback.2" for row in conflict_plan["ipam"]["conflicts"]
            )
            assert not conflict_port.ip_addresses.exists()
            checks.append(
                "populated conflicting Interface VRF is preserved and its discovered "
                "address remains unresolved"
            )

            VRFDeviceAssignment(vrf=routed, device=peer).validated_save()
            stolen_prefix = Prefix(
                prefix="10.255.3.1/32", namespace=public, type="network", status=prefix_status
            )
            stolen_prefix.validated_save()
            VRFPrefixAssignment(prefix=stolen_prefix, vrf=routed).validated_save()
            stolen_ip = IPAddress(
                address="10.255.3.1/32", parent=stolen_prefix, status=address_status
            )
            stolen_ip.validated_save()
            peer_port = Interface(
                device=peer,
                name="loopback.3",
                type="virtual",
                enabled=False,
                vrf=routed,
                status=interface_status,
            )
            peer_port.validated_save()
            IPAddressToInterface(ip_address=stolen_ip, interface=peer_port).validated_save()
            guarded_port = Interface(
                device=target,
                name="loopback.3",
                type="virtual",
                enabled=False,
                vrf=routed,
                status=interface_status,
            )
            guarded_port.validated_save()
            extra_network, extra_vsys = _extra_loopback(base_network, base_vsys, 3, "10.255.3.1/32")
            guarded_source = _collect(name, vm_uuid, network=extra_network, vsys=extra_vsys)
            guarded_plan = no_write_case(guarded_source, "PAN do-not-steal apply issued DML")
            assert any(
                "assigned elsewhere" in row["reason"] for row in guarded_plan["ipam"]["unresolved"]
            )
            assert set(stolen_ip.interfaces.values_list("pk", flat=True)) == {peer_port.pk}
            assert not guarded_port.ip_addresses.exists()
            checks.append(
                "do-not-steal preserves foreign IP assignments and never infers shared addressing"
            )

            unmapped_policy = copy.deepcopy(policy)
            unmapped_policy["panos_routing_domains"] = policy["panos_routing_domains"][:1]
            unmapped_plan = no_write_case(
                discovery, "Unmapped routing-domain apply issued DML", unmapped_policy
            )
            assert any(row.get("name") == "ae1.200" for row in unmapped_plan["ipam"]["unresolved"])
            checks.append(
                "an unmapped vsys/router never falls through to a default or inferred "
                "global namespace"
            )
            bad_policy = copy.deepcopy(policy)
            bad_policy["panos_routing_domains"][0]["namespace"] = {
                "id": str(internal.pk),
                "name": internal.name,
            }
            before_bad = counts()
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply(discovery, bad_policy)
                except InventoryError:
                    pass
                else:
                    raise AssertionError(
                        "PAN mismatched explicit VRF/Namespace mapping was accepted"
                    )
            _no_dml(captured, "Invalid PAN mapping issued DML before whole-plan rejection")
            assert counts() == before_bad
            checks.append(
                "mismatched selected VRF/Namespace identity rejects the whole native plan "
                "before DML"
            )

            for label, state in (
                ("enabled", _fixture("panos_ha_active.xml")),
                (
                    "unknown",
                    '<response status="success"><result><group><mode>active-passive</mode>'
                    "<local-info><state>active</state></local-info></group></result></response>",
                ),
            ):
                ha_source = _collect(name, vm_uuid, ha_state=state)
                ha_plan = no_write_case(ha_source, "HA sharing apply issued native DML")
                assert not ha_plan["ipam"]["prefixes"] and not ha_plan["ipam"]["ip_addresses"]
                assert not ha_plan["ipam"]["ip_assignments"] and ha_plan["ipam"]["unresolved"]
                checks.append(
                    "HA %s facts remain report-only without reviewed address-sharing semantics"
                    % label
                )

            original_init = IPAddress.__init__

            def without_cache(instance, *args, **kwargs):
                original_init(instance, *args, **kwargs)
                if hasattr(instance, "_closest_parent_cache"):
                    del instance._closest_parent_cache

            with patch.object(IPAddress, "__init__", without_cache):
                with CaptureQueriesContext(connection) as captured:
                    unsupported = snapshot()
                    assert unsupported["ipam_inventory"]["supported"] is False
                    assert "staged-parent" in unsupported["ipam_inventory"]["reason"]
                    legacy_plan = build_plan(discovery, unsupported)
                _no_dml(captured, "Missing staged-parent capability probe issued DML")
                assert not legacy_plan["ipam"]["ip_addresses"] and legacy_plan["ipam"]["unresolved"]
            checks.append(
                "synthetic missing staged-parent capability reports unsupported IPAM "
                "without DML; this is not a 2.4 runtime proof"
            )

            late_port = Interface(
                device=target,
                name="loopback.4",
                type="virtual",
                enabled=False,
                status=interface_status,
            )
            late_port.validated_save()
            extra_network, extra_vsys = _extra_loopback(
                base_network, base_vsys, 4, "10.255.4.1/32", "2001:db8:444::1/128"
            )
            failing = _collect(name, vm_uuid, network=extra_network, vsys=extra_vsys)
            before_failure, counts_before_failure = snapshot(failing), counts()
            original_save = IPAddressToInterface.validated_save
            first_saved, failure_seen = [], []

            def fail_late(assignment, *args, **kwargs):
                if assignment.interface_id == late_port.pk:
                    if first_saved:
                        assert IPAddressToInterface.objects.filter(pk=first_saved[0]).exists()
                        assert (
                            IPAddress.objects.filter(
                                parent__namespace=public, host__in=("10.255.4.1", "2001:db8:444::1")
                            ).count()
                            == 2
                        )
                        assert Interface.objects.get(pk=late_port.pk).vrf_id == routed.pk
                        failure_seen.append(True)
                        raise ValidationError(
                            {"ip_address": "Intentional PAN final assignment failure"}
                        )
                    result = original_save(assignment, *args, **kwargs)
                    first_saved.append(assignment.pk)
                    return result
                return original_save(assignment, *args, **kwargs)

            with patch.object(IPAddressToInterface, "validated_save", fail_late):
                try:
                    apply(failing)
                except ValidationError:
                    pass
                else:
                    raise AssertionError("PAN late IP assignment failure did not occur")
            assert failure_seen and first_saved
            assert snapshot(failing) == before_failure and counts() == counts_before_failure
            late_port.refresh_from_db()
            assert late_port.vrf_id is None and not late_port.ip_addresses.exists()
            checks.append(
                "late native assignment failure rolls back preceding Prefix/IP/VRF-fill "
                "and assignment writes"
            )
        finally:
            transaction.set_rollback(True)
    assert snapshot_inventory(Device.objects.get(pk=anchor.pk)) == anchor_before
    assert counts() == before_counts
    assert (
        set(anchor.location.location_type.content_types.values_list("pk", flat=True))
        == location_content_types
    )
    checks.append(
        "outer rollback restores the anchor, all tracked catalogs and Location "
        "content-type associations"
    )
    return {
        "anchor_device_id": str(anchor.pk),
        "passed": True,
        "checks": checks,
        "persistent_changes": 0,
        "compatibility_scope": (
            "Actual installed ORM only; 2.4 missing-cache case is a capability simulation."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
