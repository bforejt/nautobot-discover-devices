"""Native reciprocal PAN HA/shared-IP proof inside unconditional rollback.

Run via a configured Nautobot nbshell/runpy process. The existing anchor supplies
Location, Role and Status; no firewall is contacted and no fixture persists.
"""

import copy
import importlib.util
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

FIXTURES = Path(__file__).parent / "fixtures"
WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)
ANCHOR = "ed010564-cfd9-4039-bfad-a40ea4487157"


def _no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def _collect(name, vm_uuid, *, peer=False):
    from jobs.transport_ssh import (
        HA_STATE,
        RUNNING_HA,
        RUNNING_INTERFACES,
        RUNNING_VPN,
        RUNNING_VSYS,
    )

    spec = importlib.util.spec_from_file_location(
        "panos_native_ha_fixture", Path(__file__).with_name("nautobot_panos_integration.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    network = (FIXTURES / "panos_ipam_network.xml").read_text()
    result = ET.Element("response", status="success")
    ET.SubElement(result, "result").append(
        copy.deepcopy(ET.fromstring(network).find("result/network/interface"))
    )
    configuration = ET.fromstring((FIXTURES / "panos_ha_configured.xml").read_text())
    if peer:
        configuration.find(
            "result/deviceconfig/high-availability/group/peer-ip"
        ).text = "198.18.100.1"
        configuration.find(
            "result/deviceconfig/high-availability/interface/ha1/ip-address"
        ).text = "198.18.100.2"
        configuration.find(
            "result/deviceconfig/high-availability/group/election-option/device-priority"
        ).text = "110"
    return module._vm_discovery(
        name,
        vm_uuid,
        expected_vm_uuid=vm_uuid,
        ports=(1,),
        version="11.2.8",
        report_payloads={
            RUNNING_HA: ET.tostring(configuration, encoding="unicode"),
            HA_STATE: (
                FIXTURES / ("panos_ha_passive.xml" if peer else "panos_ha_active.xml")
            ).read_text(),
            RUNNING_INTERFACES: ET.tostring(result, encoding="unicode"),
            RUNNING_VPN: network,
            RUNNING_VSYS: (FIXTURES / "panos_ipam_vsys.xml").read_text(),
        },
    )


def run(device_id=None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Device,
        DeviceRedundancyGroup,
        DeviceType,
        Interface,
        Manufacturer,
        Platform,
        SoftwareVersion,
    )
    from nautobot.extras.models import CustomField, Status
    from nautobot.ipam.models import IPAddress, IPAddressToInterface, Namespace, Prefix

    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.panos_ha_policy import normalize_panos_ha_policy
    from jobs.panos_ipam_policy import normalize_panos_ipam_policy
    from jobs.reconcile import build_plan

    anchor = Device.objects.select_related("location", "role", "status").get(
        pk=device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID") or ANCHOR
    )
    tracked = (
        Device,
        DeviceRedundancyGroup,
        Interface,
        IPAddress,
        IPAddressToInterface,
        Namespace,
        Prefix,
        Platform,
        SoftwareVersion,
    )
    before_counts = {model._meta.label: model.objects.count() for model in tracked}
    anchor_before = copy.deepcopy(anchor._custom_field_data)
    location_types_before = set(
        anchor.location.location_type.content_types.values_list("pk", flat=True)
    )
    checks = []

    def uncached_fields(manager, model, exclude_filter_disabled=False, get_queryset=True):
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
            token = uuid.uuid4().hex[:12]
            anchor.location.location_type.content_types.add(
                ContentType.objects.get_for_model(Prefix)
            )
            manufacturer = Manufacturer.objects.get(name="Palo Alto Networks")
            device_type = DeviceType.objects.get(manufacturer=manufacturer, model="PA-VM")
            platform = Platform(
                name="PAN-HA-native-" + token,
                manufacturer=manufacturer,
                network_driver="paloalto_panos",
            )
            platform.validated_save()
            version = SoftwareVersion(
                platform=platform,
                version="11.2.8",
                status=Status.objects.get_for_model(SoftwareVersion).get(name="Active"),
            )
            version.validated_save()
            group_status = Status.objects.get(name="Active")
            group_status.content_types.add(ContentType.objects.get_for_model(DeviceRedundancyGroup))
            group = DeviceRedundancyGroup(name="PAN-HA-pair-native-" + token, status=group_status)
            group.validated_save()
            selected = Device(
                name="PAN-HA-selected-" + token,
                device_type=device_type,
                platform=platform,
                software_version=version,
                serial="",
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            peer = Device(
                name="PAN-HA-peer-" + token,
                device_type=device_type,
                platform=platform,
                software_version=version,
                serial="",
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            selected.validated_save()
            peer.validated_save()
            interface_status = Status.objects.get_for_model(Interface).get(name="Active")
            selected_uuid, peer_uuid = str(uuid.uuid4()), str(uuid.uuid4())
            observed, peer_observed = (
                _collect(selected.name, selected_uuid),
                _collect(peer.name, peer_uuid, peer=True),
            )
            for target in (selected, peer):
                for row in observed["ipam"]["interfaces"]:
                    interface = target.interfaces.filter(name=row["name"]).first()
                    expected_type = "lag" if row["kind"] == "aggregate-ethernet" else "virtual"
                    if interface is None:
                        Interface(
                            device=target,
                            name=row["name"],
                            type=expected_type,
                            status=interface_status,
                        ).validated_save()
                    else:
                        assert interface.type == expected_type
            public = Namespace(name="PAN-HA-public-" + token)
            private = Namespace(name="PAN-HA-private-" + token)
            public.validated_save()
            private.validated_save()

            def resolve_ha(kind, identifier):
                if kind == "device":
                    target = Device.objects.select_related("device_type").get(pk=identifier)
                    return {
                        "id": str(target.pk),
                        "name": target.name,
                        "model": target.device_type.model,
                    }
                target = DeviceRedundancyGroup.objects.get(pk=identifier)
                return {
                    "id": str(target.pk),
                    "name": target.name,
                    "failover_strategy": target.failover_strategy,
                }

            ha_policy = normalize_panos_ha_policy(
                json.dumps(
                    {
                        "peer_device": str(peer.pk),
                        "peer_vm_uuid": peer_uuid,
                        "redundancy_group": str(group.pk),
                    }
                ),
                resolve_ha,
                selected_device_id=selected.pk,
            )
            observed["ha_pair"] = {
                "contract": "panos-ha-pair-v1",
                "policy": ha_policy,
                "peer_discovery": peer_observed,
            }
            ipam_policy = normalize_panos_ipam_policy(
                json.dumps(
                    [
                        {
                            "vsys": "vsys1",
                            "virtual_router": "vr-public",
                            "namespace": str(public.pk),
                            "vrf": None,
                        },
                        {
                            "vsys": "vsys2",
                            "virtual_router": "vr-internal",
                            "namespace": str(private.pk),
                            "vrf": None,
                        },
                    ]
                ),
                lambda kind, identifier, namespace_id: {
                    "id": str(identifier),
                    "name": Namespace.objects.get(pk=identifier).name,
                },
                location={"id": str(anchor.location_id), "name": anchor.location.name},
            )
            selected_before = copy.deepcopy(selected._custom_field_data)
            peer_before = copy.deepcopy(peer._custom_field_data)
            prefix_status = Status.objects.get_for_model(Prefix).get(name="Active")
            address_status = Status.objects.get_for_model(IPAddress).get(name="Active")
            arguments = {
                "interface_status": interface_status,
                "ipam_policy": ipam_policy,
                "ipam_prefix_status": prefix_status,
                "ipam_ip_address_status": address_status,
            }

            with CaptureQueriesContext(connection) as captured:
                preview = build_plan(
                    observed,
                    snapshot_inventory(selected, discovery=observed, ipam_policy=ipam_policy),
                )
                validate_plan(
                    preview,
                    selected,
                    **{key: value for key, value in arguments.items() if key != "ipam_policy"},
                )
            _no_dml(captured, "HA/shared-IP preview issued inventory DML")
            assert not preview["errors"], preview["errors"]
            assert preview["summary"]["ha_groups_updated"] == 1
            assert preview["summary"]["ha_devices_updated"] == 2
            assert preview["summary"]["ip_addresses_created"] == 12, json.dumps(
                {
                    "shared_addresses": len(preview["ha"]["sharing"]["addresses"]),
                    "ha_unresolved": preview["ha"]["unresolved"],
                    "ipam_unresolved": preview["ipam"]["unresolved"],
                }
            )
            assert Device.objects.get(pk=selected.pk).device_redundancy_group_id is None
            assert Device.objects.get(pk=peer.pk).device_redundancy_group_id is None
            checks.append("native reciprocal HA/group/shared-IP preview validates without DML")

            apply_discovery(observed, selected, **arguments)
            selected.refresh_from_db()
            peer.refresh_from_db()
            group.refresh_from_db()
            assert (
                selected.device_redundancy_group_id == group.pk == peer.device_redundancy_group_id
            )
            assert (
                selected.device_redundancy_group_priority,
                peer.device_redundancy_group_priority,
            ) == (100, 110)
            assert group.failover_strategy == "active-passive"
            assert selected._custom_field_data == selected_before
            assert peer._custom_field_data == peer_before
            assert IPAddress.objects.filter(parent__namespace__in=(public, private)).count() == 12
            checks.append(
                "atomic apply populates native existing pair/group and exact static address graph"
            )

            with CaptureQueriesContext(connection) as captured:
                repeated = apply_discovery(observed, selected, **arguments)
            _no_dml(captured, "Repeated HA discovery issued inventory DML")
            assert repeated["summary"]["ha_devices_updated"] == 0
            assert repeated["summary"]["ha_groups_updated"] == 0
            checks.append("repeated HA discovery issues zero inventory DML")

            reverse_policy = normalize_panos_ha_policy(
                json.dumps(
                    {
                        "peer_device": str(selected.pk),
                        "peer_vm_uuid": selected_uuid,
                        "redundancy_group": str(group.pk),
                    }
                ),
                resolve_ha,
                selected_device_id=peer.pk,
            )
            reverse = copy.deepcopy(peer_observed)
            reverse["ha_pair"] = {
                "contract": "panos-ha-pair-v1",
                "policy": reverse_policy,
                "peer_discovery": copy.deepcopy(observed),
            }
            reverse["ha_pair"]["peer_discovery"].pop("ha_pair", None)
            shared_apply = apply_discovery(reverse, peer, **arguments)
            assert not shared_apply["errors"], shared_apply["errors"]
            addresses = IPAddress.objects.filter(parent__namespace__in=(public, private))
            assert addresses.count() == 12
            assert all(
                IPAddressToInterface.objects.filter(
                    ip_address=address, interface__device__in=(selected, peer)
                ).count()
                == 2
                for address in addresses
            )
            assert not IPAddressToInterface.objects.filter(
                ip_address__in=addresses, is_standby=True
            ).exists()
            checks.append(
                "peer discovery reuses one native IP per host "
                "with independently proven interfaces on both devices"
            )
            with CaptureQueriesContext(connection) as captured:
                apply_discovery(reverse, peer, **arguments)
            _no_dml(captured, "Repeated shared peer discovery issued inventory DML")
            checks.append("repeated peer/shared-IP discovery issues zero inventory DML")

            invalid = copy.deepcopy(observed)
            invalid["ha_pair"]["peer_discovery"]["observations"]["system"]["vm-uuid"] = (
                selected_uuid
            )
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply_discovery(invalid, selected, **arguments)
                except (InventoryError, ValidationError):
                    pass
                else:
                    raise AssertionError("Wrong directly observed peer UUID was accepted")
            _no_dml(captured, "Wrong-peer HA attempt issued inventory DML")
            checks.append("wrong directly observed peer UUID blocks the entire apply without DML")

            # Force actual pending group/membership work and reject a late native
            # peer save, after all validation, to prove the outer transaction.
            Device.objects.filter(pk__in=(selected.pk, peer.pk)).update(
                device_redundancy_group=None, device_redundancy_group_priority=None
            )
            DeviceRedundancyGroup.objects.filter(pk=group.pk).update(failover_strategy="")
            selected.refresh_from_db()
            peer.refresh_from_db()
            original_save = Device.save

            def late_failure(target, *args, **kwargs):
                if target.pk == peer.pk and target.device_redundancy_group_id is not None:
                    raise InventoryError("Synthetic late peer write failure")
                return original_save(target, *args, **kwargs)

            with patch.object(Device, "save", late_failure):
                try:
                    apply_discovery(observed, selected, **arguments)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("Late native peer failure was not raised")
            assert Device.objects.get(pk=selected.pk).device_redundancy_group_id is None
            assert Device.objects.get(pk=peer.pk).device_redundancy_group_id is None
            assert DeviceRedundancyGroup.objects.get(pk=group.pk).failover_strategy == ""
            checks.append(
                "late peer validation/save failure rolls back group "
                "and both Device membership changes"
            )
        finally:
            transaction.set_rollback(True)
    assert before_counts == {model._meta.label: model.objects.count() for model in tracked}
    assert Device.objects.get(pk=anchor.pk)._custom_field_data == anchor_before
    assert location_types_before == set(
        anchor.location.location_type.content_types.values_list("pk", flat=True)
    )
    return {"checks": checks, "count": len(checks), "rollback": True}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
