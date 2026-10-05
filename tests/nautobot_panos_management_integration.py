"""Management Interface/IPAM/primary-IP proof; every fixture write rolls back."""

import importlib.util
import os
import re
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

WRITE = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.I)
OP = (
    '<response status="success"><result><info>'
    "<name>Management Interface</name><state_c>auto</state_c><state>up</state>"
    "<hwaddr>02:00:00:00:03:01</hwaddr><ip>192.0.2.10</ip>"
    "<netmask>255.255.255.0</netmask><ip-type>dhcp-client</ip-type>"
    "<ipv6>unknown</ipv6><ip6-type>static</ip6-type></info></result></response>"
)
CONFIG = (
    '<response status="success"><result><deviceconfig><system><type><dhcp-client>'
    "<send-hostname>yes</send-hostname></dhcp-client></type>"
    "</system></deviceconfig></result></response>"
)


def run(device_id=None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, SoftwareVersion
    from nautobot.extras.models import Status
    from nautobot.ipam.models import IPAddress, IPAddressToInterface, Namespace

    from jobs import nautobot_inventory as boundary
    from jobs.discovery_job import _prefix_location
    from jobs.reconcile import build_plan
    from jobs.transport_ssh import MANAGEMENT_INTERFACE, RUNNING_HA

    spec = importlib.util.spec_from_file_location(
        "panos_management_fixture", Path(__file__).with_name("nautobot_panos_integration.py")
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    anchor = Device.objects.get(pk=device_id or os.environ["NAUTOBOT_DISCOVERY_DEVICE_ID"])
    counts = {
        model._meta.label: model.objects.count()
        for model in (Device, Namespace, IPAddress, IPAddressToInterface)
    }
    checks = []
    with transaction.atomic():
        try:
            token = uuid.uuid4().hex[:12]
            target = Device(
                name="panos-management-native-" + token,
                device_type=anchor.device_type,
                platform=anchor.platform,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            target.validated_save()
            source = fixture._vm_discovery(
                target.name,
                str(uuid.uuid4()),
                expected_vm_uuid=None,
                report_payloads={MANAGEMENT_INTERFACE: OP, RUNNING_HA: CONFIG},
            )
            source["identity_binding"] = {
                "contract": "panos-vm-identity-v1",
                "system_command": "show system info",
                "system_path": "result/system",
                "expected_uuid": source["observations"]["system"]["vm-uuid"],
                "observed_uuid": source["observations"]["system"]["vm-uuid"],
                "model": "PA-VM",
                "family": "vm",
                "vm_mode": "KVM",
            }
            namespace = Namespace(name="PAN-management-native-" + token)
            namespace.validated_save()
            location, reason = _prefix_location(target, None)
            assert location, reason
            policy = {
                "contract": "panos-ipam-policy-v1",
                "default_namespace": {"id": str(namespace.pk), "name": namespace.name},
                "panos_routing_domains": [],
                "create_missing_prefixes": True,
                "location": location,
                "location_reason": reason,
                "panos_management": {
                    "contract": "panos-management-policy-v1",
                    "namespace": {"id": str(namespace.pk), "name": namespace.name},
                    "include_dhcp": True,
                    "fill_primary": True,
                    "create_missing_prefixes": True,
                    "location": location,
                    "location_reason": reason,
                },
            }
            # Catalog software upfront to isolate management writes from identity enrichment.
            version, _ = SoftwareVersion.objects.get_or_create(
                platform=target.platform,
                version=source["identity"]["software_version"],
                defaults={
                    "status": Status.objects.get_for_model(SoftwareVersion).get(name="Active")
                },
            )
            target.software_version = version
            target.validated_save()

            def snapshot():
                return boundary.snapshot_inventory(
                    Device.objects.get(pk=target.pk), discovery=source, ipam_policy=policy
                )

            before = snapshot()
            with CaptureQueriesContext(connection) as queries:
                planned = build_plan(source, before)
                boundary.validate_plan(planned, target)
            assert not planned["errors"], planned["errors"]
            assert not any(WRITE.match(q["sql"]) for q in queries.captured_queries)
            assert snapshot() == before
            assert planned["management"]["creates"][0]["mgmt_only"] is True
            assert planned["ipam"]["ip_addresses"][0]["type"] == "dhcp"
            assert not planned["management"]["primary_updates"]
            checks.append(
                "Preview validates Interface/IPAM without DML; primary fill waits for "
                "a persisted native assignment"
            )
            boundary.apply_discovery(source, target, ipam_policy=policy)
            address = IPAddress.objects.get(parent__namespace=namespace, host="192.0.2.10")
            interface = target.interfaces.get(name="Management Interface")
            assert (
                interface.type == "virtual"
                and interface.mgmt_only
                and str(interface.mac_address).lower() == "02:00:00:00:03:01"
            )
            assert address.type == "dhcp" and address.mask_length == 24
            assert IPAddressToInterface.objects.filter(
                ip_address=address, interface=interface
            ).exists()
            assert Device.objects.get(pk=target.pk).primary_ip4_id is None
            checks.append(
                "Apply creates dedicated guest management Interface and exact DHCP lease assignment"
            )
            second = build_plan(source, snapshot())
            assert len(second["management"]["primary_updates"]) == 1
            with CaptureQueriesContext(connection) as queries:
                boundary.validate_plan(second, target)
            assert not any(WRITE.match(q["sql"]) for q in queries.captured_queries)
            raw_cf = Device.objects.get(pk=target.pk)._custom_field_data.copy()
            boundary.apply_discovery(source, target, ipam_policy=policy)
            fresh = Device.objects.get(pk=target.pk)
            assert fresh.primary_ip4_id == address.pk and fresh._custom_field_data == raw_cf
            checks.append(
                "Persisted assignment permits native primary-IP validation and exact "
                "custom-field preservation"
            )
            with CaptureQueriesContext(connection) as queries:
                repeat = boundary.apply_discovery(source, target, ipam_policy=policy)
            assert not any(WRITE.match(q["sql"]) for q in queries.captured_queries)
            assert repeat["summary"]["panos_primary_ips_updated"] == 0
            checks.append("Complete repeat emits zero DML")
            target.primary_ip4 = None
            target.save(update_fields=["primary_ip4"])
            interface.delete()
            address.delete()
            before = snapshot()
            with patch.object(
                boundary, "save_panos_vpn_catalog", side_effect=RuntimeError("late atomic proof")
            ):
                try:
                    boundary.apply_discovery(source, target, ipam_policy=policy)
                except RuntimeError as exc:
                    assert str(exc) == "late atomic proof"
                else:
                    raise AssertionError("Expected injected late failure")
            assert snapshot() == before
            checks.append("Failure after IPAM saves rolls back the complete discovery transaction")
        finally:
            transaction.set_rollback(True)
    assert counts == {
        model._meta.label: model.objects.count()
        for model in (Device, Namespace, IPAddress, IPAddressToInterface)
    }
    return {"passed": len(checks), "checks": checks, "rolled_back": True}


if __name__ == "__main__":
    import json

    print(json.dumps(run()))
