"""Native dual-stack graph checks; all fixtures require an outer transaction rollback."""

import copy
import re
import uuid
from ipaddress import ip_address
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def run(device, interface_status, checks):
    """Verify IPv6 preview, namespace policy, native relations, repeats and failure rollback."""
    from django.contrib.contenttypes.models import ContentType
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Interface
    from nautobot.extras.models import CustomField
    from nautobot.ipam.models import (
        IPAddress,
        IPAddressToInterface,
        Namespace,
        Prefix,
        VRFDeviceAssignment,
    )

    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan
    from tests.nautobot_ipam_integration import catalog_counts

    assert transaction.get_connection().in_atomic_block, "IPv6 tests require outer rollback"
    device.refresh_from_db()
    token = uuid.uuid4().hex[:12]
    namespace = Namespace(name="CODEX-IPV6-DEFAULT-" + token)
    namespace.validated_save()
    override = Namespace(name="CODEX-IPV6-OVERRIDE-" + token)
    override.validated_save()
    device.location.location_type.content_types.add(ContentType.objects.get_for_model(Prefix))
    policy = {
        "default_namespace": {"id": str(namespace.pk), "name": namespace.name},
        "override_namespace": {"id": str(override.pk), "name": override.name},
        "override_rfc1918": True,
        "override_networks": ["fd00::/8", "100.64.0.0/10"],
        "create_missing_prefixes": True,
        "group_user_vrfs": False,
        "local_vrf_names": ["Mgmt-vrf"],
        "location": {"id": str(device.location_id), "name": device.location.name},
    }
    port_base = "Loopback" + str(uuid.uuid4().int)[:12]
    corp_name = "CORP-IPV6-" + token

    def ipv6(value, **flags):
        return {
            "configured_prefix": value,
            "method": "configured",
            "eui_64": False,
            "anycast": False,
            **flags,
        }

    def whole_source(rows, *, vrf_names=()):
        return {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": {
                "hostname": device.name,
                "serial": device.serial or "CODEX-IPV6-SERIAL-" + token,
                "model": device.device_type.model,
                "software_version": (
                    device.software_version.version if device.software_version_id else "17.98.01"
                ),
            },
            "interfaces": [
                {
                    "name": row["name"],
                    "type": "virtual",
                    "enabled": True,
                    "description": "Native IPv6 verification " + token,
                    "mtu": 1500,
                    "mac_address": None,
                    "speed": None,
                    "duplex": None,
                    "type_source": "synthetic reviewed routing interface",
                    "observations": {},
                }
                for row in rows
            ],
            "lag_memberships": [],
            "warnings": [],
            "excluded_interfaces": [],
            "ipam": {
                "schema_version": 1,
                "vrfs": [
                    {
                        "name": name,
                        "rd": "65001:44",
                        "address_families": ["ipv4", "ipv6"],
                        "source": {},
                    }
                    for name in vrf_names
                ],
                "interfaces": rows,
                "unresolved": [],
                "sources": [],
            },
        }

    rows = [
        {
            "name": port_base,
            "vrf": corp_name,
            "ipv4": [
                {
                    "address": "203.0.113.10",
                    "mask": "255.255.255.0",
                    "prefix_length": 24,
                    "secondary": False,
                    "method": "configured-static",
                }
            ],
            "ipv6": [ipv6("2001:db8:440::1/64")],
            "source": {},
        },
        {
            "name": port_base + "1",
            "vrf": None,
            "ipv4": [],
            "ipv6": [ipv6("fd42:440::1/64")],
            "source": {},
        },
        {
            "name": port_base + "2",
            "vrf": None,
            "ipv4": [],
            "ipv6": [ipv6("2001:db8:441::/127")],
            "source": {},
        },
        {
            "name": port_base + "3",
            "vrf": None,
            "ipv4": [],
            "ipv6": [ipv6("2001:db8:442::1/128")],
            "source": {},
        },
        {
            "name": port_base + "5",
            "vrf": None,
            "ipv4": [],
            "ipv6": [ipv6("::192.0.2.1/128")],
            "source": {},
        },
    ]
    discovery = whole_source(rows, vrf_names=[corp_name])

    def snapshot():
        return snapshot_inventory(device, ipam_policy=policy)

    def counts():
        return {
            **catalog_counts(),
            "Interface": Interface.objects.count(),
            "CustomField": CustomField.objects.count(),
        }

    def no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    before, before_counts = snapshot(), counts()
    before_primary = (device.primary_ip4_id, device.primary_ip6_id)
    with CaptureQueriesContext(connection) as captured:
        planned = build_plan(discovery, snapshot())
        validate_plan(planned, device, interface_status=interface_status)
    no_dml(captured, "Native IPv6 graph preview issued inventory DML")
    assert snapshot() == before and counts() == before_counts
    assert not planned["errors"], planned["errors"]
    assert planned["summary"]["prefixes_created"] == 6
    assert planned["summary"]["ip_addresses_created"] == 6
    assert planned["summary"]["ip_assignments_created"] == 6
    checks.append(
        "static dual-stack IPv6, ULA override, /127 and /128 preview validates with zero DML"
    )

    apply_discovery(discovery, device, interface_status=interface_status, ipam_policy=policy)
    dual = Interface.objects.get(device=device, name=port_base)
    routed = VRFDeviceAssignment.objects.get(device=device, name=corp_name)
    assert dual.vrf_id == routed.vrf_id and routed.rd == "65001:44"
    assert routed.vrf.namespace_id == namespace.pk and routed.vrf.rd is None
    actual = {
        str(ip_address(str(assignment.ip_address.host))): assignment
        for assignment in IPAddressToInterface.objects.filter(
            interface__device=device, interface__name__in=[row["name"] for row in rows]
        ).select_related("ip_address__parent")
    }
    for host, mask, selected in (
        ("203.0.113.10", 24, namespace),
        ("2001:db8:440::1", 64, namespace),
        ("fd42:440::1", 64, override),
        ("2001:db8:441::", 127, namespace),
        ("2001:db8:442::1", 128, namespace),
        ("::192.0.2.1", 128, namespace),
    ):
        assignment = actual[str(ip_address(host))]
        assert assignment.ip_address.mask_length == mask
        assert assignment.ip_address.parent.namespace_id == selected.pk
        assert not assignment.is_secondary and not assignment.is_primary
        assert set(assignment.ip_address.parent.locations.values_list("pk", flat=True)) == {
            device.location_id
        }
        assignment.interface.full_clean()
    assert set(actual["2001:db8:440::1"].ip_address.parent.vrfs.values_list("pk", flat=True)) == {
        routed.vrf_id
    }
    device.refresh_from_db()
    assert (device.primary_ip4_id, device.primary_ip6_id) == before_primary
    assert CustomField.objects.count() == before_counts["CustomField"]
    checks.append(
        "native IPv6 addresses and site Prefixes use explicit namespaces and a non-management VRF; "
        "IPv4-compatible IPv6 literals retain numeric identity across parser representations"
    )

    stable, stable_counts = snapshot(), counts()
    with CaptureQueriesContext(connection) as captured:
        repeat = apply_discovery(
            discovery, device, interface_status=interface_status, ipam_policy=policy
        )
    no_dml(captured, "Repeated native IPv6 graph apply issued inventory DML")
    assert snapshot() == stable and counts() == stable_counts
    assert repeat["summary"]["prefixes_created"] == 0
    assert repeat["summary"]["ip_addresses_created"] == 0
    assert repeat["summary"]["ip_assignments_created"] == 0
    checks.append("repeated native dual-stack IPv6 discovery preserves UUIDs and issues zero DML")

    unsupported = whole_source(
        [
            {
                "name": port_base + "1",
                "vrf": None,
                "ipv4": [],
                "ipv6": [
                    ipv6("fd42:440::1/64", eui_64=True),
                    ipv6("fd42:441::1/64", anycast=True),
                    {"method": "configured-link-local", "address": "fe80::1"},
                    {
                        "method": "configured-named-prefix",
                        "prefix_name": "DELEGATED",
                        "configuration": {},
                    },
                ],
                "source": {},
            }
        ]
    )
    stable, stable_counts = snapshot(), counts()
    with CaptureQueriesContext(connection) as captured:
        deferred = apply_discovery(
            unsupported, device, interface_status=interface_status, ipam_policy=policy
        )
    no_dml(captured, "Unsupported IPv6 observations changed inventory")
    assert snapshot() == stable and counts() == stable_counts
    assert deferred["summary"]["unresolved_ipam"] == 4
    checks.append(
        "EUI-64, anycast, link-local and named-prefix IPv6 remain observations with zero DML"
    )

    legacy = copy.deepcopy(discovery)
    legacy_row = legacy["ipam"]["interfaces"][0]
    legacy_row["ipv6"] = [ipv6("2001:db8:444::1/64")]
    legacy_row["addressing"] = {
        "ipv6_vrf_scope": "unresolved-legacy-vrf",
        "ipv6_vrf_reason": "Reviewed legacy forwarding binds IPv4 only",
    }
    legacy_row["ipv6_routing"] = {
        "status": "unresolved",
        "binding": "legacy-vrf-forwarding",
        "source": {"path": "/data/Cisco-IOS-XE-native:native/interface"},
    }
    stable, stable_counts = snapshot(), counts()
    with CaptureQueriesContext(connection) as captured:
        deferred_legacy = apply_discovery(
            legacy, device, interface_status=interface_status, ipam_policy=policy
        )
    no_dml(captured, "Legacy IPv4-only VRF forwarding inferred an IPv6 routing context")
    assert snapshot() == stable and counts() == stable_counts
    assert deferred_legacy["summary"]["unresolved_ipam"] == 1
    dual.refresh_from_db()
    assert dual.vrf_id == routed.vrf_id
    checks.append(
        "legacy single-protocol forwarding preserves Interface VRF and IPv4 while deferring IPv6"
    )

    inactive = copy.deepcopy(legacy)
    inactive_row = inactive["ipam"]["interfaces"][0]
    inactive_row["addressing"] = {
        "ipv6_vrf_scope": "unresolved-inactive-vrf-family",
        "ipv6_vrf_reason": "Complete named VRF definition does not enable IPv6",
    }
    inactive_row["ipv6_routing"] = {
        "status": "unresolved",
        "binding": "inactive-vrf-family",
        "vrf_source": {"path": "/data/Cisco-IOS-XE-native:native/vrf", "complete": True},
    }
    inactive["ipam"]["vrfs"][0]["address_families"] = ["ipv4"]
    stable, stable_counts = snapshot(), counts()
    with CaptureQueriesContext(connection) as captured:
        deferred_inactive = apply_discovery(
            inactive, device, interface_status=interface_status, ipam_policy=policy
        )
    no_dml(captured, "Inactive named VRF IPv6 family inferred an IPv6 routing context")
    assert snapshot() == stable and counts() == stable_counts
    assert deferred_inactive["summary"]["unresolved_ipam"] == 1
    dual.refresh_from_db()
    assert dual.vrf_id == routed.vrf_id
    checks.append(
        "complete VRF definitions lacking IPv6 preserve Interface VRF and IPv4 while deferring IPv6"
    )

    cross_namespace = copy.deepcopy(discovery)
    cross_namespace["ipam"]["interfaces"][0]["ipv4"][0] = {
        "address": "10.44.0.1",
        "mask": "255.255.255.0",
        "prefix_length": 24,
        "secondary": False,
        "method": "configured-static",
    }
    stable, stable_counts = snapshot(), counts()
    with CaptureQueriesContext(connection) as captured:
        blocked = apply_discovery(
            cross_namespace, device, interface_status=interface_status, ipam_policy=policy
        )
    no_dml(captured, "Cross-family namespace conflict changed existing VRF or addresses")
    assert snapshot() == stable and counts() == stable_counts
    assert any("cannot span" in item["reason"] for item in blocked["ipam"]["unresolved"])
    checks.append("a named VRF crossing IPv4 and IPv6 namespaces remains intact and is deferred")

    failed_name = port_base + "4"
    failing = whole_source(
        [
            {
                "name": failed_name,
                "vrf": "FAIL-IPV6-" + token,
                "ipv4": [],
                "ipv6": [ipv6("2001:db8:443::1/64")],
                "source": {},
            }
        ],
        vrf_names=["FAIL-IPV6-" + token],
    )
    stable, stable_counts = snapshot(), counts()
    original = IPAddressToInterface.validated_save

    def late_failure(assignment, *args, **kwargs):
        if assignment.interface.name == failed_name:
            assert Interface.objects.filter(device=device, name=failed_name).exists()
            assert IPAddress.objects.filter(
                parent__namespace=namespace, host="2001:db8:443::1"
            ).exists()
            raise RuntimeError("Injected late native IPv6 assignment failure")
        return original(assignment, *args, **kwargs)

    with patch.object(IPAddressToInterface, "validated_save", late_failure):
        try:
            apply_discovery(failing, device, interface_status=interface_status, ipam_policy=policy)
        except RuntimeError as exc:
            assert str(exc) == "Injected late native IPv6 assignment failure"
        else:
            raise AssertionError("Late native IPv6 assignment failure was not exercised")
    assert snapshot() == stable and counts() == stable_counts
    assert not Interface.objects.filter(device=device, name=failed_name).exists()
    checks.append(
        "late IPv6 interface assignment failure rolls back new Interface, VRF, Prefix and address"
    )
