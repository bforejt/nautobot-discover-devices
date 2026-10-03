"""Real IPAM graph regressions run only within an outer inventory rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    """Count every catalog and relation model touched by IPAM discovery."""
    from nautobot.ipam.models import (
        VRF,
        IPAddress,
        IPAddressRange,
        IPAddressToInterface,
        Namespace,
        Prefix,
        PrefixLocationAssignment,
        VRFDeviceAssignment,
        VRFPrefixAssignment,
    )

    return {
        model.__name__: model.objects.count()
        for model in (
            Namespace,
            Prefix,
            IPAddress,
            IPAddressRange,
            VRF,
            VRFDeviceAssignment,
            VRFPrefixAssignment,
            PrefixLocationAssignment,
            IPAddressToInterface,
        )
    }


def run(device, interface_status, checks):
    """Exercise native validation, transactional failure and idempotent relations."""
    from django.contrib.contenttypes.models import ContentType
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import Device, Interface
    from nautobot.extras.models import Status
    from nautobot.ipam.models import (
        IPAddress,
        IPAddressToInterface,
        Namespace,
        Prefix,
        VRFDeviceAssignment,
    )

    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.nautobot_ipam import (
        ipam_objects,
        save_ipam_assignments,
        save_ipam_catalog,
        snapshot_ipam,
        validate_ipam_objects,
    )
    from jobs.reconcile import build_plan
    from jobs.reconcile_ipam import plan_ipam

    assert transaction.get_connection().in_atomic_block, "IPAM tests require outer rollback"
    device.refresh_from_db()
    token = uuid.uuid4().hex[:12]
    prefix_name = "Loopback" + str(uuid.uuid4().int)[:12]
    namespace = Namespace(name="CODEX-IPAM-" + token)
    namespace.validated_save()
    secondary_namespace = Namespace(name="CODEX-IPAM-OVERRIDE-" + token)
    secondary_namespace.validated_save()
    device.location.location_type.content_types.add(ContentType.objects.get_for_model(Prefix))
    policy = {
        "default_namespace": {"id": str(namespace.pk), "name": namespace.name},
        "override_namespace": {
            "id": str(secondary_namespace.pk),
            "name": secondary_namespace.name,
        },
        "override_rfc1918": True,
        "override_networks": [],
        "create_missing_prefixes": True,
        "group_user_vrfs": False,
        "local_vrf_names": ["Mgmt-vrf"],
        "location": {"id": str(device.location_id), "name": device.location.name},
    }

    def active(model, selected=None):
        if selected is not None:
            return selected
        return Status.objects.get_for_model(model).get(name="Active")

    def counts():
        return {**catalog_counts(), "Interface": Interface.objects.count()}

    def no_dml(captured, message):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message

    def interface(name):
        return Interface(
            device=device,
            name=name,
            type="virtual",
            status=interface_status,
            description="IPAM ORM verification " + token,
        )

    def new_plan(name, *, subnet="192.0.2.0/24", host="192.0.2.10", local_name="Mgmt-vrf"):
        return {
            "policy": copy.deepcopy(policy),
            "vrfs": [
                {
                    "key": "vrf",
                    "id": None,
                    "create": True,
                    "name": str(device.pk) + " / " + local_name,
                    "namespace_id": str(namespace.pk),
                    "rd": None,
                    "changes": [],
                }
            ],
            "vrf_device_assignments": [
                {
                    "key": "vrf-assignment",
                    "id": None,
                    "create": True,
                    "vrf_key": "vrf",
                    "device_id": str(device.pk),
                    "name": local_name,
                    "rd": "65001:7",
                    "changes": [],
                }
            ],
            "interface_vrfs": [
                {
                    "id": None,
                    "name": name,
                    "vrf_key": "vrf",
                    "changes": [{"field": "vrf_id", "before": None, "after": "vrf"}],
                }
            ],
            "prefixes": [
                {
                    "key": "prefix",
                    "id": None,
                    "create": True,
                    "prefix": subnet,
                    "namespace_id": str(namespace.pk),
                    "type": "network",
                    "location_id": str(device.location_id),
                    "vrf_keys": ["vrf"],
                    "add_vrf_keys": ["vrf"],
                    "parent_id": None,
                    "affected_ip_ids": [],
                    "affected_prefix_ids": [],
                    "affected_range_ids": [],
                }
            ],
            "ip_addresses": [
                {
                    "key": "ip",
                    "id": None,
                    "create": True,
                    "host": host,
                    "mask_length": int(subnet.split("/")[1]),
                    "address": host + "/" + subnet.split("/")[1],
                    "parent_key": "prefix",
                }
            ],
            "ip_assignments": [
                {
                    "key": "ip-assignment",
                    "id": None,
                    "create": True,
                    "ip_key": "ip",
                    "interface_id": None,
                    "name": name,
                    "is_secondary": True,
                }
            ],
        }

    def staged(plan, interfaces):
        return ipam_objects(
            plan,
            interfaces,
            device,
            prefix_status=None,
            ip_address_status=None,
            status_resolver=active,
        )

    def save(plan, interfaces, new_interfaces=()):
        with transaction.atomic():
            objects = staged(plan, interfaces)
            validate_ipam_objects(objects, device)
            save_ipam_catalog(objects, device)
            for row in new_interfaces:
                row.validated_save()
            save_ipam_assignments(objects, device)
            return objects

    new_interface = interface(prefix_name)
    plan = new_plan(prefix_name)
    before, before_counts = snapshot_ipam(device, policy), counts()
    with CaptureQueriesContext(connection) as captured:
        objects = staged(plan, {prefix_name: new_interface})
        validate_ipam_objects(objects, device)
    no_dml(captured, "IPAM preview persisted an unsaved routing-graph parent")
    assert snapshot_ipam(device, policy) == before and counts() == before_counts
    assert new_interface.vrf_id is None, "Preview mutated a shared base Interface VRF"
    checks.append(
        "new Interface, VRF, Device Assignment, Prefix and IP preview validates with zero DML"
    )

    objects = save(plan, {prefix_name: new_interface}, [new_interface])
    new_interface.refresh_from_db()
    saved_vrf = objects["vrfs"]["vrf"]
    saved_prefix = objects["prefixes"]["prefix"]
    saved_ip = objects["ip_addresses"]["ip"]
    assignment = IPAddressToInterface.objects.get(interface=new_interface, ip_address=saved_ip)
    assert new_interface.vrf_id == saved_vrf.pk
    assert saved_vrf.rd is None
    assert VRFDeviceAssignment.objects.get(vrf=saved_vrf, device=device).name == "Mgmt-vrf"
    assert VRFDeviceAssignment.objects.get(vrf=saved_vrf, device=device).rd == "65001:7"
    assert str(saved_prefix.prefix) == "192.0.2.0/24" and saved_prefix.type == "network"
    assert set(saved_prefix.locations.values_list("pk", flat=True)) == {device.location_id}
    assert set(saved_prefix.vrfs.values_list("pk", flat=True)) == {saved_vrf.pk}
    assert saved_ip.mask_length == 24 and saved_ip.type == "host"
    assert assignment.is_secondary and not assignment.is_primary
    new_interface.full_clean()
    checks.append(
        "IPAM stores local VRF name/RD, site Prefix and explicit secondary host assignment"
    )

    repeated = copy.deepcopy(plan)
    mapping = {
        "vrfs": "vrfs",
        "vrf_device_assignments": "vrf_device_assignments",
        "prefixes": "prefixes",
        "ip_addresses": "ip_addresses",
        "ip_assignments": "ip_assignments",
    }
    for collection, object_collection in mapping.items():
        for row in repeated[collection]:
            row["create"] = False
            row["id"] = str(objects[object_collection][row["key"]].pk)
    repeated["prefixes"][0]["add_vrf_keys"] = []
    repeated["interface_vrfs"][0]["id"] = str(new_interface.pk)
    repeated["interface_vrfs"][0]["changes"] = []
    before, before_counts = snapshot_ipam(device, policy), counts()
    with CaptureQueriesContext(connection) as captured:
        save(repeated, {prefix_name: new_interface})
    no_dml(captured, "Repeated IPAM apply issued inventory DML")
    assert snapshot_ipam(device, policy) == before and counts() == before_counts
    checks.append("repeated IPAM graph apply preserves UUIDs and issues zero DML")

    mismatch = copy.deepcopy(repeated)
    mismatch["ip_addresses"][0].update(mask_length=25, address="192.0.2.10/25")
    before, before_counts = snapshot_ipam(device, policy), counts()
    with CaptureQueriesContext(connection) as captured:
        try:
            validate_ipam_objects(staged(mismatch, {prefix_name: new_interface}), device)
        except InventoryError:
            pass
        else:
            raise AssertionError("Existing host mask conflict was accepted")
    no_dml(captured, "IP mask conflict validation issued DML")
    assert snapshot_ipam(device, policy) == before and counts() == before_counts
    checks.append("existing IP mask conflicts fail validation without changing IPs or assignments")

    # Creating a more specific network can reparent unrelated existing records.
    # Reject that operation when it would change their inherited routing context.
    aggregate = Prefix(prefix="198.51.100.0/24", namespace=namespace, status=active(Prefix))
    aggregate.validated_save()
    unrelated_ip = IPAddress(
        address="198.51.100.130/24", parent=aggregate, status=active(IPAddress)
    )
    unrelated_ip.validated_save()
    guard_name = prefix_name + "1"
    guard_interface = interface(guard_name)
    guarded = new_plan(guard_name, subnet="198.51.100.128/25", host="198.51.100.131")
    before, before_counts = snapshot_ipam(device, policy), counts()
    with CaptureQueriesContext(connection) as captured:
        try:
            validate_ipam_objects(staged(guarded, {guard_name: guard_interface}), device)
        except InventoryError as exc:
            assert "VRF associations" in str(exc)
        else:
            raise AssertionError("Implicit Prefix reparenting changed an unrelated IP's VRFs")
    no_dml(captured, "Unsafe Prefix reparenting preview issued DML")
    unrelated_ip.refresh_from_db()
    assert unrelated_ip.parent_id == aggregate.pk
    assert snapshot_ipam(device, policy) == before and counts() == before_counts
    checks.append("more-specific Prefix creation cannot change unrelated IP routing associations")

    # The selected device's other namespace assignments remain visible to the
    # planner even though their namespace is not part of either selected scope.
    outside_namespace = Namespace(name="CODEX-IPAM-OUTSIDE-" + token)
    outside_namespace.validated_save()
    outside_prefix = Prefix(
        prefix="203.0.113.0/24", namespace=outside_namespace, status=active(Prefix)
    )
    outside_prefix.validated_save()
    outside_ip = IPAddress(
        address="203.0.113.5/24", parent=outside_prefix, status=active(IPAddress)
    )
    outside_ip.validated_save()
    outside_assignment = IPAddressToInterface(ip_address=outside_ip, interface=new_interface)
    outside_assignment.validated_save()
    snapshot = snapshot_ipam(device, policy)
    assert any(
        row["id"] == str(outside_ip.pk) and row["namespace_id"] == str(outside_namespace.pk)
        for row in snapshot["ip_addresses"]
    )
    assert any(row["id"] == str(outside_assignment.pk) for row in snapshot["ip_assignments"])
    assert all(row["id"] != str(outside_prefix.pk) for row in snapshot["prefixes"])
    checks.append("scoped snapshots retain selected Device IP assignments in other namespaces")

    # Exercise the actual pure planner against two real Device assignments.
    # Ordinary VRFs may deliberately share identity; Mgmt-vrf remains local.
    peer = Device(
        name="CODEX-IPAM-PEER-" + token,
        device_type=device.device_type,
        status=device.status,
        role=device.role,
        location=device.location,
        platform=device.platform,
    )
    with SkipAutoComponentCreation():
        peer.validated_save()
    grouped_policy = {**policy, "group_user_vrfs": True}

    def routing_source(names):
        return {
            "ipam": {
                "schema_version": 1,
                "vrfs": [
                    {"name": local, "rd": rd, "address_families": ["ipv4"], "source": {}}
                    for _, local, rd in names
                ],
                "interfaces": [
                    {"name": port, "vrf": local, "ipv4": [], "source": {}}
                    for port, local, _ in names
                ],
                "unresolved": [],
                "sources": [],
            }
        }

    corp_name = "CORP-" + token
    corp_port = interface(prefix_name + "3")
    grouped = plan_ipam(
        routing_source([(corp_port.name, corp_name, "65001:11")]),
        {"interfaces": [], "ipam_inventory": snapshot_ipam(device, grouped_policy)},
        {"interface_creates": [{"name": corp_port.name}]},
    )
    assert not grouped["errors"] and grouped["summary"]["vrfs_created"] == 1
    grouped_objects = save(grouped, {corp_port.name: corp_port}, [corp_port])
    shared_vrf = next(iter(grouped_objects["vrfs"].values()))
    peer_corp = Interface(
        device=peer, name=prefix_name + "4", type="virtual", status=interface_status
    )
    peer_mgmt = Interface(
        device=peer, name=prefix_name + "5", type="virtual", status=interface_status
    )
    peer_plan = plan_ipam(
        routing_source(
            [(peer_corp.name, corp_name, "65002:11"), (peer_mgmt.name, "Mgmt-vrf", None)]
        ),
        {"interfaces": [], "ipam_inventory": snapshot_ipam(peer, grouped_policy)},
        {"interface_creates": [{"name": peer_corp.name}, {"name": peer_mgmt.name}]},
    )
    assert not peer_plan["errors"] and peer_plan["summary"]["vrfs_created"] == 1
    with transaction.atomic():
        peer_objects = ipam_objects(
            peer_plan,
            {peer_corp.name: peer_corp, peer_mgmt.name: peer_mgmt},
            peer,
            prefix_status=None,
            ip_address_status=None,
            status_resolver=active,
        )
        with CaptureQueriesContext(connection) as captured:
            validate_ipam_objects(peer_objects, peer)
        no_dml(captured, "Shared and local peer VRF preview issued DML")
        save_ipam_catalog(peer_objects, peer)
        peer_corp.validated_save()
        peer_mgmt.validated_save()
        save_ipam_assignments(peer_objects, peer)
    peer_corp.refresh_from_db()
    peer_mgmt.refresh_from_db()
    assert peer_corp.vrf_id == shared_vrf.pk
    assert peer_mgmt.vrf_id != saved_vrf.pk
    assert VRFDeviceAssignment.objects.get(device=device, vrf=shared_vrf).rd == "65001:11"
    assert VRFDeviceAssignment.objects.get(device=peer, vrf=shared_vrf).rd == "65002:11"
    assert shared_vrf.rd is None
    assert VRFDeviceAssignment.objects.get(device=peer, vrf=peer_mgmt.vrf).name == "Mgmt-vrf"
    checks.append(
        "opt-in user VRF grouping reuses a shared domain with distinct device RDs; "
        "Mgmt-vrf remains device-local"
    )

    addressless_prefix = Prefix(
        prefix="203.0.113.64/26", namespace=namespace, status=active(Prefix)
    )
    addressless_prefix.validated_save()
    addressless_prefix.vrfs.add(shared_vrf)
    addressless_ip = IPAddress(
        address="203.0.113.65/26", parent=addressless_prefix, status=active(IPAddress)
    )
    addressless_ip.validated_save()
    IPAddressToInterface(ip_address=addressless_ip, interface=corp_port).validated_save()
    corp_port.vrf = None
    corp_port.validated_save()
    addressless_plan = plan_ipam(
        routing_source([(corp_port.name, corp_name, "65001:11")]),
        {
            "interfaces": [{"id": str(corp_port.pk), "name": corp_port.name, "vrf_id": None}],
            "ipam_inventory": snapshot_ipam(device, grouped_policy),
        },
    )
    assert not addressless_plan["errors"] and not addressless_plan["prefixes"]
    assert len(addressless_plan["interface_vrfs"]) == 1
    before, before_counts = snapshot_ipam(device, grouped_policy), counts()
    with CaptureQueriesContext(connection) as captured:
        validate_ipam_objects(staged(addressless_plan, {corp_port.name: corp_port}), device)
    no_dml(captured, "Addressless VRF discovery preview issued DML")
    assert snapshot_ipam(device, grouped_policy) == before and counts() == before_counts
    save(addressless_plan, {corp_port.name: corp_port})
    corp_port.refresh_from_db()
    addressless_ip.refresh_from_db()
    assert corp_port.vrf_id == shared_vrf.pk
    assert addressless_ip.parent_id == addressless_prefix.pk
    checks.append(
        "addressless named VRF discovery fills Interface VRF using existing compatible IP prefixes"
    )

    whole_name = prefix_name + "6"
    device.refresh_from_db()
    discovery = {
        "schema_version": 1,
        "adapter": "cisco_iosxe",
        "identity": {
            "hostname": device.name,
            "serial": device.serial or "CODEX-IPAM-SERIAL-" + token,
            "model": device.device_type.model,
            "software_version": (
                device.software_version.version if device.software_version_id else "17.98.01"
            ),
        },
        "interfaces": [
            {
                "name": whole_name,
                "type": "virtual",
                "enabled": True,
                "description": "IPAM complete reconciliation " + token,
                "mtu": 1500,
                "mac_address": None,
                "speed": None,
                "duplex": None,
                "type_source": "synthetic reviewed routing interface",
                "observations": {},
            }
        ],
        "lag_memberships": [],
        "warnings": [],
        "excluded_interfaces": [],
        "ipam": {
            "schema_version": 1,
            "vrfs": [],
            "interfaces": [
                {
                    "name": whole_name,
                    "vrf": None,
                    "ipv4": [
                        {
                            "address": "100.127.252.1",
                            "mask": "255.255.255.252",
                            "prefix_length": 30,
                            "secondary": False,
                            "method": "configured-static",
                        }
                    ],
                    "source": {},
                }
            ],
            "unresolved": [],
            "sources": [],
        },
    }
    before, before_counts = snapshot_inventory(device, ipam_policy=policy), counts()
    with CaptureQueriesContext(connection) as captured:
        full_plan = build_plan(discovery, snapshot_inventory(device, ipam_policy=policy))
        validate_plan(full_plan, device, interface_status=interface_status)
    no_dml(captured, "Complete IPAM reconciliation preview issued inventory DML")
    assert snapshot_inventory(device, ipam_policy=policy) == before and counts() == before_counts
    assert full_plan["summary"]["prefixes_created"] == 1
    assert full_plan["summary"]["ip_addresses_created"] == 1
    assert full_plan["summary"]["ip_assignments_created"] == 1
    apply_discovery(discovery, device, interface_status=interface_status, ipam_policy=policy)
    whole = Interface.objects.get(device=device, name=whole_name)
    whole_assignment = IPAddressToInterface.objects.get(interface=whole)
    assert str(whole_assignment.ip_address.address) == "100.127.252.1/30"
    assert whole.vrf_id is None and not whole_assignment.is_secondary
    with CaptureQueriesContext(connection) as captured:
        repeated_whole = apply_discovery(
            discovery, device, interface_status=interface_status, ipam_policy=policy
        )
    no_dml(captured, "Repeated complete IPAM reconciliation issued DML")
    assert repeated_whole["summary"]["prefixes_created"] == 0
    assert repeated_whole["summary"]["ip_addresses_created"] == 0
    assert repeated_whole["summary"]["ip_assignments_created"] == 0
    checks.append(
        "complete discovery preview, atomic apply and repeat preserve static global addressing "
        "without repeat DML"
    )

    classification_policy = {**policy, "override_networks": ["100.64.0.0/10"]}
    classification_cases = [
        (prefix_name + "7", "10.254.253.1", "10.254.253.0/30", secondary_namespace),
        (prefix_name + "8", "198.51.100.201", "198.51.100.200/30", namespace),
        (prefix_name + "9", "100.64.253.1", "100.64.253.0/30", secondary_namespace),
    ]
    classified_discovery = copy.deepcopy(discovery)
    classified_discovery["interfaces"] = [
        {**discovery["interfaces"][0], "name": port} for port, _, _, _ in classification_cases
    ]
    classified_discovery["ipam"]["interfaces"] = [
        {
            "name": port,
            "vrf": None,
            "ipv4": [
                {
                    "address": host,
                    "mask": "255.255.255.252",
                    "prefix_length": 30,
                    "secondary": False,
                    "method": "configured-static",
                }
            ],
            "source": {},
        }
        for port, host, _, _ in classification_cases
    ]
    before = snapshot_inventory(device, ipam_policy=classification_policy)
    before_counts = counts()
    before_primary = (device.primary_ip4_id, device.primary_ip6_id)
    with CaptureQueriesContext(connection) as captured:
        classified_plan = build_plan(
            classified_discovery, snapshot_inventory(device, ipam_policy=classification_policy)
        )
        validate_plan(classified_plan, device, interface_status=interface_status)
    no_dml(captured, "Default, RFC1918 and manual override namespace preview issued DML")
    assert snapshot_inventory(device, ipam_policy=classification_policy) == before
    assert counts() == before_counts
    assert classified_plan["summary"]["prefixes_created"] == 3
    assert classified_plan["summary"]["ip_addresses_created"] == 3
    assert classified_plan["summary"]["ip_assignments_created"] == 3
    apply_discovery(
        classified_discovery,
        device,
        interface_status=interface_status,
        ipam_policy=classification_policy,
    )
    for port, host, connected_network, selected_namespace in classification_cases:
        discovered_interface = Interface.objects.get(device=device, name=port)
        discovered_assignment = IPAddressToInterface.objects.get(interface=discovered_interface)
        discovered_ip = discovered_assignment.ip_address
        assert str(discovered_ip.address) == host + "/30"
        assert discovered_ip.parent.namespace_id == selected_namespace.pk
        assert str(discovered_ip.parent.prefix) == connected_network
        assert set(discovered_ip.parent.locations.values_list("pk", flat=True)) == {
            device.location_id
        }
        assert discovered_interface.vrf_id is None and not discovered_assignment.is_secondary
    device.refresh_from_db()
    assert (device.primary_ip4_id, device.primary_ip6_id) == before_primary
    before = snapshot_inventory(device, ipam_policy=classification_policy)
    before_counts = counts()
    with CaptureQueriesContext(connection) as captured:
        repeated_classification = apply_discovery(
            classified_discovery,
            device,
            interface_status=interface_status,
            ipam_policy=classification_policy,
        )
    no_dml(captured, "Repeated default, RFC1918 and manual override namespace apply issued DML")
    assert snapshot_inventory(device, ipam_policy=classification_policy) == before
    assert counts() == before_counts
    for field in ("prefixes_created", "ip_addresses_created", "ip_assignments_created"):
        assert repeated_classification["summary"][field] == 0
    checks.append(
        "default, RFC1918 and manual CIDR override policies create site prefixes in correct "
        "namespaces and repeat without DML or primary IP changes"
    )

    failing_name = prefix_name + "2"
    failing_interface = interface(failing_name)
    failing = new_plan(failing_name, subnet="203.0.113.128/25", host="203.0.113.129")
    before, before_counts = snapshot_ipam(device, policy), counts()
    written = []
    original_save = IPAddressToInterface.validated_save

    def fail_final_assignment(row, *args, **kwargs):
        if row.interface_id == failing_interface.pk:
            assert Interface.objects.filter(pk=failing_interface.pk, vrf__isnull=False).exists()
            assert IPAddress.objects.filter(
                host="203.0.113.129", parent__namespace=namespace
            ).exists()
            written.append("routing catalog and Interface already saved")
            raise InventoryError("Intentional final IP assignment failure")
        return original_save(row, *args, **kwargs)

    with patch.object(IPAddressToInterface, "validated_save", fail_final_assignment):
        try:
            save(failing, {failing_name: failing_interface}, [failing_interface])
        except InventoryError:
            pass
        else:
            raise AssertionError("Injected final IP assignment failure did not occur")
    assert written
    assert snapshot_ipam(device, policy) == before and counts() == before_counts
    assert not Interface.objects.filter(pk=failing_interface.pk).exists()
    checks.append(
        "final IP assignment failure rolls back VRFs, Prefixes, IPs and Interface changes"
    )
