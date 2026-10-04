"""Native route target graph checks enclosed by the harness's outer rollback."""

import copy
import re
import uuid
from unittest.mock import patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def catalog_counts():
    from nautobot.ipam.models import VRF, RouteTarget

    models = [RouteTarget]
    models.extend(
        VRF._meta.get_field(field).remote_field.through
        for field in ("import_targets", "export_targets")
    )
    return {model.__name__: model.objects.count() for model in models}


def run(device, interface_status, checks):
    """Verify native membership, empty-set filling, exact scope and atomic IPv6 writes."""
    from django.contrib.contenttypes.models import ContentType
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.apps.dcim import SkipAutoComponentCreation
    from nautobot.dcim.models import Device, Interface
    from nautobot.extras.models import CustomField
    from nautobot.ipam.models import (
        VRF,
        IPAddress,
        Namespace,
        Prefix,
        RouteTarget,
        VRFDeviceAssignment,
    )

    from jobs.exceptions import InventoryError
    from jobs.nautobot_inventory import apply_discovery, snapshot_inventory, validate_plan
    from jobs.reconcile import build_plan

    assert transaction.get_connection().in_atomic_block, (
        "Route target checks require outer rollback"
    )
    suffix = uuid.uuid4().hex[:12]
    namespace = Namespace(name="CODEX-ROUTE-TARGETS-" + suffix)
    namespace.validated_save()
    other_namespace = Namespace(name="CODEX-RT-OTHER-" + suffix)
    other_namespace.validated_save()
    target = Device(
        name="route-targets-" + suffix,
        serial="ROUTE-TARGET-" + suffix,
        device_type=device.device_type,
        location=device.location,
        role=device.role,
        status=device.status,
        platform=device.platform,
        software_version=device.software_version,
    )
    with SkipAutoComponentCreation():
        target.validated_save()
    target.location.location_type.content_types.add(ContentType.objects.get_for_model(Prefix))
    policy = {
        "default_namespace": {"id": str(namespace.pk), "name": namespace.name},
        "override_namespace": None,
        "override_rfc1918": False,
        "override_networks": [],
        "create_missing_prefixes": True,
        "group_user_vrfs": False,
        "local_vrf_names": ["Mgmt-vrf", "LOCAL"],
        "location": {"id": str(target.location_id), "name": target.location.name},
    }
    # Globally unique literal catalog; the numeric values are explicit test configuration.
    administrator = 4200000000 + int(suffix[:4], 16)
    literals = {
        label: "%s:%s" % (administrator, index)
        for index, label in enumerate(("import", "export", "operator", "new"), 1)
    }
    port_base = "Loopback" + str(uuid.uuid4().int)[:12]

    def observed(name="BLUE", port=None, subnet="2001:db8:1111::1/64"):
        port = port or port_base
        return {
            "schema_version": 1,
            "adapter": "cisco_iosxe",
            "identity": {
                "hostname": target.name,
                "serial": target.serial,
                "model": target.device_type.model,
                "software_version": target.software_version.version
                if target.software_version_id
                else "17.98.01",
            },
            "interfaces": [
                {
                    "name": port,
                    "type": "virtual",
                    "enabled": True,
                    "description": "Native RT check " + suffix,
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
                "vrfs": [
                    {
                        "name": name,
                        "rd": None,
                        "address_families": ["ipv6"],
                        "source": {},
                        "route_targets": {
                            "status": "available",
                            "import": [literals["import"]],
                            "export": [literals["export"]],
                            "source": {
                                "complete": True,
                                "module": "Cisco-IOS-XE-native",
                                "path": "/data/native/vrf/definition",
                            },
                        },
                    }
                ],
                "interfaces": [
                    {
                        "name": port,
                        "vrf": name,
                        "ipv4": [],
                        "ipv6": [
                            {
                                "configured_prefix": subnet,
                                "method": "configured",
                                "eui_64": False,
                                "anycast": False,
                            }
                        ],
                        "source": {},
                    }
                ],
                "unresolved": [],
                "sources": [],
            },
        }

    def inventory(selected_policy=policy):
        return snapshot_inventory(Device.objects.get(pk=target.pk), ipam_policy=selected_policy)

    def counts():
        return {
            **catalog_counts(),
            **{
                model.__name__: model.objects.count()
                for model in (VRF, VRFDeviceAssignment, Prefix, IPAddress, Interface, CustomField)
            },
        }

    def no_dml(captured):
        assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries)

    def apply(data, selected_policy=policy):
        return apply_discovery(
            data, target, interface_status=interface_status, ipam_policy=selected_policy
        )

    discovery = observed()
    baseline, initial_counts = inventory(), counts()
    with CaptureQueriesContext(connection) as captured:
        preview = build_plan(discovery, inventory())
        validate_plan(preview, target, interface_status=interface_status)
    no_dml(captured)
    assert not preview["errors"]
    assert preview["summary"]["route_targets_created"] == 2
    assert preview["summary"]["vrf_import_targets_added"] == 1
    assert preview["summary"]["vrf_export_targets_added"] == 1
    assert preview["summary"]["prefixes_created"] == 1
    assert preview["summary"]["ip_addresses_created"] == 1
    assert inventory() == baseline and counts() == initial_counts
    checks.append(
        "route target and IPv6 graph preview validates new native VRFs and targets without DML"
    )

    apply(discovery)
    assignment = VRFDeviceAssignment.objects.get(device=target, name="BLUE")
    blue = assignment.vrf
    assert set(blue.import_targets.values_list("name", flat=True)) == {literals["import"]}
    assert set(blue.export_targets.values_list("name", flat=True)) == {literals["export"]}
    interface = Interface.objects.get(device=target, name=port_base)
    assert interface.vrf_id == blue.pk
    assert str(interface.ip_addresses.get().address) == "2001:db8:1111::1/64"
    assert CustomField.objects.count() == initial_counts["CustomField"]
    baseline, initial_counts = inventory(), counts()
    with CaptureQueriesContext(connection) as captured:
        repeated = apply(discovery)
    no_dml(captured)
    assert inventory() == baseline and counts() == initial_counts
    assert all(
        repeated["summary"][field] == 0
        for field in (
            "route_targets_created",
            "vrf_import_targets_added",
            "vrf_export_targets_added",
            "prefixes_created",
            "ip_addresses_created",
        )
    )
    checks.append(
        "native import/export targets, IPv6 address and Device-local VRF persist "
        "and repeat without DML or custom fields"
    )

    conflicts = copy.deepcopy(discovery)
    conflicts["ipam"]["vrfs"][0]["route_targets"].update(
        {"import": [], "export": [literals["new"]]}
    )
    with CaptureQueriesContext(connection) as captured:
        conflicted = apply(conflicts)
    no_dml(captured)
    assert inventory() == baseline and counts() == initial_counts
    assert (
        len([row for row in conflicted["conflicts"] if row.get("scope") == "vrf_route_targets"])
        == 2
    )
    assert not RouteTarget.objects.filter(name=literals["new"]).exists()
    checks.append(
        "populated native target sets are preserved whole, "
        "including when observed direction is empty"
    )

    management = observed("Mgmt-vrf", port_base + "1", "2001:db8:1112::1/64")
    apply(management)
    management_vrf = VRFDeviceAssignment.objects.get(device=target, name="Mgmt-vrf").vrf
    assert not management_vrf.import_targets.exists() and not management_vrf.export_targets.exists()
    assert catalog_counts() == {key: initial_counts[key] for key in catalog_counts()}
    checks.append(
        "Mgmt-vrf address inventory remains eligible "
        "while its native route target writes are excluded"
    )

    local_user = observed("LOCAL", port_base + "2", "2001:db8:1113::1/64")
    local_user["ipam"]["vrfs"][0]["route_targets"]["export"] = []
    apply(local_user)
    local_vrf = VRFDeviceAssignment.objects.get(device=target, name="LOCAL").vrf
    assert local_vrf.import_targets.get().pk == blue.import_targets.get().pk
    assert not local_vrf.export_targets.exists()
    assert local_vrf.pk != blue.pk and local_vrf.namespace_id == namespace.pk
    checks.append(
        "device-local user VRF exceptions remain target-eligible "
        "and reuse global literals without merging VRF identities"
    )

    cross_namespace_policy = copy.deepcopy(policy)
    cross_namespace_policy["default_namespace"] = {
        "id": str(other_namespace.pk),
        "name": other_namespace.name,
    }
    baseline, initial_counts = inventory(), counts()
    with CaptureQueriesContext(connection) as captured:
        cross_namespace = apply(discovery, cross_namespace_policy)
    no_dml(captured)
    assert inventory() == baseline and counts() == initial_counts
    assert any(
        row.get("scope") == "vrf_route_targets" for row in cross_namespace["ipam"]["unresolved"]
    )
    checks.append(
        "existing Device VRF namespace identity prevents cross-scope route target adoption"
    )

    # A direction can be filled once from one complete source while its existing
    # other direction stays untouched. A peer assignment blocks that filling.
    shared = VRF(name="CODEX-RT-SHARED-" + suffix, namespace=namespace)
    shared.validated_save()
    VRFDeviceAssignment(vrf=shared, device=target, name="SHARED").validated_save()
    peer = Device(
        name="route-target-peer-" + suffix,
        device_type=target.device_type,
        location=target.location,
        role=target.role,
        status=target.status,
    )
    with SkipAutoComponentCreation():
        peer.validated_save()
    VRFDeviceAssignment(vrf=shared, device=peer, name="SHARED").validated_save()
    shared_observed = observed("SHARED", port_base + "3", "2001:db8:1114::1/64")
    shared_preview = build_plan(shared_observed, inventory())
    assert shared_preview["summary"]["vrf_import_targets_added"] == 0
    assert shared_preview["summary"]["vrf_export_targets_added"] == 0
    assert (
        len(
            [
                row
                for row in shared_preview["ipam"]["unresolved"]
                if row.get("scope") == "vrf_route_targets"
            ]
        )
        == 2
    )
    assert not shared.import_targets.exists() and not shared.export_targets.exists()
    checks.append(
        "blank shared native VRF target directions defer instead of guessing unobserved peer policy"
    )

    canonical = VRF(name="ADOPT", namespace=namespace)
    canonical.validated_save()
    canonical.import_targets.add(blue.import_targets.get())
    canonical.export_targets.add(blue.export_targets.get())
    VRFDeviceAssignment(vrf=canonical, device=peer, name="ADOPT").validated_save()
    adoption_policy = {**policy, "group_user_vrfs": True}
    adoption = observed("ADOPT", port_base + "5", "2001:db8:1116::1/64")
    for status in ("different", "unavailable"):
        unconfirmed = copy.deepcopy(adoption)
        facts = unconfirmed["ipam"]["vrfs"][0]["route_targets"]
        if status == "different":
            facts["import"] = [literals["new"]]
        else:
            facts["status"] = "unavailable"
        baseline, initial_counts = inventory(adoption_policy), counts()
        with CaptureQueriesContext(connection) as captured:
            refused = build_plan(unconfirmed, inventory(adoption_policy))
            validate_plan(refused, target, interface_status=interface_status)
        no_dml(captured)
        assert not refused["ipam"]["vrf_device_assignments"]
        assert not refused["ipam"]["interface_vrfs"]
        assert not refused["ipam"]["prefixes"]
        assert not refused["ipam"]["ip_addresses"]
        assert inventory(adoption_policy) == baseline and counts() == initial_counts
    apply(adoption, adoption_policy)
    adopted = VRFDeviceAssignment.objects.get(device=target, name="ADOPT")
    assert adopted.vrf_id == canonical.pk
    assert Interface.objects.get(device=target, name=port_base + "5").vrf_id == canonical.pk
    assert set(canonical.import_targets.values_list("name", flat=True)) == {literals["import"]}
    assert set(canonical.export_targets.values_list("name", flat=True)) == {literals["export"]}
    checks.append(
        "new shared VRF endpoints adopt confirmed populated policies; "
        "mismatched or unavailable target policy defers the whole IPAM bundle"
    )

    failing = observed("FAILURE", port_base + "4", "2001:db8:1115::1/64")
    failing["ipam"]["vrfs"][0]["route_targets"].update({"import": [literals["new"]], "export": []})
    import_manager = type(blue.import_targets)
    original_add = import_manager.add
    staged = []

    def fail_late(manager, *objects, **kwargs):
        if manager.instance.name.endswith(" / FAILURE"):
            assert IPAddress.objects.filter(
                host="2001:db8:1115::1", parent__namespace=namespace
            ).exists()
            assert RouteTarget.objects.filter(name=literals["new"]).exists()
            assert VRFDeviceAssignment.objects.filter(device=target, name="FAILURE").exists()
            staged.append("native IPv6/VRF/target catalogs were saved")
            raise InventoryError("Intentional late native target M2M failure")
        return original_add(manager, *objects, **kwargs)

    baseline, initial_counts = inventory(), counts()
    with patch.object(import_manager, "add", fail_late):
        try:
            apply(failing)
        except InventoryError:
            pass
        else:
            raise AssertionError("Injected native target M2M failure did not occur")
    assert staged and inventory() == baseline and counts() == initial_counts
    assert not VRFDeviceAssignment.objects.filter(device=target, name="FAILURE").exists()
    assert not RouteTarget.objects.filter(name=literals["new"]).exists()
    checks.append(
        "late native route target M2M failure rolls back IPv6, VRF, "
        "literal catalogs and Interface changes atomically"
    )
