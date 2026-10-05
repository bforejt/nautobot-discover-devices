"""Native PAN VPN proof inside unconditional rollback; no firewall is contacted."""

import copy
import json
import os
import re
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

FIXTURES = Path(__file__).parent / "fixtures"
ANCHOR = "ed010564-cfd9-4039-bfad-a40ea4487157"
WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def no_dml(captured, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in captured.captured_queries), message


def run(device_id=None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from django.contrib.contenttypes.models import ContentType
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import Device, DeviceType, Interface, Manufacturer
    from nautobot.extras.models import CustomField, Status
    from nautobot.ipam.models import IPAddress, IPAddressToInterface, Namespace, Prefix
    from nautobot.vpn.models import (
        VPN,
        VPNPhase1Policy,
        VPNPhase2Policy,
        VPNProfile,
        VPNProfilePhase1PolicyAssignment,
        VPNProfilePhase2PolicyAssignment,
        VPNTunnel,
        VPNTunnelEndpoint,
    )

    from jobs.adapters.panos_vpn_config import parse_vpn_configuration
    from jobs.exceptions import InventoryError
    from jobs.nautobot_panos_vpn import (
        panos_vpn_objects,
        save_panos_vpn_assignments,
        save_panos_vpn_catalog,
        snapshot_panos_vpn,
        validate_panos_vpn_objects,
    )
    from jobs.reconcile_panos_vpn import crypto_policy_name, plan_panos_vpn

    anchor = Device.objects.select_related("location", "role", "status").get(
        pk=device_id or os.environ.get("NAUTOBOT_DISCOVERY_DEVICE_ID") or ANCHOR
    )
    tracked = (
        Device,
        Interface,
        Namespace,
        Prefix,
        IPAddress,
        IPAddressToInterface,
        VPN,
        VPNProfile,
        VPNPhase1Policy,
        VPNPhase2Policy,
        VPNTunnel,
        VPNTunnelEndpoint,
        VPNProfilePhase1PolicyAssignment,
        VPNProfilePhase2PolicyAssignment,
        VPNTunnelEndpoint.protected_prefixes.through,
    )
    before_counts = {model._meta.label: model.objects.count() for model in tracked}
    anchor_before = copy.deepcopy(anchor._custom_field_data)
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
            manufacturer = Manufacturer.objects.get(name="Palo Alto Networks")
            device_type = DeviceType.objects.get(manufacturer=manufacturer, model="PA-VM")
            selected = Device(
                name="PAN-VPN-selected-" + token,
                device_type=device_type,
                location=anchor.location,
                role=anchor.role,
                status=anchor.status,
            )
            selected.validated_save()
            interface_status = Status.objects.get_for_model(Interface).get(name="Active")
            source = Interface.objects.filter(device=selected, name="ethernet1/1").first()
            if source is None:
                source = Interface(
                    device=selected, name="ethernet1/1", type="virtual", status=interface_status
                )
                source.validated_save()
            tunnel_interface = Interface.objects.filter(device=selected, name="tunnel.1").first()
            if tunnel_interface is None:
                tunnel_interface = Interface(
                    device=selected, name="tunnel.1", type="virtual", status=interface_status
                )
                tunnel_interface.validated_save()
            namespace = Namespace(name="PAN-VPN-explicit-" + token)
            namespace.validated_save()
            prefix_status = Status.objects.get_for_model(Prefix).get(name="Active")
            ip_status = Status.objects.get_for_model(IPAddress).get(name="Active")
            public = Prefix(prefix="198.18.101.0/29", namespace=namespace, status=prefix_status)
            public.validated_save()
            local_ip = IPAddress(address="198.18.101.1/29", parent=public, status=ip_status)
            remote_ip = IPAddress(address="198.18.101.3/29", parent=public, status=ip_status)
            local_ip.validated_save()
            remote_ip.validated_save()
            IPAddressToInterface(ip_address=local_ip, interface=source).validated_save()
            local_protected = Prefix(
                prefix="10.255.101.1/32", namespace=namespace, status=prefix_status
            )
            remote_protected = Prefix(
                prefix="10.255.103.1/32", namespace=namespace, status=prefix_status
            )
            local_protected.validated_save()
            remote_protected.validated_save()
            tunnel_status = Status.objects.get_for_model(VPNTunnel).get(name="Active")
            intended_profile = VPNProfile(
                name="PAN Profile " + token, keepalive_enabled=False, nat_traversal=False
            )
            intended_profile.validated_save()
            scope = {"id": str(namespace.pk), "name": namespace.name}
            policy = {
                "contract": "panos-vpn-policy-v1",
                "tunnels": [
                    {
                        "tunnel": "lab-ipsec",
                        "vpn_name": "PAN VPN " + token,
                        "tunnel_name": "PAN Tunnel " + token,
                        "profile_name": "PAN Profile " + token,
                        "status": {"id": str(tunnel_status.pk), "name": tunnel_status.name},
                        **{
                            key: scope
                            for key in (
                                "local_namespace",
                                "remote_namespace",
                                "local_protected_namespace",
                                "remote_protected_namespace",
                            )
                        },
                    }
                ],
            }
            observed = {
                "adapter": "panos",
                "observations": {
                    "vpn": {
                        "configuration": parse_vpn_configuration(
                            (FIXTURES / "panos_vpn_applied_network.xml").read_text()
                        ),
                        "runtime": {"ipsec_sas": [{"name": "do:not:infer:peer", "state": "up"}]},
                    }
                },
            }

            def plan(mapping=policy, discovery=observed, lock=False):
                snapshot = snapshot_panos_vpn(selected, mapping, lock=lock, discovery=discovery)
                return plan_panos_vpn(
                    discovery,
                    {
                        "device": {"id": str(selected.pk), "name": selected.name},
                        "panos_vpn_inventory": snapshot,
                    },
                )

            def validate(mapping=policy, discovery=observed, lock=False):
                planned = plan(mapping, discovery, lock)
                objects = panos_vpn_objects(planned, selected)
                validate_panos_vpn_objects(objects, selected)
                return planned, objects

            def apply(mapping=policy, discovery=observed):
                with transaction.atomic():
                    planned, objects = validate(mapping, discovery, True)
                    save_panos_vpn_catalog(objects)
                    save_panos_vpn_assignments(objects)
                return planned

            with CaptureQueriesContext(connection) as captured:
                preview, _ = validate()
            no_dml(captured, "Native VPN preview issued inventory DML")
            assert not preview["errors"] and not preview["unresolved"], preview
            assert preview["summary"]["vpn_objects_created"] == 6
            assert preview["summary"]["vpn_policy_assignments_created"] == 2
            assert preview["summary"]["vpn_prefix_assignments_created"] == 2
            assert not VPNTunnel.objects.filter(name=policy["tunnels"][0]["tunnel_name"]).exists()
            checks.append(
                "scoped native VPN preview validates six new catalogs and "
                "an existing explicit Profile with zero DML"
            )

            apply()
            tunnel = VPNTunnel.objects.select_related(
                "endpoint_a", "endpoint_z", "vpn", "vpn_profile"
            ).get(name=policy["tunnels"][0]["tunnel_name"])
            phase1 = VPNPhase1Policy.objects.get(
                name=crypto_policy_name(str(selected.pk), "IKE", "lab-ike-profile", "ikev2")
            )
            phase2 = VPNPhase2Policy.objects.get(
                name=crypto_policy_name(str(selected.pk), "IPsec", "lab-ipsec-profile")
            )
            assert phase1.ike_version == "IKEv2"
            assert phase1.encryption_algorithm == ["AES-256-CBC"]
            assert phase1.integrity_algorithm == ["SHA256"] and phase1.dh_group == ["14"]
            assert phase1.lifetime_seconds == 28800
            assert phase2.encryption_algorithm == ["AES-256-CBC"]
            assert phase2.integrity_algorithm == ["SHA256"] and phase2.pfs_group == ["14"]
            assert phase2.lifetime == 3600
            assert tunnel.vpn.vpn_profile_id == tunnel.vpn_profile_id
            assert tunnel.status_id == tunnel_status.pk and tunnel.encapsulation == "IPsec-Tunnel"
            assert tunnel.endpoint_a.device_id == selected.pk
            assert tunnel.endpoint_a.source_interface_id == source.pk
            assert tunnel.endpoint_a.tunnel_interface_id == tunnel_interface.pk
            assert tunnel.endpoint_a.source_ipaddress_id == local_ip.pk
            assert tunnel.endpoint_z.source_ipaddress_id == remote_ip.pk
            assert (
                tunnel.endpoint_z.device_id is None
                and tunnel.endpoint_z.source_interface_id is None
            )
            assert tunnel.endpoint_z.source_fqdn == ""
            assert list(tunnel.endpoint_a.protected_prefixes.values_list("pk", flat=True)) == [
                local_protected.pk
            ]
            assert list(tunnel.endpoint_z.protected_prefixes.values_list("pk", flat=True)) == [
                remote_protected.pk
            ]
            assert (
                VPNProfilePhase1PolicyAssignment.objects.get(vpn_profile=tunnel.vpn_profile).weight
                == 100
            )
            assert (
                VPNProfilePhase2PolicyAssignment.objects.get(vpn_profile=tunnel.vpn_profile).weight
                == 100
            )
            assert phase1.authentication_method == "" and tunnel.secrets_group_id is None
            checks.append(
                "atomic apply creates policies, service, tunnel, owned local and "
                "scoped remote-IP endpoints and protected prefixes"
            )

            with CaptureQueriesContext(connection) as captured:
                repeated = apply()
            no_dml(captured, "Repeated native VPN discovery issued inventory DML")
            assert repeated["summary"]["vpn_objects_created"] == 0
            assert repeated["summary"]["vpn_objects_updated"] == 0
            assert not repeated["assignments"] and not repeated["prefix_assignments"]
            checks.append("repeat discovery preserves the native graph with zero DML")

            # Multiple configured tunnels may share a physical WAN Interface.
            # The native OneToOne source_interface relation cannot express this
            # on every endpoint, but exact Device/IP/tunnel ownership can.
            second_interface = Interface(
                device=selected, name="tunnel.2", type="virtual", status=interface_status
            )
            second_interface.validated_save()
            second_profile = VPNProfile(
                name="PAN Second Profile " + token, keepalive_enabled=False, nat_traversal=False
            )
            second_profile.validated_save()
            shared_observed = copy.deepcopy(observed)
            second_config = copy.deepcopy(
                shared_observed["observations"]["vpn"]["configuration"]["ipsec_tunnels"][0]
            )
            second_config.update(name="lab-second-ipsec", tunnel_interface="tunnel.2")
            shared_observed["observations"]["vpn"]["configuration"]["ipsec_tunnels"].append(
                second_config
            )
            shared_policy = copy.deepcopy(policy)
            second_mapping = copy.deepcopy(shared_policy["tunnels"][0])
            second_mapping.update(
                tunnel="lab-second-ipsec",
                vpn_name="PAN Second VPN " + token,
                tunnel_name="PAN Second Tunnel " + token,
                profile_name=second_profile.name,
            )
            shared_policy["tunnels"].append(second_mapping)
            with CaptureQueriesContext(connection) as captured:
                shared_preview, shared_objects = validate(shared_policy, shared_observed)
            no_dml(captured, "Shared-WAN VPN preview issued inventory DML")
            assert not shared_preview["errors"] and not shared_preview["unresolved"], shared_preview
            local_specs = [row for row in shared_preview["catalog"] if row.get("source_binding")]
            assert len(local_specs) == 2
            assert all(
                row["source_binding"]["source_interface_id"] == str(source.pk)
                for row in local_specs
            )
            second_spec = next(
                row
                for row in local_specs
                if row["source_binding"]["tunnel_interface_id"] == str(second_interface.pk)
            )
            second_endpoint = shared_objects["catalog"][second_spec["key"]]
            assert second_endpoint.source_interface_id is None
            assert second_endpoint.device_id == selected.pk
            # Full native clean does not validate a omitted source Interface;
            # the independent observed binding must still reject wrong IPAM.
            assignment = IPAddressToInterface.objects.get(ip_address=local_ip, interface=source)
            with transaction.atomic():
                assignment.delete()
                with CaptureQueriesContext(connection) as captured:
                    try:
                        validate_panos_vpn_objects(shared_objects, selected)
                    except InventoryError:
                        pass
                    else:
                        raise AssertionError("Unassigned shared-WAN source IP was accepted")
                no_dml(captured, "Shared-WAN binding rejection issued inventory DML")
                transaction.set_rollback(True)
            apply(shared_policy, shared_observed)
            second_tunnel = VPNTunnel.objects.select_related("endpoint_a", "endpoint_z").get(
                name=second_mapping["tunnel_name"]
            )
            assert second_tunnel.endpoint_a.device_id == selected.pk
            assert second_tunnel.endpoint_a.source_ipaddress_id == local_ip.pk
            assert second_tunnel.endpoint_a.tunnel_interface_id == second_interface.pk
            assert second_tunnel.endpoint_a.source_interface_id is None
            assert second_tunnel.endpoint_z.vpn_profile_id == second_profile.pk
            assert second_tunnel.endpoint_z_id != tunnel.endpoint_z_id
            assert (
                VPNTunnelEndpoint.objects.get(pk=tunnel.endpoint_a_id).source_interface_id
                == source.pk
            )
            with CaptureQueriesContext(connection) as captured:
                shared_repeat = apply(shared_policy, shared_observed)
            no_dml(captured, "Repeated shared-WAN VPN discovery issued inventory DML")
            assert shared_repeat["summary"]["vpn_objects_created"] == 0
            checks.append(
                "multiple native tunnels share a verified WAN IP with distinct exact "
                "tunnel Interfaces and zero-DML repeat"
            )
            checks.append(
                "independent shared-WAN binding rejects a missing real "
                "source-IP assignment before DML"
            )

            # Populated arrays, explicit zero lifetime, booleans and assignment
            # order survive even when the appliance reports different values.
            phase1.encryption_algorithm = ["AES-128-CBC", "AES-256-CBC"]
            phase1.lifetime_seconds = 0
            phase1.validated_save()
            profile = tunnel.vpn_profile
            profile.keepalive_enabled = True
            profile.nat_traversal = True
            profile.validated_save()
            assignment = VPNProfilePhase1PolicyAssignment.objects.get(vpn_profile=profile)
            assignment.weight = 7
            assignment.validated_save()
            with CaptureQueriesContext(connection) as captured:
                preserved = apply()
            no_dml(captured, "Populated native VPN preservation issued inventory DML")
            phase1.refresh_from_db()
            profile.refresh_from_db()
            assignment.refresh_from_db()
            assert phase1.encryption_algorithm == ["AES-128-CBC", "AES-256-CBC"]
            assert phase1.lifetime_seconds == 0 and assignment.weight == 7
            assert profile.keepalive_enabled and profile.nat_traversal
            assert any(row["field"] == "encryption_algorithm" for row in preserved["conflicts"])
            checks.append(
                "populated algorithm order, explicit zero, profile booleans and "
                "policy weight remain unchanged with mismatches reported"
            )

            with (
                patch("jobs.nautobot_panos_vpn._models", return_value=None),
                CaptureQueriesContext(connection) as captured,
            ):
                unavailable, _ = validate()
            no_dml(captured, "Missing optional VPN capability issued inventory DML")
            assert not unavailable["catalog"] and unavailable["summary"]["unresolved_vpn"] == 1
            checks.append("missing optional native VPN models stay report-only with zero DML")

            wrong_namespace = Namespace(name="PAN-VPN-wrong-" + token)
            wrong_namespace.validated_save()
            wrong_policy = copy.deepcopy(policy)
            wrong_policy["tunnels"][0]["remote_namespace"] = {
                "id": str(wrong_namespace.pk),
                "name": wrong_namespace.name,
            }
            with CaptureQueriesContext(connection) as captured:
                unresolved, _ = validate(wrong_policy)
            no_dml(captured, "Wrong remote Namespace preview issued inventory DML")
            assert any("Literal peer IP" in row["reason"] for row in unresolved["unresolved"])
            assert not any(row["name"].startswith("ip:") for row in unresolved["catalog"])
            checks.append("literal peer lookup does not infer a namespace or peer Device")

            missing_profile_policy = copy.deepcopy(policy)
            for key in ("vpn_name", "tunnel_name", "profile_name"):
                missing_profile_policy["tunnels"][0][key] += " missing-profile"
            with CaptureQueriesContext(connection) as captured:
                no_profile, _ = validate(missing_profile_policy)
            no_dml(captured, "Missing native Profile preview issued inventory DML")
            assert any("required keepalive" in row["reason"] for row in no_profile["unresolved"])
            assert not any(row["model"] == "VPNProfile" for row in no_profile["catalog"])
            assert not no_profile["assignments"]
            apply(missing_profile_policy)
            incomplete = VPNTunnel.objects.select_related("vpn").get(
                name=missing_profile_policy["tunnels"][0]["tunnel_name"]
            )
            assert incomplete.vpn_profile_id is None and incomplete.vpn.vpn_profile_id is None
            assert not VPNProfile.objects.filter(
                name=missing_profile_policy["tunnels"][0]["profile_name"]
            ).exists()
            with CaptureQueriesContext(connection) as captured:
                apply(missing_profile_policy)
            no_dml(captured, "Repeated missing-Profile discovery issued inventory DML")
            checks.append(
                "missing native Profile remains unresolved while independent service/tunnel "
                "apply and repeat preserve unknown booleans"
            )

            invalid = copy.deepcopy(observed)
            invalid["observations"]["vpn"]["configuration"]["sources"]["ike_gateways"][
                "command"
            ] = "candidate"
            with CaptureQueriesContext(connection) as captured:
                try:
                    apply(discovery=invalid)
                except (InventoryError, ValueError):
                    pass
                else:
                    raise AssertionError("Invalid applied VPN provenance was accepted")
            no_dml(captured, "Invalid provenance apply issued inventory DML")
            checks.append("invalid applied-source provenance is rejected before DML")

            # A second native tunnel explicitly sharing the configured source
            # may reuse endpoints. Reject its late save after earlier new VPN
            # and crypto rows are written, and prove the transaction restores
            # all catalogs and assignment tables.
            late_policy = copy.deepcopy(policy)
            for key in ("vpn_name", "tunnel_name"):
                late_policy["tunnels"][0][key] += " late"
            late_observed = copy.deepcopy(observed)
            late_configuration = late_observed["observations"]["vpn"]["configuration"]
            for collection, old_name in (
                ("ike_crypto_profiles", "lab-ike-profile"),
                ("ipsec_crypto_profiles", "lab-ipsec-profile"),
            ):
                for row in late_configuration[collection]:
                    if row["name"] == old_name:
                        row["name"] += " late"
            for row in late_configuration["ike_gateways"]:
                if row["name"] == "lab-ike":
                    row["protocol"]["ikev2_profile"] += " late"
            for row in late_configuration["ipsec_tunnels"]:
                if row["name"] == "lab-ipsec":
                    row["auto_key"]["crypto_profile"] += " late"
            late_counts = {model._meta.label: model.objects.count() for model in tracked}
            original_save = VPNTunnel.save
            reached_earlier_writes = []

            def late_failure(target, *args, **kwargs):
                if target.name == late_policy["tunnels"][0]["tunnel_name"]:
                    assert VPN.objects.filter(name=late_policy["tunnels"][0]["vpn_name"]).exists()
                    assert VPNPhase1Policy.objects.filter(
                        name=crypto_policy_name(
                            str(selected.pk), "IKE", "lab-ike-profile late", "ikev2"
                        )
                    ).exists()
                    reached_earlier_writes.append(True)
                    raise InventoryError("Synthetic late native tunnel failure")
                return original_save(target, *args, **kwargs)

            with patch.object(VPNTunnel, "save", late_failure):
                try:
                    apply(late_policy, late_observed)
                except InventoryError:
                    pass
                else:
                    raise AssertionError("Late native tunnel failure was not raised")
            assert reached_earlier_writes
            assert late_counts == {model._meta.label: model.objects.count() for model in tracked}
            checks.append(
                "late native tunnel save failure rolls back earlier service/crypto "
                "writes and all VPN graph tables"
            )
        finally:
            transaction.set_rollback(True)
    assert before_counts == {model._meta.label: model.objects.count() for model in tracked}
    assert Device.objects.get(pk=anchor.pk)._custom_field_data == anchor_before
    return {"checks": checks, "count": len(checks), "rollback": True}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
