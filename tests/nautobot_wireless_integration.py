"""Native controller/AP acceptance inside unconditional outer rollback.

Run from a configured Nautobot Django shell. All controller/catalog/AP records
are temporary; fixtures contact no endpoint and no permanent inventory is changed.
"""

import copy
import json
import re
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

WRITE_SQL = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b", re.IGNORECASE)


def _no_dml(queries, message):
    assert not any(WRITE_SQL.match(row["sql"]) for row in queries.captured_queries), message


def run():
    """Prove onboarding, AP updates, location constraints, rollback and repeats."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import nautobot
    from django.contrib.contenttypes.models import ContentType
    from django.core.exceptions import ValidationError
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from nautobot.dcim.models import (
        Controller,
        ControllerManagedDeviceGroup,
        Device,
        DeviceType,
        Interface,
        InterfaceTemplate,
        Location,
        LocationType,
        Manufacturer,
        Platform,
        Rack,
        SoftwareVersion,
    )
    from nautobot.extras.models import Role, Status

    from jobs import nautobot_wireless as native
    from jobs.controller_sources import resolve_controller_source
    from jobs.reconcile_wireless import build_wireless_plan
    from jobs.wireless_policy import normalize_wireless_policy

    token = uuid.uuid4().hex[:12]
    tracked = (
        Controller,
        ControllerManagedDeviceGroup,
        Device,
        Interface,
        SoftwareVersion,
        Manufacturer,
        DeviceType,
        Platform,
        Location,
        LocationType,
        Status,
        Role,
        InterfaceTemplate,
        Rack,
    )
    baseline = {model.__name__: model.objects.count() for model in tracked}
    checks = []
    with transaction.atomic():
        status = Status(name="Wireless rollback %s" % token, color="4caf50")
        status.validated_save()
        status.content_types.add(
            *[
                ContentType.objects.get_for_model(model)
                for model in (Device, Controller, Interface, SoftwareVersion, Location, Rack)
            ]
        )
        role = Role(name="Wireless rollback %s" % token, color="2196f3")
        role.validated_save()
        role.content_types.add(ContentType.objects.get_for_model(Device))
        manufacturer, _ = Manufacturer.objects.get_or_create(name="Cisco Systems")
        location_type = LocationType(name="Wireless rollback %s" % token)
        location_type.validated_save()
        location_type.content_types.add(
            ContentType.objects.get_for_model(Device),
            ContentType.objects.get_for_model(Controller),
            ContentType.objects.get_for_model(Rack),
        )
        locations = []
        for index in range(2):
            location = Location(
                name="Wireless rollback %s site %s" % (token, index),
                location_type=location_type,
                status=status,
            )
            location.validated_save()
            locations.append(location)
        ap_type, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer, model="C9130AXI-B", defaults={"u_height": 0}
        )
        controller_type, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer, model="C9800-CL", defaults={"u_height": 0}
        )
        template = InterfaceTemplate(
            device_type=ap_type,
            name="MustNotAppear-%s" % token,
            type="1000base-t",
        )
        template.validated_save()
        platform = Platform(
            name="Wireless rollback AP %s" % token,
            manufacturer=manufacturer,
            network_driver="cisco_ios",
        )
        platform.validated_save()
        from jobs.nautobot_stack import _suppression_context

        def make_device(name, serial, device_type=ap_type, location=locations[0]):
            obj = Device(
                name=name,
                serial=serial,
                device_type=device_type,
                platform=platform,
                role=role,
                status=status,
                location=location,
            )
            with _suppression_context(device_type):
                obj.validated_save()
            return obj

        endpoint = make_device("rollback-wlc-%s" % token, "", controller_type)
        controller = Controller(
            name="Rollback controller %s" % token,
            controller_device=endpoint,
            location=locations[0],
            status=status,
        )
        controller.validated_save()
        group = ControllerManagedDeviceGroup(
            name="Rollback group %s" % token, controller=controller
        )
        group.validated_save()
        existing = make_device("operator-alias-%s" % token, "WAP-%s-1" % token)
        existing.controller_managed_device_group = group
        old = SoftwareVersion(platform=platform, version="17.15.1.1", status=status)
        old.validated_save()
        existing.software_version = old
        existing.validated_save()
        source = resolve_controller_source(
            existing, source_policy={"expected_hostname": endpoint.name}
        )
        assert source["credential_device"].pk == endpoint.pk
        direct = resolve_controller_source(
            endpoint, source_policy={"expected_hostname": endpoint.name}
        )
        assert source["controller_id"] == direct["controller_id"]
        checks.append("both native entry paths resolve one remote controller")
        policy = normalize_wireless_policy(
            {
                "manufacturer": str(manufacturer.pk),
                "platform": str(platform.pk),
                "role": str(role.pk),
                "status": str(status.pk),
                "managed_group": str(group.pk),
                "naming": "reported",
                "ethernet_enabled": True,
                "locations": [
                    {"match": {"site_tag": "remote-site"}, "location": str(locations[1].pk)}
                ],
            },
            native.resolve_wireless_target,
            controller_id=str(controller.pk),
        )

        def ap(index):
            return {
                "name": "reported-ap-%s-%s" % (token, index),
                "serial": "WAP-%s-%s" % (token, index),
                "model": ap_type.model,
                "state": "registered",
                "wtp_mac": "02:11:22:33:44:%02x" % index,
                "ethernet_mac": "02:11:22:33:55:%02x" % index,
                "software_version": "17.12.4.22",
                "tags": {"site": "remote-site"},
                "ethernet_interfaces": [
                    {
                        "name": "GigabitEthernet0",
                        "physical_ethernet": True,
                        "mac_address": "02:11:22:33:55:%02x" % index,
                        "speed": 1000000,
                        "provenance": {"module": "fixture", "path": "ethernet-if-stats"},
                    }
                ],
                "provenance": {"module": "fixture", "path": "capwap-data"},
                "errors": [],
                "warnings": [],
            }

        discovery = {
            "contract": "cisco-9800-snapshot-v1",
            "adapter": "cisco_9800",
            "controller_id": str(controller.pk),
            "complete": True,
            "source": {"verified": True},
            "source_binding": source["source_snapshot"],
            "aps": [ap(1), ap(2)],
            "errors": [],
        }
        with CaptureQueriesContext(connection) as queries:
            plan = build_wireless_plan(
                discovery, native.snapshot_wireless_inventory(discovery, policy), policy
            )
            native.validate_wireless_plan(
                plan, interface_status=status, software_version_status=status
            )
        _no_dml(queries, "Preview issued inventory DML")
        assert not plan["errors"] and all(not row["errors"] for row in plan["aps"]), plan
        assert plan["summary"]["created"] == 1 and plan["summary"]["updated"] == 1, plan
        checks.append("preview stages complete roster with zero inventory DML")
        result = native.apply_wireless_discovery(
            discovery, policy, interface_status=status, software_version_status=status
        )
        assert not result["partial"], result
        assert {row["outcome"] for row in result["aps"]} == {"created", "updated"}, result
        existing.refresh_from_db()
        assert existing.name.startswith("operator-alias-")
        assert existing.location_id == locations[1].pk
        assert existing.software_version.version == "17.12.4.22"
        software_change = next(
            change
            for change in result["aps"][0]["updates"]
            if change["field"] == "software_version_id"
        )
        assert software_change["after"] == str(existing.software_version_id)
        assert result["aps"][0]["software"]["result_id"] == str(existing.software_version_id)
        created = Device.objects.get(serial="WAP-%s-2" % token)
        assert created.controller_managed_device_group_id == group.pk
        assert created.location_id == locations[1].pk
        assert created.interfaces.count() == 1
        assert not Interface.objects.filter(
            device__in=[existing, created], name=template.name
        ).exists()
        checks.append(
            "new AP admission, remote Location move, exact software downgrade, "
            "alias and template suppression"
        )
        with CaptureQueriesContext(connection) as queries:
            repeat = native.apply_wireless_discovery(
                discovery, policy, interface_status=status, software_version_status=status
            )
        _no_dml(queries, "Unchanged full-roster repeat issued inventory DML")
        assert repeat["summary"]["unchanged"] == 2, repeat
        checks.append("repeat issues zero inventory DML")
        late = copy.deepcopy(discovery)
        late["aps"] = [ap(3), ap(4)]
        late["aps"][0]["software_version"] = "17.12.4.23"
        original_save = Interface.validated_save

        def fail_one(interface, *args, **kwargs):
            if interface.device.serial == "WAP-%s-3" % token:
                raise ValidationError("Deliberate late graph failure")
            return original_save(interface, *args, **kwargs)

        with patch.object(Interface, "validated_save", fail_one):
            failed = native.apply_wireless_discovery(
                late, policy, interface_status=status, software_version_status=status
            )
        assert failed["partial"] and failed["summary"]["failed"] == 1, failed
        assert failed["summary"]["created"] == 1, failed
        assert not Device.objects.filter(serial="WAP-%s-3" % token).exists()
        assert not SoftwareVersion.objects.filter(platform=platform, version="17.12.4.23").exists()
        assert Device.objects.filter(serial="WAP-%s-4" % token).exists()
        checks.append("late interface failure rolls back AP plus catalog while another AP succeeds")
        rack = Rack(name="Rollback rack %s" % token, location=locations[1], status=status)
        rack.validated_save()
        existing.rack = rack
        existing.validated_save()
        constrained = copy.deepcopy(discovery)
        constrained["aps"][0]["software_version"] = "17.12.4.24"
        constrained["aps"][1]["software_version"] = "17.12.4.24"
        constrained_policy = copy.deepcopy(policy)
        constrained_policy["locations"] = [
            {
                "match": {"site_tag": "remote-site"},
                "location": native.resolve_wireless_target("location", str(locations[0].pk)),
            }
        ]
        with CaptureQueriesContext(connection) as queries:
            constrained_plan = build_wireless_plan(
                constrained,
                native.snapshot_wireless_inventory(constrained, constrained_policy),
                constrained_policy,
            )
            native.validate_wireless_plan(
                constrained_plan, interface_status=status, software_version_status=status
            )
        _no_dml(queries, "Rack constraint preview wrote inventory")
        assert constrained_plan["aps"][0]["errors"], constrained_plan
        constrained_result = native.apply_wireless_discovery(
            constrained, constrained_policy, interface_status=status, software_version_status=status
        )
        assert constrained_result["aps"][0]["outcome"] == "failed", constrained_result
        assert constrained_result["aps"][1]["outcome"] == "updated", constrained_result
        existing.refresh_from_db()
        assert existing.rack_id == rack.pk and existing.location_id == locations[1].pk
        checks.append(
            "incompatible rack Location preserves native graph while eligible peer updates"
        )
        other_controller = Controller(
            name="Rollback alternate controller %s" % token,
            controller_device=endpoint,
            location=locations[0],
            status=status,
        )
        other_controller.validated_save()
        configured_group = ControllerManagedDeviceGroup(
            name="Rollback alternate group %s" % token, controller=other_controller
        )
        configured_group.validated_save()
        existing.controller_managed_device_group = configured_group
        existing.validated_save()
        observed_elsewhere = copy.deepcopy(discovery)
        observed_elsewhere["source_binding"] = direct["source_snapshot"]
        observed_elsewhere["aps"] = [ap(1)]
        observed_elsewhere["aps"][0]["software_version"] = "17.12.4.25"
        preserved = native.apply_wireless_discovery(
            observed_elsewhere, policy, interface_status=status, software_version_status=status
        )
        assert preserved["aps"][0]["outcome"] == "updated", preserved
        existing.refresh_from_db()
        assert existing.controller_managed_device_group_id == configured_group.pk
        assert existing.software_version.version == "17.12.4.25"
        assert preserved["aps"][0]["warnings"], preserved
        checks.append(
            "observed remote controller does not replace existing configured primary group"
        )
        whitespace_device = make_device("whitespace-alias-%s" % token, " WAP-%s-8 " % token)
        whitespace = {**discovery, "source_binding": direct["source_snapshot"], "aps": [ap(8)]}
        whitespace_plan = build_wireless_plan(
            whitespace, native.snapshot_wireless_inventory(whitespace, policy), policy
        )
        assert not whitespace_plan["aps"][0]["create"]
        assert whitespace_plan["aps"][0]["device_id"] == str(whitespace_device.pk), whitespace_plan
        checks.append(
            "native trimmed serial collision query preserves whitespace alias asset identity"
        )

        from billiard.exceptions import SoftTimeLimitExceeded

        interrupted = {
            **discovery,
            "source_binding": direct["source_snapshot"],
            "aps": [ap(6), ap(7)],
        }
        progress = []
        original_graph_save = native._save

        def interrupt_second(graph):
            if graph["device"].serial == "WAP-%s-7" % token:
                raise SoftTimeLimitExceeded()
            return original_graph_save(graph)

        with patch.object(native, "_save", interrupt_second):
            try:
                native.apply_wireless_discovery(
                    interrupted,
                    policy,
                    interface_status=status,
                    software_version_status=status,
                    progress_callback=lambda current: progress.append(copy.deepcopy(current)),
                )
            except SoftTimeLimitExceeded:
                pass
            else:
                raise AssertionError("SoftTimeLimitExceeded was swallowed")
        assert Device.objects.filter(serial="WAP-%s-6" % token).exists()
        assert not Device.objects.filter(serial="WAP-%s-7" % token).exists()
        assert progress[-1]["incomplete"] and progress[-1]["summary"]["created"] == 1, progress
        assert progress[-1]["aps"][1]["outcome"] == "pending", progress
        checks.append(
            "cancellation preserves committed per-AP progress and rolls back current graph"
        )

        # Exercise the installed native Job, actual collector parsing, native
        # policy/snapshot/staging and Advanced/download report lifecycle.
        from jobs import discovery_job
        from jobs.adapters import cisco_9800 as wlc

        fixtures = Path(__file__).resolve().parent / "fixtures"
        payloads = {
            wlc.HOSTNAME_PATH: {"Cisco-IOS-XE-native:hostname": endpoint.name},
            wlc.YANG_LIBRARY_PATH: {
                "ietf-yang-library:modules-state": {
                    "module": [
                        {"name": wlc.AP_MODULE, "revision": "2023-07-01"},
                        {"name": wlc.JOIN_MODULE, "revision": "2023-07-01"},
                        {"name": wlc.AP_CFG_MODULE, "revision": "2022-11-01"},
                    ]
                }
            },
        }
        for path, filename in (
            (wlc.HARDWARE_PATH, "wlc_device_hardware_9800.json"),
            (wlc.CAPWAP_PATH, "wlc_capwap_data.json"),
            (wlc.MAC_MAP_PATH, "wlc_ap_name_mac_map.json"),
            (wlc.ETHERNET_PATH, "wlc_ethernet_if_stats.json"),
            (wlc.CDP_PATH, "wlc_cdp_cache_data.json"),
            (wlc.LLDP_PATH, "wlc_lldp_neigh.json"),
            (wlc.JOIN_PATH, "wlc_ap_join_stats.json"),
            (wlc.RADIO_PATH, "wlc_radio_oper_data.json"),
            (wlc.AP_TAG_PATH, "wlc_ap_tags.json"),
        ):
            payloads[path] = json.loads((fixtures / filename).read_text())

        class FixtureClient:
            def __init__(self):
                self.trace = []

            def get(self, path, **kwargs):
                self.trace.append({"path": path, "method": "GET"})
                return copy.deepcopy(payloads[path.split("?", 1)[0]])

            def close(self):
                pass

        for model in ("C9120AXI-B", "C9105AXI-B"):
            DeviceType.objects.get_or_create(
                manufacturer=manufacturer, model=model, defaults={"u_height": 0}
            )
        fixture_existing = make_device("fixture-operator-alias-%s" % token, "FGL0000AB01")
        fixture_existing.controller_managed_device_group = group
        fixture_existing.software_version = old
        fixture_existing.validated_save()
        fixture_existing_id = fixture_existing.pk
        job_policy = {
            "manufacturer": str(manufacturer.pk),
            "platform": str(platform.pk),
            "role": str(role.pk),
            "status": str(status.pk),
            "managed_group": str(group.pk),
            "naming": "reported",
            "ethernet_enabled": True,
            "locations": [
                {"match": {"serial": serial}, "location": str(locations[index].pk)}
                for serial, index in (("FGL0000AB01", 1), ("FGL0000AB02", 0), ("FGL0000AB03", 1))
            ],
        }

        def run_fixture_job(*, dryrun):
            job = discovery_job.DiscoverDevice()
            job.logger = Mock()
            job.request = SimpleNamespace(meta={})
            job.create_file = Mock()
            client = FixtureClient()
            with (
                patch.object(
                    discovery_job,
                    "resolve_credentials",
                    return_value=("fixture-user", "fixture-secret"),
                ) as credentials,
                patch.object(discovery_job, "RestconfClient", return_value=client),
            ):
                job.run(
                    fixture_existing,
                    dryrun=dryrun,
                    wireless_controller=str(controller.pk),
                    wireless_source_policy=json.dumps({"expected_hostname": endpoint.name}),
                    wireless_policy=json.dumps(job_policy),
                    interface_status=status,
                    software_version_status=status,
                )
            assert credentials.call_args.args[0].pk == endpoint.pk
            assert all(row["method"] == "GET" for row in client.trace)
            job.create_file.assert_called_once()
            return job.request.meta["discovery_report"]

        with CaptureQueriesContext(connection) as queries:
            report = run_fixture_job(dryrun=True)
        _no_dml(queries, "Actual Job preview wrote inventory")
        assert report["batch_outcome"] == "preview" and not report["applied"]
        assert report["plan"]["summary"]["observed"] == 3, report
        assert report["plan"]["summary"]["created"] == 2, report
        assert report["plan"]["summary"]["updated"] == 1, report
        assert all(not row["errors"] for row in report["plan"]["aps"]), report
        checks.append(
            "actual native Job preview parses full fixtures and stages "
            "two creates plus one update without DML"
        )
        applied_report = run_fixture_job(dryrun=False)
        assert applied_report["applied"] and applied_report["batch_outcome"] == "applied", (
            applied_report
        )
        assert applied_report["plan"]["summary"]["created"] == 2, applied_report
        assert applied_report["plan"]["summary"]["updated"] == 1, applied_report
        fixture_existing.refresh_from_db()
        assert fixture_existing.pk == fixture_existing_id
        assert fixture_existing.name == "fixture-operator-alias-%s" % token
        assert fixture_existing.controller_managed_device_group_id == group.pk
        assert fixture_existing.location_id == locations[1].pk
        assert fixture_existing.software_version.version == "17.12.4.42"
        fixture_new = [
            Device.objects.get(serial=serial) for serial in ("FGL0000AB02", "FGL0000AB03")
        ]
        assert [obj.location_id for obj in fixture_new] == [locations[0].pk, locations[1].pk]
        assert all(obj.controller_managed_device_group_id == group.pk for obj in fixture_new)
        assert fixture_new[1].software_version.version == "17.9.5.47"
        assert not Interface.objects.filter(
            device__in=[fixture_existing] + fixture_new, name=template.name
        ).exists()
        checks.append(
            "actual native Job apply on parsed fixtures creates remote APs and replaces "
            "proven Location/exact software while preserving identity"
        )
        with CaptureQueriesContext(connection) as queries:
            repeated_report = run_fixture_job(dryrun=False)
        _no_dml(queries, "Actual parsed-fixture Job repeat issued inventory DML")
        assert repeated_report["plan"]["summary"]["unchanged"] == 3, repeated_report
        checks.append("actual native Job parsed-fixture repeat issues zero inventory DML")
        stale = copy.deepcopy(discovery)
        stale["source_binding"]["endpoint"] = "wrong-endpoint"
        with CaptureQueriesContext(connection) as queries:
            try:
                native.apply_wireless_discovery(
                    stale, policy, interface_status=status, software_version_status=status
                )
            except native.InventoryError:
                pass
            else:
                raise AssertionError("Changed controller source binding was accepted")
        _no_dml(queries, "Changed shared controller source wrote inventory")
        checks.append("stale shared controller binding blocks before writes")
        transaction.set_rollback(True)
    for model in tracked:
        assert model.objects.count() == baseline[model.__name__], "Outer rollback failed"
    result = {
        "passed": checks,
        "checks_passed": len(checks),
        "nautobot_version": nautobot.__version__,
        "source_evidence": "synthetic fixtures and mocked GET transport",
        "persistent_inventory_changes": 0,
        "outer_rollback": True,
    }
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    run()
