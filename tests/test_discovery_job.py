"""Offline coverage for human-readable job logs and Advanced discovery reports."""

import json
import re
import sys
import unittest
from copy import deepcopy
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from tests._loader import load


def load_discovery_job():
    """Import the job with temporary Nautobot stubs that cannot leak into other tests."""
    job_api = ModuleType("nautobot.apps.jobs")
    job_api.Job = type("Job", (), {})
    for name in ("BooleanVar", "DryRunVar", "IntegerVar", "ObjectVar"):
        setattr(job_api, name, lambda **kwargs: SimpleNamespace(**kwargs))
    dcim = ModuleType("nautobot.dcim.models")
    dcim.Device = type("Device", (), {"objects": SimpleNamespace(get=Mock())})
    extras = ModuleType("nautobot.extras.models")
    extras.SecretsGroup = type("SecretsGroup", (), {})
    extras.Status = type("Status", (), {})
    ipam = ModuleType("nautobot.ipam.models")
    ipam.VLANGroup = type("VLANGroup", (), {})
    inventory = ModuleType("jobs.nautobot_inventory")
    inventory.InventoryError = type("InventoryError", (RuntimeError,), {})
    for name in ("apply_discovery", "snapshot_inventory", "validate_plan"):
        setattr(inventory, name, Mock())
    stubs = {
        "nautobot": ModuleType("nautobot"),
        "nautobot.apps": ModuleType("nautobot.apps"),
        "nautobot.apps.jobs": job_api,
        "nautobot.dcim": ModuleType("nautobot.dcim"),
        "nautobot.dcim.models": dcim,
        "nautobot.extras": ModuleType("nautobot.extras"),
        "nautobot.extras.models": extras,
        "nautobot.ipam": ModuleType("nautobot.ipam"),
        "nautobot.ipam.models": ipam,
        "jobs.nautobot_inventory": inventory,
    }
    package = sys.modules["jobs"]
    missing = object()
    original_job = getattr(package, "discovery_job", missing)
    try:
        with patch.dict(sys.modules, stubs):
            sys.modules.pop("jobs.discovery_job", None)
            return load("discovery_job")
    finally:
        if original_job is missing:
            package.__dict__.pop("discovery_job", None)
        else:
            package.discovery_job = original_job


def discovery():
    """Normalized observations with evidence that should stay out of the main log."""
    return {
        "identity": {
            "hostname": "example-9300",
            "serial": "LAB93000001",
            "model": "C9300-48UXM",
            "software_version": "17.12.8",
        },
        "interfaces": [{"name": "GigabitEthernet1/0/1"}],
        "components": {"items": [{"name": "Switch 1"}]},
        "excluded_interfaces": [],
        "warnings": [],
        "evidence": {"sources": {"path": "/restconf/data/raw-evidence-sentinel"}},
    }


CHANGE_COUNTERS = {
    "interfaces_created": (r"interfaces?", r"creat|new|add"),
    "interfaces_updated": (r"interfaces?", r"updat|enrich"),
    "console_ports_created": (r"console ports?", r"creat|new|add"),
    "console_ports_updated": (r"console ports?", r"updat|enrich"),
    "management_interfaces_updated": (r"management interfaces?", r"mark"),
    "lag_memberships_updated": (r"lag|link aggregation|port-channel", r"members|updat"),
    "device_fields_updated": (r"device fields?", r"updat|fill"),
    "module_types_created": (r"(?:module|hardware) types?", r"creat|new|add"),
    "module_types_updated": (r"(?:module|hardware) types?", r"updat|enrich"),
    "module_bays_created": (r"(?:module )?bays?", r"creat|new|add"),
    "module_bays_updated": (r"(?:module )?bays?", r"updat|enrich"),
    "modules_created": (r"modules?", r"creat|new|add"),
    "modules_updated": (r"modules?", r"updat|enrich"),
    "interface_modules_updated": (r"interface", r"ownership|module|link"),
    "vlans_created": (r"vlans?", r"creat|new|add"),
    "vlans_updated": (r"vlans?", r"updat|enrich"),
    "interface_vlan_assignments_updated": (r"interface vlan assignments?", r"updat"),
}


def plan(**counts):
    summary = {key: 0 for key in CHANGE_COUNTERS}
    summary.update(
        conflicts=0,
        missing_interfaces=0,
        excluded_interfaces=0,
        unresolved_components=0,
        unresolved_switching=0,
        switching_defaults=0,
        switching_dynamic=0,
        switching_not_applicable=0,
        switching_inferred=0,
        interface_vlan_assignments_inferred=0,
        unresolved_console_ports=0,
        blocked=False,
    )
    summary.update(counts)
    return {"summary": summary, "warnings": [], "conflicts": [], "errors": []}


def rendered_logs(logger, level=None):
    """Render logger printf arguments as Nautobot would display the messages."""
    calls = logger.mock_calls if level is None else getattr(logger, level).mock_calls
    messages = []
    for call in calls:
        if not call.args:
            continue
        message, *arguments = call.args
        messages.append(message % tuple(arguments) if arguments else str(message))
    return messages


class DiscoveryJobTests(unittest.TestCase):
    def setUp(self):
        self.module = load_discovery_job()
        self.device = SimpleNamespace(
            pk="device-1",
            name="example-9300",
            primary_ip=SimpleNamespace(host="192.0.2.1"),
            platform=SimpleNamespace(network_driver="cisco_iosxe", name="Cisco IOS XE"),
            device_type=SimpleNamespace(manufacturer=SimpleNamespace(name="Cisco")),
        )
        self.module.Device.objects.get.return_value = self.device
        self.job = self.module.DiscoverDevice()
        self.job.request = SimpleNamespace(meta={"existing": "keep me"})
        self.job.logger = Mock()
        self.job.create_file = Mock()
        self.observed = discovery()
        self.preview_plan = plan()
        self.client = Mock(trace=[{"path": "/restconf/data/request-evidence-sentinel"}])
        patches = {
            "resolve_credentials": Mock(return_value=("test-user", "test-password")),
            "RestconfClient": Mock(return_value=self.client),
            "build_plan": Mock(return_value=self.preview_plan),
        }
        for name, replacement in patches.items():
            patcher = patch.object(self.module, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        collector = patch.object(
            self.module.cisco_iosxe, "collect", Mock(return_value=self.observed)
        )
        collector.start()
        self.addCleanup(collector.stop)
        self.module.snapshot_inventory.return_value = {"device": {"id": self.device.pk}}
        self.module.apply_discovery.return_value = plan()

    def assert_saved_report(self):
        report = self.job.request.meta["discovery_report"]
        self.assertEqual(self.job.request.meta["existing"], "keep me")
        filename, attachment = self.job.create_file.call_args.args
        self.assertEqual(filename, "discovery_device-1.json")
        self.assertEqual(json.loads(attachment), report)
        return report

    def test_import_stubs_are_restored(self):
        names = (
            "nautobot",
            "nautobot.apps.jobs",
            "nautobot.dcim.models",
            "nautobot.extras.models",
            "jobs.nautobot_inventory",
            "jobs.discovery_job",
        )
        before = {name: sys.modules.get(name) for name in names}
        package = sys.modules["jobs"]
        before_attribute = getattr(package, "discovery_job", None)
        load_discovery_job()
        for name in names:
            self.assertIs(sys.modules.get(name), before[name])
        self.assertIs(getattr(package, "discovery_job", None), before_attribute)

    def test_preview_saves_complete_report_under_advanced_and_returns_none(self):
        self.preview_plan["summary"].update(interfaces_created=2, conflicts=1)
        warning = "/restconf/data/warning-evidence-sentinel: unsupported raw field"
        self.preview_plan["warnings"] = [warning, "second raw warning"]
        self.preview_plan["conflicts"] = [
            {
                "scope": "device",
                "name": "example-9300",
                "field": "name",
                "before": "operator-value-sentinel",
                "observed": "observed-value-sentinel",
            }
        ]
        result = self.job.run(self.device, dryrun=True)
        self.assertIsNone(result)
        report = self.assert_saved_report()
        self.assertEqual(report["discovery"], self.observed)
        self.assertEqual(report["plan"], self.preview_plan)
        self.assertEqual(report["requests"], self.client.trace)
        self.assertFalse(report["applied"])
        self.assertTrue(report["dry_run"])
        self.module.apply_discovery.assert_not_called()
        self.module.validate_plan.assert_called_once()
        self.client.close.assert_called_once()
        messages = "\n".join(rendered_logs(self.job.logger)).lower()
        for context in ("example-9300", "preview", "advanced"):
            self.assertIn(context, messages)
        self.assertRegex(messages, r"2[^\n]*interfaces?")
        self.assertRegex(messages, r"2[^\n]*warnings?|warnings?[^\n]*2")
        self.assertRegex(messages, r"1[^\n]*conflicts?|conflicts?[^\n]*1")
        for evidence in (
            "/restconf/",
            "operator-value-sentinel",
            "observed-value-sentinel",
            "unsupported raw field",
            "second raw warning",
        ):
            self.assertNotIn(evidence, messages)

    def test_ntc_option_defaults_off_and_reaches_the_collector(self):
        option = self.module.DiscoverDevice.use_ntc_defaults
        self.assertFalse(option.default)
        self.assertEqual(option.label, "Use NTC defaults when guessing")
        self.assertIn("uncertain values blank", option.description)
        self.job.run(self.device)
        self.module.cisco_iosxe.collect.assert_called_once_with(self.client, use_ntc_defaults=False)
        self.assertFalse(self.assert_saved_report()["use_ntc_defaults"])
        self.assertNotIn("guessing is enabled", "\n".join(rendered_logs(self.job.logger)))

    def test_opt_in_reports_inferences_and_keeps_raw_evidence_out_of_logs(self):
        self.observed["layer2"] = {
            "settings": [{"inference": {"reason": "raw-inference-sentinel"}}]
        }
        self.preview_plan["summary"].update(
            switching_dynamic=34,
            switching_inferred=33,
            interface_vlan_assignments_inferred=33,
            interface_vlan_assignments_updated=33,
            interfaces_updated=33,
        )
        self.job.run(self.device, use_ntc_defaults=True)
        self.module.cisco_iosxe.collect.assert_called_once_with(self.client, use_ntc_defaults=True)
        report = self.assert_saved_report()
        self.assertTrue(report["use_ntc_defaults"])
        self.assertEqual(report["discovery"]["layer2"], self.observed["layer2"])
        messages = "\n".join(rendered_logs(self.job.logger))
        self.assertIn("NTC default guessing is enabled", messages)
        self.assertIn("33 match the opt-in NTC guessing policy", messages)
        self.assertIn("Would use NTC-inferred VLAN assignments on 33 interfaces", messages)
        self.assertNotIn("negotiated 802.1Q mode remains blank", messages)
        self.assertNotIn("raw-inference-sentinel", messages)
        self.job.logger.warning.assert_not_called()

    def test_repeat_inference_observations_do_not_report_inventory_changes(self):
        repeated = plan(switching_dynamic=34, switching_inferred=33)
        self.module.apply_discovery.return_value = repeated
        self.job.run(self.device, dryrun=False, use_ntc_defaults=True)
        messages = "\n".join(rendered_logs(self.job.logger))
        self.assertIn("No inventory changes are needed", messages)
        self.assertIn("33 match the opt-in NTC guessing policy", messages)
        self.assertNotIn("Used NTC-inferred", messages)
        self.assertTrue(self.assert_saved_report()["use_ntc_defaults"])

    def test_non_boolean_ntc_option_cannot_enable_collection(self):
        for value in ("false", "true", 1, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "must be true or false"):
                    self.job.run(self.device, use_ntc_defaults=value)
        self.module.resolve_credentials.assert_not_called()
        self.module.RestconfClient.assert_not_called()
        self.module.cisco_iosxe.collect.assert_not_called()

    def test_apply_summaries_and_report_use_final_plan(self):
        self.preview_plan["summary"]["interfaces_created"] = 19
        self.preview_plan["warnings"] = ["preliminary raw warning sentinel"]
        applied = plan(module_types_updated=3, module_bays_updated=4, conflicts=2)
        applied["warnings"] = ["final raw warning sentinel", "other final raw warning sentinel"]
        applied["conflicts"] = [{"before": "final operator sentinel"}] * 2
        self.module.apply_discovery.return_value = applied
        self.assertIsNone(self.job.run(self.device, dryrun=False))
        report = self.assert_saved_report()
        self.assertEqual(report["plan"], applied)
        self.assertTrue(report["applied"])
        self.assertFalse(report["dry_run"])
        self.module.apply_discovery.assert_called_once_with(
            self.observed,
            self.device,
            interface_status=None,
            software_version_status=None,
            module_status=None,
            vlan_group=None,
            vlan_status=None,
        )
        self.module.validate_plan.assert_called_once()
        messages = "\n".join(rendered_logs(self.job.logger)).lower()
        self.assertIn("saving", messages)
        self.assertIn("complete", messages)
        self.assertRegex(messages, r"3[^\n]*(?:module|hardware) types?")
        self.assertRegex(messages, r"4[^\n]*(?:module )?bays?")
        self.assertRegex(messages, r"2[^\n]*warnings?|warnings?[^\n]*2")
        self.assertRegex(messages, r"2[^\n]*conflicts?|conflicts?[^\n]*2")
        for raw in ("19", "preliminary raw", "final raw", "final operator"):
            self.assertNotIn(raw, messages)

    def test_each_mutable_counter_has_a_human_readable_nonzero_summary(self):
        for counter, (subject, action) in CHANGE_COUNTERS.items():
            with self.subTest(counter=counter):
                self.module.build_plan.return_value = plan(**{counter: 3})
                self.job.logger.reset_mock()
                self.job.run(self.device)
                summaries = [
                    message.lower()
                    for message in rendered_logs(self.job.logger, "info")
                    if re.search(r"\b3\b", message)
                ]
                self.assertTrue(summaries, "No log includes the change count")
                self.assertTrue(
                    any(re.search(subject, row) and re.search(action, row) for row in summaries),
                    "No readable description for %s: %s" % (counter, summaries),
                )
                self.assertFalse(
                    any(re.search(r"(?<![\d.])0(?![\d.])", row) for row in summaries),
                    "Zero change counts should not clutter the summary",
                )

    def test_unchanged_inventory_is_explicit_in_preview_and_apply(self):
        for dryrun in (True, False):
            with self.subTest(dryrun=dryrun):
                self.job.logger.reset_mock()
                self.job.run(self.device, dryrun=dryrun)
                messages = "\n".join(rendered_logs(self.job.logger, "info")).lower()
                self.assertRegex(messages, r"no (?:inventory )?changes")
                self.assertFalse(re.search(r"\b0 (?:interfaces?|modules?|bays?)", messages))

    def test_dynamic_defaults_and_not_applicable_interfaces_are_informational(self):
        self.preview_plan["summary"].update(
            switching_defaults=53,
            switching_dynamic=34,
            switching_not_applicable=5,
        )
        self.job.run(self.device)
        messages = "\n".join(rendered_logs(self.job.logger, "info")).lower()
        self.assertRegex(messages, r"documented switchport defaults[^\n]*53")
        self.assertRegex(messages, r"34 interfaces have dynamic")
        self.assertRegex(messages, r"does not apply[^\n]*5")
        self.assertIn("802.1q mode remains blank", messages)
        self.assertIn("no inventory changes are needed", messages)
        self.job.logger.warning.assert_not_called()
        self.job.logger.error.assert_not_called()
        self.assertEqual(self.assert_saved_report()["plan"], self.preview_plan)

    def test_actual_source_gaps_and_unsupported_mapping_remain_warnings(self):
        self.preview_plan["summary"].update(unresolved_switching=2)
        self.preview_plan["warnings"] = ["/restconf/data/private-source: HTTP 503"]
        self.job.run(self.device)
        warnings = "\n".join(rendered_logs(self.job.logger, "warning")).lower()
        self.assertIn("1 discovery warning", warnings)
        self.assertIn("2 interface vlan observations unresolved", warnings)
        self.assertIn("required evidence is missing or has no reviewed mapping", warnings)
        self.assertNotIn("/restconf/", warnings)
        self.assertNotIn("http 503", warnings)
        self.job.logger.error.assert_not_called()
        self.assertEqual(self.assert_saved_report()["plan"], self.preview_plan)

    def test_optional_actual_source_failures_continue_without_exposing_raw_evidence(self):
        for status in ("unsupported", "unavailable", "invalid"):
            with self.subTest(status=status):
                self.job.logger.reset_mock()
                self.preview_plan["layer2"] = {
                    "operational_source": {
                        "status": status,
                        "reason": "private-response-sentinel",
                    }
                }
                self.job.run(self.device)
                messages = "\n".join(rendered_logs(self.job.logger))
                self.assertIn(status, messages)
                self.assertIn("Preview complete", messages)
                self.assertNotIn("private-response-sentinel", messages)
                self.job.logger.error.assert_not_called()
                if status == "invalid":
                    self.assertIn("NTC mode guessing", messages)
                self.assertEqual(
                    self.assert_saved_report()["plan"]["layer2"]["operational_source"]["status"],
                    status,
                )

    def test_valid_direct_probe_explains_unknown_revision_without_guessing(self):
        self.preview_plan["layer2"] = {
            "operational_source": {
                "status": "available",
                "capability_status": "unknown",
                "probed_without_advertisement": True,
                "revision": None,
            }
        }
        self.job.run(self.device)
        messages = "\n".join(rendered_logs(self.job.logger))
        self.assertIn("validated by a direct RESTCONF probe", messages)
        self.assertIn("revision remains unknown", messages)
        self.job.logger.warning.assert_not_called()
        self.job.logger.error.assert_not_called()

    def test_known_type_conflict_identifies_the_preserved_interface(self):
        self.preview_plan["summary"].update(conflicts=1)
        self.preview_plan["conflicts"] = [
            {
                "scope": "interface",
                "name": "Vlan2",
                "field": "type",
                "before": "other",
                "observed": "virtual",
            }
        ]
        self.job.run(self.device)
        warnings = "\n".join(rendered_logs(self.job.logger, "warning"))
        self.assertIn("Interface Vlan2: kept type Other", warnings)
        self.assertIn("discovery identifies it as Virtual", warnings)
        self.assertIn("existing interface was preserved", warnings)
        self.job.logger.error.assert_not_called()

    def test_unknown_conflict_values_are_kept_out_of_main_log(self):
        self.preview_plan["summary"].update(conflicts=1)
        self.preview_plan["conflicts"] = [
            {
                "scope": "interface",
                "name": "Vlan2",
                "field": "type",
                "before": {"private": "raw-type-sentinel"},
                "observed": "virtual",
            }
        ]
        self.job.run(self.device)
        messages = "\n".join(rendered_logs(self.job.logger))
        self.assertNotIn("raw-type-sentinel", messages)
        self.assertNotIn("Interface Vlan2:", messages)
        self.assertEqual(self.assert_saved_report()["plan"], self.preview_plan)

    def test_hardware_warning_identifies_missing_identity_and_other_gaps_separately(self):
        self.preview_plan["summary"].update(unresolved_components=5)
        self.preview_plan["components"] = {
            "unresolved": [
                {
                    "name": name,
                    "model": None,
                    "serial": None,
                    "platform_type": type_,
                    "empty": False,
                    "oper_status": "disabled" if type_ == "comp-power-supply" else "enabled",
                    "reason": (
                        "Component identity is unavailable; presence or occupancy "
                        "is not inferred from operational state"
                    ),
                }
                for name, type_ in (
                    ("Switch 1 - Fan 1", "comp-fan"),
                    ("Switch 1 - Fan 2", "comp-fan"),
                    ("Switch 1 - Fan 3", "comp-fan"),
                    ("Switch 1 - Power Supply A", "comp-power-supply"),
                )
            ]
            + [{"reason": "private-placement-sentinel"}]
        }
        self.job.run(self.device)
        warnings = "\n".join(rendered_logs(self.job.logger, "warning")).lower()
        self.assertIn("4 serialized hardware records", warnings)
        self.assertIn("device did not provide model or serial identity", warnings)
        self.assertIn("1 hardware observation unresolved", warnings)
        self.assertIn("existing hardware was preserved", warnings)
        self.assertNotIn("private-placement-sentinel", warnings)
        self.job.logger.error.assert_not_called()
        self.assertEqual(self.assert_saved_report()["plan"], self.preview_plan)

    def test_repeat_run_keeps_dynamic_classification_without_reporting_a_change(self):
        repeated = plan(switching_dynamic=34, switching_defaults=53, switching_not_applicable=5)
        self.module.apply_discovery.return_value = repeated
        self.job.run(self.device, dryrun=False)
        messages = "\n".join(rendered_logs(self.job.logger, "info")).lower()
        self.assertIn("no inventory changes are needed", messages)
        self.assertIn("34 interfaces have dynamic", messages)
        self.assertNotIn("recorded", messages)
        self.job.logger.warning.assert_not_called()
        self.assertEqual(self.assert_saved_report()["plan"], repeated)

    def test_management_evidence_is_reported_without_namespace_or_address_writes(self):
        self.observed["management"] = {
            "interfaces": [{"name": "GigabitEthernet0/0", "vrf": "private-vrf-sentinel"}],
            "writes_deferred_reason": "Namespace mapping has not been selected",
        }
        self.preview_plan["summary"].update(
            console_ports_created=2, management_interfaces_updated=1, interfaces_updated=1
        )
        self.job.run(self.device)
        messages = "\n".join(rendered_logs(self.job.logger, "info"))
        self.assertIn("Would add 2 console ports", messages)
        self.assertIn("Would mark 1 dedicated management interface", messages)
        self.assertIn("VRF/IP assignments are deferred", messages)
        self.assertNotIn("private-vrf-sentinel", messages)
        self.assertEqual(self.assert_saved_report()["discovery"], self.observed)

    def test_ambiguous_console_inventory_has_readable_warning_without_raw_evidence(self):
        self.preview_plan["summary"]["unresolved_console_ports"] = 1
        self.preview_plan["console_ports"] = {
            "unresolved": [{"reason": "private-console-sentinel"}]
        }
        self.job.run(self.device)
        messages = "\n".join(rendered_logs(self.job.logger, "warning"))
        self.assertIn("1 console-port observations unresolved", messages)
        self.assertNotIn("private-console-sentinel", messages)
        self.job.logger.error.assert_not_called()

    def test_optional_management_gaps_keep_available_hardware_and_report_evidence(self):
        self.observed["management"] = {
            "interfaces": [],
            "unresolved": [{"reason": "private-management-gap-sentinel"}],
        }
        self.job.run(self.device)
        messages = "\n".join(rendered_logs(self.job.logger, "warning"))
        self.assertIn("1 management configuration observations", messages)
        self.assertIn("Available hardware and configuration evidence", messages)
        self.assertNotIn("private-management-gap-sentinel", messages)
        self.job.logger.error.assert_not_called()
        self.assertEqual(self.assert_saved_report()["discovery"], self.observed)

    def test_expected_collection_failure_saves_report_and_suppresses_exception_cause(self):
        failure = self.module.RestconfError("Device connection timed out")
        self.module.cisco_iosxe.collect.side_effect = failure
        with self.assertRaises(RuntimeError) as raised:
            self.job.run(self.device)
        self.assertIs(type(raised.exception), RuntimeError)
        self.assertEqual(str(raised.exception), str(failure))
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        report = self.assert_saved_report()
        self.assertEqual(report["error"], str(failure))
        self.assertEqual(report["requests"], self.client.trace)
        self.assertFalse(report["applied"])
        self.client.close.assert_called_once()
        self.module.apply_discovery.assert_not_called()

    def test_unexpected_failure_keeps_original_exception_and_complete_report(self):
        failure = ValueError("Unexpected inventory snapshot failure")
        self.module.snapshot_inventory.side_effect = failure
        with self.assertRaises(ValueError) as raised:
            self.job.run(self.device)
        self.assertIs(raised.exception, failure)
        report = self.assert_saved_report()
        self.assertEqual(report["error"], str(failure))
        self.assertEqual(report["discovery"], self.observed)
        self.assertEqual(report["requests"], self.client.trace)
        self.client.close.assert_called_once()

    def test_failure_before_collection_is_saved_under_advanced(self):
        failure = self.module.CredentialsError("No usable discovery credentials")
        self.module.resolve_credentials.side_effect = failure
        with self.assertRaises(RuntimeError):
            self.job.run(self.device)
        report = self.assert_saved_report()
        self.assertEqual(report["error"], str(failure))
        self.assertNotIn("requests", report)
        self.module.RestconfClient.assert_not_called()

    def test_attachment_failure_keeps_advanced_report_and_explains_fallback(self):
        self.job.create_file.side_effect = OSError("Attachment storage unavailable")
        self.assertIsNone(self.job.run(self.device))
        report = self.job.request.meta["discovery_report"]
        self.assertEqual(report["discovery"], self.observed)
        self.assertEqual(report["plan"], self.preview_plan)
        self.assertEqual(self.job.request.meta["existing"], "keep me")
        warnings = "\n".join(rendered_logs(self.job.logger, "warning")).lower()
        self.assertIn("advanced", warnings)
        self.assertRegex(warnings, r"attach|download")

    def test_advanced_report_is_also_saved_when_failed_attachment_cannot_be_written(self):
        self.job.create_file.side_effect = OSError("Attachment storage unavailable")
        self.module.cisco_iosxe.collect.side_effect = self.module.RestconfError("Read failed")
        with self.assertRaises(RuntimeError):
            self.job.run(self.device)
        report = deepcopy(self.job.request.meta["discovery_report"])
        self.assertEqual(report["error"], "Read failed")
        self.assertEqual(report["requests"], self.client.trace)
        self.client.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
