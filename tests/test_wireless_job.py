"""Job entry paths, remote fleet scope and controller-only credential handling."""

import json
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from tests._loader import load
from tests.test_discovery_job import load_discovery_job, rendered_logs

CONTROLLER_ID = "00000000-0000-4000-8000-000000000001"
SEED_ID = "00000000-0000-4000-8000-000000000002"


def fleet_plan():
    return {
        "contract": "wireless-plan-v1",
        "controller_id": CONTROLLER_ID,
        "errors": [],
        "aps": [
            {"identity": {"serial": "AP-LOCAL"}, "outcome": "updated", "errors": []},
            {"identity": {"serial": "AP-REMOTE"}, "outcome": "created", "errors": []},
        ],
        "summary": {"created": 1, "updated": 1, "software_updates": 1, "location_updates": 1},
    }


class WirelessJobTests(unittest.TestCase):
    def setUp(self):
        self.module = load_discovery_job()
        self.seed = SimpleNamespace(pk=SEED_ID, name="seed-ap", primary_ip=None)
        self.endpoint = SimpleNamespace(pk="controller-device", name="wlc", primary_ip=None)
        self.source = {
            "controller_id": CONTROLLER_ID,
            "credential_device": self.endpoint,
            "secrets_group": object(),
            "host": "192.0.2.8",
            "port": 8443,
            "source_policy": {"kind": "logical", "expected_hostname": "wlc"},
            "source_snapshot": {"id": CONTROLLER_ID, "seed_device_id": SEED_ID},
        }
        self.module.Device.objects.get.return_value = self.seed
        self.job = self.module.DiscoverDevice()
        self.job.logger = Mock()
        self.job.request = SimpleNamespace(meta={})
        self.job.create_file = Mock()
        self.discovery = {
            "contract": "cisco-9800-snapshot-v1",
            "controller_id": CONTROLLER_ID,
            "complete": True,
            "source": {"verified": True},
            "aps": [{"serial": "AP-LOCAL"}, {"serial": "AP-REMOTE"}],
        }
        self.native = ModuleType("jobs.nautobot_wireless")
        self.native.resolve_wireless_target = Mock()
        self.native.snapshot_wireless_inventory = Mock(return_value={"supported": True})
        self.native.validate_wireless_plan = Mock()
        self.native.apply_wireless_discovery = Mock(return_value=fleet_plan())
        native_patch = patch.dict(sys.modules, {"jobs.nautobot_wireless": self.native})
        native_patch.start()
        self.addCleanup(native_patch.stop)
        self.client = Mock(trace=[{"path": "capwap-data"}])
        patches = (
            patch.object(self.module, "_controller_source", return_value=self.source),
            patch.object(self.module, "_adapter", side_effect=AssertionError("AP dispatch")),
            patch.object(self.module, "_host", side_effect=AssertionError("AP endpoint")),
            patch.object(self.module, "resolve_credentials", return_value=("user", "secret")),
            patch.object(self.module, "RestconfClient", return_value=self.client),
            patch.object(self.module.cisco_9800, "collect", return_value=self.discovery),
            patch.object(
                load("wireless_policy"),
                "normalize_wireless_policy",
                return_value={"contract": "wireless-policy-v1"},
            ),
            patch.object(
                load("reconcile_wireless"), "build_wireless_plan", return_value=fleet_plan()
            ),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_ap_seed_collects_full_remote_roster_using_only_controller_credentials(self):
        self.job.run(self.seed)
        self.module.resolve_credentials.assert_called_once_with(
            self.endpoint, override_group=self.source["secrets_group"]
        )
        self.module.RestconfClient.assert_called_once_with(
            "192.0.2.8",
            "user",
            "secret",
            port=8443,
            verify=True,
            max_response_bytes=32 * 1024 * 1024,
        )
        self.module.cisco_9800.collect.assert_called_once_with(
            self.client,
            controller_id=CONTROLLER_ID,
            source_policy=self.source["source_policy"],
            max_aps=10000,
        )
        report = self.job.request.meta["discovery_report"]
        self.assertEqual(len(report["discovery"]["aps"]), 2)
        self.assertEqual(report["discovery"]["source_binding"], self.source["source_snapshot"])
        self.assertFalse(report["applied"])
        self.client.close.assert_called_once()
        self.native.apply_wireless_discovery.assert_not_called()
        self.assertIn("including other sites", " ".join(rendered_logs(self.job.logger)))

    def test_logical_controller_input_needs_no_device(self):
        self.job.run(wireless_controller=CONTROLLER_ID)
        self.module.Device.objects.get.assert_not_called()
        self.module._controller_source.assert_called_once_with(
            None, controller_id=CONTROLLER_ID, source_policy=None
        )
        name, data = self.job.create_file.call_args.args
        self.assertEqual(name, "discovery_%s.json" % CONTROLLER_ID)
        self.assertEqual(json.loads(data)["controller_id"], CONTROLLER_ID)

    def test_missing_controller_fails_before_credentials_or_connections_and_keeps_report(self):
        self.module._controller_source.side_effect = ValueError("configure native Controller")
        with self.assertRaisesRegex(ValueError, "configure native Controller"):
            self.job.run(self.seed)
        self.module.resolve_credentials.assert_not_called()
        self.module.RestconfClient.assert_not_called()
        self.assertEqual(
            self.job.request.meta["discovery_report"]["error"], "configure native Controller"
        )

    def test_bad_admission_policy_fails_before_credentials(self):
        load("wireless_policy").normalize_wireless_policy.side_effect = ValueError("wrong group")
        with self.assertRaisesRegex(ValueError, "wrong group"):
            self.job.run(self.seed, wireless_policy="{}")
        self.module.resolve_credentials.assert_not_called()
        self.module.RestconfClient.assert_not_called()

    def test_apply_uses_complete_snapshot_and_reports_mixed_outcomes(self):
        applied = fleet_plan()
        applied["aps"][1]["outcome"] = "failed"
        applied["aps"][1]["errors"] = ["native move rolled back"]
        applied["summary"]["created"] = 0
        self.native.apply_wireless_discovery.return_value = applied
        self.job.run(self.seed, dryrun=False)
        call = self.native.apply_wireless_discovery.call_args
        self.assertEqual(len(call.args[0]["aps"]), 2)
        report = self.job.request.meta["discovery_report"]
        self.assertTrue(report["applied"])
        self.assertEqual(report["batch_outcome"], "mixed")
        self.assertIn("mixed batch", " ".join(rendered_logs(self.job.logger, "warning")))

    def test_unresolved_admission_candidates_are_explicit_mixed_apply(self):
        applied = fleet_plan()
        applied["aps"][1].update(outcome="unresolved", unresolved=["missing Location"])
        applied["summary"]["created"] = 0
        applied["partial"] = True
        self.native.apply_wireless_discovery.return_value = applied
        self.job.run(self.seed, dryrun=False)
        self.assertEqual(self.job.request.meta["discovery_report"]["batch_outcome"], "mixed")

    def test_interrupted_apply_retains_committed_graph_and_pending_outcomes(self):
        def interrupt(discovery, policy, **options):
            progress = fleet_plan()
            progress["aps"][0]["outcome"] = "updated"
            progress["aps"][1]["outcome"] = "pending"
            progress["summary"]["created"] = 0
            options["progress_callback"](progress)
            raise RuntimeError("worker interrupted")

        self.native.apply_wireless_discovery.side_effect = interrupt
        with self.assertRaisesRegex(RuntimeError, "worker interrupted"):
            self.job.run(self.seed, dryrun=False)
        report = self.job.request.meta["discovery_report"]
        self.assertTrue(report["applied"])
        self.assertEqual(report["batch_outcome"], "incomplete")
        self.assertEqual([row["outcome"] for row in report["plan"]["aps"]], ["updated", "pending"])

    def test_collection_failure_closes_client_and_records_request_diagnostics(self):
        self.module.cisco_9800.collect.side_effect = self.module.cisco_9800.DiscoveryError(
            "required roster failed"
        )
        with self.assertRaisesRegex(RuntimeError, "required roster failed"):
            self.job.run(self.seed)
        self.client.close.assert_called_once()
        self.native.snapshot_wireless_inventory.assert_not_called()
        report = self.job.request.meta["discovery_report"]
        self.assertEqual(report["requests"], self.client.trace)
        self.assertFalse(report["applied"])

    def test_invalid_limits_are_rejected_before_connection(self):
        for kwargs in (
            {"wireless_max_aps": True},
            {"wireless_max_aps": 0},
            {"verify_tls": "false"},
            {"restconf_port": 0},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.job.run(self.seed, **kwargs)
        self.module.resolve_credentials.assert_not_called()


if __name__ == "__main__":
    unittest.main()
