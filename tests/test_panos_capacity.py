"""Palo-only capacity evidence, source guards and honest unresolved quantities."""

import json
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

from tests import test_discovery_job, test_panos, test_panos_framework
from tests._loader import load

capacity = load("adapters.panos_capacity")
panos = load("adapters.panos")
ssh = load("transport_ssh")


class CapacityEvidenceTests(unittest.TestCase):
    def collect(self, *, cores="4", memory="8157880", vm_mode="KVM", model="PA-VM", family="vm"):
        payloads = test_panos.vm_payloads()
        for original, replacement in (
            ("<vm-cores>4</vm-cores>", "<vm-cores>%s</vm-cores>" % cores),
            ("<vm-mem>8157880</vm-mem>", "<vm-mem>%s</vm-mem>" % memory),
            ("<vm-mode>KVM</vm-mode>", "<vm-mode>%s</vm-mode>" % vm_mode),
            ("<model>PA-VM</model>", "<model>%s</model>" % model),
            ("<family>vm</family>", "<family>%s</family>" % family),
        ):
            payloads[ssh.SYSTEM_INFO] = payloads[ssh.SYSTEM_INFO].replace(original, replacement)
        client = Mock(run=Mock(side_effect=payloads.__getitem__))
        result = panos.collect(client)
        self.assertTrue(
            all(ssh.is_read_command(call.args[0]) for call in client.run.call_args_list)
        )
        return result

    def test_xml_core_count_can_populate_existing_field_without_extra_queries(self):
        discovery = self.collect()
        result = discovery["capacity"]
        self.assertEqual(set(result["fields"]), {"vcpus"})
        self.assertEqual(
            result["fields"]["vcpus"],
            {
                "value": 4,
                "source": {
                    "command": ssh.SYSTEM_INFO,
                    "path": "result/system/vm-cores",
                    "raw_value": "4",
                    "unit": "count",
                },
            },
        )
        self.assertTrue(capacity.validate_capacity(discovery, result))

    def test_capacity_source_does_not_assume_a_hypervisor(self):
        for vm_mode in ("ESXi", "XEN", "Microsoft Hyper-V", "unknown", "", "KVM"):
            with self.subTest(vm_mode=vm_mode):
                result = self.collect(vm_mode=vm_mode)
                self.assertEqual(result["capacity"]["fields"]["vcpus"]["value"], 4)
                self.assertTrue(capacity.validate_capacity(result, result["capacity"]))

    def test_unknown_memory_units_and_missing_primary_disk_capacity_stay_unresolved(self):
        for raw in ("8157880", "8192", "8 GB", "0", "", "unknown"):
            with self.subTest(raw=raw):
                result = self.collect(memory=raw)["capacity"]
                self.assertNotIn("memory_mb", result["fields"])
                self.assertNotIn("disk_gb", result["fields"])
                self.assertEqual(
                    [row["field"] for row in result["unresolved"]], ["memory_mb", "disk_gb"]
                )
                self.assertEqual(result["unresolved"][0]["raw_value"], raw or None)

    def test_invalid_or_missing_cpu_count_stays_unknown(self):
        for raw in ("0", "-1", "4.0", "4 cores", "true", "unknown", "", "2147483648"):
            with self.subTest(raw=raw):
                result = self.collect(cores=raw)["capacity"]
                self.assertFalse(result["fields"])
                self.assertEqual(len(result["unresolved"]), 3)

    def test_vm_scope_requires_explicit_model_and_family(self):
        for kwargs in ({"model": "PA-5250"}, {"family": "hardware"}):
            with self.subTest(kwargs=kwargs):
                result = self.collect(**kwargs)["capacity"]
                self.assertFalse(result["fields"])
                self.assertEqual(result["scope"], "unsupported")

    def test_duplicate_cpu_xml_scalar_is_rejected_by_normal_parser(self):
        payloads = test_panos.vm_payloads()
        payloads[ssh.SYSTEM_INFO] = payloads[ssh.SYSTEM_INFO].replace(
            "<vm-cores>4</vm-cores>", "<vm-cores>4</vm-cores><vm-cores>8</vm-cores>"
        )
        with self.assertRaises(panos.DiscoveryError):
            panos.collect(SimpleNamespace(run=payloads.__getitem__))

    def test_tampered_provenance_quantities_and_extra_fields_are_rejected(self):
        original = self.collect()
        mutations = (
            lambda row: row["capacity"]["fields"]["vcpus"].update(value=True),
            lambda row: row["capacity"]["fields"]["vcpus"]["source"].update(unit="MHz"),
            lambda row: row["capacity"]["fields"]["vcpus"]["source"].update(path="unreviewed"),
            lambda row: row["capacity"]["fields"].update(memory_mb={"value": 8192}),
            lambda row: row["sources"]["identity"].update(command="unreviewed"),
            lambda row: row["observations"]["system"].update(**{"vm-cores": "8"}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = deepcopy(original)
                mutation(result)
                self.assertFalse(capacity.validate_capacity(result, result["capacity"]))
        json.dumps(original["capacity"])


class CapacityJobTests(unittest.TestCase):
    def setUp(self):
        test_panos_framework.PanosJobTests.setUp(self)

    def test_capacity_change_and_unresolved_counts_have_plain_logs(self):
        self.preview_plan["summary"]["capacity_fields_updated"] = 1
        self.preview_plan["capacity"] = {"unresolved": [{"reason": "raw-evidence-sentinel"}]}
        self.job.run(self.device)
        logs = "\n".join(test_discovery_job.rendered_logs(self.job.logger))
        self.assertIn("Would fill 1 empty VM capacity field", logs)
        self.assertIn("Left 1 VM capacity observations unresolved", logs)
        self.assertNotIn("raw-evidence-sentinel", logs)


if __name__ == "__main__":
    unittest.main()
