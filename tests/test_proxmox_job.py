"""Proxmox Job dispatch, credential separation and lifecycle regressions."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.test_discovery_job import load_discovery_job, plan
from tests.test_proxmox import HOST_UUID, NODE, Client


class ProxmoxJobTests(unittest.TestCase):
    def setUp(self):
        self.module = load_discovery_job()
        self.device = SimpleNamespace(
            pk="00000001-0000-4000-8000-000000000002",
            name="operator-host-name",
            primary_ip=SimpleNamespace(host="192.0.2.10"),
            platform=SimpleNamespace(network_driver="proxmox", name="Proxmox VE"),
            device_type=SimpleNamespace(manufacturer=SimpleNamespace(name="Lenovo")),
        )
        self.module.Device.objects.get.return_value = self.device
        self.job = self.module.DiscoverDevice()
        self.job.request = SimpleNamespace(meta={})
        self.job.logger = Mock()
        self.job.create_file = Mock()
        self.client = Client()
        self.client.trace = [{"transport": "https", "path": "/version"}]
        self.client.close = Mock()
        patches = {
            "resolve_credentials": Mock(
                side_effect=[("api@pve!reader", "token"), ("linux", "ssh")]
            ),
            "ProxmoxClient": Mock(return_value=self.client),
            "build_plan": Mock(return_value=plan()),
        }
        for name, replacement in patches.items():
            patcher = patch.object(self.module, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.module.snapshot_inventory.return_value = {"device": {"id": self.device.pk}}
        self.module.apply_discovery.return_value = plan()

    def test_real_adapter_preview_resolves_independent_transports_and_closes(self):
        self.job.run(self.device, expected_proxmox_node=NODE, expected_proxmox_host_uuid=HOST_UUID)
        self.assertEqual(
            [call.kwargs["transport"] for call in self.module.resolve_credentials.call_args_list],
            ["proxmox", "proxmox_ssh"],
        )
        self.module.ProxmoxClient.assert_called_once_with(
            "192.0.2.10",
            "api@pve!reader",
            "token",
            "linux",
            "ssh",
            port=8006,
            ssh_port=22,
            verify=True,
            host_key_sha256=None,
        )
        self.client.close.assert_called_once()
        self.module.apply_discovery.assert_not_called()
        report = self.job.request.meta["discovery_report"]
        self.assertEqual(report["transport"], "proxmox-json-ssh")
        self.assertEqual(report["discovery"]["identity"]["software_version"], "9.2.2")
        self.assertEqual(report["discovery"]["identity_binding"]["observed_uuid"], HOST_UUID)
        self.assertEqual(report["requests"], self.client.trace)
        self.assertFalse(report["applied"])

    def test_host_key_pin_reaches_transport(self):
        self.job.run(self.device, proxmox_ssh_host_key="SHA256:public-fingerprint")
        self.assertEqual(
            self.module.ProxmoxClient.call_args.kwargs["host_key_sha256"],
            "SHA256:public-fingerprint",
        )

    def test_irrelevant_domain_policy_and_insecure_ssh_fail_before_secrets(self):
        for kwargs in (
            {"ipam_namespace": SimpleNamespace(pk="namespace")},
            {"vlan_group": SimpleNamespace(pk="vlan", name="VLANs")},
            {"module_status": SimpleNamespace(pk="status")},
            {"panos_routing_domains": "[]"},
            {"ssh_strict": False},
            {"proxmox_port": True},
            {"proxmox_port": 65536},
            {"ssh_port": "22"},
            {"expected_proxmox_host_uuid": "invalid"},
            {"expected_proxmox_node": 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.job.run(self.device, **kwargs)
        self.module.resolve_credentials.assert_not_called()

    def test_api_read_failure_is_worker_safe_and_still_closes(self):
        self.client.get = Mock(side_effect=self.module.ProxmoxError("Proxmox read failed"))
        with self.assertRaisesRegex(RuntimeError, "Proxmox read failed") as error:
            self.job.run(self.device)
        self.assertIs(type(error.exception), RuntimeError)
        self.client.close.assert_called_once()
        self.assertEqual(self.job.request.meta["discovery_report"]["requests"], self.client.trace)
        self.module.apply_discovery.assert_not_called()

    def test_apply_receives_collected_source_and_explicit_guest_policy(self):
        self.job.run(self.device, dryrun=False)
        self.module.apply_discovery.assert_called_once()
        source = self.module.apply_discovery.call_args.args[0]
        self.assertEqual(source["source"]["contract"], "proxmox-host-v1")
        self.assertIsNone(source["guest_policy"])
        self.assertTrue(self.job.request.meta["discovery_report"]["applied"])

    def test_dispatch_accepts_hardware_manufacturer_independently(self):
        for manufacturer in ("Dell", "HPE", "Lenovo", "QEMU", "Intel Corporation"):
            self.device.device_type.manufacturer.name = manufacturer
            self.assertIs(self.module._adapter(self.device), self.module.proxmox)
        self.device.platform.network_driver = ""
        self.assertIs(self.module._adapter(self.device), self.module.proxmox)


if __name__ == "__main__":
    unittest.main()
