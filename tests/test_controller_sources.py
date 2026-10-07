"""Controller association failures occur before transport and secret lookup."""

import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from tests._loader import load

sources = load("controller_sources")
is_wireless_ap = sources.is_wireless_ap
resolve_controller_source = sources.resolve_controller_source
InventoryError = sources.InventoryError


def device(model="C9800-L-C-K9", *, name="wlc.remote.example", serial="WLC123"):
    return NS(
        pk="controller-device",
        name=name,
        serial=serial,
        primary_ip=None,
        device_type=NS(model=model, manufacturer=NS(name="Cisco Systems")),
        platform=NS(name="Cisco IOS XE"),
        platform_id="iosxe",
        role=NS(name="Controller"),
        secrets_group=NS(pk="controller-secrets"),
        secrets_group_id="controller-secrets",
        controller_managed_device_group=None,
    )


def controller(endpoint=None, *, integration=None, redundancy=None):
    return NS(
        pk="controller",
        controller_device=endpoint,
        controller_device_id=endpoint.pk if endpoint else None,
        controller_device_redundancy_group_id=redundancy,
        external_integration=integration,
        external_integration_id=integration.pk if integration else None,
    )


class Manager:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def filter(self, **kwargs):
        self.calls.append(kwargs)
        return [row for row in self.rows if row.controller_device is kwargs["controller_device"]]

    def get(self, pk):
        matches = [row for row in self.rows if row.pk == pk]
        if len(matches) != 1:
            raise LookupError
        return matches[0]


def models(rows):
    manager = Manager(rows)
    model = NS(
        objects=manager,
        DoesNotExist=LookupError,
        _meta=NS(
            get_fields=lambda: [
                NS(name=name)
                for name in (
                    "controller_device",
                    "controller_device_redundancy_group",
                    "external_integration",
                )
            ]
        ),
    )
    return model, NS(), NS()


class ControllerSourceTests(unittest.TestCase):
    def test_unrelated_fake_device_needs_no_native_import(self):
        unrelated = device("C9300-48P")
        with patch.object(sources, "_models", side_effect=AssertionError("native lookup")):
            self.assertIsNone(resolve_controller_source(unrelated))

    def test_reviewed_ap_families(self):
        for model in ("AIR-AP3802I-B-K9", "AIR-CAP3702I-E-K9", "C9130AXI-B"):
            self.assertTrue(is_wireless_ap(device(model)), model)
        self.assertFalse(is_wireless_ap(device("C9300-48P")))

    def test_unrelated_managed_sources_preserve_platform_dispatch(self):
        for manufacturer, model in (
            ("Palo Alto Networks", "PA-440"),
            ("Cisco Systems", "C9300-48P"),
        ):
            unrelated = device(model)
            unrelated.device_type.manufacturer.name = manufacturer
            unrelated.controller_managed_device_group = NS(controller=controller(device("OTHER")))
            with patch.object(sources, "_models", side_effect=AssertionError("native lookup")):
                self.assertIsNone(resolve_controller_source(unrelated))

    def test_missing_group_fails_before_secrets(self):
        ap = device("C9130AXI-B", name="seed-ap", serial="AP123")
        with patch.object(sources, "_models", return_value=models([])):
            with self.assertRaisesRegex(InventoryError, "seed-ap.*controller_managed_device_group"):
                resolve_controller_source(ap)

    def test_ap_seed_uses_remote_controller_own_credentials(self):
        endpoint = device()
        wlc = controller(endpoint)
        ap = device("C9130AXI-B", name="local-ap", serial="AP123")
        ap.controller_managed_device_group = NS(pk="group", controller=wlc, controller_id=wlc.pk)
        with patch.object(sources, "_models", return_value=models([wlc])):
            source = resolve_controller_source(ap)
        self.assertIs(source["credential_device"], endpoint)
        self.assertIs(source["secrets_group"], endpoint.secrets_group)
        self.assertEqual(source["host"], "wlc.remote.example")
        self.assertTrue(source["full_controller_roster"])
        self.assertEqual(source["source_policy"]["expected_serial"], "WLC123")
        self.assertEqual(source["source_snapshot"]["seed_group_id"], "group")

    def test_controller_ambiguity_never_selects_first(self):
        endpoint = device()
        a, b = controller(endpoint), controller(endpoint)
        b.pk = "second"
        with patch.object(sources, "_models", return_value=models([a, b])):
            with self.assertRaisesRegex(InventoryError, "multiple native Controllers"):
                resolve_controller_source(endpoint)
            self.assertEqual(
                resolve_controller_source(endpoint, controller_id="second")["controller_id"],
                "second",
            )

    def test_native_9800_group_routes_unknown_cisco_ap_without_model_catalog(self):
        endpoint = device()
        wlc = controller(endpoint)
        ap = device("CW9166I-B", name="unlisted-ap", serial="APUNKNOWN")
        ap.controller_managed_device_group = NS(pk="group", controller=wlc, controller_id=wlc.pk)
        with patch.object(sources, "_models", return_value=models([wlc])):
            source = resolve_controller_source(ap)
        self.assertIs(source["credential_device"], endpoint)
        self.assertEqual(source["source_snapshot"]["seed_kind"], "ap")

    def test_unknown_cisco_ap_logical_wireless_group_stops_without_binding(self):
        integration = NS(pk="integration", remote_url="https://wlc.example", secrets_group=None)
        wlc = controller(integration=integration)
        wlc.capabilities = ["wireless"]
        ap = device("CW9166I-B", name="unlisted-ap")
        ap.controller_managed_device_group = NS(pk="group", controller=wlc, controller_id=wlc.pk)
        with patch.object(sources, "_models", return_value=models([wlc])):
            with self.assertRaisesRegex(InventoryError, "expected_hostname"):
                resolve_controller_source(ap)

    def test_unconfigured_controller_fails(self):
        with patch.object(sources, "_models", return_value=models([])):
            with self.assertRaisesRegex(InventoryError, "native Controller linked"):
                resolve_controller_source(device())

    def test_physical_controller_alias_does_not_become_hostname_proof(self):
        endpoint = device(name="operator-controller-alias")
        wlc = controller(endpoint)
        with patch.object(sources, "_models", return_value=models([wlc])):
            proof = resolve_controller_source(endpoint)["source_policy"]
            self.assertEqual(proof["expected_serial"], endpoint.serial)
            self.assertEqual(proof["expected_model"], endpoint.device_type.model)
            self.assertNotIn("expected_hostname", proof)
            explicit = resolve_controller_source(
                endpoint, source_policy={"expected_hostname": "reported-controller"}
            )
            self.assertEqual(explicit["source_policy"]["expected_hostname"], "reported-controller")

    def test_controller_device_uses_own_source_despite_managing_group(self):
        endpoint = device()
        own = controller(endpoint)
        upstream = controller(device(name="upstream.example"))
        upstream.pk = "upstream"
        endpoint.controller_managed_device_group = NS(
            pk="upstream-group", controller=upstream, controller_id=upstream.pk
        )
        with patch.object(sources, "_models", return_value=models([own, upstream])):
            source = resolve_controller_source(endpoint)
            self.assertEqual(source["controller_id"], own.pk)
            self.assertFalse(source["source_snapshot"]["seed_is_ap"])
            self.assertEqual(
                resolve_controller_source(endpoint, controller_id=own.pk)["controller_id"], own.pk
            )
            with self.assertRaisesRegex(InventoryError, "not bound"):
                resolve_controller_source(endpoint, controller_id=upstream.pk)

    def test_cl_uses_explicit_logical_hostname_not_serial(self):
        endpoint = device("C9800-CL-K9", serial="")
        wlc = controller(endpoint)
        with patch.object(sources, "_models", return_value=models([wlc])):
            with self.assertRaisesRegex(InventoryError, "expected_hostname"):
                resolve_controller_source(endpoint)
            source = resolve_controller_source(
                endpoint, source_policy='{"expected_hostname":"logical-wlc"}'
            )
        self.assertEqual(source["source_policy"]["kind"], "logical")
        self.assertNotIn("expected_serial", source["source_policy"])

    def test_external_integration_is_authority_only_and_has_own_secrets(self):
        integration = NS(
            pk="integration",
            remote_url="https://remote.example:8443",
            secrets_group=NS(pk="remote-secrets"),
            secrets_group_id="remote-secrets",
        )
        wlc = controller(integration=integration)
        with patch.object(sources, "_models", return_value=models([wlc])):
            source = resolve_controller_source(
                controller_id="controller", source_policy={"expected_hostname": "logical-wlc"}
            )
            self.assertEqual((source["host"], source["port"]), ("remote.example", 8443))
            self.assertIs(source["credential_device"], integration)
            for url in (
                "http://remote.example",
                "https://user:pass@remote.example",
                "https://remote.example/restconf",
                "https://remote.example?token=x",
            ):
                integration.remote_url = url
                with self.assertRaisesRegex(InventoryError, "HTTPS authority-only"):
                    resolve_controller_source(
                        controller_id="controller",
                        source_policy={"expected_hostname": "logical-wlc"},
                    )

    def test_ha_does_not_sort_members(self):
        wlc = controller(redundancy="ha-group")
        with patch.object(sources, "_models", return_value=models([wlc])):
            with self.assertRaisesRegex(InventoryError, "active endpoint"):
                resolve_controller_source(controller_id="controller")

    def test_invalid_policy_rejected(self):
        for value in ("{", [], {"guess": True}, {"expected_hostname": "invalid name"}):
            with self.assertRaises(InventoryError):
                resolve_controller_source(device(), source_policy=value)


if __name__ == "__main__":
    unittest.main()
