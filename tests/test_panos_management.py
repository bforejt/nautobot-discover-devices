"""Management source provenance, opt-in leases and preservation boundaries."""

import json
import unittest
from copy import deepcopy

from tests._loader import load
from tests.test_ipam_reconcile import inventory

parser = load("adapters.panos_management")
planner = load("reconcile_panos_management")
vpn_policy = load("panos_vpn_policy")

OP = (
    '<response status="success"><result><info>'
    "<name>Management Interface</name><state_c>auto</state_c><state>up</state>"
    "<hwaddr>02:00:00:00:03:01</hwaddr><ip>192.0.2.10</ip>"
    "<netmask>255.255.255.0</netmask><ip-type>dhcp-client</ip-type>"
    "<ipv6>unknown</ipv6><ip6-type>static</ip6-type></info></result></response>"
)
CONFIG = (
    '<response status="success"><result><deviceconfig><system><type><dhcp-client>'
    "<send-hostname>yes</send-hostname></dhcp-client></type>"
    "</system></deviceconfig></result></response>"
)


def facts(op=OP, config=CONFIG):
    return {
        "adapter": "panos",
        "identity": {"model": "PA-VM"},
        "management": parser.parse_management(op, config, {"model": "PA-VM"}),
    }


def existing(*, include_dhcp=False, fill_primary=False):
    result = inventory()
    result["device"] = {
        "id": "device",
        "name": "lab",
        "primary_ip4_id": None,
        "primary_ip6_id": None,
    }
    result["interfaces"] = []
    result["ipam_inventory"]["policy"]["panos_management"] = {
        "contract": "panos-management-policy-v1",
        "namespace": {"id": "public", "name": "Public"},
        "include_dhcp": include_dhcp,
        "fill_primary": fill_primary,
        "create_missing_prefixes": True,
        "location": {"id": "site", "name": "Site"},
        "location_reason": None,
    }
    return result


def plan(source=None, before=None):
    return planner.plan_panos_management(
        source or facts(),
        before or existing(),
        {"interface_creates": [], "interface_updates": []},
        identity_verified=True,
    )


class ManagementTests(unittest.TestCase):
    def test_vm_management_uses_dedicated_mac_and_positive_state_without_hypervisor(self):
        value = facts()["management"]
        self.assertEqual(value["interface"]["type"], "virtual")
        self.assertIs(value["interface"]["enabled"], True)
        self.assertEqual(value["interface"]["mac_address"], "02:00:00:00:03:01")
        self.assertEqual(value["addresses"][0]["method"], "dhcp-client")
        self.assertNotIn("KVM", json.dumps(value))

    def test_runtime_down_does_not_invent_administrative_disable(self):
        value = plan(facts(OP.replace("<state>up", "<state>down")))
        self.assertFalse(value["creates"])
        self.assertIsNone(
            facts(OP.replace("<state>up", "<state>down"))["management"]["interface"]["enabled"]
        )

    def test_explicit_admin_down_can_create_disabled_management_inventory(self):
        value = plan(
            facts(OP.replace("<state_c>auto", "<state_c>down").replace("<state>up", "<state>down"))
        )
        self.assertIs(value["creates"][0]["enabled"], False)

    def test_lease_stays_observed_without_explicit_opt_in(self):
        value = plan()
        self.assertEqual(len(value["creates"]), 1)
        self.assertIsNone(value["ipam"])
        self.assertTrue(value["unresolved"])

    def test_lease_opt_in_creates_dhcp_type_with_exact_mask_and_defers_primary(self):
        source, before = facts(), existing(include_dhcp=True, fill_primary=True)
        untouched = deepcopy((source, before))
        value = plan(source, before)
        self.assertFalse(value["errors"])
        self.assertFalse(value["ipam"]["errors"])
        self.assertEqual(value["ipam"]["ip_addresses"][0]["type"], "dhcp")
        self.assertEqual(value["ipam"]["ip_addresses"][0]["address"], "192.0.2.10/24")
        self.assertFalse(value["primary_updates"])
        self.assertEqual((source, before), untouched)

    def test_static_address_requires_applied_corroboration(self):
        op = OP.replace("dhcp-client", "static")
        self.assertFalse(facts(op)["management"]["addresses"])
        config = CONFIG.replace(
            "<type><dhcp-client><send-hostname>yes</send-hostname></dhcp-client></type>",
            "<ip-address>192.0.2.10</ip-address><netmask>255.255.255.0</netmask>",
        )
        value = plan(facts(op, config))
        self.assertEqual(value["ipam"]["ip_addresses"][0]["type"], "host")

    def test_populated_fields_including_false_are_preserved(self):
        before = existing()
        before["interfaces"] = [
            {
                "id": "mgmt",
                "name": "Management Interface",
                "type": "other",
                "enabled": False,
                "mac_address": "02:00:00:00:04:01",
                "mgmt_only": False,
                "mtu": 0,
            }
        ]
        value = plan(before=before)
        changes = value["updates"][0]["changes"]
        self.assertEqual([v["field"] for v in changes], ["mgmt_only"])
        self.assertTrue(value["conflicts"])

    def test_no_guest_type_for_unreviewed_physical_model_without_template(self):
        source = facts()
        source["identity"]["model"] = "PA-440"
        source["management"] = parser.parse_management(OP, CONFIG, {"model": "PA-440"})
        self.assertFalse(plan(source)["creates"])

    def test_secrets_in_deviceconfig_are_never_copied(self):
        value = facts(
            config=CONFIG.replace(
                "</system>", "<secret-password>sentinel-secret</secret-password></system>"
            )
        )
        self.assertNotIn("sentinel-secret", json.dumps(value))

    def test_bad_xml_duplicate_and_nested_scalars_fail(self):
        for op in (
            OP.replace('status="success"', 'status="error"'),
            OP.replace("</name>", "</name><name>other</name>"),
            OP.replace("<ip>192.0.2.10</ip>", "<ip><value>192.0.2.10</value></ip>"),
        ):
            with self.subTest(op=op), self.assertRaises(parser.DiscoveryError):
                facts(op)

    def test_tampered_management_provenance_blocks_plan(self):
        for field, value in (
            ("enabled", False),
            ("type", "1000base-t"),
            ("mac_address", "02:00:00:00:05:01"),
            ("mtu", 9000),
        ):
            source = facts()
            source["management"]["interface"][field] = value
            self.assertTrue(plan(source)["errors"])

    def test_policy_normalizers_reject_duplicate_and_unknown_fields(self):
        def resolve(kind, name, *args):
            return {"id": "existing", "name": name}

        for text in (
            '{"namespace":"A","namespace":"B"}',
            '{"namespace":"A","include_dhcp":1}',
            '{"namespace":"A","unknown":true}',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parser.normalize_management_policy(text, resolve)
        mapped = vpn_policy.normalize_panos_vpn_policy(
            '[{"tunnel":"t","vpn_name":"v","tunnel_name":"native-t","profile_name":"p","local_namespace":"A"}]',
            resolve,
        )
        self.assertEqual(mapped["tunnels"][0]["local_namespace"]["id"], "existing")


if __name__ == "__main__":
    unittest.main()
