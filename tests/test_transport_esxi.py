"""SOAP boundary tests with synthetic replies and no live credentials or network."""

import json
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch
from xml.sax.saxutils import escape

import requests

from tests._loader import load

transport = load("transport_esxi")
SECRET = "fixture-password-&-secret"
SESSION = "fixture-session-key-secret"
CURSOR = "fixture-pagination-token-secret"


def reply(method, inner="", status=200):
    body = (
        f'<s:Envelope xmlns:s="{transport.SOAP}" xmlns="{transport.VIM}" '
        f'xmlns:xsi="{transport.XSI}"><s:Body><{method}Response>{inner}'
        f"</{method}Response></s:Body></s:Envelope>"
    ).encode()
    return raw_reply(body, status)


def raw_reply(body, status=200):
    response = Mock()
    response.status_code = status
    response.iter_content.return_value = [body]
    return response


def service(api_type="HostAgent", product="embeddedEsx", root_type="Folder", root="ha-root"):
    return reply(
        "RetrieveServiceContent",
        f'''<returnval>
        <rootFolder type="{root_type}">{root}</rootFolder>
        <sessionManager type="SessionManager">ha-session</sessionManager>
        <propertyCollector type="PropertyCollector">ha-collector</propertyCollector>
        <about><apiType>{api_type}</apiType><apiVersion>8.0.3.0</apiVersion>
        <productLineId>{product}</productLineId><vendor>VMware</vendor><version>8.0.3</version>
        <build>24674464</build><password>response-secret</password></about></returnval>''',
    )


def prop(name, value):
    return f"<propSet><name>{name}</name><val>{value}</val></propSet>"


def host_object(reference="ha-host", extra="", omit=None):
    properties = {
        "name": "esxi104.lab",
        "hardware.systemInfo": "<vendor>QEMU</vendor><model>Standard PC</model>"
        "<uuid>00000000-0000-0000-0000-000000000104</uuid>"
        "<otherIdentifyingInfo><identifierType><key>ServiceTag</key>"
        "</identifierType><identifierValue>example-serial</identifierValue>"
        "</otherIdentifyingInfo>",
        "hardware.cpuInfo": "<numCpuPackages>1</numCpuPackages><numCpuCores>2</numCpuCores>"
        "<numCpuThreads>2</numCpuThreads><hz>3000000000</hz>",
        "summary": "<hardware><vendor>QEMU</vendor><model>Standard PC</model>"
        "<memorySize>8589934592</memorySize><numCpuCores>2</numCpuCores></hardware>"
        "<runtime><inMaintenanceMode>false</inMaintenanceMode></runtime>"
        "<password>response-secret</password>",
        "config.product": "<apiType>HostAgent</apiType><productLineId>embeddedEsx</productLineId>"
        "<apiVersion>8.0.3.0</apiVersion><vendor>VMware</vendor>"
        "<version>8.0.3</version><build>24674464</build>",
    }
    if omit is not None:
        del properties[omit]
    values = "".join(prop(name, value) for name, value in properties.items())
    return f'<objects><obj type="HostSystem">{reference}</obj>{values}{extra}</objects>'


def inventory(objects="", token=None, continuation=False):
    token_xml = f"<token>{token}</token>" if token else ""
    method = "ContinueRetrievePropertiesEx" if continuation else "RetrievePropertiesEx"
    return reply(method, f"<returnval>{objects}{token_xml}</returnval>")


def guest_object(reference="ha-vm-1", owner="ha-host", extra=""):
    properties = {
        "name": "nfv-router",
        "config.uuid": "00000000-0000-0000-0000-000000000201",
        "config.template": "false",
        "config.hardware.numCPU": "2",
        "config.hardware.memoryMB": "1024",
        "runtime.powerState": "poweredOff",
        "runtime.connectionState": "connected",
        "runtime.host": f'<x type="HostSystem">{owner}</x>',
    }
    values = "".join(
        prop(name, value) for name, value in properties.items() if name != "runtime.host"
    )
    values += f'<propSet><name>runtime.host</name><val type="HostSystem">{owner}</val></propSet>'
    return f'<objects><obj type="VirtualMachine">{reference}</obj>{values}{extra}</objects>'


def datastore_object(reference="ha-ds-1"):
    return (
        f'<objects><obj type="Datastore">{reference}</obj>'
        + prop("name", "datastore1")
        + prop(
            "summary",
            "<name>datastore1</name><type>VMFS</type><capacity>10737418240</capacity>"
            "<freeSpace>0</freeSpace><accessible>true</accessible>",
        )
        + "</objects>"
    )


def login():
    return reply("Login", f"<returnval><key>{SESSION}</key></returnval>")


def logout():
    return reply("Logout")


def fault():
    return raw_reply(
        (
            f'<s:Envelope xmlns:s="{transport.SOAP}"><s:Body><s:Fault>'
            f"<faultstring>{escape(SECRET)} raw body {SESSION}</faultstring>"
            "</s:Fault></s:Body></s:Envelope>"
        ).encode(),
        500,
    )


class EsxiTransportTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        session_patch = patch.object(transport.requests, "Session", return_value=self.session)
        session_patch.start()
        self.addCleanup(session_patch.stop)

    def client(self, **options):
        return transport.EsxiClient("192.0.2.104", "fixture-user", SECRET, **options)

    def queued(self, *responses):
        self.session.post.side_effect = list(responses)

    def methods(self):
        return [
            ET.fromstring(call.kwargs["data"])[0][0].tag.rsplit("}", 1)[1]
            for call in self.session.post.call_args_list
        ]

    def prime(self, client):
        client._logged_in = True
        client._root, client._collector, client._session_manager = "ha-root", "ha-pc", "ha-sm"
        client._references.update(
            {
                "Folder": {"ha-root"},
                "PropertyCollector": {"ha-pc"},
                "SessionManager": {"ha-sm"},
                "VirtualMachine": {"ha-vm-1"},
            }
        )

    def test_host_only_success_preserves_unknown_arrays_and_sanitizes(self):
        self.queued(service(), login(), inventory(host_object()), logout())
        client = self.client()
        result = client.discovery()
        self.assertEqual(result["host"]["ref"], "ha-host")
        self.assertEqual(result["host"]["properties"]["hardware.cpuInfo"]["numCpuCores"], 2)
        self.assertFalse(result["host"]["properties"]["summary"]["runtime"]["inMaintenanceMode"])
        self.assertNotIn("config.network.pnic", result["host"]["properties"])
        self.assertEqual(
            result["completeness"],
            {"host": True, "guests": "permission-scoped", "datastores": "permission-scoped"},
        )
        self.assertEqual(
            self.methods(), ["RetrieveServiceContent", "Login", "RetrievePropertiesEx", "Logout"]
        )
        self.session.close.assert_called_once()
        client.close()
        self.session.close.assert_called_once()
        for secret in (SECRET, SESSION, "response-secret", "fixture-user"):
            self.assertNotIn(secret, json.dumps(result))
            self.assertNotIn(secret, json.dumps(client.trace))
        for call in self.session.post.call_args_list:
            self.assertTrue(call.kwargs["verify"])
            self.assertFalse(call.kwargs["allow_redirects"])
            self.assertTrue(call.kwargs["stream"])
            self.assertEqual(call.kwargs["timeout"], (10, 30))
        self.assertFalse(self.session.trust_env)
        self.assertIsNone(client._password)
        self.session.get.assert_not_called()
        self.session.put.assert_not_called()
        self.session.delete.assert_not_called()

    def test_scoped_guests_datastores_and_only_nic_disk_device_data(self):
        references = prop(
            "vm", '<ManagedObjectReference type="VirtualMachine">ha-vm-1</ManagedObjectReference>'
        )
        references += prop(
            "datastore", '<ManagedObjectReference type="Datastore">ha-ds-1</ManagedObjectReference>'
        )
        devices = prop(
            "config.hardware.device",
            """
            <VirtualDevice xsi:type="VirtualVmxnet3">
            <key>4000</key><macAddress>00:11:22:33:44:55</macAddress>
            <connectable><connected>false</connected></connectable><password>device-secret</password></VirtualDevice>
            <VirtualDevice xsi:type="VirtualDisk">
            <key>2000</key><capacityInKB>1024</capacityInKB></VirtualDevice>
            <VirtualDevice xsi:type="VirtualSerialPort">
            <key>9000</key><userData>device-secret</userData></VirtualDevice>""",
        )
        self.queued(
            service(),
            login(),
            inventory(host_object(extra=references)),
            inventory(guest_object(extra=devices)),
            inventory(datastore_object()),
            logout(),
        )
        client = self.client()
        result = client.discovery()
        self.assertEqual(result["guests"][0]["properties"]["config.hardware.memoryMB"], 1024)
        observed = result["guests"][0]["properties"]["config.hardware.device"]
        self.assertEqual([item["type"] for item in observed], ["VirtualVmxnet3", "VirtualDisk"])
        self.assertFalse(observed[0]["connectable"]["connected"])
        self.assertEqual(result["datastores"][0]["properties"]["summary"]["freeSpace"], 0)
        self.assertNotIn("device-secret", json.dumps(result))
        wire = b"".join(call.kwargs["data"] for call in self.session.post.call_args_list)
        for forbidden in (b"config.extraConfig", b"customValue", b"userData", b"ReconfigVM"):
            self.assertNotIn(forbidden, wire)
        self.assertEqual(self.methods().count("RetrievePropertiesEx"), 3)

    def test_explicit_empty_array_is_preserved(self):
        self.queued(
            service(),
            login(),
            inventory(host_object(extra=prop("config.network.pnic", ""))),
            logout(),
        )
        result = self.client().discovery()
        self.assertEqual(result["host"]["properties"]["config.network.pnic"], [])

    def test_pnic_repeated_link_specifications_decode_without_invented_values(self):
        nics = prop(
            "config.network.pnic",
            """<PhysicalNic><device>vmnic0</device><driver>nvmxnet3</driver>
            <validLinkSpecification><speedMb>1000</speedMb><duplex>true</duplex></validLinkSpecification>
            <validLinkSpecification><speedMb>10000</speedMb><duplex>true</duplex></validLinkSpecification>
            </PhysicalNic>""",
        )
        self.queued(service(), login(), inventory(host_object(extra=nics)), logout())
        nic = self.client().discovery()["host"]["properties"]["config.network.pnic"][0]
        self.assertEqual([row["speedMb"] for row in nic["validLinkSpecification"]], [1000, 10000])
        self.assertNotIn("linkSpeed", nic)

    def test_malformed_array_text_and_nil_registered_reference_fail(self):
        cases = (
            prop("config.network.pnic", "not-an-array"),
            prop("vm", '<ManagedObjectReference xsi:nil="true"/>'),
            '<propSet><name>vm</name><val xsi:nil="true"/></propSet>',
        )
        for added in cases:
            with self.subTest(added=added):
                self.session.reset_mock()
                self.queued(service(), login(), inventory(host_object(extra=added)), logout())
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()
                self.assertEqual(self.methods()[-1], "Logout")

    def test_reviewed_network_policy_and_management_selection_are_retained(self):
        policies = prop(
            "config.network.vswitch",
            """
            <HostVirtualSwitch><name>vSwitch0</name><spec><policy>
            <security><allowPromiscuous>false</allowPromiscuous></security>
            <nicTeaming><nicOrder><activeNic>vmnic0</activeNic></nicOrder></nicTeaming>
            </policy></spec></HostVirtualSwitch>""",
        )
        policies += prop(
            "config.virtualNicManagerInfo",
            """
            <netConfig><nicType>management</nicType><selectedVnic>key-vmk0</selectedVnic>
            </netConfig>""",
        )
        self.queued(service(), login(), inventory(host_object(extra=policies)), logout())
        properties = self.client().discovery()["host"]["properties"]
        policy = properties["config.network.vswitch"][0]["spec"]["policy"]
        self.assertFalse(policy["security"]["allowPromiscuous"])
        self.assertEqual(policy["nicTeaming"]["nicOrder"]["activeNic"], ["vmnic0"])
        selection = properties["config.virtualNicManagerInfo"]["netConfig"][0]
        self.assertEqual(selection["selectedVnic"], ["key-vmk0"])

    def test_vcenter_is_rejected_before_login(self):
        self.queued(service("VirtualCenter", "vpx"))
        with self.assertRaisesRegex(transport.EsxiError, "standalone"):
            self.client().discovery()
        self.assertEqual(self.methods(), ["RetrieveServiceContent"])
        self.session.close.assert_called_once()

    def test_foreign_or_malformed_service_reference_is_rejected(self):
        for root_type, root in (("VirtualMachine", "ha-root"), ("Folder", "../../secret")):
            with self.subTest(root_type=root_type, root=root):
                self.session.reset_mock()
                self.queued(service(root_type=root_type, root=root))
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()
                self.assertEqual(self.methods(), ["RetrieveServiceContent"])

    def test_multiple_hostsystems_and_duplicate_host_ref_fail(self):
        for rows in (host_object() + host_object("ha-other"), host_object() + host_object(), ""):
            with self.subTest(rows=rows[:25]):
                self.session.reset_mock()
                self.queued(service(), login(), inventory(rows), logout())
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()
                self.assertEqual(self.methods()[-1], "Logout")

    def test_missing_core_property_and_missing_set_fail_closed(self):
        cases = (
            host_object(omit="hardware.systemInfo"),
            host_object(extra="<missingSet><path>config.network.pnic</path></missingSet>"),
        )
        for rows in cases:
            with self.subTest(rows=rows[-35:]):
                self.session.reset_mock()
                self.queued(service(), login(), inventory(rows), logout())
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()
                self.assertEqual(self.methods()[-1], "Logout")

    def test_unreviewed_duplicate_and_malformed_property_fail(self):
        for added in (
            prop("config.extraConfig", "secret"),
            prop("name", "duplicate"),
            prop(
                "config.network.pnic",
                "<PhysicalNic><linkSpeed><speedMb>nan</speedMb></linkSpeed></PhysicalNic>",
            ),
        ):
            with self.subTest(added=added[:50]):
                self.session.reset_mock()
                self.queued(service(), login(), inventory(host_object(extra=added)), logout())
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()

    def test_foreign_guest_return_and_foreign_owner_fail(self):
        references = prop(
            "vm", '<ManagedObjectReference type="VirtualMachine">ha-vm-1</ManagedObjectReference>'
        )
        for guest in (guest_object("ha-vm-other"), guest_object(owner="ha-other")):
            with self.subTest(guest=guest[:70]):
                self.session.reset_mock()
                self.queued(
                    service(),
                    login(),
                    inventory(host_object(extra=references)),
                    inventory(guest),
                    logout(),
                )
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()
                self.assertEqual(self.methods()[-1], "Logout")

    def test_duplicate_host_inventory_references_fail_before_guest_fetch(self):
        reference = '<ManagedObjectReference type="VirtualMachine">ha-vm-1</ManagedObjectReference>'
        self.queued(
            service(), login(), inventory(host_object(extra=prop("vm", reference * 2))), logout()
        )
        with self.assertRaisesRegex(transport.EsxiError, "Duplicate"):
            self.client().discovery()
        self.assertEqual(self.methods().count("RetrievePropertiesEx"), 1)

    def test_missing_scoped_object_fails(self):
        references = prop(
            "datastore", '<ManagedObjectReference type="Datastore">ha-ds-1</ManagedObjectReference>'
        )
        self.queued(
            service(), login(), inventory(host_object(extra=references)), inventory(), logout()
        )
        with self.assertRaisesRegex(transport.EsxiError, "coverage"):
            self.client().discovery()

    def test_pagination_is_bounded_and_tokens_are_not_traced(self):
        self.queued(
            service(),
            login(),
            inventory(token=CURSOR),
            inventory(host_object(), continuation=True),
            logout(),
        )
        client = self.client()
        client.discovery()
        self.assertEqual(self.methods()[3], "ContinueRetrievePropertiesEx")
        self.assertNotIn(CURSOR, json.dumps(client.trace))

    def test_repeated_token_page_limit_and_duplicate_page_object_fail(self):
        for first, second, options in (
            (inventory(token=CURSOR), inventory(token=CURSOR, continuation=True), {}),
            (inventory(token=CURSOR), None, {"max_pages": 1}),
            (inventory(host_object(), CURSOR), inventory(host_object(), continuation=True), {}),
        ):
            with self.subTest(options=options):
                self.session.reset_mock()
                responses = [service(), login(), first] + ([second] if second else []) + [logout()]
                self.queued(*responses)
                with self.assertRaises(transport.EsxiError):
                    self.client(**options).discovery()
                self.assertEqual(self.methods()[-1], "Logout")

    def test_request_and_object_budgets_still_allow_logout(self):
        references = prop(
            "vm", '<ManagedObjectReference type="VirtualMachine">ha-vm-1</ManagedObjectReference>'
        )
        for options in ({"max_requests": 4}, {"max_objects": 1}):
            with self.subTest(options=options):
                self.session.reset_mock()
                responses = [service(), login(), inventory(host_object(extra=references))]
                if "max_objects" in options:
                    responses.append(inventory(guest_object()))
                self.queued(*responses, logout())
                with self.assertRaisesRegex(transport.EsxiError, "budget"):
                    self.client(**options).discovery()
                self.assertEqual(self.methods()[-1], "Logout")

    def test_method_type_reference_and_token_fences_precede_network(self):
        client = self.client()
        self.prime(client)
        calls = (
            ("ReconfigVM_Task", {}),
            ("CreateVM_Task", {}),
            ("RetrievePropertiesEx", {"object_type": "Folder"}),
            ("RetrievePropertiesEx", {"object_type": "VirtualMachine", "refs": ["foreign-vm"]}),
            ("RetrievePropertiesEx", {"object_type": "HostSystem", "refs": ["ha-host"]}),
            ("ContinueRetrievePropertiesEx", {"token": "unreviewed-token"}),
        )
        for method, kwargs in calls:
            with self.subTest(method=method, kwargs=kwargs), self.assertRaises(transport.EsxiError):
                client._request(method, **kwargs)
        with self.assertRaises(TypeError):
            client._request(
                "RetrievePropertiesEx", object_type="HostSystem", paths=["config.extraConfig"]
            )
        self.session.post.assert_not_called()

    def test_unsafe_xml_redirect_method_namespace_and_malformed_body_fail(self):
        cases = (
            raw_reply(b'<!DOCTYPE x [<!ENTITY s "secret">]><x/>'),
            raw_reply(b"<x>\x00</x>"),
            raw_reply(b"<broken"),
            raw_reply(b"ignored", 302),
            reply("Logout"),
            raw_reply(b"<Envelope><Body/></Envelope>"),
            raw_reply(
                (f'<s:Envelope xmlns:s="{transport.SOAP}"><s:Body/><s:Body/></s:Envelope>').encode()
            ),
        )
        for response in cases:
            with self.subTest(response=response):
                self.session.reset_mock()
                self.queued(response)
                with self.assertRaises(transport.EsxiError):
                    self.client().discovery()
                self.assertEqual(self.session.post.call_count, 1)
                response.close.assert_called_once()
                self.session.close.assert_called_once()

    def test_stream_bytes_node_count_and_depth_have_limits(self):
        oversized = raw_reply(b"x" * 1024)
        with patch.object(transport, "MAX_XML_BYTES", 512):
            self.queued(oversized)
            with self.assertRaisesRegex(transport.EsxiError, "size limit"):
                self.client().discovery()
        self.session.reset_mock()
        with patch.object(transport, "MAX_XML_NODES", 2):
            self.queued(service())
            with self.assertRaisesRegex(transport.EsxiError, "structure"):
                self.client().discovery()
        self.session.reset_mock()
        self.queued(reply("RetrieveServiceContent", "<x>" * 70 + "</x>" * 70))
        with self.assertRaisesRegex(transport.EsxiError, "structure"):
            self.client().discovery()

    def test_fault_connection_and_tls_errors_are_sanitized_without_retry(self):
        for outcome in (
            fault(),
            requests.RequestException(SECRET),
            requests.exceptions.SSLError(SECRET),
        ):
            with self.subTest(outcome=type(outcome).__name__):
                self.session.reset_mock()
                self.queued(outcome)
                client = self.client()
                with self.assertRaises(transport.EsxiError) as raised:
                    client.discovery()
                self.assertNotIn(SECRET, str(raised.exception))
                self.assertNotIn(SESSION, str(raised.exception))
                self.assertNotIn(SECRET, json.dumps(client.trace))
                self.assertEqual(self.session.post.call_count, 1)
                self.session.mount.assert_not_called()

    def test_login_fault_closes_session_without_logout(self):
        self.queued(service(), fault())
        with self.assertRaises(transport.EsxiError):
            self.client().discovery()
        self.assertEqual(self.methods(), ["RetrieveServiceContent", "Login"])
        self.session.close.assert_called_once()

    def test_cancellation_survives_cleanup_fault_and_session_closes(self):
        self.queued(service(), login(), KeyboardInterrupt(), fault())
        with self.assertRaises(KeyboardInterrupt):
            self.client().discovery()
        self.assertEqual(self.methods()[-1], "Logout")
        self.session.close.assert_called_once()

    def test_logout_failure_cannot_claim_success(self):
        self.queued(service(), login(), inventory(host_object()), fault())
        with self.assertRaisesRegex(transport.EsxiError, "Logout"):
            self.client().discovery()
        self.session.close.assert_called_once()

    def test_invalid_connection_arguments_and_limits_do_not_connect(self):
        for host in ("https://192.0.2.104", "user@host", "host/path", "host?secret", "host\\path"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                transport.EsxiClient(host, "user", "password")
        for options in (
            {"verify": 1},
            {"port": True},
            {"timeout": float("nan")},
            {"timeout": 0},
            {"max_requests": 3},
            {"max_pages": True},
            {"max_objects": 0},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.client(**options)
        self.session.post.assert_not_called()

    def test_ipv6_and_explicit_unverified_lab_connection(self):
        self.queued(service(), login(), inventory(host_object()), logout())
        client = transport.EsxiClient(
            "2001:db8::104", "fixture-user", SECRET, verify=False, port=8443
        )
        client.discovery()
        for call in self.session.post.call_args_list:
            self.assertEqual(call.args[0], "https://[2001:db8::104]:8443/sdk")
            self.assertFalse(call.kwargs["verify"])


if __name__ == "__main__":
    unittest.main()
