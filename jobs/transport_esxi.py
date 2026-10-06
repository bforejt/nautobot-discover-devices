"""Fenced, read-only SOAP discovery of one standalone ESXi HTTPS endpoint."""

import ipaddress
import math
import re
import sys
import warnings
import xml.etree.ElementTree as ET

import requests
from urllib3.exceptions import InsecureRequestWarning

SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
VIM = "urn:vim25"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
ET.register_namespace("soapenv", SOAP)
ET.register_namespace("vim", VIM)
ET.register_namespace("xsi", XSI)
MAX_XML_BYTES = 4 * 1024 * 1024
MAX_XML_NODES = 65536
MAX_XML_DEPTH = 64
METHODS = frozenset(
    {
        "RetrieveServiceContent",
        "Login",
        "Logout",
        "RetrievePropertiesEx",
        "ContinueRetrievePropertiesEx",
    }
)
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_INTEGER = re.compile(r"-?[0-9]{1,20}\Z")


class EsxiError(RuntimeError):
    """Operator-safe failure without remote bodies or credential values."""


def _array(schema):
    return ("array", schema)


def _reference(*types):
    return ("reference", frozenset(types))


_PRODUCT = dict.fromkeys(
    ("apiType", "apiVersion", "productLineId", "vendor", "version", "build"), "str"
)
_LINK = {"speedMb": "int", "duplex": "bool"}
_CONNECTABLE = {"connected": "bool", "startConnected": "bool", "allowGuestControl": "bool"}
_SYSTEM = {
    "vendor": "str",
    "model": "str",
    "uuid": "str",
    "serialNumber": "str",
    "otherIdentifyingInfo": _array(
        {
            "identifierType": {"key": "str"},
            "identifierValue": "str",
        }
    ),
}
_HARDWARE = {
    "vendor": "str",
    "model": "str",
    "uuid": "str",
    "cpuModel": "str",
    "numCpuPkgs": "int",
    "numCpuCores": "int",
    "numCpuThreads": "int",
    "memorySize": "int",
    "numNics": "int",
    "numHBAs": "int",
}
_DEVICE_COMMON = {
    "key": "int",
    "controllerKey": "int",
    "unitNumber": "int",
    "deviceInfo": {"label": "str"},
    "connectable": _CONNECTABLE,
}
_NIC_DEVICE = {
    **_DEVICE_COMMON,
    "macAddress": "str",
    "addressType": "str",
    "backing": {
        "deviceName": "str",
        "network": _reference("Network", "DistributedVirtualPortgroup"),
        "port": {"switchUuid": "str", "portgroupKey": "str", "portKey": "str"},
    },
}
_DISK_DEVICE = {
    **_DEVICE_COMMON,
    "capacityInKB": "int",
    "capacityInBytes": "int",
    "backing": {
        "fileName": "str",
        "datastore": _reference("Datastore"),
        "diskMode": "str",
        "thinProvisioned": "bool",
        "eagerlyScrub": "bool",
        "uuid": "str",
    },
}
_NIC_TYPES = frozenset(
    {
        "VirtualEthernetCard",
        "VirtualVmxnet",
        "VirtualVmxnet2",
        "VirtualVmxnet3",
        "VirtualPCNet32",
        "VirtualE1000",
        "VirtualE1000e",
        "VirtualSriovEthernetCard",
        "VirtualVmxnet3Vrdma",
    }
)
HOST_SCHEMAS = {
    "name": "str",
    "hardware.systemInfo": _SYSTEM,
    "hardware.cpuInfo": {
        "numCpuPackages": "int",
        "numCpuCores": "int",
        "numCpuThreads": "int",
        "hz": "int",
    },
    "hardware.pciDevice": _array(
        {
            **dict.fromkeys(("id", "deviceName", "vendorName"), "str"),
            **dict.fromkeys(
                (
                    "vendorId",
                    "deviceId",
                    "subVendorId",
                    "subDeviceId",
                    "classId",
                    "bus",
                    "slot",
                    "function",
                ),
                "int",
            ),
        }
    ),
    "summary": {
        "hardware": _HARDWARE,
        "config": {"name": "str", "product": _PRODUCT},
        "runtime": {"connectionState": "str", "powerState": "str", "inMaintenanceMode": "bool"},
    },
    "config.product": _PRODUCT,
    "config.network.pnic": _array(
        {
            **dict.fromkeys(("device", "key", "mac", "pci", "driver"), "str"),
            "linkSpeed": _LINK,
            "validLinkSpecification": _array(_LINK),
        }
    ),
    "config.network.vnic": _array(
        {
            "device": "str",
            "key": "str",
            "portgroup": "str",
            "spec": {
                "ip": {"dhcp": "bool", "ipAddress": "str", "subnetMask": "str"},
                "mac": "str",
                "mtu": "int",
                "netStackInstanceKey": "str",
            },
        }
    ),
    "config.network.vswitch": _array(
        {
            "name": "str",
            "key": "str",
            "numPorts": "int",
            "numPortsAvailable": "int",
            "mtu": "int",
            "pnic": _array("str"),
            "portgroup": _array("str"),
        }
    ),
    "config.network.portgroup": _array(
        {
            "key": "str",
            "spec": {"name": "str", "vlanId": "int", "vswitchName": "str"},
        }
    ),
    "config.storageDevice.scsiLun": _array(
        {
            **dict.fromkeys(
                ("key", "displayName", "canonicalName", "vendor", "model", "lunType"), "str"
            ),
            "capacity": {"blockSize": "int", "block": "int"},
        }
    ),
    "config.fileSystemVolume.mountInfo": _array(
        {
            "mountInfo": {"mounted": "bool", "accessible": "bool", "accessMode": "str"},
            "volume": {"name": "str", "type": "str", "uuid": "str", "capacity": "int"},
        }
    ),
    "vm": _array(_reference("VirtualMachine")),
    "datastore": _array(_reference("Datastore")),
}
GUEST_SCHEMAS = {
    "name": "str",
    "config.uuid": "str",
    "config.instanceUuid": "str",
    "config.template": "bool",
    "config.hardware.numCPU": "int",
    "config.hardware.memoryMB": "int",
    "config.hardware.device": "devices",
    "runtime.powerState": "str",
    "runtime.connectionState": "str",
    "runtime.host": _reference("HostSystem"),
    "guest.net": _array(
        {
            "network": "str",
            "macAddress": "str",
            "connected": "bool",
            "deviceConfigId": "int",
            "ipAddress": _array("str"),
        }
    ),
}
DATASTORE_SCHEMAS = {
    "name": "str",
    "summary": {
        "name": "str",
        "type": "str",
        "capacity": "int",
        "freeSpace": "int",
        "uncommitted": "int",
        "accessible": "bool",
        "maintenanceMode": "str",
        "multipleHostAccess": "bool",
        "datastore": _reference("Datastore"),
    },
    "info": {
        "name": "str",
        "freeSpace": "int",
        "maxFileSize": "int",
        "maxVirtualDiskCapacity": "int",
        "vmfs": {
            "name": "str",
            "uuid": "str",
            "type": "str",
            "capacity": "int",
            "version": "str",
            "blockSize": "int",
            "extent": _array({"diskName": "str", "partition": "int"}),
        },
        "nas": {"name": "str", "remoteHost": "str", "remotePath": "str", "type": "str"},
    },
}
# Optional operational observations share the adapter's reviewed NFV allowlists.
_NETWORK_POLICY = {
    "security": {
        "allowPromiscuous": "bool",
        "macChanges": "bool",
        "forgedTransmits": "bool",
    },
    "nicTeaming": {
        "policy": "str",
        "notifySwitches": "bool",
        "rollingOrder": "bool",
        "nicOrder": {"activeNic": _array("str"), "standbyNic": _array("str")},
    },
}
_PORT = {"switchUuid": "str", "portgroupKey": "str", "portKey": "str"}
HOST_SCHEMAS["config.network.vswitch"][1]["spec"] = {"policy": _NETWORK_POLICY}
HOST_SCHEMAS["config.network.portgroup"][1].update(
    {
        "vswitch": "str",
        "computedPolicy": _NETWORK_POLICY,
    }
)
HOST_SCHEMAS["config.network.portgroup"][1]["spec"]["policy"] = _NETWORK_POLICY
HOST_SCHEMAS["config.network.vnic"][1]["spec"].update(
    {
        "distributedVirtualPort": _PORT,
        "pinnedPnic": "str",
    }
)
HOST_SCHEMAS["config.network.vnic"][1]["spec"]["ip"]["ipV6Config"] = {
    "autoConfigurationEnabled": "bool",
    "dhcpV6Enabled": "bool",
    "ipV6Address": _array(
        {
            "ipAddress": "str",
            "prefixLength": "int",
            "origin": "str",
            "dadState": "str",
        }
    ),
}
HOST_SCHEMAS["config.virtualNicManagerInfo"] = {
    "netConfig": _array({"nicType": "str", "selectedVnic": _array("str")}),
}
GUEST_SCHEMAS.update(
    {
        "config.guestId": "str",
        "config.version": "str",
        "config.hardware.numCoresPerSocket": "int",
        "config.cpuAllocation": {"reservation": "int", "limit": "int"},
        "config.memoryAllocation": {"reservation": "int", "limit": "int"},
        "config.memoryReservationLockedToMax": "bool",
        "config.latencySensitivity": {"level": "str"},
        "guest.toolsRunningStatus": "str",
    }
)
DATASTORE_SCHEMAS["info"]["vmfs"]["local"] = "bool"


_SCHEMAS = {
    "HostSystem": HOST_SCHEMAS,
    "VirtualMachine": GUEST_SCHEMAS,
    "Datastore": DATASTORE_SCHEMAS,
}
_REQUIRED = {
    "HostSystem": {"name", "summary", "hardware.systemInfo", "hardware.cpuInfo", "config.product"},
    "VirtualMachine": {
        "name",
        "config.uuid",
        "config.template",
        "config.hardware.numCPU",
        "config.hardware.memoryMB",
        "runtime.powerState",
        "runtime.connectionState",
        "runtime.host",
    },
    "Datastore": {"name", "summary"},
}


def _children(node, name):
    return [item for item in node if item.tag == f"{{{VIM}}}{name}"]


def _one(node, name, required=True):
    found = _children(node, name)
    if len(found) > 1 or (required and not found):
        raise EsxiError("Malformed SOAP response structure")
    return found[0] if found else None


def _text(node):
    if node is None or len(node) or len(node.text or "") > 4096:
        raise EsxiError("Malformed SOAP primitive value")
    return node.text or ""


def _mor(node, allowed):
    reference = _text(node)
    object_type = node.get("type")
    if object_type not in allowed or not _REF.fullmatch(reference):
        raise EsxiError("Unreviewed or malformed managed-object reference")
    return {"type": object_type, "ref": reference}


def _add(parent, name, text=None, **attributes):
    node = ET.SubElement(parent, f"{{{VIM}}}{name}", attributes)
    if text is not None:
        node.text = str(text)
    return node


def _host_for_url(host):
    if not isinstance(host, str) or not host:
        raise ValueError("ESXi host must be an IP address or DNS name")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        return f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ValueError("ESXi host must be an IP address or DNS name") from None
        return host


class EsxiClient:
    """One session with reviewed inventory reads and no configuration API."""

    def __init__(
        self,
        host,
        username,
        password,
        *,
        port=443,
        verify=True,
        timeout=30,
        max_requests=128,
        max_pages=32,
        max_objects=4096,
    ):
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("ESXi port must be between 1 and 65535")
        if not isinstance(verify, bool):
            raise ValueError("TLS verification must be a boolean")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 1 <= timeout <= 120
        ):
            raise ValueError("ESXi read timeout must be between 1 and 120 seconds")
        for name, limit, minimum, maximum in (
            ("max_requests", max_requests, 4, 512),
            ("max_pages", max_pages, 1, 128),
            ("max_objects", max_objects, 1, 16384),
        ):
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not minimum <= limit <= maximum
            ):
                raise ValueError(f"Invalid ESXi {name} limit")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not username
            or not password
        ):
            raise ValueError("ESXi username and password must be nonempty strings")
        self.host = host
        self.base = f"https://{_host_for_url(host)}:{port}/sdk"
        self.verify, self.timeout = verify, timeout
        self.max_requests, self.max_pages, self.max_objects = max_requests, max_pages, max_objects
        self.trace = []
        self.session = requests.Session()
        self.session.trust_env = False
        self._username, self._password = username, password
        self._requests = self._objects = 0
        self._closed = self._logged_in = False
        self._references = {"ServiceInstance": {"ServiceInstance"}}
        self._session_manager = self._collector = self._root = self._pagination_token = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self.close()
        except BaseException:
            if args[0] is None:
                raise

    def _decode(self, node, schema, depth=0):
        if depth > MAX_XML_DEPTH:
            raise EsxiError("SOAP property nesting exceeded the limit")
        if node.get(f"{{{XSI}}}nil") in {"true", "1"}:
            if len(node) or (node.text or "").strip():
                raise EsxiError("Malformed nil SOAP property")
            if schema == "devices" or (isinstance(schema, tuple) and schema[0] == "array"):
                raise EsxiError("Malformed nil SOAP array")
            return None
        if schema == "str":
            return _text(node)
        if schema == "int":
            text = _text(node)
            if not _INTEGER.fullmatch(text):
                raise EsxiError("Malformed integer SOAP property")
            return int(text)
        if schema == "bool":
            text = _text(node)
            if text not in {"true", "false", "0", "1"}:
                raise EsxiError("Malformed boolean SOAP property")
            return text in {"true", "1"}
        if schema == "devices":
            if (node.text or "").strip():
                raise EsxiError("Malformed SOAP virtual-device array")
            if len(node) > self.max_objects:
                raise EsxiError("SOAP virtual-device array exceeded the limit")
            decoded, keys = [], set()
            for item in node:
                kind = item.get(f"{{{XSI}}}type", "").split(":")[-1]
                selected = (
                    _NIC_DEVICE
                    if kind in _NIC_TYPES
                    else (_DISK_DEVICE if kind == "VirtualDisk" else None)
                )
                if selected is None:
                    continue
                device = self._decode(item, selected, depth + 1)
                if device.get("key") is None or device["key"] in keys:
                    raise EsxiError("Duplicate or missing virtual-device key")
                keys.add(device["key"])
                decoded.append({"type": kind, **device})
            return decoded
        if isinstance(schema, tuple):
            kind, nested = schema
            if kind == "reference":
                return _mor(node, nested)
            if (node.text or "").strip():
                raise EsxiError("Malformed SOAP property array")
            if len(node) > self.max_objects:
                raise EsxiError("SOAP property array exceeded the limit")
            return [self._decode(item, nested, depth + 1) for item in node]
        if not isinstance(schema, dict) or (node.text or "").strip():
            raise EsxiError("Malformed structured SOAP property")
        result = {}
        for name, nested in schema.items():
            items = _children(node, name)
            # Arrays within data objects repeat directly, without a wrapper.
            if isinstance(nested, tuple) and nested[0] == "array":
                if len(items) > self.max_objects:
                    raise EsxiError("SOAP property array exceeded the limit")
                if items:
                    result[name] = [self._decode(item, nested[1], depth + 1) for item in items]
                continue
            if len(items) > 1:
                raise EsxiError("Duplicate structured SOAP property field")
            if items:
                result[name] = self._decode(items[0], nested, depth + 1)
        return result

    def _request(self, method, *, object_type=None, refs=(), token=None):
        if method not in METHODS:
            raise EsxiError("Unreviewed SOAP method")
        if self._closed:
            raise EsxiError("ESXi session is closed")
        ceiling = self.max_requests if method == "Logout" else self.max_requests - 1
        if self._requests >= ceiling:
            raise EsxiError("ESXi request budget exceeded")
        if method in {"RetrievePropertiesEx", "ContinueRetrievePropertiesEx", "Logout"}:
            if not self._logged_in:
                raise EsxiError("Authenticated ESXi session required")
        request = ET.Element(f"{{{VIM}}}{method}")
        if method == "RetrieveServiceContent":
            this_type, this_ref = "ServiceInstance", "ServiceInstance"
        elif method in {"Login", "Logout"}:
            this_type, this_ref = "SessionManager", self._session_manager
        else:
            this_type, this_ref = "PropertyCollector", self._collector
        if this_ref not in self._references.get(this_type, set()):
            raise EsxiError("Unreviewed SOAP target reference")
        _add(request, "_this", this_ref, type=this_type)
        if method == "Login":
            if self._logged_in:
                raise EsxiError("ESXi session already authenticated")
            _add(request, "userName", self._username)
            _add(request, "password", self._password)
        paths = []
        if method == "RetrievePropertiesEx":
            if object_type not in _SCHEMAS or token is not None:
                raise EsxiError("Unreviewed SOAP property type or arguments")
            paths = list(_SCHEMAS[object_type])
            spec = _add(request, "specSet")
            prop = _add(spec, "propSet")
            _add(prop, "type", object_type)
            _add(prop, "all", "false")
            for path in paths:
                _add(prop, "pathSet", path)
            if object_type == "HostSystem":
                if refs or self._root not in self._references.get("Folder", set()):
                    raise EsxiError("Host discovery requires the reviewed root folder")
                obj = _add(spec, "objectSet")
                _add(obj, "obj", self._root, type="Folder")
                _add(obj, "skip", "true")
                self._traversal(obj)
            else:
                if not refs or len(refs) != len(set(refs)) or len(refs) > self.max_objects:
                    raise EsxiError("Invalid scoped SOAP reference list")
                for reference in refs:
                    if reference not in self._references.get(object_type, set()):
                        raise EsxiError("SOAP reference outside the reviewed host scope")
                    obj = _add(spec, "objectSet")
                    _add(obj, "obj", reference, type=object_type)
                    _add(obj, "skip", "false")
            _add(_add(request, "options"), "maxObjects", min(100, self.max_objects))
        elif method == "ContinueRetrievePropertiesEx":
            if (
                object_type is not None
                or refs
                or not isinstance(token, str)
                or not token
                or len(token) > 4096
                or token != self._pagination_token
            ):
                raise EsxiError("Unreviewed or malformed SOAP pagination token")
            _add(request, "token", token)
        elif object_type is not None or refs or token is not None:
            raise EsxiError("Unexpected SOAP request arguments")
        envelope = ET.Element(f"{{{SOAP}}}Envelope")
        ET.SubElement(envelope, f"{{{SOAP}}}Body").append(request)
        encoded = ET.tostring(envelope, encoding="utf-8", xml_declaration=True)
        if len(encoded) > MAX_XML_BYTES:
            raise EsxiError("SOAP request exceeded the size limit")
        self.trace.append({"method": method, "properties": paths})
        self._requests += 1
        try:
            with warnings.catch_warnings():
                if not self.verify:
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                response = self.session.post(
                    self.base,
                    data=encoded,
                    verify=self.verify,
                    timeout=(10, self.timeout),
                    allow_redirects=False,
                    stream=True,
                    headers={
                        "Content-Type": "text/xml; charset=utf-8",
                        "SOAPAction": '"urn:vim25/6.7"',
                    },
                )
                try:
                    if 300 <= response.status_code < 400:
                        raise EsxiError("ESXi HTTPS redirects are prohibited")
                    payload = bytearray()
                    for chunk in response.iter_content(chunk_size=8192):
                        if len(payload) + len(chunk) > MAX_XML_BYTES:
                            raise EsxiError("SOAP response exceeded the size limit")
                        payload.extend(chunk)
                    status = response.status_code
                finally:
                    response.close()
        except requests.exceptions.SSLError:
            raise EsxiError("ESXi TLS handshake or certificate verification failed") from None
        except requests.RequestException:
            raise EsxiError("ESXi HTTPS connection failed or timed out") from None
        if b"\x00" in payload or re.search(rb"<!\s*(DOCTYPE|ENTITY)", payload, re.IGNORECASE):
            raise EsxiError("Unsafe SOAP XML declaration")
        try:
            document = ET.fromstring(payload)
        except ET.ParseError:
            raise EsxiError("Invalid SOAP XML response") from None
        pending, nodes = [(document, 0)], 0
        while pending:
            element, depth = pending.pop()
            nodes += 1
            if nodes > MAX_XML_NODES or depth > MAX_XML_DEPTH:
                raise EsxiError("SOAP XML structure exceeded the limit")
            pending.extend((item, depth + 1) for item in element)
        if document.tag != f"{{{SOAP}}}Envelope":
            raise EsxiError("Malformed SOAP envelope")
        bodies = [item for item in document if item.tag == f"{{{SOAP}}}Body"]
        if len(bodies) != 1 or len(bodies[0]) != 1:
            raise EsxiError("Malformed SOAP response body")
        result = bodies[0][0]
        if result.tag == f"{{{SOAP}}}Fault":
            raise EsxiError(f"{method}: SOAP fault")
        if status != 200:
            raise EsxiError(f"{method}: HTTP {status}")
        if result.tag != f"{{{VIM}}}{method}Response":
            raise EsxiError("Unexpected SOAP response method")
        return result

    @staticmethod
    def _traversal(object_set):
        def traverse(parent, name, object_type, path):
            node = _add(parent, "selectSet")
            node.set(f"{{{XSI}}}type", "vim:TraversalSpec")
            for field, value in (
                ("name", name),
                ("type", object_type),
                ("path", path),
                ("skip", "false"),
            ):
                _add(node, field, value)
            return node

        def recurse(parent):
            node = _add(parent, "selectSet")
            node.set(f"{{{XSI}}}type", "vim:SelectionSpec")
            _add(node, "name", "visitFolders")

        folder = traverse(object_set, "visitFolders", "Folder", "childEntity")
        recurse(folder)
        recurse(traverse(folder, "datacenterHosts", "Datacenter", "hostFolder"))
        traverse(folder, "computeHosts", "ComputeResource", "host")

    def _collect(self, object_type, refs=()):
        response = self._request("RetrievePropertiesEx", object_type=object_type, refs=refs)
        objects, seen, tokens = [], set(), set()
        for page in range(self.max_pages):
            returned = _one(response, "returnval", required=False)
            if returned is None:
                break
            for item in _children(returned, "objects"):
                self._objects += 1
                if self._objects > self.max_objects:
                    raise EsxiError("ESXi object budget exceeded")
                reference = _mor(_one(item, "obj"), {object_type})["ref"]
                if reference in seen or (refs and reference not in refs):
                    raise EsxiError("Duplicate or out-of-scope SOAP object")
                seen.add(reference)
                if _children(item, "missingSet"):
                    raise EsxiError("A requested SOAP property is inaccessible or unavailable")
                properties = {}
                for prop in _children(item, "propSet"):
                    name = _text(_one(prop, "name"))
                    if name not in _SCHEMAS[object_type] or name in properties:
                        raise EsxiError("Duplicate or unreviewed SOAP property")
                    properties[name] = self._decode(_one(prop, "val"), _SCHEMAS[object_type][name])
                if not _REQUIRED[object_type].issubset(properties):
                    raise EsxiError("Required SOAP property coverage is incomplete")
                objects.append({"ref": reference, "properties": properties})
            token_node = _one(returned, "token", required=False)
            token = _text(token_node) if token_node is not None else ""
            if not token:
                break
            if token in tokens or page + 1 >= self.max_pages:
                raise EsxiError("Repeated or excessive SOAP pagination")
            tokens.add(token)
            self._pagination_token = token
            response = self._request("ContinueRetrievePropertiesEx", token=token)
        self._pagination_token = None
        if refs and seen != set(refs):
            raise EsxiError("Scoped SOAP object coverage is incomplete")
        return objects

    def discovery(self):
        """Collect allowlisted inventory with permission-scoped guest and datastore data."""
        try:
            content = _one(self._request("RetrieveServiceContent"), "returnval")
            service = self._decode(_one(content, "about"), _PRODUCT)
            if (
                service.get("apiType") != "HostAgent"
                or service.get("productLineId") != "embeddedEsx"
            ):
                raise EsxiError("Discovery requires a standalone ESXi HostAgent endpoint")
            if any(not isinstance(service.get(key), str) or not service[key] for key in _PRODUCT):
                raise EsxiError("ESXi service identity is incomplete")
            for name, object_type in (
                ("rootFolder", "Folder"),
                ("sessionManager", "SessionManager"),
                ("propertyCollector", "PropertyCollector"),
            ):
                reference = _mor(_one(content, name), {object_type})["ref"]
                self._references[object_type] = {reference}
                if name == "rootFolder":
                    self._root = reference
                elif name == "sessionManager":
                    self._session_manager = reference
                else:
                    self._collector = reference
            login = self._request("Login")
            self._logged_in = True
            if not _text(_one(_one(login, "returnval"), "key")):
                raise EsxiError("Malformed SOAP Login response")
            hosts = self._collect("HostSystem")
            if len(hosts) != 1:
                raise EsxiError("Exactly one visible standalone ESXi HostSystem is required")
            host = hosts[0]
            self._references["HostSystem"] = {host["ref"]}
            for path, object_type in (("vm", "VirtualMachine"), ("datastore", "Datastore")):
                references = host["properties"].get(path) or []
                if any(not isinstance(item, dict) for item in references):
                    raise EsxiError("Malformed host inventory reference")
                values = [item["ref"] for item in references]
                if len(values) != len(set(values)):
                    raise EsxiError("Duplicate host inventory reference")
                self._references[object_type] = set(values)
            guests = (
                self._collect("VirtualMachine", sorted(self._references["VirtualMachine"]))
                if self._references["VirtualMachine"]
                else []
            )
            for guest in guests:
                owner = guest["properties"].get("runtime.host")
                if owner is not None and owner["ref"] != host["ref"]:
                    raise EsxiError("Guest observation belongs to a foreign HostSystem")
            datastores = (
                self._collect("Datastore", sorted(self._references["Datastore"]))
                if self._references["Datastore"]
                else []
            )
            return {
                "service": service,
                "host": host,
                "guests": guests,
                "datastores": datastores,
                "completeness": {
                    "host": True,
                    "guests": "permission-scoped",
                    "datastores": "permission-scoped",
                },
            }
        finally:
            active_failure = sys.exc_info()[0] is not None
            try:
                self.close()
            except BaseException:
                if not active_failure:
                    raise

    def close(self):
        if self._closed:
            return
        try:
            if self._logged_in:
                try:
                    self._request("Logout")
                finally:
                    self._logged_in = False
        finally:
            self._closed = True
            self._username = self._password = None
            self.session.close()
