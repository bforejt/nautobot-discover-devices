"""Resolve a native wireless controller before selecting device transport.

Only reviewed Cisco AP/controller models are classified without a relationship.
Names and management addresses never establish controller ownership.
"""

import json
import re
from urllib.parse import urlsplit

from .exceptions import InventoryError


def _models():
    from nautobot.dcim.models import Controller, ControllerManagedDeviceGroup, Device

    return Controller, ControllerManagedDeviceGroup, Device


def _id(value):
    return str(value) if value is not None else None


def _cisco(device):
    manufacturer = getattr(getattr(device, "device_type", None), "manufacturer", None)
    name = str(getattr(manufacturer, "name", "") or "").lower()
    return name in {"cisco", "cisco systems", "cisco systems, inc."}


def is_wireless_ap(device):
    """Reviewed Cisco AP model families, or an explicit AP role/platform marker."""
    if not _cisco(device):
        return False
    model = str(getattr(getattr(device, "device_type", None), "model", "") or "").upper()
    if re.fullmatch(r"(?:AIR-(?:AP|CAP)[A-Z0-9-]+|C(?:91|92)[0-9]{2}[A-Z0-9-]*)", model):
        return True
    markers = {
        str(getattr(getattr(device, field, None), "name", "") or "").strip().lower()
        for field in ("role", "platform")
    }
    return bool(markers & {"wap", "wireless ap", "wireless access point", "access point"})


def _controller_model(device):
    model = str(getattr(getattr(device, "device_type", None), "model", "") or "").upper()
    return _cisco(device) and bool(re.fullmatch(r"C9800[A-Z0-9-]*|CATALYST 9800[A-Z0-9 -]*", model))


def _wireless_group(group, policy, explicit_controller):
    if group is None:
        return False
    controller = group.controller
    endpoint = getattr(controller, "controller_device", None)
    if endpoint is not None:
        return _controller_model(endpoint)
    wireless = "wireless" in (getattr(controller, "capabilities", None) or [])
    return wireless or bool(
        getattr(controller, "external_integration", None)
        and (policy.get("expected_hostname") or explicit_controller)
    )


def _host(device):
    primary = getattr(device, "primary_ip", None)
    if primary is not None:
        value = getattr(primary, "host", None)
        if value:
            return str(value)
        address = getattr(primary, "address", None)
        if getattr(address, "ip", None) is not None:
            return str(address.ip)
    name = getattr(device, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    raise InventoryError("Configure a controller management IP or explicit DNS endpoint")


def _policy(value):
    if value is None or isinstance(value, str) and not value.strip():
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise InventoryError("Controller source policy must be a JSON object") from None
    if not isinstance(value, dict) or set(value) - {"expected_hostname"}:
        raise InventoryError("Controller source policy accepts only expected_hostname")
    hostname = value.get("expected_hostname")
    if hostname is not None and (
        not isinstance(hostname, str)
        or not hostname.strip()
        or len(hostname) > 253
        or re.search(r"[\s/\\@]", hostname)
    ):
        raise InventoryError("Controller expected_hostname must be an explicit hostname")
    return {"expected_hostname": hostname.strip()} if hostname is not None else {}


def controller_snapshot(controller, endpoint_device=None):
    """Administrative source facts checked again under the apply lock."""
    integration = getattr(controller, "external_integration", None)
    return {
        "id": _id(controller.pk),
        "controller_device_id": _id(getattr(controller, "controller_device_id", None)),
        "controller_device_redundancy_group_id": _id(
            getattr(controller, "controller_device_redundancy_group_id", None)
        ),
        "external_integration_id": _id(getattr(controller, "external_integration_id", None)),
        "remote_url": getattr(integration, "remote_url", None),
        "integration_secrets_group_id": _id(getattr(integration, "secrets_group_id", None)),
        "endpoint": _host(endpoint_device) if endpoint_device is not None else None,
        "endpoint_serial": getattr(endpoint_device, "serial", None),
        "endpoint_model": getattr(getattr(endpoint_device, "device_type", None), "model", None),
        "endpoint_platform_id": _id(getattr(endpoint_device, "platform_id", None)),
        "endpoint_primary_ip4_id": _id(getattr(endpoint_device, "primary_ip4_id", None)),
        "endpoint_primary_ip6_id": _id(getattr(endpoint_device, "primary_ip6_id", None)),
        "endpoint_secrets_group_id": _id(getattr(endpoint_device, "secrets_group_id", None)),
    }


def resolve_controller_source(device=None, *, controller_id=None, source_policy=None):
    """Return a resolved controller scope, or None for an unrelated device.

    Does not read secrets or contact an endpoint. A missing AP association is
    an actionable failure before the general vendor dispatcher can run.
    """
    policy = _policy(source_policy)
    group = getattr(device, "controller_managed_device_group", None) if device is not None else None
    controller_seed = device is not None and _controller_model(device)
    ap_seed = (
        device is not None
        and not controller_seed
        and (
            is_wireless_ap(device)
            or _cisco(device)
            and _wireless_group(group, policy, controller_id is not None)
        )
    )
    if (
        device is not None
        and controller_id is None
        and not ap_seed
        and not _controller_model(device)
    ):
        return None
    Controller, _Group, _Device = _models()
    required = {"controller_device", "controller_device_redundancy_group", "external_integration"}
    fields = {field.name for field in Controller._meta.get_fields()}
    if not required.issubset(fields):
        raise InventoryError("Installed Nautobot lacks reviewed native Controller capabilities")
    associated = (
        list(Controller.objects.filter(controller_device=device)) if device is not None else []
    )
    if controller_id is not None:
        try:
            controller = Controller.objects.get(pk=controller_id)
        except (Controller.DoesNotExist, ValueError):
            raise InventoryError(
                "The explicitly selected native Controller does not exist"
            ) from None
        if ap_seed and group is None:
            raise InventoryError(
                "Selected AP has no native managed group; configure its Controller before discovery"
            )
        if ap_seed and str(group.controller_id) != str(controller.pk):
            raise InventoryError(
                "Selected AP's configured Controller differs from the explicit input"
            )
        if device is not None and not ap_seed and controller not in associated:
            raise InventoryError("Selected Device is not bound to the explicit native Controller")
    elif group is not None and ap_seed:
        controller = group.controller
    elif associated:
        if len(associated) != 1:
            raise InventoryError("Device has multiple native Controllers; select one explicitly")
        controller = associated[0]
    elif device is not None and is_wireless_ap(device):
        raise InventoryError(
            "AP %s (%s) has no controller_managed_device_group; configure its native group "
            "and Controller before discovery" % (device.name, device.pk)
        )
    elif device is not None and _controller_model(device):
        raise InventoryError("Configure a native Controller linked to the selected 9800 Device")
    else:
        return None
    if getattr(controller, "controller_device_redundancy_group_id", None):
        raise InventoryError(
            "9800 redundancy group source requires a reviewed shared endpoint/identity policy; "
            "member priority does not establish the active endpoint"
        )
    endpoint_device = getattr(controller, "controller_device", None)
    integration = getattr(controller, "external_integration", None)
    if endpoint_device is not None:
        if not _controller_model(endpoint_device):
            raise InventoryError("Native Controller endpoint must be a reviewed Cisco 9800 Device")
        model = endpoint_device.device_type.model.upper()
        logical = model in {"C9800-CL", "C9800-CL-K9"}
        if logical and not policy.get("expected_hostname"):
            raise InventoryError("C9800-CL requires an explicit expected_hostname source binding")
        if not logical and not getattr(endpoint_device, "serial", ""):
            raise InventoryError("Physical 9800 endpoint requires its verified controller serial")
        proof = {"kind": "logical" if logical else "physical"}
        if policy.get("expected_hostname"):
            proof["expected_hostname"] = policy["expected_hostname"]
        if not logical:
            proof["expected_model"] = endpoint_device.device_type.model
            proof["expected_serial"] = endpoint_device.serial
        host = _host(endpoint_device)
        credentials = endpoint_device
        secrets = getattr(endpoint_device, "secrets_group", None)
        port = None
    elif integration is not None:
        url = urlsplit(str(getattr(integration, "remote_url", "") or ""))
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
            or not policy.get("expected_hostname")
        ):
            raise InventoryError(
                "Logical Controller requires an HTTPS authority-only external integration URL "
                "and explicit expected_hostname source binding"
            )
        try:
            port = url.port
        except ValueError:
            raise InventoryError("Logical Controller endpoint has an invalid port") from None
        host, credentials = url.hostname, integration
        secrets = getattr(integration, "secrets_group", None)
        proof = {"kind": "logical", "expected_hostname": policy["expected_hostname"]}
    else:
        raise InventoryError(
            "Configure the native Controller's Device or approved logical endpoint"
        )
    binding = controller_snapshot(controller, endpoint_device)
    binding.update(
        seed_device_id=_id(getattr(device, "pk", None)),
        seed_group_id=_id(getattr(group, "pk", None)) if ap_seed else None,
        seed_is_ap=ap_seed,
        seed_kind="ap" if ap_seed else "controller" if device is not None else "logical",
    )
    return {
        "controller_id": str(controller.pk),
        "controller": controller,
        "controller_device": endpoint_device,
        "credential_device": credentials,
        "secrets_group": secrets,
        "host": host,
        "port": port,
        "source_policy": proof,
        "configured_policy": policy,
        "seed_device_id": _id(getattr(device, "pk", None)),
        "seed_group_id": _id(getattr(group, "pk", None)),
        "source_snapshot": binding,
        "full_controller_roster": True,
    }
