"""Plan native StackWise inventory without moving existing network components.

Device Onboarding 5.6.0 supplies the VirtualChassis/member naming behavior.
Structured identities, rather than response order or active role, determine
which physical chassis an existing Device represents.
"""

from collections import defaultdict

from .adapters.cisco_iosxe import INSTALL_PATH, canonical_software_version


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 255


def _member_install_row(row, position, release):
    """Recheck the reviewed evidence shape before using it as an assignment."""
    if not isinstance(row, dict):
        return False
    fru, current = row.get("fru"), row.get("current")
    extension = row.get("version-extension")
    return (
        type(row.get("chassis")) is int
        and row["chassis"] == position
        and isinstance(fru, str)
        and fru.split(":")[-1] == "fru-rp"
        and isinstance(current, str)
        and current.split(":")[-1]
        in {
            "install-version-state-provisioned-committed",
            "install-version-state-provisioned-uncommitted",
        }
        and canonical_software_version(row.get("version")) == release
        and canonical_software_version(row.get("release")) == release
        and (extension is None or isinstance(extension, str) and extension.isdecimal())
    )


def _finish(plan):
    vc = plan["virtual_chassis"]
    plan["summary"] = {
        "virtual_chassis_created": int(bool(vc and vc["create"])),
        "virtual_chassis_updated": int(bool(vc and not vc["create"] and vc["master_changed"])),
        "stack_members_created": sum(member["create"] for member in plan["members"]),
        "stack_members_updated": sum(
            bool(member["changes"]) for member in plan["members"] if not member["create"]
        ),
        "device_types_created": sum(row["create"] for row in plan["device_types"]),
        "stack_member_software_assigned": sum(
            bool(member.get("software_version_key")) for member in plan["members"]
        ),
    }
    return plan


def plan_stack(discovery, existing):
    """Preserve serial identities, names and ownership; add confirmed stack membership.

    New Devices inherit only location, role, status, platform and tenant at the
    ORM boundary. Active role selects the VC master, never a Device's serial.
    Established member positions are preserved; conflicting renumbering blocks
    application. Reported priority and master can follow fresh operational facts.
    """
    identity = dict(discovery["identity"])
    plan = {
        "schema_version": 1,
        "virtual_chassis": None,
        "device_types": [],
        "software_versions": [],
        "members": [],
        "identity": identity,
        "errors": [],
        "conflicts": [],
        "warnings": [],
    }
    source = discovery.get("stack")
    if source is None:
        return _finish(plan)
    if (
        not isinstance(source, dict)
        or type(source.get("schema_version")) is not int
        or source["schema_version"] != 1
        or type(source.get("is_stack")) is not bool
    ):
        plan["errors"].append("Unsupported structured stack schema")
        return _finish(plan)
    if source["is_stack"] is False:
        if existing.get("stack", {}).get("selected", {}).get("virtual_chassis_id"):
            plan["warnings"].append(
                "Only one chassis is currently present; existing VirtualChassis membership "
                "is preserved"
            )
        return _finish(plan)
    members = source.get("members")
    name = _text(source.get("name"))
    if (
        not isinstance(members, list)
        or len(members) < 2
        or name is None
        or name != _text(identity.get("hostname"))
        or not _integer(source.get("active_position"), 1)
    ):
        plan["errors"].append("Stack identity requires a hostname and at least two present members")
        return _finish(plan)
    positions, serials, active = set(), set(), []
    for member in members:
        if (
            not isinstance(member, dict)
            or not _integer(member.get("position"), 1)
            or (member.get("priority") is not None and not _integer(member["priority"]))
            or _text(member.get("serial")) != member.get("serial")
            or _text(member.get("model")) != member.get("model")
            or not _text(member.get("serial"))
            or not _text(member.get("model"))
            or member.get("role") not in {"role-active", "role-standby", "role-member"}
            or member.get("state") != "state-ready"
            or member.get("stack_mode") != "mode-stackwise-rear"
            or not isinstance(member.get("sources"), dict)
            or not member["sources"]
        ):
            plan["errors"].append("Stack member has incomplete or unsupported structured identity")
            continue
        if member["position"] in positions or member["serial"] in serials:
            plan["errors"].append("Several stack members share a position or serial identity")
        positions.add(member["position"])
        serials.add(member["serial"])
        if member["role"] == "role-active":
            active.append(member)
    if len(active) != 1 or active[0]["position"] != source["active_position"]:
        plan["errors"].append("Stack active member is missing, ambiguous or inconsistent")
    if plan["errors"]:
        return _finish(plan)
    active = active[0]
    if any(identity.get(field) != active[field] for field in ("serial", "model")):
        plan["errors"].append("Discovered chassis identity does not match the active stack member")
        return _finish(plan)
    catalog = existing.get("stack")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("selected"), dict):
        plan["errors"].append("Native stack inventory snapshot is unavailable")
        return _finish(plan)
    selected = catalog["selected"]
    selected_id = str(existing["device"]["id"])
    if str(selected.get("id")) != selected_id:
        plan["errors"].append("Stack snapshot does not represent the selected Device")
        return _finish(plan)
    if selected.get("manufacturer_name", "Cisco").casefold() != "cisco":
        plan["errors"].append("The selected DeviceType manufacturer must be Cisco")
    manufacturer_id = selected.get("manufacturer_id")
    if not manufacturer_id:
        plan["errors"].append("The selected DeviceType has no manufacturer identity")
    selected_serial = _text(existing["device"].get("serial"))
    matched = [member for member in members if member["serial"] == selected_serial]
    if selected_serial and len(matched) != 1:
        plan["errors"].append("Selected Device serial does not identify a present stack member")
        return _finish(plan)
    selected_member = matched[0] if matched else active
    plan["identity"].update(serial=selected_member["serial"], model=selected_member["model"])
    if existing["device"].get("model") != selected_member["model"]:
        plan["errors"].append("Selected DeviceType differs from its serial-matched stack chassis")

    def conflict(scope, row_name, field, before, observed):
        plan["conflicts"].append(
            {
                "scope": scope,
                "name": row_name,
                "field": field,
                "before": before,
                "observed": observed,
            }
        )

    devices = catalog.get("devices", [])
    by_serial = defaultdict(list)
    for row in devices:
        if _text(row.get("serial")):
            by_serial[row["serial"].strip()].append(row)
    vcs = catalog.get("virtual_chassis", [])
    named = [row for row in vcs if row["name"] == name]
    selected_vc_id = selected.get("virtual_chassis_id")
    linked = [row for row in vcs if str(row["id"]) == str(selected_vc_id)] if selected_vc_id else []
    if len(named) > 1 or len(linked) > 1 or (selected_vc_id and not linked):
        plan["errors"].append("Existing VirtualChassis identity is missing or ambiguous")
        return _finish(plan)
    if linked and named and linked[0]["id"] != named[0]["id"]:
        plan["errors"].append("Selected Device membership conflicts with the named VirtualChassis")
        return _finish(plan)
    vc = linked[0] if linked else named[0] if named else None
    vc_id = str(vc["id"]) if vc else None
    linked_devices = [row for row in devices if vc_id and row.get("virtual_chassis_id") == vc_id]
    if (
        vc
        and not linked
        and linked_devices
        and not any(_text(row.get("serial")) in serials for row in linked_devices)
    ):
        plan["errors"].append("The named VirtualChassis belongs to a different set of chassis")
    if (
        vc
        and vc.get("master_id")
        and not any(str(row["id"]) == str(vc["master_id"]) for row in linked_devices)
    ):
        plan["errors"].append("Existing VirtualChassis master is not a member of that chassis")
    if vc and vc["name"] != name:
        conflict("virtual_chassis", vc["name"], "name", vc["name"], name)

    types = defaultdict(list)
    for row in catalog.get("device_types", []):
        if str(row["manufacturer_id"]) == str(manufacturer_id):
            types[row["model"]].append(row)
    for model in sorted({member["model"] for member in members}):
        candidates = types[model]
        if len(candidates) > 1:
            plan["errors"].append("Several Cisco DeviceTypes represent stack model %s" % model)
        plan["device_types"].append(
            {
                "model": model,
                "manufacturer_id": manufacturer_id,
                "existing_id": str(candidates[0]["id"]) if len(candidates) == 1 else None,
                "create": not candidates,
            }
        )
    used_ids = set()
    software_catalog = {}

    def member_software(member, row, is_selected):
        """Only explicit member install evidence can fill a blank assignment."""
        # The selected Device retains the established top-level software path.
        if is_selected:
            return None
        release = canonical_software_version(member.get("software_version"))
        source = member["sources"].get("software_version")
        rows = source.get("install_rows") if isinstance(source, dict) else None
        if (
            release is None
            or release != canonical_software_version(identity.get("software_version"))
            or not isinstance(source, dict)
            or source.get("module") != "Cisco-IOS-XE-install-oper"
            or source.get("path") != INSTALL_PATH
            or type(source.get("chassis")) is not int
            or source["chassis"] != member["position"]
            or not isinstance(rows, list)
            or not rows
            or any(not _member_install_row(item, member["position"], release) for item in rows)
        ):
            plan["warnings"].append(
                "Stack member %s software is deferred: verified member installation evidence "
                "is missing or inconsistent" % member["position"]
            )
            return None
        before = row.get("software_version") if row else None
        if _text(before):
            if canonical_software_version(before) != release:
                conflict("stack_member", row.get("name"), "software_version", before, release)
            return None
        platform_id = row.get("platform_id") if row else selected.get("platform_id")
        if not platform_id:
            plan["warnings"].append(
                "Stack member %s software is deferred: assign its Platform before loading "
                "software; existing member Platforms are preserved" % member["position"]
            )
            return None
        platform_id = str(platform_id)
        member_driver = _text((row if row else selected).get("platform_network_driver"))
        if member_driver and member_driver.casefold() not in {"cisco_ios", "cisco_iosxe"}:
            conflict(
                "stack_member",
                row.get("name") if row else "%s:%s" % (name, member["position"]),
                "platform",
                platform_id,
                selected.get("platform_id"),
            )
            plan["warnings"].append(
                "Stack member %s software is deferred: its existing Platform network driver "
                "does not identify supported IOS XE; the Platform is preserved" % member["position"]
            )
            return None
        key = "%s:%s" % (platform_id, release)
        if key not in software_catalog:
            candidates = [
                candidate
                for candidate in catalog.get("software_versions", [])
                if str(candidate.get("platform_id")) == platform_id
                and canonical_software_version(candidate.get("version")) == release
            ]
            # Older pure snapshots carry only the selected Platform's catalog.
            if not candidates and platform_id == str(selected.get("platform_id")):
                candidates = [
                    candidate
                    for candidate in existing.get("software_versions", [])
                    if canonical_software_version(candidate.get("version")) == release
                ]
            if len(candidates) > 1:
                plan["errors"].append(
                    "Several SoftwareVersion records represent release %s for stack member "
                    "Platform %s" % (release, platform_id)
                )
                return None
            software_catalog[key] = {
                "key": key,
                "platform_id": platform_id,
                "version": release,
                "existing_id": str(candidates[0]["id"]) if candidates else None,
                "create": not candidates,
            }
        return key

    for member in sorted(members, key=lambda item: item["position"]):
        is_selected = member["position"] == selected_member["position"]
        candidates = by_serial[member["serial"]]
        if len(candidates) > 1:
            plan["errors"].append("Several Devices share stack serial %s" % member["serial"])
            continue
        desired_name = name if is_selected else "%s:%s" % (name, member["position"])
        same_name = [
            row
            for row in devices
            if row.get("name") == desired_name
            and row.get("location_id") == selected.get("location_id")
            and row.get("tenant_id") == selected.get("tenant_id")
        ]
        if is_selected:
            if candidates and str(candidates[0]["id"]) != selected_id:
                plan["errors"].append("Active serial is already assigned to another Device")
                continue
            if not _text(selected.get("name")) and any(
                str(candidate["id"]) != selected_id for candidate in same_name
            ):
                plan["errors"].append("Discovered stack hostname is occupied by another Device")
                continue
            row = selected
        elif candidates:
            row = candidates[0]
        elif len(same_name) == 1 and not _text(same_name[0].get("serial")):
            row = same_name[0]
        elif same_name:
            plan["errors"].append("Stack member name %s is occupied or ambiguous" % desired_name)
            continue
        else:
            row = None
        changes = []
        if row:
            row_id = str(row["id"])
            if row_id in used_ids:
                plan["errors"].append("One Device cannot represent several stack members")
            used_ids.add(row_id)
            if row.get("model") != member["model"] or str(row.get("manufacturer_id")) != str(
                manufacturer_id
            ):
                plan["errors"].append("Stack serial matches a different DeviceType or manufacturer")
            if row.get("location_id") != selected.get("location_id"):
                plan["errors"].append("Stack serial matches a Device at a different location")
            if not is_selected and not _text(row.get("name")):
                if any(
                    candidate.get("name") == desired_name
                    and candidate.get("location_id") == row.get("location_id")
                    and candidate.get("tenant_id") == row.get("tenant_id")
                    and str(candidate["id"]) != row_id
                    for candidate in devices
                ):
                    plan["errors"].append(
                        "Generated stack member name is occupied by another Device"
                    )
                else:
                    changes.append(
                        {"field": "name", "before": row.get("name"), "after": desired_name}
                    )
            membership = row.get("virtual_chassis_id")
            if membership and str(membership) != vc_id:
                plan["errors"].append("Stack member already belongs to another VirtualChassis")
            if not _text(row.get("serial")) and not is_selected:
                changes.append(
                    {"field": "serial", "before": row.get("serial"), "after": member["serial"]}
                )
            if not membership:
                changes.append({"field": "virtual_chassis", "before": None, "after": vc_id or name})
            before_position = row.get("vc_position")
            if before_position is None:
                changes.append(
                    {"field": "vc_position", "before": None, "after": member["position"]}
                )
            elif before_position != member["position"]:
                conflict(
                    "stack_member",
                    row.get("name"),
                    "vc_position",
                    before_position,
                    member["position"],
                )
                plan["errors"].append("Established stack member position differs from observation")
            if member["priority"] is not None and row.get("vc_priority") != member["priority"]:
                changes.append(
                    {
                        "field": "vc_priority",
                        "before": row.get("vc_priority"),
                        "after": member["priority"],
                    }
                )
        if vc_id:
            occupied = [
                item
                for item in linked_devices
                if item.get("vc_position") == member["position"]
                and (not row or str(item["id"]) != str(row["id"]))
            ]
            if occupied:
                plan["errors"].append("Observed stack position is occupied by another Device")
        software_key = member_software(member, row, is_selected)
        if software_key and row:
            changes.append(
                {
                    "field": "software_version",
                    "before": row.get("software_version"),
                    "after": software_catalog[software_key]["version"],
                }
            )
        plan["members"].append(
            {
                "position": member["position"],
                "priority": member["priority"],
                "serial": member["serial"],
                "model": member["model"],
                "name": (row.get("name") or desired_name) if row else desired_name,
                "existing_id": str(row["id"]) if row else None,
                "selected": is_selected,
                "create": row is None,
                "changes": changes,
                "platform_id": row.get("platform_id") if row else selected.get("platform_id"),
                "software_version": member.get("software_version"),
                "software_version_key": software_key,
                "software_source": member["sources"].get("software_version"),
            }
        )
    plan["software_versions"] = [software_catalog[key] for key in sorted(software_catalog)]
    active_plan = next(
        (row for row in plan["members"] if row["position"] == active["position"]), None
    )
    plan["virtual_chassis"] = {
        "name": vc["name"] if vc else name,
        "existing_id": vc_id,
        "create": vc is None,
        "master_position": active["position"],
        "master_changed": bool(
            not vc or not active_plan or vc.get("master_id") != active_plan["existing_id"]
        ),
    }
    if selected_member["position"] != active["position"]:
        plan["warnings"].append(
            "Selected Device represents a non-active stack chassis. Its name, primary IPs, "
            "credentials and interface ownership are preserved; the reported active Device "
            "is the VirtualChassis master"
        )
    if any(_text(row.get("serial")) not in serials for row in linked_devices):
        plan["warnings"].append(
            "Existing unobserved stack members are preserved without detachment"
        )
    return _finish(plan)
