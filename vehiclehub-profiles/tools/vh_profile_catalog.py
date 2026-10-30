#!/usr/bin/env python3
"""VehicleHub WiCAN profile catalog checks (WICAN-163).  Standard library only.

  vh_profile_catalog.py validate [--base-ref REF]   schema + contract + catalog checks,
                                                    and immutability against REF
  vh_profile_catalog.py add-versions                list unlisted version files in catalog.json
  vh_profile_catalog.py hash FILE                   print sha256 and size

Published versions are immutable: once a version is in the catalog at the base ref,
its file bytes and sha256 must never change and it must never be removed.  Publish a
correction as a new version instead.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog.json"
SCHEMA = ROOT / "schema.json"
CATALOG_SCHEMA_ID = "vehiclehub.wican.profile-catalog.v1"
MAX_PROFILE_BYTES = 128 * 1024

# Shared safety policy; main/vehicle_profile.c enforces the same lists on the device.
READ_SERVICES = {"01", "02", "03", "07", "09", "0A", "21", "22"}
DTC_SERVICES = {"03", "07", "0A"}
INIT_COMMANDS = re.compile(r"^AT(SP[0-9A-C]|TP[0-9A-C]|SH[0-9A-F]{3}|SH[0-9A-F]{6}|SH[0-9A-F]{8}|"
                           r"CRA([0-9A-F]{3}|[0-9A-F]{8})?|ST[0-9A-F]{1,2}|AT[0-2]|CAF[01]|"
                           r"CEA([0-9A-F]{2})?|FCSH[0-9A-F]{3,8}|FCSD[0-9A-F]{2,10}|FCSM[0-2]|H[01]|S[01])$")
# The characters main/expression_parser.c accepts (digits, V, B<n>, S<n>, [Ba:Bb], bit :n, operators).
EXPRESSION_CHARS = re.compile(r"^[0-9.VBS\[\]:+\-*/&|^<>() ]*$")
SECRET_KEYS = re.compile(r"(^|_)(pass|passwd|password|secret|token|psk|private_key|api_key|apikey|auth|cert|ssid|vin)(_|$)", re.I)
VIN_LIKE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


def semver_key(text):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$", text)
    if not m:
        raise ValueError(text)
    pre = m.group(4)
    parts = []
    for item in (pre.split(".") if pre else []):
        parts.append((0, int(item), "") if item.isdigit() else (1, 0, item))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, tuple(parts))


# ----------------------------------------------------------------------------- schema subset

def _type_ok(value, expected):
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        if name == "null" and value is None:
            return True
        if name == "boolean" and isinstance(value, bool):
            return True
        if name == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if name == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if name == "string" and isinstance(value, str):
            return True
        if name == "array" and isinstance(value, list):
            return True
        if name == "object" and isinstance(value, dict):
            return True
    return False


def schema_errors(value, schema, root, path="$"):
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return schema_errors(value, root["$defs"][name], root, path)
    errors = []
    if "const" in schema and value != schema["const"]:
        return [f"{path}: must be {schema['const']!r}"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{path}: {value!r} is not one of {schema['enum']}"]
    if "type" in schema and not _type_ok(value, schema["type"]):
        return [f"{path}: expected {schema['type']}"]
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 30):
            errors.append(f"{path}: length {len(value)} out of range")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            errors.append(f"{path}: {value} out of range")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 30):
            errors.append(f"{path}: {len(value)} items out of range")
        if "items" in schema:
            for i, item in enumerate(value):
                errors += schema_errors(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        if len(value) > schema.get("maxProperties", 1 << 30):
            errors.append(f"{path}: too many properties")
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in props:
                errors += schema_errors(item, props[key], root, f"{path}.{key}")
            elif extra is False:
                errors.append(f"{path}: unknown key {key}")
            elif isinstance(extra, dict):
                errors += schema_errors(item, extra, root, f"{path}.{key}")
    return errors


# ----------------------------------------------------------------------------- contract checks

def byte_indices(expression):
    return [int(n) for n in re.findall(r"B(\d+)", expression)]


def init_errors(init, where):
    errors = []
    for command in [c.strip().upper() for c in init.split(";") if c.strip()]:
        if not INIT_COMMANDS.match(command):
            errors.append(f"{where}: init command {command!r} is not allowed")
    return errors


def secret_errors(node, path="$"):
    errors = []
    if isinstance(node, dict):
        for key, value in node.items():
            if SECRET_KEYS.search(key):
                errors.append(f"{path}.{key}: credential-like key is not allowed in a public profile")
            errors += secret_errors(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            errors += secret_errors(value, f"{path}[{i}]")
    elif isinstance(node, str):
        if VIN_LIKE.search(node):
            errors.append(f"{path}: looks like a VIN")
        if IPV4.search(node):
            errors.append(f"{path}: contains an IP address")
    return errors


def contract_errors(profile):
    errors = []
    complete = profile.get("status") == "complete"
    compat = profile["compatibility"]
    autopid = profile["autopid"]
    bounds = autopid["period_bounds_ms"]
    if bounds["min"] > bounds["max"]:
        errors.append("period_bounds_ms: min > max")
    if profile.get("status") == "draft" and "draft" not in profile["title"].lower():
        errors.append("title: a draft profile must say 'draft' in its title")
    if complete:
        for key in ("obd_protocol", "can_datarate"):
            if key not in compat:
                errors.append(f"compatibility.{key}: required for a complete profile")
        if autopid["car_init"] is None:
            errors.append("autopid.car_init: required for a complete profile")
    if autopid["car_init"]:
        errors += init_errors(autopid["car_init"], "autopid.car_init")
    group_ids, group_names, activity_hits = set(), set(), []
    enabled_fields = {}
    for g in autopid["groups"]:
        where = f"group {g['id']}"
        if g["id"] in group_ids or g["name"] in group_names:
            errors.append(f"{where}: duplicate group id or name")
        group_ids.add(g["id"])
        group_names.add(g["name"])
        experimental = g["status"] == "experimental"
        if complete and g["period_ms"] is None:
            errors.append(f"{where}: period_ms is required for a complete profile")
        if g["period_ms"] is not None and g.get("adjustable_period", True) and \
                not bounds["min"] <= g["period_ms"] <= bounds["max"] and not experimental:
            errors.append(f"{where}: period {g['period_ms']} outside period_bounds_ms")
        if "init" in g:
            errors += init_errors(g["init"], where)
        topic = g["mqtt_topic"]
        if not experimental and topic and not re.match(r"^\{topic_base\}/autopid/group/[a-z0-9-]{1,32}$", topic):
            errors.append(f"{where}: mqtt_topic must be {{topic_base}}/autopid/group/<slug> or empty")
        pid_ids, names = set(), set()
        fields = enabled_fields.setdefault(g["id"], set())
        for p in g["pids"]:
            pw = f"{where} pid {p['id']}"
            if p["id"] in pid_ids:
                errors.append(f"{pw}: duplicate pid id")
            pid_ids.add(p["id"])
            req = p["pid"].upper()
            service = req[:2]
            if service not in READ_SERVICES:
                errors.append(f"{pw}: service {service} is not a read-only diagnostic service")
            if p.get("pid_type") == "std" and not re.match(r"^01[0-9A-F]{2}$", req):
                errors.append(f"{pw}: a standard PID must be 01XX")
            for prm in p["parameters"]:
                mw = f"{pw} parameter {prm['name']}"
                if prm["name"] in names:
                    errors.append(f"{mw}: duplicate parameter name in group")
                names.add(prm["name"])
                expr = prm["expression"]
                if complete and prm["status"] == "unverified":
                    errors.append(f"{mw}: a complete profile cannot carry unverified parameters")
                if expr == "DTC_RAW":
                    if service not in DTC_SERVICES or prm["destination_type"] != "MQTT_Topic":
                        errors.append(f"{mw}: DTC_RAW needs service 03/07/0A and MQTT_Topic")
                elif expr == "":
                    if p.get("pid_type") != "std":
                        errors.append(f"{mw}: only standard PIDs may omit the expression")
                else:
                    if not EXPRESSION_CHARS.match(expr):
                        errors.append(f"{mw}: expression has disallowed characters")
                    if any(i > 255 for i in byte_indices(expr)):
                        errors.append(f"{mw}: expression byte index above B255")
                if prm["destination_type"] == "MQTT_Topic":
                    if not prm.get("send_to", "").startswith("{topic_base}/"):
                        errors.append(f"{mw}: MQTT_Topic send_to must start with {{topic_base}}/")
                elif "send_to" in prm and prm["send_to"] not in ("",):
                    errors.append(f"{mw}: send_to is only meaningful for MQTT_Topic")
                if prm.get("parameter_id"):
                    activity_hits.append((g, p, prm))
                if prm["status"] in ("canonical", "optional") and prm.get("enabled", True) and \
                        p.get("enabled", True) and g.get("enabled", True):
                    fields.add(prm["name"])
    if compat["vehicle_state_provider"] == "configured_activity_signal":
        wanted = compat.get("activity_parameter_id")
        hits = [h for h in activity_hits if h[2]["parameter_id"] == wanted]
        if not wanted or len(hits) != 1:
            errors.append("compatibility.activity_parameter_id must resolve to exactly one parameter")
        else:
            g, p, prm = hits[0]
            if g.get("can_disable", True) or p.get("user_toggle", True) or prm["status"] != "canonical":
                errors.append("activity parameter must be canonical and locked (can_disable/user_toggle false)")
    vh = profile["vehiclehub"]
    for gid in vh["trip_groups"]:
        if gid not in group_ids:
            errors.append(f"vehiclehub.trip_groups: unknown group {gid}")
    if complete:
        for gid, required in vh["required_fields"].items():
            if gid not in group_ids:
                errors.append(f"vehiclehub.required_fields: unknown group {gid}")
                continue
            missing = sorted(set(required) - enabled_fields.get(gid, set()))
            if missing:
                errors.append(f"vehiclehub.required_fields.{gid}: not enabled in the profile: {missing}")
    rule_ids = set()
    for rule in profile["passive_can"]["rules"]:
        if rule["id"] in rule_ids:
            errors.append(f"passive_can rule {rule['id']}: duplicate id")
        rule_ids.add(rule["id"])
    errors += secret_errors({k: v for k, v in profile.items() if k != "provenance"})
    return errors


def profile_errors(path, schema):
    raw = path.read_bytes()
    if len(raw) > MAX_PROFILE_BYTES:
        return [f"{path}: {len(raw)} bytes exceeds {MAX_PROFILE_BYTES}"]
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw:
        return [f"{path}: must be UTF-8 without BOM and with LF line endings"]
    try:
        profile = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    errors = schema_errors(profile, schema, schema)
    if not errors:
        errors = contract_errors(profile)
    rel = path.relative_to(ROOT).as_posix()
    if not errors and not rel.endswith("/" + profile["profile_version"] + ".json"):
        errors.append("file name must be <profile_version>.json")
    return [f"{rel}: {e}" for e in errors]


# ----------------------------------------------------------------------------- catalog

def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile_files():
    return sorted(p for p in ROOT.glob("*/*/*.json") if p.relative_to(ROOT).parts[0] != "tools")


def catalog_errors(catalog):
    errors = []
    if catalog.get("schema") != CATALOG_SCHEMA_ID:
        errors.append(f"catalog.json: schema must be {CATALOG_SCHEMA_ID}")
    listed = set()
    ids = set()
    for entry in catalog.get("profiles", []):
        pid = entry.get("profile_id")
        if pid in ids:
            errors.append(f"catalog.json: duplicate profile {pid}")
        ids.add(pid)
        versions = entry.get("versions", [])
        if not versions:
            errors.append(f"catalog.json {pid}: no versions")
        seen = set()
        for v in versions:
            path = ROOT / v["path"]
            listed.add(path.resolve())
            if v["version"] in seen:
                errors.append(f"catalog.json {pid}: duplicate version {v['version']}")
            seen.add(v["version"])
            if not path.exists():
                errors.append(f"catalog.json {pid} {v['version']}: missing file {v['path']}")
                continue
            profile = json.loads(path.read_text(encoding="utf-8"))
            if profile["profile_id"] != pid or profile["profile_version"] != v["version"] or \
                    profile["status"] != v["status"]:
                errors.append(f"catalog.json {pid} {v['version']}: id/version/status differ from the file")
            if sha256_file(path) != v["sha256"] or path.stat().st_size != v["size"]:
                errors.append(f"catalog.json {pid} {v['version']}: sha256/size mismatch")
        complete = [v["version"] for v in versions if v["status"] == "complete"]
        expected_latest = max(complete, key=semver_key) if complete else None
        if entry.get("latest") != expected_latest:
            errors.append(f"catalog.json {pid}: latest must be {expected_latest}")
    for path in profile_files():
        if path.resolve() not in listed:
            errors.append(f"{path.relative_to(ROOT).as_posix()}: not listed in catalog.json")
    return errors


def git_prefix():
    """This directory relative to its Git work tree ("vehiclehub-profiles/" here and in the
    public catalog repository; WICAN-167), so a different layout cannot skip the check."""
    proc = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-prefix"], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else "vehiclehub-profiles/"


def git_ref_exists(ref):
    proc = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                          capture_output=True)
    return proc.returncode == 0


def git_show(ref, rel):
    proc = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:{git_prefix()}{rel}"], capture_output=True)
    return proc.stdout if proc.returncode == 0 else None


def immutability_errors(catalog, base_ref):
    old_raw = git_show(base_ref, "catalog.json")
    if old_raw is None:
        return []  # nothing was published at base_ref yet
    old = json.loads(old_raw.decode("utf-8"))
    current = {(e["profile_id"], v["version"]): v for e in catalog["profiles"] for v in e["versions"]}
    errors = []
    for entry in old.get("profiles", []):
        for v in entry["versions"]:
            key = (entry["profile_id"], v["version"])
            now = current.get(key)
            if now is None:
                errors.append(f"published version {key} was removed")
            elif now["sha256"] != v["sha256"] or now["path"] != v["path"]:
                errors.append(f"published version {key} was modified; publish a new version instead")
            old_file = git_show(base_ref, v["path"])
            if old_file is not None and hashlib.sha256(old_file).hexdigest() != v["sha256"]:
                errors.append(f"published version {key}: base file does not match its catalog sha256")
    return errors


def cmd_validate(args):
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = []
    for path in profile_files():
        errors += profile_errors(path, schema)
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    errors += catalog_errors(catalog)
    if args.base_ref:
        if git_ref_exists(args.base_ref):
            errors += immutability_errors(catalog, args.base_ref)
        else:
            errors.append(f"--base-ref {args.base_ref}: not a commit in this repository")
    for e in errors:
        print("ERROR", e)
    print(f"{len(profile_files())} profile files, {len(errors)} errors")
    return 1 if errors else 0


def cmd_add_versions(_args):
    catalog = json.loads(CATALOG.read_text(encoding="utf-8")) if CATALOG.exists() else \
        {"schema": CATALOG_SCHEMA_ID, "profiles": []}
    by_id = {e["profile_id"]: e for e in catalog["profiles"]}
    for path in profile_files():
        profile = json.loads(path.read_text(encoding="utf-8"))
        entry = by_id.get(profile["profile_id"])
        if entry is None:
            vehicle = profile["vehicle"]
            entry = {"profile_id": profile["profile_id"], "title": profile["title"], "make": vehicle["make"],
                     "model": vehicle["model"], "powertrain": vehicle["powertrain"], "latest": None, "versions": []}
            for key in ("model_years", "generation", "variant"):
                if key in vehicle:
                    entry[key] = vehicle[key]
            catalog["profiles"].append(entry)
            by_id[profile["profile_id"]] = entry
        if any(v["version"] == profile["profile_version"] for v in entry["versions"]):
            continue
        entry["versions"].append({"version": profile["profile_version"], "status": profile["status"],
                                  "path": path.relative_to(ROOT).as_posix(), "sha256": sha256_file(path),
                                  "size": path.stat().st_size})
        entry["title"] = profile["title"] if profile["status"] == "complete" or entry["latest"] is None else entry["title"]
        complete = [v["version"] for v in entry["versions"] if v["status"] == "complete"]
        entry["latest"] = max(complete, key=semver_key) if complete else None
    catalog["profiles"].sort(key=lambda e: e["profile_id"])
    CATALOG.write_bytes((json.dumps(catalog, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(CATALOG)
    return 0


def cmd_hash(args):
    path = Path(args.file)
    print(sha256_file(path), path.stat().st_size)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--base-ref")
    v.set_defaults(func=cmd_validate)
    a = sub.add_parser("add-versions")
    a.set_defaults(func=cmd_add_versions)
    h = sub.add_parser("hash")
    h.add_argument("file")
    h.set_defaults(func=cmd_hash)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
