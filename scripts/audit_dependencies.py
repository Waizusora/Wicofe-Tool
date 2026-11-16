#!/usr/bin/env python3
"""Inventory dependencies and enforce Wicofe's human-approved license decisions.

Cargo metadata is the authoritative resolved graph input. Lockfiles without
license metadata are inventoried but deliberately remain UNKNOWN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

POLICY_VERSION = "0.2.0"
MANIFEST_NAMES = {
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo-lock",
    "package.json": "npm",
    "package-lock.json": "npm-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "yarn.lock": "yarn-lock",
    "go.mod": "go",
    "go.sum": "go-lock",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "meson.build": "meson",
    "CMakeLists.txt": "cmake",
    "Makefile": "make",
}


def classify_license(expression: str | None) -> str:
    """Conservative policy classification; this is not an SPDX legal parser."""
    if not expression or not expression.strip():
        return "UNKNOWN"
    value = expression.upper()
    # AGPL must be checked before GPL because its identifier contains GPL.
    if re.search(r"\bAGPL(?:-|\s)", value) or "AGPL" in value:
        return "PROHIBITED_AGPL"
    if re.search(r"\bGPL(?:-|\s)", value) or re.search(r"\bGPL\b", value):
        return "PROHIBITED_GPL"
    if "LGPL" in value:
        return "LGPL"
    if any(token in value for token in ("MPL", "EPL", "CDDL", "OSL", "EUPL", "SSPL")):
        return "COPYLEFT_REVIEW"
    if any(token in value for token in ("UNLICENSED", "PROPRIETARY", "CUSTOM", "SEE LICENSE")):
        return "RESTRICTED_REVIEW"
    return "OTHER_REVIEW"


def load_decisions(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("policy_version") != POLICY_VERSION:
        raise ValueError(f"decision registry must declare policy_version {POLICY_VERSION}")
    decisions = data.get("decisions", {})
    if not isinstance(decisions, dict):
        raise ValueError("decisions must be a JSON object")
    for key, decision in decisions.items():
        required = ("status", "reviewer", "approved_by", "evidence", "scope", "conditions")
        if not isinstance(decision, dict) or any(not decision.get(k) for k in required):
            raise ValueError(f"decision {key!r} lacks required human-review fields: {required}")
        if decision["status"] != "approved":
            raise ValueError(f"decision {key!r} must use status 'approved' or be omitted")
    return decisions


def package_key(name: str, version: str) -> str:
    return f"cargo:{name}:{version}"


def cargo_records(metadata: dict[str, Any], repository: str, decisions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    packages = {p["id"]: p for p in metadata.get("packages", [])}
    resolve = metadata.get("resolve") or {}
    nodes = {n["id"]: n for n in resolve.get("nodes", [])}
    members = set(metadata.get("workspace_members", []))
    direct_ids: set[str] = set()
    reachable: set[str] = set()
    stack: list[str] = []
    for member in members:
        node = nodes.get(member)
        if not node:
            continue
        for dep in node.get("deps", []):
            pkg_id = dep.get("pkg")
            if pkg_id in packages:
                direct_ids.add(pkg_id)
                stack.append(pkg_id)
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        node = nodes.get(current, {})
        for dep in node.get("deps", []):
            child = dep.get("pkg")
            if child in packages and child not in reachable:
                stack.append(child)

    records = []
    for pkg_id in sorted(reachable):
        pkg = packages[pkg_id]
        name, version = pkg.get("name", "unknown"), pkg.get("version", "unknown")
        license_expr = pkg.get("license")
        license_file = pkg.get("license_file")
        evidence = []
        if license_expr:
            evidence.append({"kind": "cargo_metadata_license", "value": license_expr})
        if license_file:
            file_path = Path(pkg.get("manifest_path", "")).parent / license_file
            if file_path.is_file():
                raw = file_path.read_bytes()
                evidence.append({"kind": "license_file", "path": str(file_path), "sha256": hashlib.sha256(raw).hexdigest()})
            else:
                evidence.append({"kind": "missing_license_file", "path": str(file_path)})
        key = package_key(name, version)
        decision = decisions.get(key)
        category = classify_license(license_expr)
        if category.startswith("PROHIBITED"):
            status = "REJECTED"
        elif category == "UNKNOWN":
            status = "UNKNOWN"
        elif decision:
            status = "APPROVED_WITH_CONDITIONS" if category == "LGPL" else "PASS"
        else:
            status = "NEEDS_REVIEW"
        node = nodes.get(pkg_id, {})
        enabled_features = sorted(node.get("features", []))
        records.append({
            "repository": repository, "ecosystem": "cargo", "name": name, "version": version,
            "package_id": pkg_id, "source": pkg.get("source"), "checksum": pkg.get("checksum"),
            "upstream_url": pkg.get("repository"), "license": license_expr,
            "license_category": category, "license_evidence": evidence,
            "dependency_type": "direct" if pkg_id in direct_ids else "transitive",
            "enabled_features": enabled_features, "targets": [t.get("kind", []) for t in pkg.get("targets", [])],
            "status": status, "distribution": "not_established_by_metadata",
            "decision": decision,
        })
    return records


def lockfile_records(path: Path, repository: str) -> list[dict[str, Any]]:
    """Cargo.lock contains versions/checksums, not authoritative license metadata."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc
    records = []
    for pkg in data.get("package", []):
        records.append({
            "repository": repository, "ecosystem": "cargo-lock", "name": pkg.get("name", "unknown"),
            "version": pkg.get("version", "unknown"), "source": pkg.get("source"),
            "checksum": pkg.get("checksum"), "license": None, "license_category": "UNKNOWN",
            "license_evidence": [{"kind": "lockfile_only", "path": str(path)}],
            "dependency_type": "unresolved_without_cargo_metadata", "enabled_features": [],
            "status": "UNKNOWN", "distribution": "not_established_by_lockfile",
        })
    return records


def scan_manifests(workspace: Path, repository: str) -> list[dict[str, Any]]:
    found = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or any(part in {".git", "target", "node_modules", ".venv"} for part in path.parts):
            continue
        ecosystem = MANIFEST_NAMES.get(path.name)
        if ecosystem:
            found.append({"repository": repository, "path": str(path.relative_to(workspace)),
                          "ecosystem": ecosystem, "status": "DISCOVERED",
                          "resolution": "requires ecosystem-specific resolver and license evidence"})
    return found


def markdown_report(report: dict[str, Any]) -> str:
    lines = ["# Dependency License Audit", "", f"- Policy: {report['policy_version']}",
             f"- Repository: {report['repository']}", f"- Generated: {report['generated_at']}",
             f"- Dependency records: {len(report['dependencies'])}", "",
             "## Status summary", "", "| Status | Count |", "|---|---:|"]
    for status, count in sorted(report["summary"].items()):
        lines.append(f"| {status} | {count} |")
    lines += ["", "## Dependencies", "", "| Package | Version | License | Directness | Status |",
              "|---|---|---|---|---|"]
    for item in report["dependencies"]:
        lines.append("| {name} | {version} | {license} | {dependency_type} | {status} |".format(
            name=item.get("name", ""), version=item.get("version", ""),
            license=item.get("license") or "UNKNOWN", dependency_type=item.get("dependency_type", ""),
            status=item.get("status", "UNKNOWN")))
    lines += ["", "## Manifest coverage", "", "| Path | Ecosystem | Discovery status | Resolution |",
              "|---|---|---|---|"]
    for item in report["manifests"]:
        lines.append(f"| {item['path']} | {item['ecosystem']} | {item['status']} | {item['resolution']} |")
    lines += ["", "## Enforcement", "",
              "This report is technical evidence, not legal approval. GPL/AGPL records are rejected. "
              "Unknown, unreviewed, or incomplete ecosystems block release. Human decisions must be "
              "recorded in the scoped decision registry; the scanner never grants approval.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--repository", default=None)
    parser.add_argument("--cargo-metadata", type=Path, action="append", default=[])
    parser.add_argument("--decisions", type=Path)
    parser.add_argument("--json", type=Path, default=Path("dependency-audit.json"))
    parser.add_argument("--markdown", type=Path, default=Path("DEPENDENCY_LICENSE_AUDIT.md"))
    parser.add_argument("--strict", action="store_true", help="fail for any non-PASS dependency or unresolved manifest")
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        parser.error(f"workspace is not a directory: {workspace}")
    repository = args.repository or workspace.name
    try:
        decisions = load_decisions(args.decisions)
        manifests = scan_manifests(workspace, repository)
        dependencies = []
        metadata_paths = {p.resolve() for p in args.cargo_metadata}
        for metadata_path in sorted(metadata_paths):
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            dependencies.extend(cargo_records(data, repository, decisions))
        # Without cargo metadata, preserve lockfile inventory but never infer licenses.
        if not metadata_paths:
            for lock in workspace.rglob("Cargo.lock"):
                if not any(part in {".git", "target"} for part in lock.parts):
                    dependencies.extend(lockfile_records(lock, repository))
        from datetime import datetime, timezone
        statuses: dict[str, int] = {}
        for item in dependencies:
            statuses[item["status"]] = statuses.get(item["status"], 0) + 1
        report = {"schema_version": "1.0", "policy_version": POLICY_VERSION, "repository": repository,
                  "generated_at": datetime.now(timezone.utc).isoformat(), "dependencies": dependencies,
                  "manifests": manifests, "summary": statuses,
                  "limitations": ["non-Cargo ecosystems are discovery-only in this version",
                                  "final image, firmware, font, codec and binary asset inventory is not established"]}
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.markdown.write_text(markdown_report(report), encoding="utf-8")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    unresolved = [m for m in manifests if m["ecosystem"] != "cargo" and m["ecosystem"] != "cargo-lock"]
    blocked = any(d["status"] != "PASS" for d in dependencies)
    if any(d["status"] == "REJECTED" for d in dependencies):
        print("BLOCKED: prohibited GPL/AGPL dependency detected")
    if args.strict and (blocked or unresolved):
        print(f"BLOCKED: {len(dependencies)} dependency records; {len(unresolved)} unresolved manifest(s)")
        return 1
    print(f"Inventory written: {args.json} and {args.markdown}")
    print(f"Dependencies: {len(dependencies)}; manifests: {len(manifests)}; unresolved manifests: {len(unresolved)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
