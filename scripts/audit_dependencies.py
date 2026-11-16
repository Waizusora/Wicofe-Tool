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
    "build.rs": "cargo-build-script",
    "package.json": "npm",
    "package-lock.json": "npm-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "yarn.lock": "yarn-lock",
    "go.mod": "go",
    "go.sum": "go-lock",
    "go.work": "go-workspace",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
    "gradle.lockfile": "gradle-lock",
    "libs.versions.toml": "gradle-version-catalog",
    "pyproject.toml": "python",
    "requirements.txt": "python-requirements",
    "requirements-dev.txt": "python-requirements",
    "poetry.lock": "poetry-lock",
    "uv.lock": "uv-lock",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv-lock",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler-lock",
    "composer.json": "composer",
    "composer.lock": "composer-lock",
    "conanfile.py": "conan",
    "conanfile.txt": "conan",
    "vcpkg.json": "vcpkg",
    "meson.build": "meson",
    "CMakeLists.txt": "cmake",
    "CMakePresets.json": "cmake-presets",
    "Makefile": "make",
    ".gitmodules": "git-submodule",
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


def load_coverage(path: Path | None) -> dict[str, dict[str, Any]]:
    """Load human-reviewed evidence for repositories with no dependency manifests."""
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("policy_version") != POLICY_VERSION:
        raise ValueError(f"coverage registry must declare policy_version {POLICY_VERSION}")
    records = data.get("repositories", {})
    if not isinstance(records, dict):
        raise ValueError("coverage registry repositories must be a JSON object")
    required = ("status", "reviewer", "approved_by", "evidence", "scope", "conditions")
    for repository, record in records.items():
        if not isinstance(record, dict) or record.get("status") != "reviewed_no_dependencies":
            raise ValueError(f"coverage record {repository!r} must use status 'reviewed_no_dependencies'")
        if any(not record.get(field) for field in required):
            raise ValueError(f"coverage record {repository!r} lacks required human-review fields")
    return records


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
        package_root = Path(pkg.get("manifest_path", "")).parent
        license_candidates = [package_root / license_file] if license_file else [
            package_root / candidate for candidate in
            ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.LESSER", "NOTICE")
        ]
        for file_path in license_candidates:
            if file_path.is_file():
                raw = file_path.read_bytes()
                evidence.append({"kind": "license_file", "path": str(file_path),
                                 "sha256": hashlib.sha256(raw).hexdigest()})
        if license_file and not any(item.get("kind") == "license_file" for item in evidence):
            evidence.append({"kind": "missing_license_file", "path": str(package_root / license_file)})
        key = package_key(name, version)
        decision = decisions.get(key)
        category = classify_license(license_expr)
        if category.startswith("PROHIBITED"):
            status = "REJECTED"
        elif category == "UNKNOWN":
            status = "UNKNOWN"
        elif decision:
            if category == "LGPL" and not decision.get("conditions_verified"):
                status = "NEEDS_REVIEW"
            else:
                status = "APPROVED_WITH_CONDITIONS" if category == "LGPL" else "PASS"
        else:
            status = "NEEDS_REVIEW"
        node = nodes.get(pkg_id, {})
        enabled_features = sorted(node.get("features", []))
        dependency_kinds = sorted({
            kind.get("kind") or "normal"
            for dep in node.get("deps", [])
            for kind in dep.get("dep_kinds", [])
        })
        source = pkg.get("source")
        source_commit = source.rsplit("#", 1)[-1] if source and source.startswith("git+") and "#" in source else None
        records.append({
            "repository": repository, "ecosystem": "cargo", "name": name, "version": version,
            "package_id": pkg_id, "source": source, "source_commit": source_commit,
            "checksum": pkg.get("checksum"),
            "upstream_url": pkg.get("repository"), "license": license_expr,
            "license_category": category, "license_evidence": evidence,
            "dependency_type": "direct" if pkg_id in direct_ids else "transitive",
            "enabled_features": enabled_features, "dependency_kinds": dependency_kinds,
            "targets": [t.get("kind", []) for t in pkg.get("targets", [])],
            "status": status, "distribution": "not_established_by_metadata",
            "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
            "decision": decision,
        })
    return records


def merge_cargo_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge repeated metadata captures while preserving conflicting license evidence."""
    grouped: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record.get("package_id") or f"{record.get('name')}@{record.get('version')}"
        if key not in grouped:
            grouped[key] = record
            continue
        current = grouped[key]
        for field in ("enabled_features", "dependency_kinds", "targets"):
            current[field] = sorted({json.dumps(v, sort_keys=True) for v in current.get(field, [])}
                                    | {json.dumps(v, sort_keys=True) for v in record.get(field, [])})
            current[field] = [json.loads(v) for v in current[field]]
        if record.get("dependency_type") == "direct":
            current["dependency_type"] = "direct"
        evidence = current.setdefault("license_evidence", [])
        for item in record.get("license_evidence", []):
            if item not in evidence:
                evidence.append(item)
        if current.get("license") != record.get("license"):
            license_values = {str(current.get("license")), str(record.get("license"))}
            current["status"] = "UNKNOWN"
            current["license_category"] = "UNKNOWN"
            current["license"] = None
            evidence.append({"kind": "conflicting_license_metadata", "values": sorted(license_values)})
    return [grouped[key] for key in sorted(grouped)]


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


def scan_assets(workspace: Path, repository: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Hash non-code assets and vendored/generated trees without assuming approval."""
    assets: list[dict[str, Any]] = []
    license_documents: list[dict[str, Any]] = []
    vendor_dirs = {"vendor", "vendors", "third_party", "third-party", "external"}
    generated_dirs = {"generated", "autogenerated", "autogen"}
    categories = {
        ".fw": "firmware", ".bin": "binary_or_firmware", ".rom": "firmware",
        ".hex": "firmware", ".uf2": "firmware", ".dfu": "firmware", ".cap": "firmware",
        ".ttf": "font", ".otf": "font", ".woff": "font", ".woff2": "font",
        ".bdf": "font", ".pcf": "font", ".psf": "font",
        ".so": "native_library", ".a": "native_library", ".dll": "native_library",
        ".dylib": "native_library", ".flac": "media_codec_asset", ".ogg": "media_codec_asset",
        ".opus": "media_codec_asset", ".wav": "media_codec_asset", ".mp3": "media_codec_asset",
        ".aac": "media_codec_asset", ".m4a": "media_codec_asset", ".mp4": "media_codec_asset",
        ".mkv": "media_codec_asset", ".webm": "media_codec_asset",
        ".proto": "schema", ".fbs": "schema", ".capnp": "schema", ".avsc": "schema",
        ".xsd": "schema", ".dtd": "schema", ".jsonschema": "schema",
        ".png": "image_asset", ".jpg": "image_asset", ".jpeg": "image_asset",
        ".webp": "image_asset", ".ico": "image_asset", ".icns": "image_asset",
        ".pdf": "document_asset", ".zip": "archive_asset", ".tar": "archive_asset",
        ".gz": "archive_asset", ".xz": "archive_asset", ".7z": "archive_asset",
        ".apk": "package_binary", ".aab": "package_binary",
    }
    excluded = {".git", "target", "node_modules", ".venv", ".gradle"}
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        rel = path.relative_to(workspace)
        parts = {part.lower() for part in rel.parts[:-1]}
        name = path.name.lower()
        if name.startswith(("license", "copying", "notice")):
            raw = path.read_bytes()
            license_documents.append({"path": str(rel), "size_bytes": len(raw),
                                      "sha256": hashlib.sha256(raw).hexdigest()})
        category = categories.get(path.suffix.lower())
        vendor = bool(parts & vendor_dirs)
        generated = bool(parts & generated_dirs)
        if "schema" in name and path.suffix.lower() in {".json", ".yaml", ".yml"}:
            category = "schema"
        if not (category or vendor or generated):
            continue
        raw = path.read_bytes()
        assets.append({
            "repository": repository, "path": str(rel), "category": category or ("vendored_source" if vendor else "generated_source"),
            "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "status": "UNKNOWN" if category or vendor else "NEEDS_REVIEW",
            "license_evidence": [], "distribution": "not_established",
        })
    submodules = []
    for gitmodules in sorted(workspace.rglob(".gitmodules")):
        if any(part in excluded for part in gitmodules.parts):
            continue
        text = gitmodules.read_text(encoding="utf-8", errors="replace")
        current: dict[str, str] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[submodule "):
                if current:
                    submodules.append(current)
                current = {"repository": repository, "status": "UNKNOWN",
                           "manifest": str(gitmodules.relative_to(workspace))}
            elif "=" in stripped and current:
                key, value = (part.strip() for part in stripped.split("=", 1))
                if key in {"path", "url", "branch"}:
                    current[key] = value
        if current:
            submodules.append(current)
    for item in submodules:
        item["license_evidence"] = []
        item["source_commit"] = None
    return assets, [*license_documents, *submodules]


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
    sections = [
        ("Replacement / rejection queue", [d for d in report["dependencies"] if d.get("status") == "REJECTED"]),
        ("LGPL requiring conditional approval", [d for d in report["dependencies"] if d.get("license_category") == "LGPL"]),
        ("Unknown license evidence", [d for d in report["dependencies"] if d.get("status") == "UNKNOWN"]),
        ("Approved dependencies", [d for d in report["dependencies"] if d.get("status") in {"PASS", "APPROVED_WITH_CONDITIONS"}]),
    ]
    for heading, rows in sections:
        lines += ["", f"## {heading}", ""]
        if not rows:
            lines.append("None recorded.")
        else:
            for item in rows:
                lines.append(f"- {item.get('name')} {item.get('version')} — {item.get('license') or 'UNKNOWN'} ({item.get('status')})")
    lines += ["", "## Non-manifest assets and provenance", "",
              f"- Asset/vendor/generated-code records: {len(report['assets'])}",
              f"- License documents hashed: {len(report['license_documents'])}",
              f"- Submodule records: {len(report['submodules'])}", "",
              "| Path | Category | SHA-256 | Status |", "|---|---|---|---|"]
    for item in report["assets"]:
        lines.append(f"| {item['path']} | {item['category']} | {item['sha256']} | {item['status']} |")
    lines += ["", "### License and notice documents", "",
              "| Path | Size (bytes) | SHA-256 |", "|---|---:|---|"]
    for item in report["license_documents"]:
        lines.append(f"| {item['path']} | {item['size_bytes']} | {item['sha256']} |")
    for item in report["submodules"]:
        if "url" in item:
            lines.append(f"| {item.get('path', 'submodule')} | git submodule: {item.get('url')} | source commit UNKNOWN | UNKNOWN |")
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
    parser.add_argument("--coverage", type=Path, help="human-reviewed no-manifest coverage registry")
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
        coverage_records = load_coverage(args.coverage)
        coverage_decision = coverage_records.get(repository)
        manifests = scan_manifests(workspace, repository)
        assets, provenance = scan_assets(workspace, repository)
        license_documents = [item for item in provenance if "sha256" in item]
        submodules = [item for item in provenance if "url" in item]
        dependencies = []
        metadata_paths = {p.resolve() for p in args.cargo_metadata}
        for metadata_path in sorted(metadata_paths):
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            dependencies.extend(cargo_records(data, repository, decisions))
        dependencies = merge_cargo_records(dependencies)
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
                  "manifests": manifests, "assets": assets,
                  "license_documents": license_documents, "submodules": submodules,
                  "summary": statuses,
                  "limitations": ["non-Cargo ecosystems are discovery-only in this version",
                                  "final image, firmware, font, codec and binary asset inventory is not established"]}
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.markdown.write_text(markdown_report(report), encoding="utf-8")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    cargo_manifest_count = sum(m["ecosystem"] == "cargo" for m in manifests)
    unresolved = [m for m in manifests
                  if m["ecosystem"] not in {"cargo", "cargo-lock"}]
    if cargo_manifest_count != len(metadata_paths):
        unresolved.extend(m for m in manifests if m["ecosystem"] == "cargo")
    blocked = (any(d["status"] not in {"PASS", "APPROVED_WITH_CONDITIONS"} for d in dependencies)
               or any(a["status"] != "PASS" for a in assets) or bool(submodules))
    if any(d["status"] == "REJECTED" for d in dependencies):
        print("BLOCKED: prohibited GPL/AGPL dependency detected")
    if args.strict and (blocked or unresolved):
        print(f"BLOCKED: {len(dependencies)} dependency records; {len(unresolved)} unresolved manifest(s)")
        return 1
    print(f"Inventory written: {args.json} and {args.markdown}")
    print(f"Dependencies: {len(dependencies)}; manifests: {len(manifests)}; unresolved manifests: {len(unresolved)}; assets: {len(assets)}; submodules: {len(submodules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
