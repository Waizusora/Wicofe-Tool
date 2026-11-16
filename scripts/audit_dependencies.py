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
import shlex
import sys
import subprocess
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
    "rust-toolchain.toml": "rust-toolchain",
}


def split_top_level_or(expression: str) -> list[str]:
    """Split an SPDX expression only at top-level OR operators."""
    branches = []
    depth = 0
    start = 0
    for match in re.finditer(r"\(|\)|\bOR\b", expression, re.IGNORECASE):
        token = match.group(0).upper()
        if token == "(":
            depth += 1
        elif token == ")":
            depth = max(0, depth - 1)
        elif token == "OR" and depth == 0:
            branches.append(expression[start:match.start()].strip())
            start = match.end()
    branches.append(expression[start:].strip())
    return [branch for branch in branches if branch]


def is_permissive_license_branch(branch: str) -> bool:
    value = branch.upper()
    if any(token in value for token in ("GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL",
                                        "OSL", "EUPL", "SSPL", "PROPRIETARY", "UNLICENSED")):
        return False
    return bool(re.search(
        r"\b(?:MIT|APACHE-2\.0|BSD-[23]-CLAUSE|ISC|ZLIB|UNLICENSE|CC0-1\.0|0BSD|BSL-1\.0)\b",
        value,
    ))


def license_alternatives(expression: str | None) -> list[str]:
    if not expression:
        return []
    return [branch for branch in split_top_level_or(expression)
            if is_permissive_license_branch(branch)]


def classify_license(expression: str | None) -> str:
    """Conservative SPDX identifier trigger classification; not a legal parser."""
    if not expression or not expression.strip():
        return "UNKNOWN"
    value = expression.upper()
    if re.search(r"\bAGPL(?:-|\\s)", value) or "AGPL" in value:
        return "PROHIBITED_AGPL"
    if re.search(r"\bGPL(?:-|\\s)", value) or re.search(r"\bGPL\b", value):
        return "PROHIBITED_GPL"
    if "LGPL" in value:
        return "LGPL_OPTIONAL_ALTERNATIVE" if license_alternatives(expression) else "LGPL"
    if any(token in value for token in ("MPL", "EPL", "CDDL", "OSL", "EUPL", "SSPL")):
        return "COPYLEFT_REVIEW"
    if any(token in value for token in ("UNLICENSED", "PROPRIETARY", "CUSTOM", "SEE LICENSE")):
        return "RESTRICTED_REVIEW"
    return "OTHER_REVIEW"


def load_decisions(path: Path | None) -> dict[str, dict[str, Any]]:
    """Load explicit human decisions; evidence fields are mandatory."""
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("policy_version") != POLICY_VERSION:
        raise ValueError(f"decision registry must declare policy_version {POLICY_VERSION}")
    records = data.get("decisions", {})
    if not isinstance(records, dict):
        raise ValueError("decision registry decisions must be a JSON object")
    required = ("status", "reviewer", "approved_by", "evidence", "scope", "conditions")
    for key, decision in records.items():
        if not isinstance(decision, dict):
            raise ValueError(f"decision {key!r} must be a JSON object")
        if any(not decision.get(field) for field in required):
            raise ValueError(f"decision {key!r} lacks required human-review fields")
        if decision.get("status") not in {"approved", "rejected"}:
            raise ValueError(f"decision {key!r} status must be 'approved' or 'rejected'")
    return records


def load_upstream_evidence(path: Path | None) -> dict[str, dict[str, Any]]:
    """Load source/license evidence only; entries do not imply approval."""
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("policy_version") != POLICY_VERSION:
        raise ValueError(f"upstream evidence must declare policy_version {POLICY_VERSION}")
    records = data.get("dependencies", {})
    if not isinstance(records, dict):
        raise ValueError("upstream evidence dependencies must be a JSON object")
    for key, record in records.items():
        if not record.get("license") or not re.fullmatch(r"[0-9a-fA-F]{40}", record.get("source_commit", "")):
            raise ValueError(f"upstream evidence {key!r} lacks license or immutable source commit")
        if not record.get("upstream_url") or not record.get("license_evidence"):
            raise ValueError(f"upstream evidence {key!r} lacks upstream URL or license evidence")
    return records


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


def cargo_lock_checksums(workspace: Path) -> dict[tuple[str, str, str | None], str]:
    """Read Cargo.lock SHA-256 checksums for registry packages."""
    checksums: dict[tuple[str, str, str | None], str] = {}
    for lockfile in workspace.rglob("Cargo.lock"):
        if any(part in {".git", "target", "node_modules", ".venv"} for part in lockfile.parts):
            continue
        try:
            data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"cannot parse {lockfile}: {exc}") from exc
        for package in data.get("package", []):
            checksum = package.get("checksum")
            if checksum:
                key = (package.get("name", ""), package.get("version", ""), package.get("source"))
                checksums[key] = checksum
    return checksums


def cargo_records(metadata: dict[str, Any], repository: str, decisions: dict[str, dict[str, Any]],
                  resolution_context: str = "default",
                  lock_checksums: dict[tuple[str, str, str | None], str] | None = None) -> list[dict[str, Any]]:
    packages = {p["id"]: p for p in metadata.get("packages", [])}
    resolve = metadata.get("resolve") or {}
    nodes = {n["id"]: n for n in resolve.get("nodes", [])}
    members = set(metadata.get("workspace_members", []))
    direct_ids: set[str] = set()
    reachable: set[str] = set()
    incoming: dict[str, list[dict[str, Any]]] = {}
    stack: list[str] = []
    for parent_id, node in nodes.items():
        parent_pkg = packages.get(parent_id, {})
        for dep in node.get("deps", []):
            child_id = dep.get("pkg")
            if child_id not in packages:
                continue
            if parent_id in members:
                direct_ids.add(child_id)
            stack.append(child_id)
            child_pkg = packages[child_id]
            dep_name = dep.get("name")
            declarations = []
            for declaration in parent_pkg.get("dependencies", []):
                if declaration.get("name") == dep_name or declaration.get("rename") == dep_name:
                    declarations.append({
                        field: declaration.get(field) for field in
                        ("name", "rename", "req", "kind", "optional", "uses_default_features",
                         "features", "target", "registry")
                    })
            incoming.setdefault(child_id, []).append({
                "parent_name": parent_pkg.get("name", parent_id),
                "parent_version": parent_pkg.get("version"),
                "dependency_name": dep_name,
                "dependency_kinds": dep.get("dep_kinds", []),
                "declarations": declarations,
            })
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
    lock_checksums = lock_checksums or {}
    for pkg_id in sorted(reachable):
        pkg = packages[pkg_id]
        name, version = pkg.get("name", "unknown"), pkg.get("version", "unknown")
        source = pkg.get("source")
        license_expr = pkg.get("license")
        license_file = pkg.get("license_file")
        evidence = []
        if license_expr:
            evidence.append({"kind": "cargo_metadata_license", "value": license_expr})
        manifest_path = pkg.get("manifest_path")
        package_root = Path(manifest_path).parent if manifest_path else None
        if package_root:
            if license_file:
                license_candidates = [package_root / license_file]
            else:
                try:
                    license_candidates = [item for item in package_root.iterdir()
                                          if item.is_file() and item.name.upper().startswith(
                                              ("LICENSE", "COPYING", "NOTICE"))]
                except OSError:
                    license_candidates = []
        else:
            license_candidates = []
        for file_path in sorted(set(license_candidates)):
            if file_path.is_file():
                raw = file_path.read_bytes()
                evidence.append({"kind": "license_file", "path": str(file_path),
                                 "sha256": hashlib.sha256(raw).hexdigest()})
        if license_file and not package_root:
            evidence.append({"kind": "unresolved_license_file_path", "path": license_file})
        elif license_file and not any(item.get("kind") == "license_file" for item in evidence):
            evidence.append({"kind": "missing_license_file", "path": str(package_root / license_file)})
        key = package_key(name, version)
        decision = decisions.get(key)
        category = classify_license(license_expr)
        safe_alternatives = license_alternatives(license_expr)
        if category.startswith("PROHIBITED"):
            status = "REJECTED"
        elif category == "UNKNOWN":
            status = "UNKNOWN"
        elif category == "LGPL":
            status = "APPROVED_WITH_CONDITIONS" if decision and decision.get("conditions_verified") else "NEEDS_REVIEW"
        elif category == "LGPL_OPTIONAL_ALTERNATIVE":
            selected = decision.get("selected_license") if decision else None
            normalized = {branch.upper() for branch in safe_alternatives}
            if decision and selected and selected.upper() in normalized:
                status = "PASS"
            elif decision and selected and "LGPL" in selected.upper() and decision.get("conditions_verified"):
                status = "APPROVED_WITH_CONDITIONS"
            else:
                status = "NEEDS_REVIEW"
        elif decision:
            status = "PASS"
        else:
            status = "NEEDS_REVIEW"
        node = nodes.get(pkg_id, {})
        enabled_features = sorted(node.get("features", []))
        incoming_edges = incoming.get(pkg_id, [])
        dependency_kinds = sorted({
            kind.get("kind") or "normal"
            for edge in incoming_edges
            for kind in edge.get("dependency_kinds", [])
        })
        source_commit = source.rsplit("#", 1)[-1] if source and source.startswith("git+") and "#" in source else None
        checksum = pkg.get("checksum") or lock_checksums.get((name, version, source))
        records.append({
            "repository": repository, "ecosystem": "cargo", "name": name, "version": version,
            "package_id": pkg_id, "source": source, "source_commit": source_commit,
            "checksum": checksum, "upstream_url": pkg.get("repository"), "license": license_expr,
            "license_category": category, "license_alternatives": safe_alternatives,
            "license_evidence": evidence,
            "dependency_type": "direct" if pkg_id in direct_ids else "transitive",
            "required_by": incoming_edges, "enabled_features": enabled_features,
            "dependency_kinds": dependency_kinds,
            "outgoing_dependency_kinds": sorted({
                kind.get("kind") or "normal"
                for dep in node.get("deps", []) for kind in dep.get("dep_kinds", [])
            }),
            "resolution_contexts": [resolution_context],
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
        for field in ("enabled_features", "dependency_kinds", "outgoing_dependency_kinds",
                      "resolution_contexts", "targets", "required_by"):
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


def scan_rust_toolchain(workspace: Path, repository: str,
                        decisions: dict[str, dict[str, Any]],
                        upstream_evidence: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    path = workspace / "rust-toolchain.toml"
    if not path.is_file():
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    toolchain = data.get("toolchain", {})
    channel = str(toolchain.get("channel", "UNKNOWN"))
    key = f"rust-toolchain:rustc:{channel}"
    evidence_record = upstream_evidence.get(key, {})
    decision = decisions.get(key)
    license_expr = evidence_record.get("license")
    category = classify_license(license_expr)
    if category.startswith("PROHIBITED"):
        status = "REJECTED"
    elif category == "UNKNOWN":
        status = "UNKNOWN"
    elif decision:
        status = "PASS"
    else:
        status = "NEEDS_REVIEW"
    license_evidence = [{"kind": "rust-toolchain-config", "path": "rust-toolchain.toml",
                         "channel": channel, "targets": toolchain.get("targets", []),
                         "components": toolchain.get("components", [])}]
    license_evidence.extend(evidence_record.get("license_evidence", []))
    return [{
        "repository": repository, "ecosystem": "rust-toolchain", "name": "rustc",
        "version": channel, "package_id": key,
        "source": evidence_record.get("upstream_url"),
        "source_commit": evidence_record.get("source_commit"),
        "upstream_url": evidence_record.get("upstream_url"),
        "license": license_expr, "license_category": category,
        "license_evidence": license_evidence,
        "dependency_type": "build-time", "enabled_features": [],
        "targets": toolchain.get("targets", []),
        "components": toolchain.get("components", []),
        "status": status, "distribution": "build toolchain; not established in final image",
        "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
        "decision": decision,
    }]


def scan_build_scripts(workspace: Path, repository: str,
                       decisions: dict[str, dict[str, Any]],
                       upstream_evidence: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Inventory build scripts, host tools, container images and pinned downloads."""
    scripts = []
    dependencies = []
    excluded = {".git", "target", "node_modules", ".venv", ".gradle"}
    script_names = {"Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "meson.build",
                    "build.rs", "Dockerfile", "Containerfile", "docker-compose.yml",
                    "docker-compose.yaml", "compose.yml", "compose.yaml"}
    script_extensions = {".sh", ".bash", ".ps1", ".bat", ".cmd", ".mk"}
    external_patterns = [
        ("apt-update", re.compile(r"\bapt(?:-get)?\s+update\b", re.IGNORECASE)),
        ("curl", re.compile(r"\bcurl\b", re.IGNORECASE)),
        ("wget", re.compile(r"\bwget\b", re.IGNORECASE)),
        ("git-clone", re.compile(r"\bgit\s+clone\b", re.IGNORECASE)),
        ("apt-install", re.compile(r"\bapt(?:-get)?\s+install\b", re.IGNORECASE)),
        ("dnf-install", re.compile(r"\bdnf\s+install\b", re.IGNORECASE)),
        ("yum-install", re.compile(r"\byum\s+install\b", re.IGNORECASE)),
        ("pacman-install", re.compile(r"\bpacman\s+-S\b", re.IGNORECASE)),
        ("brew-install", re.compile(r"\bbrew\s+install\b", re.IGNORECASE)),
        ("cargo-install", re.compile(r"\bcargo\s+install\b", re.IGNORECASE)),
        ("npm-install", re.compile(r"\bnpm\s+(?:install|i)\b", re.IGNORECASE)),
        ("pnpm-install", re.compile(r"\bpnpm\s+(?:add|install)\b", re.IGNORECASE)),
        ("pip-install", re.compile(r"\bpip(?:3)?\s+install\b", re.IGNORECASE)),
        ("maven", re.compile(r"\bmvn\b", re.IGNORECASE)),
        ("gradle", re.compile(r"\bgradle\b", re.IGNORECASE)),
        ("cmake-fetch", re.compile(r"\b(?:FetchContent_Declare|ExternalProject_Add|file\s*\(\s*DOWNLOAD)", re.IGNORECASE)),
        ("rustup-install", re.compile(r"\brustup\s+(?:target|toolchain)\s+add\b", re.IGNORECASE)),
        ("go-install", re.compile(r"\bgo\s+install\b", re.IGNORECASE)),
        ("git-submodule", re.compile(r"\bgit\s+submodule\s+(?:add|update)\b", re.IGNORECASE)),
        ("apk-install", re.compile(r"\bapk\s+add\b", re.IGNORECASE)),
        ("zypper-install", re.compile(r"\bzypper\s+install\b", re.IGNORECASE)),
    ]
    tool_patterns = [
        ("make", re.compile(r"\bmake\b", re.IGNORECASE)),
        ("tar", re.compile(r"\btar\b", re.IGNORECASE)),
        ("sha256sum", re.compile(r"\bsha256sum\b", re.IGNORECASE)),
        ("xorriso", re.compile(r"\bxorriso\b", re.IGNORECASE)),
        ("nasm", re.compile(r"\bnasm\b", re.IGNORECASE)),
        ("qemu-img", re.compile(r"\bqemu-img\b", re.IGNORECASE)),
        ("qemu-system", re.compile(r"\bqemu-system-[a-z0-9_-]+\b", re.IGNORECASE)),
        ("readelf", re.compile(r"\breadelf\b", re.IGNORECASE)),
        ("dpkg-query", re.compile(r"\bdpkg-query\b", re.IGNORECASE)),
        ("mtools", re.compile(r"\b(?:mformat|mcopy|mmd)\b", re.IGNORECASE)),
        ("grub-mkrescue", re.compile(r"\bgrub-mkrescue\b", re.IGNORECASE)),
        ("objcopy", re.compile(r"\bobjcopy\b", re.IGNORECASE)),
        ("linker", re.compile(r"\b(?:ld|lld)\b", re.IGNORECASE)),
        ("compiler", re.compile(r"\b(?:gcc|clang)\b", re.IGNORECASE)),
        ("rust-toolchain", re.compile(r"\b(?:rustc|cargo)\b", re.IGNORECASE)),
    ]
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        is_workflow = (".github" in path.parts and "workflows" in path.parts
                       and path.suffix.lower() in {".yml", ".yaml"})
        if (path.name not in script_names and not path.name.startswith("Dockerfile.")
                and path.suffix.lower() not in script_extensions and not is_workflow):
            continue
        try:
            raw = path.read_bytes()
            content = raw.decode("utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(workspace))
        matches = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            runner_match = re.match(r"^\s*runs-on:\s*(.+)$", line)
            if runner_match:
                runner = runner_match.group(1).strip().strip("'\"")
                dependencies.append({
                    "repository": repository, "ecosystem": "github-runner-image",
                    "name": runner, "version": runner if "latest" not in runner else "UNPINNED",
                    "package_id": f"github-runner-image:{runner}",
                    "license": None, "license_category": "UNKNOWN",
                    "license_evidence": [{"kind": "workflow_runs_on", "path": rel, "line": line_number}],
                    "dependency_type": "build-time", "enabled_features": [],
                    "status": "UNKNOWN", "distribution": "hosted build environment; not in final image",
                    "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
                })
        logical_lines = []
        pending = ""
        pending_line = 1
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not pending:
                pending_line = line_number
            pending = (pending + " " + stripped.rstrip("\\")).strip()
            if stripped.endswith("\\"):
                continue
            if pending:
                logical_lines.append((pending_line, pending))
            pending = ""
        if pending:
            logical_lines.append((pending_line, pending))
        for line_number, line in logical_lines:
            if line.startswith("#"):
                continue
            for label, pattern in external_patterns + tool_patterns:
                if pattern.search(line):
                    matches.append({"command": label, "line": line_number, "text": line.strip()[:300]})
            apt_match = re.search(r"\bapt(?:-get)?\s+install\b(.*)", line)
            if apt_match:
                for token in shlex.split(apt_match.group(1)):
                    if token.startswith("-"):
                        continue
                    package, separator, version = token.partition("=")
                    if not package:
                        continue
                    package_id = f"system-package:{package}:{version if separator else 'UNPINNED'}"
                    dependencies.append({
                        "repository": repository, "ecosystem": "system-package",
                        "name": package, "version": version if separator else "UNPINNED",
                        "package_id": package_id, "license": None, "license_category": "UNKNOWN",
                        "license_evidence": [{"kind": "apt_install", "path": rel, "line": line_number}],
                        "dependency_type": "build-time", "enabled_features": [],
                        "status": "UNKNOWN", "distribution": "build environment package; not in final image",
                        "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
                    })
        scripts.append({"repository": repository, "path": rel, "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "external_command_matches": matches,
                        "status": "NEEDS_REVIEW" if matches or path.name == "build.rs" else "DISCOVERED"})
        for match in matches:
            ecosystem = "build-script-command" if match["command"] in {p[0] for p in external_patterns} else "build-tool-command"
            dependencies.append({
                "repository": repository, "ecosystem": ecosystem,
                "name": match["command"], "version": "UNPINNED",
                "package_id": f"build-script:{rel}:{match['line']}:{match['command']}",
                "license": None, "license_category": "UNKNOWN",
                "license_evidence": [{"kind": "build_script_match", "path": rel,
                                     "line": match["line"], "text": match["text"]}],
                "dependency_type": "build-time", "enabled_features": [],
                "status": "UNKNOWN", "distribution": "build-time tool/command; payload not established",
                "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
            })
        if path.name in {"Dockerfile", "Containerfile"} or path.name.startswith("Dockerfile."):
            for line_number, line in enumerate(content.splitlines(), start=1):
                match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", line, re.IGNORECASE)
                if match and match.group(1).lower() != "scratch":
                    image = match.group(1)
                    dependencies.append({
                        "repository": repository, "ecosystem": "container-image",
                        "name": image, "version": "tag-or-digest-not-verified",
                        "package_id": f"container-image:{image}",
                        "license": None, "license_category": "UNKNOWN",
                        "license_evidence": [{"kind": "docker_from", "path": rel, "line": line_number}],
                        "dependency_type": "build-time", "enabled_features": [],
                        "status": "UNKNOWN", "distribution": "container base image; final inclusion unknown",
                        "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
                    })
        if path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            for line_number, line in enumerate(content.splitlines(), start=1):
                match = re.match(r"^\s*image:\s*([^\s#]+)", line, re.IGNORECASE)
                if match:
                    image = match.group(1).strip("'\"")
                    dependencies.append({
                        "repository": repository, "ecosystem": "container-image",
                        "name": image, "version": "tag-or-digest-not-verified",
                        "package_id": f"container-image:{image}",
                        "license": None, "license_category": "UNKNOWN",
                        "license_evidence": [{"kind": "compose_image", "path": rel, "line": line_number}],
                        "dependency_type": "runtime", "enabled_features": [],
                        "status": "UNKNOWN", "distribution": "container image; final inclusion unknown",
                        "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
                    })

        version_values = {m.group(1): m.group(2) for m in re.finditer(
            r"^\s*([A-Z0-9_]*VERSION)\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)}
        checksum_values = {m.group(1): m.group(2).lower() for m in re.finditer(
            r"^\s*([A-Z0-9_]*SHA256)\s*=\s*['\"]([0-9a-fA-F]{64})['\"]", content, re.MULTILINE)}
        for url_match in re.finditer(r"https?://[^'\"\s]+", content):
            raw_url = url_match.group(0).rstrip("),")
            url = raw_url
            for variable, value in version_values.items():
                url = url.replace(" + variable + ", value)
            release_match = re.search(
                r"github\.com/([^/]+)/([^/]+)/releases/download/v([^/]+)/([^/?]+)", url)
            if not release_match:
                continue
            owner, repo_name, version, filename = release_match.groups()
            component_name = "Limine" if repo_name.lower() == "limine" else repo_name
            key = f"downloaded-artifact:{component_name}:{version}"
            evidence_record = upstream_evidence.get(key, {})
            decision = decisions.get(key)
            checksum = next(iter(checksum_values.values()), None)
            published_checksum = evidence_record.get("release_asset_sha256")
            checksum_matches = bool(checksum and published_checksum and checksum == published_checksum.lower())
            license_expr = evidence_record.get("license")
            category = classify_license(license_expr)
            if checksum and published_checksum and not checksum_matches:
                status = "BLOCKED"
            elif category.startswith("PROHIBITED"):
                status = "REJECTED"
            elif category == "UNKNOWN":
                status = "UNKNOWN"
            elif decision:
                status = "PASS"
            else:
                status = "NEEDS_REVIEW"
            line_number = content[:url_match.start()].count("\n") + 1
            license_evidence = [{"kind": "build_script_download", "path": rel,
                                 "line": line_number, "url": url}]
            license_evidence.extend(evidence_record.get("license_evidence", []))
            notices_in_iso = ("NOTICE_DEST" in content and "3RDPARTY.md" in content
                              and "COPYING" in content)
            dependencies.append({
                "repository": repository, "ecosystem": "downloaded-artifact",
                "name": component_name, "version": version,
                "package_id": key, "source": evidence_record.get("upstream_url"),
                "source_commit": evidence_record.get("source_commit"),
                "upstream_url": evidence_record.get("upstream_url"),
                "download_url": url, "filename": filename,
                "checksum": checksum, "checksum_verified_against_release_metadata": checksum_matches,
                "license": license_expr, "license_category": category,
                "license_evidence": license_evidence,
                "bundled_component_licenses": evidence_record.get("bundled_component_licenses", []),
                "tag_signature_verified": evidence_record.get("tag_signature_verified", False),
                "dependency_type": "build-time", "enabled_features": [],
                "status": status,
                "distribution": ("/boot/limine/licenses/limine-12.9.6/ (COPYING and 3RDPARTY.md staged by build script)"
                                if notices_in_iso else "final distribution path not established"),
                "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
                "decision": decision,
            })
    return scripts, dependencies


def scan_github_actions(workspace: Path, repository: str,
                       decisions: dict[str, dict[str, Any]],
                       upstream_evidence: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Inventory external actions as build-time dependencies; never auto-approve."""
    upstream_evidence = upstream_evidence or {}
    records = []
    uses_pattern = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
    action_files = list(workspace.glob(".github/workflows/*.yml"))
    action_files += list(workspace.glob(".github/workflows/*.yaml"))
    action_files += list(workspace.glob(".github/actions/**/action.yml"))
    action_files += list(workspace.glob(".github/actions/**/action.yaml"))
    for path in sorted(set(action_files)):
        content = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(content.splitlines(), start=1):
            found = uses_pattern.match(line)
            if not found:
                continue
            value = found.group(1).strip("'\"")
            if value.startswith(("./", "../")):
                continue
            if value.startswith("docker://"):
                name, revision = value[len("docker://"):], "container-reference"
                source = value
            else:
                if "@" not in value:
                    name, revision = value, "UNPINNED"
                else:
                    name, revision = value.rsplit("@", 1)
                source = f"https://github.com/{name.split('/')[0]}/{name.split('/')[1]}" if "/" in name else None
            key = f"github-actions:{name}:{revision}"
            evidence_record = upstream_evidence.get(key, {})
            decision = decisions.get(key)
            license_expr = evidence_record.get("license")
            category = classify_license(license_expr)
            immutable_ref = bool(re.fullmatch(r"[0-9a-fA-F]{40}", revision))
            if category.startswith("PROHIBITED"):
                status = "REJECTED"
            elif category == "UNKNOWN":
                status = "UNKNOWN"
            elif not immutable_ref:
                status = "NEEDS_REVIEW"
            elif decision:
                if category == "LGPL" and not decision.get("conditions_verified"):
                    status = "NEEDS_REVIEW"
                else:
                    status = "APPROVED_WITH_CONDITIONS" if category == "LGPL" else "PASS"
            else:
                status = "NEEDS_REVIEW"
            license_evidence = [{"kind": "workflow_uses", "path": str(path.relative_to(workspace)),
                                 "line": line_number, "value": value}]
            license_evidence.extend(evidence_record.get("license_evidence", []))
            source_commit = evidence_record.get("source_commit")
            if not source_commit and immutable_ref:
                source_commit = revision
            records.append({
                "repository": repository, "ecosystem": "github-actions", "name": name,
                "version": revision, "package_id": key, "source": evidence_record.get("upstream_url") or source,
                "source_commit": source_commit, "upstream_url": evidence_record.get("upstream_url") or source,
                "license": license_expr, "license_category": category,
                "license_evidence": license_evidence, "ref_is_immutable": immutable_ref,
                "dependency_type": "build-time", "enabled_features": [],
                "status": status, "distribution": "build-time dependency; release inclusion not established",
                "security_status": "NOT_ASSESSED", "maintenance_status": "NOT_ASSESSED",
                "decision": decision,
            })
    return records


def scan_assets(workspace: Path, repository: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Hash non-code assets and vendored/generated trees without assuming approval."""
    assets: list[dict[str, Any]] = []
    license_documents: list[dict[str, Any]] = []
    vendor_dirs = {"vendor", "vendors", "third_party", "third-party", "external"}
    generated_dirs = {"generated", "autogenerated", "autogen"}
    asset_dirs = {"assets", "asset", "firmware", "fonts", "font", "codecs", "codec",
                  "schemas", "schema", "resources"}
    categories = {
        ".fw": "firmware", ".bin": "binary_or_firmware", ".rom": "firmware",
        ".hex": "firmware", ".uf2": "firmware", ".dfu": "firmware", ".cap": "firmware",
        ".elf": "firmware_or_executable", ".efi": "firmware", ".dtb": "firmware",
        ".dtbo": "firmware", ".ko": "kernel_module", ".o": "object_binary",
        ".obj": "object_binary", ".wasm": "binary_module", ".jar": "java_binary",
        ".class": "java_binary",
        ".ttf": "font", ".otf": "font", ".woff": "font", ".woff2": "font",
        ".bdf": "font", ".pcf": "font", ".psf": "font", ".fnt": "font",
        ".fon": "font", ".ttc": "font",
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
        ".gz": "archive_asset", ".xz": "archive_asset", ".zst": "archive_asset",
        ".br": "archive_asset", ".lz4": "archive_asset", ".7z": "archive_asset",
        ".apk": "package_binary", ".aab": "package_binary", ".deb": "package_binary",
        ".rpm": "package_binary", ".msi": "package_binary", ".dmg": "package_binary",
        ".pkg": "package_binary", ".iso": "disk_image", ".img": "disk_image",
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
        in_asset_dir = bool(parts & asset_dirs)
        if "schema" in name and path.suffix.lower() in {".json", ".yaml", ".yml"}:
            category = "schema"
        if not (category or vendor or generated or in_asset_dir):
            continue
        raw = path.read_bytes()
        assets.append({
            "repository": repository, "path": str(rel),
            "category": category or ("vendored_source" if vendor else "generated_source" if generated else "asset_unknown"),
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


def git_revision(workspace: Path) -> str | None:
    """Capture the exact checked-out repository revision for audit reproducibility."""
    try:
        result = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        value = result.stdout.strip()
        return value if re.fullmatch(r"[0-9a-fA-F]{40}", value) else None
    except (OSError, subprocess.SubprocessError):
        return None


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
    lines += ["", "## Build scripts", "",
              "| Path | External command matches | SHA-256 |", "|---|---|---|"]
    for item in report["build_scripts"]:
        lines.append(f"| {item['path']} | {len(item['external_command_matches'])} | {item['sha256']} |")
    lines += ["", "## Non-manifest assets and provenance", "",
              f"- Build scripts inventoried: {len(report['build_scripts'])}",
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
    parser.add_argument("--evidence", type=Path, help="upstream license/source evidence catalog")
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
        upstream_evidence = load_upstream_evidence(args.evidence)
        manifests = scan_manifests(workspace, repository)
        assets, provenance = scan_assets(workspace, repository)
        license_documents = [item for item in provenance if "sha256" in item]
        submodules = [item for item in provenance if "url" in item]
        dependencies = []
        metadata_paths = {p.resolve() for p in args.cargo_metadata}
        lock_checksums = cargo_lock_checksums(workspace)
        for metadata_path in sorted(metadata_paths):
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            dependencies.extend(cargo_records(data, repository, decisions, metadata_path.stem, lock_checksums))
        build_scripts, build_dependencies = scan_build_scripts(workspace, repository, decisions, upstream_evidence)
        dependencies.extend(build_dependencies)
        dependencies.extend(scan_rust_toolchain(workspace, repository, decisions, upstream_evidence))
        dependencies.extend(scan_github_actions(workspace, repository, decisions, upstream_evidence))
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
        cargo_manifest_count = sum(m["ecosystem"] == "cargo" for m in manifests)
        unresolved = [m for m in manifests if m["ecosystem"] not in {"cargo", "cargo-lock", "rust-toolchain"}]
        if len(metadata_paths) < cargo_manifest_count:
            unresolved.extend(m for m in manifests if m["ecosystem"] == "cargo")
        if not manifests:
            coverage_status = "REVIEWED_NO_DEPENDENCIES" if coverage_decision else "UNKNOWN"
        elif unresolved:
            coverage_status = "INCOMPLETE"
        else:
            coverage_status = "RESOLVED_MANIFESTS"
        report = {"schema_version": "1.0", "policy_version": POLICY_VERSION, "repository": repository,
                  "repository_commit": git_revision(workspace),
                  "generated_at": datetime.now(timezone.utc).isoformat(), "dependencies": dependencies,
                  "coverage_status": coverage_status, "coverage_decision": coverage_decision,
                  "manifests": manifests, "build_scripts": build_scripts, "assets": assets,
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
    blocked = (coverage_status in {"UNKNOWN", "INCOMPLETE"}
               or bool(unresolved)
               or any(d["status"] not in {"PASS", "APPROVED_WITH_CONDITIONS"} for d in dependencies)
               or any(s["external_command_matches"] for s in build_scripts)
               or any(a["status"] != "PASS" for a in assets) or bool(submodules))
    if any(d["status"] == "REJECTED" for d in dependencies):
        print("BLOCKED: prohibited GPL/AGPL dependency detected")
    if args.strict and (blocked or unresolved):
        script_matches = sum(len(s["external_command_matches"]) for s in build_scripts)
        print(f"BLOCKED: coverage={coverage_status}; {len(dependencies)} dependency records; "
              f"{len(unresolved)} unresolved manifest(s); {script_matches} build-command match(es); "
              f"{len(assets)} asset(s); {len(submodules)} submodule(s)")
        return 1
    print(f"Inventory written: {args.json} and {args.markdown}")
    print(f"Coverage: {coverage_status}; dependencies: {len(dependencies)}; manifests: {len(manifests)}; unresolved manifests: {len(unresolved)}; build scripts: {len(build_scripts)}; assets: {len(assets)}; submodules: {len(submodules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
