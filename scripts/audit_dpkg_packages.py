#!/usr/bin/env python3
"""Inventory newly installed Debian/Ubuntu packages using their copyright metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from audit_dependencies import POLICY_VERSION, classify_license


def read_package_delta(path: Path) -> list[dict[str, str]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"{path}:{line_number}: expected package, old version, new version")
        package, old_version, new_version = fields
        records.append({"name": package.split(":", 1)[0], "architecture": package.split(":", 1)[1]
                        if ":" in package else None, "old_version": old_version,
                        "version": new_version})
    return records


def copyright_metadata(root: Path, package: dict[str, str]) -> dict[str, Any]:
    path = root / "usr/share/doc" / package["name"] / "copyright"
    if not path.is_file():
        return {
            **package, "license_expressions": [], "license_category": "UNKNOWN",
            "status": "UNKNOWN", "source": None, "license_evidence": [],
        }
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    source = None
    upstream_name = None
    licenses = []
    for line in text.splitlines():
        if line.startswith("Source:"):
            source = line.partition(":")[2].strip()
        elif line.startswith("Upstream-Name:"):
            upstream_name = line.partition(":")[2].strip()
        elif line.startswith("License:"):
            value = line.partition(":")[2].strip()
            if value and value not in licenses:
                licenses.append(value)
    categories = [classify_license(value) for value in licenses]
    if any(category.startswith("PROHIBITED") for category in categories):
        category, status = next((category, "REJECTED") for category in categories
                                if category.startswith("PROHIBITED"))
    elif not licenses or any(category == "UNKNOWN" for category in categories):
        category, status = "UNKNOWN", "UNKNOWN"
    elif "LGPL" in categories or "LGPL_OPTIONAL_ALTERNATIVE" in categories:
        category, status = "LGPL", "NEEDS_REVIEW"
    else:
        category, status = "OTHER_REVIEW", "NEEDS_REVIEW"
    return {
        **package, "upstream_name": upstream_name, "source": source,
        "license_expressions": licenses, "license_category": category, "status": status,
        "license_evidence": [{
            "kind": "debian_copyright", "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license_declarations": licenses,
        }],
    }


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        f"# System Package License Inventory — {report['repository']}", "",
        f"- Policy: {report['policy_version']}",
        f"- Package records: {len(report['packages'])}",
        f"- REJECTED: {report['summary'].get('REJECTED', 0)}",
        f"- NEEDS_REVIEW: {report['summary'].get('NEEDS_REVIEW', 0)}",
        f"- UNKNOWN: {report['summary'].get('UNKNOWN', 0)}", "",
        "| Package | Version | License declarations | Status | Copyright evidence |",
        "|---|---|---|---|---|",
    ]
    for item in report["packages"]:
        licenses = "; ".join(item.get("license_expressions", [])) or "UNKNOWN"
        evidence = item.get("license_evidence", [])
        digest = evidence[0]["sha256"] if evidence else "missing"
        lines.append(f"| {item['name']} | {item['version']} | {licenses} | {item['status']} | {digest} |")
    lines += ["", "Packages in this inventory were added or changed in the CI build environment. "
              "They are not asserted to be part of the final Wicofe image. "
              "Missing copyright files and unrecognized declarations remain UNKNOWN."]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", type=Path, required=True, help="dpkg package delta TSV")
    parser.add_argument("--root", type=Path, default=Path("/"), help="root filesystem to inspect")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    packages = [copyright_metadata(args.root, item) for item in read_package_delta(args.packages)]
    summary: dict[str, int] = {}
    for item in packages:
        summary[item["status"]] = summary.get(item["status"], 0) + 1
    report = {
        "schema_version": "1.0", "policy_version": POLICY_VERSION,
        "repository": args.repository, "inventory_scope": "CI build environment package delta",
        "packages": packages, "summary": summary,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown.write_text(markdown_report(report), encoding="utf-8")
    print(f"System package records: {len(packages)}; summary={summary}")
    if summary.get("REJECTED", 0) or summary.get("UNKNOWN", 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
