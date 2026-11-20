#!/usr/bin/env python3
"""Generate a repository-wide dependency manifest coverage inventory."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_dependencies import scan_manifests


def build_report(manifest_path: Path, workspace: Path) -> dict:
    config = json.loads(manifest_path.read_text(encoding="utf-8"))
    repositories = config["repositories"]
    rows = []
    for repository in repositories:
        root = workspace / repository
        if not root.is_dir():
            raise ValueError(f"repository workspace is missing: {repository}")
        manifests = scan_manifests(root, repository)
        rows.append({
            "repository": repository,
            "manifest_count": len(manifests),
            "coverage": "MANIFESTS_DISCOVERED" if manifests else "NO_SUPPORTED_MANIFEST_FOUND",
            "manifests": manifests,
        })
    return {
        "schema_version": "1.0",
        "repository_count": len(rows),
        "repositories_with_manifests": sum(row["manifest_count"] > 0 for row in rows),
        "repositories_without_supported_manifests": sum(row["manifest_count"] == 0 for row in rows),
        "repositories": rows,
        "limitations": [
            "Manifest discovery does not resolve dependencies or establish license compliance.",
            "Repositories without supported manifests are not attested as dependency-free.",
            "Build scripts, CI actions, downloaded artifacts, submodules, and binary assets require separate review.",
        ],
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Repository Dependency Manifest Coverage",
        "",
        f"- Repositories scanned: {report['repository_count']}",
        f"- Repositories with supported manifests: {report['repositories_with_manifests']}",
        f"- Repositories without supported manifests: {report['repositories_without_supported_manifests']}",
        "",
        "| Repository | Manifest count | Discovery status |",
        "|---|---:|---|",
    ]
    for row in report["repositories"]:
        lines.append(f"| {row['repository']} | {row['manifest_count']} | {row['coverage']} |")
    lines.extend(["", "## Discovered manifest paths", ""])
    for row in report["repositories"]:
        if row["manifests"]:
            lines.append(f"### {row['repository']}")
            for manifest in row["manifests"]:
                lines.append(f"- `{manifest['path']}` — {manifest['ecosystem']}")
            lines.append("")
    lines.extend(["## Interpretation", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.manifest, args.workspace)
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.markdown.write_text(render_markdown(report), encoding="utf-8")
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Manifest coverage written: {args.markdown}; repositories={report['repository_count']}; "
          f"with_manifests={report['repositories_with_manifests']}; "
          f"without_supported_manifests={report['repositories_without_supported_manifests']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
