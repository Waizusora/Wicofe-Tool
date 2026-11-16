#!/usr/bin/env python3
"""Validate the baseline README across a checked-out Wicofe repository set."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    repositories = manifest.get("repositories")
    if manifest.get("schema_version") != 1 or not isinstance(repositories, list) or not repositories:
        parser.error("manifest must have schema_version 1 and a non-empty repositories list")
    if len(repositories) != len(set(repositories)):
        parser.error("manifest contains duplicate repository names")

    failures = 0
    warnings = 0
    for name in repositories:
        if not isinstance(name, str) or not name or "/" in name or name in {".", ".."}:
            parser.error(f"invalid repository name: {name!r}")
        repo = args.workspace / name
        readme = repo / "README.md"
        if not repo.is_dir() or not readme.is_file() or not readme.read_text(encoding="utf-8").strip():
            failures += 1
            print(f"FAIL {name}: repository checkout or non-empty README.md missing")
            continue
        license_file = repo / "LICENSE"
        if not license_file.is_file() or not license_file.read_text(encoding="utf-8").strip():
            warnings += 1
            print(f"WARN {name}: LICENSE missing or empty; resolve repository licensing status")
        else:
            print(f"PASS {name}: README.md present; LICENSE file present (not legally audited)")

    print(f"Checked {len(repositories)} repositories; failures: {failures}; warnings: {warnings}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
