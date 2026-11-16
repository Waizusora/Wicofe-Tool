#!/usr/bin/env python3
"""Read-only check of local repository checkouts against the canonical inventory."""
from __future__ import annotations
import argparse
from pathlib import Path

def load_expected(path: Path) -> list[str]:
    names = [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if len(names) != len(set(names)):
        raise ValueError("expected repository list contains duplicate names")
    return names

def validate_inventory(workspace: Path, expected: list[str], allow_extra: bool = False) -> list[str]:
    actual = {p.name for p in workspace.iterdir() if p.is_dir() and not p.name.startswith(".")}
    wanted = set(expected)
    findings = [f"MISSING_CHECKOUT: {name}" for name in sorted(wanted - actual)]
    if not allow_extra:
        findings += [f"UNLISTED_DIRECTORY: {name}" for name in sorted(actual - wanted)]
    return findings

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--expected", type=Path, default=Path(__file__).resolve().parents[1] / "config" / "repository_inventory.txt")
    parser.add_argument("--allow-extra", action="store_true")
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        parser.error(f"workspace is not a directory: {workspace}")
    try:
        expected = load_expected(args.expected)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(f"cannot load expected inventory: {exc}")
    findings = validate_inventory(workspace, expected, args.allow_extra)
    for item in findings:
        print(f"FAIL {item}")
    if not findings:
        print(f"PASS: all {len(expected)} expected repository checkouts found")
    actual_count = sum(1 for p in workspace.iterdir() if p.is_dir() and not p.name.startswith("."))
    print(f"Expected: {len(expected)}; actual directories: {actual_count}; findings: {len(findings)}")
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())
