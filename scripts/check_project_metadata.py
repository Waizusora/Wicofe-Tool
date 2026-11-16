#!/usr/bin/env python3
"""Check required baseline files in a local Wicofe checkout.

This is a local filesystem check; it does not query GitHub or certify license
compatibility. Run it from the root of a directory containing cloned repos.
"""
from __future__ import annotations

import argparse
from pathlib import Path

REQUIRED_FILES = ("README.md", "LICENSE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="repository directories")
    args = parser.parse_args()

    failures = 0
    for repo in args.paths:
        missing = [name for name in REQUIRED_FILES if not (repo / name).is_file()]
        if missing:
            failures += 1
            print(f"FAIL {repo}: missing {', '.join(missing)}")
        else:
            readme = (repo / "README.md").read_text(encoding="utf-8")
            license_text = (repo / "LICENSE").read_text(encoding="utf-8")
            if not readme.strip():
                failures += 1
                print(f"FAIL {repo}: README.md is empty")
            elif not license_text.strip():
                failures += 1
                print(f"FAIL {repo}: LICENSE is empty")
            else:
                print(f"PASS {repo}: README.md and LICENSE present")

    print(f"Checked {len(args.paths)} repositories; failures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
