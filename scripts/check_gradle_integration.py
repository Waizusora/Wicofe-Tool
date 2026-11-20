#!/usr/bin/env python3
"""Validate a real Gradle resolution graph exported by the integration fixture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_dependencies import parse_gradle_resolution_graph


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("graph", type=Path)
    args = parser.parse_args()
    rows, failures = parse_gradle_resolution_graph(
        args.graph.read_text(encoding="utf-8")
    )
    if failures:
        raise SystemExit("Gradle integration graph contains unresolved dependencies: "
                         + "; ".join(failures))
    by_name = {row["name"]: row for row in rows}
    required = {
        "com.google.guava:guava",
        "org.junit.jupiter:junit-jupiter-api",
        "org.apache.commons:commons-lang3",
    }
    missing = sorted(required - by_name.keys())
    if missing:
        raise SystemExit("Gradle integration graph is missing modules: " + ", ".join(missing))
    substituted = by_name["org.apache.commons:commons-lang3"]
    if not any(
        "org.apache.commons:commons-text" in edge.get("requested", "")
        and edge.get("selected", "").startswith("org.apache.commons:commons-lang3:")
        for edge in substituted["selection_edges"]
    ):
        raise SystemExit("Gradle integration graph did not preserve dependency substitution")
    if by_name["org.apache.commons:commons-lang3"]["dependency_type"] != "direct":
        raise SystemExit("Gradle constraints incorrectly changed a selected direct dependency")
    guava = by_name["com.google.guava:guava"]
    if ":library" not in guava["projects"]:
        raise SystemExit("Gradle integration graph lost :library project provenance for Guava")
    if not any(row["variants"] for row in rows):
        raise SystemExit("Gradle integration graph contains no selected variant metadata")
    if not any(
        edge.get("selected_variant")
        for row in rows for edge in row["edges"]
    ):
        raise SystemExit("Gradle integration graph contains no edge selected-variant metadata")
    print(json.dumps({
        "dependency_count": len(rows),
        "required_modules": sorted(required),
        "variant_records": sum(len(row["variants"]) for row in rows),
        "edge_count": sum(len(row["edges"]) for row in rows),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
