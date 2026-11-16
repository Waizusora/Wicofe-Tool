# Dependency License Auditor

**Status:** Initial implementation; Cargo resolved-graph ingestion and manifest discovery are implemented. Non-Cargo dependency resolution and release-image inventory remain incomplete.

## Inputs

Generate authoritative Cargo package and resolution metadata in each repository checkout:

```sh
cargo metadata --format-version 1 --locked > cargo-metadata.json
```

For workspace-wide optional-feature review, run a separate metadata capture for each supported feature/target configuration; do not treat `--all-features` as a substitute for the supported build matrix. The auditor consumes the resolved package graph, workspace members, enabled features, package license metadata, repository URLs, source identifiers and checksums.

```sh
python3 scripts/audit_dependencies.py --workspace ../Wicofe-Kernel \
  --repository Wicofe-Kernel --cargo-metadata ../Wicofe-Kernel/cargo-metadata.json \
  --decisions config/dependency_license_decisions.json --strict \
  --json reports/Wicofe-Kernel.json --markdown reports/Wicofe-Kernel.md
```

Without Cargo metadata, Cargo.lock entries are still inventoried, but their license is UNKNOWN. A lockfile does not contain authoritative license declarations.

## Decision registry

`config/dependency_license_decisions.example.json` is an empty template. Copy it to a controlled decision file and add a scoped human decision only after review. Each entry is keyed by `cargo:NAME:VERSION` and requires status, reviewer, approver, evidence, scope and conditions. The scanner validates the presence of these fields; it does not authenticate reviewers, interpret legal terms or grant approval.

GPL/AGPL always produce REJECTED regardless of registry entries. LGPL becomes APPROVED_WITH_CONDITIONS only when a scoped decision exists. Other licenses require an explicit decision before PASS. Unknown or missing license metadata remains UNKNOWN.

## Current support and limitations

- Cargo: resolved direct/transitive graph from `cargo metadata`; package features and metadata recorded.
- Cargo.lock alone: package/version/source/checksum inventory only; license UNKNOWN.
- npm, pnpm, Yarn, Go, Maven, Gradle, CMake, Meson and Make: manifest discovery only; resolver integration is pending and strict mode blocks unresolved ecosystems.
- Vendored source, submodules, compiler toolchains, firmware, fonts, codecs, generated assets, binary payloads and final images require separate evidence/inventory; this initial tool does not certify them.
- SPDX expressions are classified conservatively for policy triggers, not fully parsed or legally interpreted.

## Exit behavior

- 0: inventory generated; strict enforcement was not requested or no strict blocker exists.
- 1: strict mode found a dependency not PASS or an unresolved manifest.
- 2: invalid input, decision registry or I/O/parse failure.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## CI enforcement

The workflow runs unit tests and strict inventory on the Wicofe-Tools checkout. This is not yet a 29-repository release gate. Cross-repository enforcement must provide checked-out repositories and Cargo metadata for each supported feature/target matrix, and must reconcile the final image SBOM before release.
