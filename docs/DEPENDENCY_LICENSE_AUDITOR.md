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

## Decision and repository-coverage registries

`config/upstream_license_evidence.json` records upstream license text references, immutable source commit snapshots and upstream URLs. It is evidence input only and never constitutes approval. Mutable consumer refs remain NEEDS_REVIEW even when the tag/branch was resolved to a commit.

`config/dependency_license_decisions.example.json` is an empty template. Copy it to a controlled decision file and add a scoped human decision only after review.

`config/repository_dependency_coverage.example.json` records human-reviewed repositories where no dependency manifests are present. An empty repository is UNKNOWN by default; it is not silently treated as dependency-free. A coverage entry must state `reviewed_no_dependencies`, reviewer, approver, evidence, scope and conditions. This is a coverage attestation, not a license approval. Cargo entries are keyed by `cargo:NAME:VERSION`; GitHub Actions entries use `github-actions:OWNER/REPO:REF`. Each entry requires status, reviewer, approver, evidence, scope and conditions. LGPL entries additionally require `conditions_verified: true` after a human verifies the applicable source/relinking, notices, distribution and replacement obligations; an approval record without that field remains NEEDS_REVIEW. The scanner validates the presence of these fields; it does not authenticate reviewers, interpret legal terms or grant approval.

GPL/AGPL always produce REJECTED regardless of registry entries. LGPL becomes APPROVED_WITH_CONDITIONS only when a scoped decision exists. Other licenses require an explicit decision before PASS. Unknown or missing license metadata remains UNKNOWN.

## Current support and limitations

- Cargo: resolved direct/transitive graph from `cargo metadata`; package features, dependency kinds, source identifiers, checksums and upstream license-file hashes recorded. The cross-repository workflow resolves missing lockfiles in its disposable checkout and uploads the generated lockfiles as audit evidence; this does not add lockfiles to source repositories.
- GitHub Actions: external `uses:` references in workflow and composite-action files are inventoried as build-time dependencies. Mutable tags and Docker action references remain UNKNOWN/NEEDS_REVIEW until their source commit and license are verified.
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

The local workflow runs unit tests and produces an informational inventory. The cross-repository workflow checks out all 29 repositories and runs strict enforcement; repositories with no manifests remain UNKNOWN until a human coverage attestation is supplied. This workflow is not yet wired into the Wicofe-Build release pipeline. Cargo feature/target matrices and final image SBOM reconciliation are still required before release.
