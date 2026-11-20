# Dependency License Auditor

**Status:** Initial implementation; Cargo, npm lockfile, Python requirements/uv/Poetry/Pipenv lockfile, Go module, Gradle lockfile, Maven dependency graph, Nix flake.lock and Bazel Bzlmod lockfile resolvers are implemented. Other non-Cargo ecosystems and release-image inventory remain incomplete.

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

- Cargo: resolved direct/transitive graph from `cargo metadata` in both default-feature and `--all-features` contexts. Metadata is captured without `--filter-platform` so target-conditioned dependency edges are retained; this is dependency resolution, not a compile/test for each target. Package features, dependency kinds, source identifiers, checksums and upstream license-file hashes are recorded. The cross-repository workflow resolves missing lockfiles in its disposable checkout and uploads generated lockfiles as audit evidence; this does not add lockfiles to source repositories.
- Build scripts and workflows: shell/Make/CMake/Meson/build.rs, GitHub workflow YAML, Docker/Compose inputs, hosted runner labels, apt package installs, common download/package-manager commands and container base images are inventoried. A `rust-toolchain.toml` pin is captured as a build-time toolchain dependency.
- Apt package inventories from actual CI runners can be attached as evidence artifacts; source scanning alone records declared package names/versions but does not resolve all transitive system packages.
- GitHub Actions: external `uses:` references in workflow and composite-action files are inventoried as build-time dependencies. Mutable tags and Docker action references remain UNKNOWN/NEEDS_REVIEW until their source commit and license are verified.
- Cargo.lock alone: package/version/source/checksum inventory only; license UNKNOWN.
- npm package-lock v2/v3, Python requirements/uv/Poetry/Pipenv lockfiles, Go modules, Gradle lockfiles, Maven dependency graphs, Nix flake.lock and Bazel Bzlmod lockfiles: dependency versions are resolved by dedicated adapters. Python and Go may require network access; Python resolution is binary-only. Missing license evidence or scoped approval remains blocked. pnpm, Yarn, Gradle build files without lockfiles, pnpm, Yarn, Conda, Bundler, Composer, CMake, Meson and Make remain discovery-only until dedicated resolvers exist.
- Vendored source, submodules, compiler toolchains, firmware, fonts, codecs, generated assets, binary payloads and final images require separate evidence/inventory; this initial tool does not certify them.
- SPDX expression operator/parenthesis grammar is validated before conservative policy classification. This does not verify every identifier against the current SPDX license/exception catalog or provide legal interpretation; invalid syntax is NEEDS_REVIEW and cannot be approved through the decision registry. GPL/AGPL-only or required branches are REJECTED. An expression with a non-GPL/AGPL OR branch (for example GPL OR BSD or GPL OR LGPL) becomes NEEDS_REVIEW until a human explicitly selects an exact branch; the auditor never chooses an alternative. AND expressions that require GPL/AGPL remain REJECTED. Selecting LGPL still requires verified LGPL conditions and explicit approval.

## Exit behavior

- 0: inventory generated; strict enforcement was not requested or no strict blocker exists.
- 1: strict mode found a dependency not PASS or an unresolved manifest.
- 2: invalid input, decision registry or I/O/parse failure.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## CI enforcement

The local workflow runs unit tests and produces an informational inventory. The cross-repository workflow checks out all 29 repositories and runs strict enforcement; repositories with no manifests remain UNKNOWN until a human coverage attestation is supplied. Wicofe-Build now has a reusable/tag-triggered release dependency gate that invokes this workflow using an immutable workflow revision and a separately pinned auditor source revision. This is an integration point, not a completed end-to-end release pipeline: final-image publication is not yet wired to a successful strict audit, and final image SBOM reconciliation remains outstanding. The latest verified cross-repository run is BLOCKED, as required by the unresolved findings documented in Wicofe-ThirdParty.

## Ecosystem resolver support

The auditor resolves dependency versions with native ecosystem data and keeps
license approval separate from graph resolution:

- **Cargo:** `cargo metadata` in default and all-features modes; Cargo.lock
  checksums and package metadata are retained.
- **npm:** package-lock v2/v3 package graph, exact versions, registry source,
  integrity value, and direct/transitive classification.
- **Python:** pip `install --dry-run --ignore-installed --report` for
  requirements files, plus exact-version parsing for uv, Poetry and Pipenv
  lockfiles. No packages are installed by this resolver.
- **Go:** `go list -m -json all` module graph and module checksums.
- **Gradle:** exact module coordinates from `gradle.lockfile`; Gradle build
  files without an adjacent lockfile remain unresolved.
- **Maven:** dependency graph from the pinned Maven dependency plugin's TGF output; the adapter invokes only the dependency-tree goal, not the project lifecycle.
- **Nix:** reachable flake inputs from `flake.lock`, retaining locked revisions and nar hashes. `follows` input forms not handled by the current adapter remain unresolved.
- **Bazel:** reachable Bzlmod modules from `MODULE.bazel.lock`; legacy or unsupported lock schemas remain unresolved.
- **pnpm, Yarn, Conda, Bundler, Composer and other discovered formats:**
  currently discovery-only and explicitly unresolved.

A resolved version is not a license finding. An upstream license-evidence record is provenance, not approval; even a recognized permissive license requires an explicit scoped decision for these non-Cargo resolver records. The resolver consults the
existing upstream evidence catalog and human decision registry using
ecosystem-qualified keys (`npm:name:version`, `python:name:version`,
`go:module-path:version`). Missing license evidence remains `UNKNOWN`;
evidence without an approved decision remains subject to the policy gate.
Resolver execution failures and unsupported manifests are recorded as
unresolved and cause strict mode to fail.

The Python requirements adapter uses pip's dry-run report with `--only-binary=:all:`, so it can require network access to resolve uncached packages. Source-only distributions remain unresolved. uv, Poetry and Pipenv lockfiles are parsed locally. The Go adapter uses the Go module tool and may also require network access. Maven resolution requires Maven and may fetch the pinned dependency plugin and project artifacts. npm package-lock v2/v3 is parsed locally without
running package lifecycle scripts. No resolver executes dependency build
scripts as part of graph discovery.
