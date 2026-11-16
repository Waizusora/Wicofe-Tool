# Wicofe Developer Tooling Architecture 0.1

**Status:** Draft proposal. This document defines shared project tooling boundaries and quality requirements; it does not claim that the proposed tool suite is implemented.

## 1. Purpose

Wicofe-Tools provides shared developer, repository-maintenance, validation, release-support and diagnostic utilities used across multiple Wicofe repositories. It should reduce duplicated project automation without absorbing component-specific implementation tools.

## 2. Ownership boundaries

| Repository | Canonical responsibility |
|---|---|
| Wicofe-Tools | Shared repository checks, project-wide metadata/policy validation, common developer automation and generic artifact inspection |
| Wicofe-Build | Whole-system build graph and orchestration |
| Wicofe-SDK | Compiler/toolchain distribution, sysroots, SDK-specific helpers and templates |
| Wicofe-Tests | Canonical cross-repository test suites and test evidence |
| Wicofe-Image | System filesystem tree and bootable image construction/validation |
| ONWFS | ONWFS-specific formatter, inspector, checker, recovery and format tests |
| Wicofe-Kernel | Kernel-specific build, boot and runtime diagnostics |
| Wicofe-ThirdParty | Third-party provenance, license records and intake policy |
| Wicofe-Ports | Third-party port recipes and integration patches |

A shared utility may call a component-owned tool through a documented interface, but must not create a competing implementation or specification. For example, a generic disk metadata viewer may live here; an ONWFS semantic checker belongs to ONWFS.

## 3. Tool categories

Candidate categories include:

- **Repository hygiene:** required-file checks, documentation-link checks, metadata consistency and repository-map validation.
- **Policy validation:** SPDX syntax checks, license inventory aggregation, dependency/provenance reference checks and forbidden-artifact detection.
- **Artifact inspection:** generic ELF/object metadata, symbol, hash, manifest and build-provenance inspection.
- **Developer workflow:** workspace discovery, environment preflight, log collection and common command wrappers.
- **Release support:** version consistency, changelog/manifest validation and release artifact integrity checks.
- **Diagnostics:** structured log filtering and generic report generation.

The current project metadata checker is a limited baseline: it checks that supplied local repositories contain non-empty README.md and LICENSE files. It is not a license compatibility or complete policy auditor.

## 4. CLI conventions

Every command should document:
- command and subcommand names;
- positional arguments and options;
- supported host platforms and runtime requirements;
- input and output formats;
- exit status meanings;
- filesystem/network side effects;
- failure modes and recovery guidance;
- examples and version compatibility.

Prefer predictable subcommands, explicit options and non-interactive operation for CI. Destructive or modifying operations must require an explicit opt-in and, where appropriate, a confirmation step. A dry-run mode should be provided for operations that change repository or release state.

## 5. Input validation and safe execution

Treat repository paths, archives, manifests, URLs, environment variables and metadata as untrusted input. Canonicalize paths and prevent traversal outside designated workspaces. Avoid following unexpected symlinks, overwriting user data, shell interpolation of untrusted values, or executing downloaded files without integrity and provenance checks.

Default to read-only inspection. Any write operation must declare its destination and expected effects. Never silently change source files, Git history, release assets or shared caches.

## 6. Output and diagnostics

Support human-readable output for interactive use and stable machine-readable output (such as versioned JSON) for automation. Machine-readable schemas must be documented and versioned; do not change field meaning silently.

Diagnostics should include:
- stable error code where practical;
- concise problem statement;
- affected path/component;
- actionable remediation;
- relevant command context without leaking secrets.

Write logs to stderr and reserve stdout for primary command output when practical. Do not print credentials, tokens, private keys or secret environment values.

## 7. Integration with CI and Build

Wicofe-Tools may provide reusable validation actions/scripts, but Wicofe-Build owns whole-system orchestration and Wicofe-Tests owns canonical cross-repository test suites. Avoid maintaining a second orchestration graph in this repository.

CI-facing commands must be deterministic, non-interactive by default, return meaningful exit codes and avoid network access unless explicitly requested. Network-dependent checks should support pinned inputs, integrity verification and clear offline behavior.

## 8. Dependencies, licensing and provenance

Keep dependencies minimal and justify each runtime/build dependency. Pin versions for release-critical tools and record upstream origin, version/commit, content hash, license and local patches. Link third-party records to Wicofe-ThirdParty.

Original Wicofe-Tools code targets MPL-2.0. Third-party libraries and bundled tools retain upstream licenses and notices; review exact transitive dependencies and redistribution obligations before packaging.

## 9. Packaging and compatibility

Each released tool should publish:
- tool version and source commit;
- supported host platforms and runtime versions;
- input/output schema versions;
- compatibility with Wicofe repository metadata and manifest revisions;
- dependency and license inventory;
- checksums and release notes;
- known limitations.

Prefer small independently versioned tools over a monolithic utility that forces unrelated workflows to share release cycles.

## 10. Testing strategy

- Unit tests for parsers, validators and path handling.
- Fixture-based tests for valid and malformed metadata/manifests.
- Security tests for path traversal, symlinks, archive extraction and shell injection.
- CLI tests for exit codes, stdout/stderr and non-interactive operation.
- Schema compatibility tests for machine-readable output.
- Tests proving read-only commands do not modify inputs.
- Dry-run and explicit-confirmation tests for modifying commands.
- Cross-platform tests for every claimed host.
- Dependency/license/provenance inventory checks.

Tests must use disposable fixtures and must not require credentials. A test should be marked passed only after execution.

## 11. Open decisions

- Supported implementation languages and minimum runtime versions.
- Common CLI framework and command naming conventions.
- JSON schema/versioning policy.
- Distribution mechanism and release cadence.
- Supported host OS/version matrix.
- Whether generic artifact inspectors are a single CLI or separate tools.
- Integration contract with Wicofe-Build and Wicofe-Tests.
- Signing and provenance attestation format.

## 12. Completion criteria

A tool is ready for general use when its scope and owner are clear, inputs are validated, side effects are documented, outputs and exit codes are stable, tests cover failure and security paths, dependencies have provenance/license records, and supported platforms are stated. This architecture remains a proposal until individual tools meet those criteria.
