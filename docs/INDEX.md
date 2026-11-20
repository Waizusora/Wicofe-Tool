# Tooling Documentation Index

This directory documents project-wide development, maintenance, validation, and release tooling.

## Validation tools

- [Repository documentation validator](REPOSITORY_DOCUMENTATION_VALIDATOR.md) — local Markdown link, anchor, workspace-safety and forbidden-term checks.
- [Repository inventory validator](REPOSITORY_INVENTORY_VALIDATOR.md) — compares a local checkout workspace with the canonical 29-repository inventory.
- [Dependency License Auditor](DEPENDENCY_LICENSE_AUDITOR.md) — resolves Cargo dependency metadata, inventories manifests, build-time actions and assets, applies scoped human decisions, and fails closed on unresolved evidence.
- [Dependency License CI Enforcement](DEPENDENCY_LICENSE_CI_ENFORCEMENT.md) — documents local and 29-repository workflows, strict-gate semantics, and release integration boundaries.
- [Upstream license evidence catalog](../config/upstream_license_evidence.json) — immutable source snapshots and license-file evidence; not approvals.
- [Debian package license inventory](../scripts/audit_dpkg_packages.py) — extracts package versions and Debian copyright evidence from CI runner package deltas.
- [Repository coverage review template](../config/repository_dependency_coverage.example.json) — explicit human attestation for repositories with no dependency manifests.
- [Cross-repository dependency audit workflow](../.github/workflows/cross-repository-dependency-audit.yml) — scheduled/manual audit of all 29 repositories with evidence artifacts.

## Architecture

- [Developer tooling architecture 0.1](DEVELOPER_TOOLING_ARCHITECTURE_0.1.md) — draft design for shared utilities, CLI conventions, safe execution, diagnostics and testing.

## Policy

- [Wicofe dependency license policy](https://github.com/Waizusora/Wicofe-ThirdParty/blob/main/policies/DEPENDENCY_LICENSE_POLICY_0.2.md) — binding project rule for GPL/AGPL prohibition, conditional LGPL approval, and review of other license obligations.

## Ownership

Component-specific tools should remain with their component when they require private implementation details. Wicofe-Tool owns shared project automation consumed by multiple repositories. Whole-system build orchestration belongs to [Wicofe-Build](https://github.com/Waizusora/Wicofe-Build). ONWFS-specific format tools belong to [ONWFS](https://github.com/Waizusora/ONWFS), image construction to [Wicofe-Image](https://github.com/Waizusora/Wicofe-Image), and canonical cross-repository test suites to [Wicofe-Test](https://github.com/Waizusora/Wicofe-Test).

## Tool requirements

Document inputs, outputs, supported platforms, exit codes, failure modes, side effects, and tests. Tools must be deterministic where possible and must not silently modify user data.
