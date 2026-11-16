# Tooling Documentation Index

This directory documents project-wide development, maintenance, validation, and release tooling.

## Validation tools
- [Repository documentation validator](REPOSITORY_DOCUMENTATION_VALIDATOR.md) — local Markdown link, anchor, workspace-safety and forbidden-term checks.

## Architecture
- [Developer tooling architecture 0.1](DEVELOPER_TOOLING_ARCHITECTURE_0.1.md) — draft design for shared utilities, CLI conventions, safe execution, diagnostics and testing.

## Scope
- Repository metadata and policy validation.
- Shared developer scripts and CI helpers.
- Release, packaging, and artifact inspection utilities.
- Dependency, license, and provenance audit helpers.

## Ownership
Component-specific tools should remain with their component when they require private implementation details. Wicofe-Tools owns shared project automation consumed by multiple repositories. Whole-system build orchestration belongs to [Wicofe-Build](https://github.com/Waizusora/Wicofe-Build). ONWFS-specific format tools belong to [ONWFS](https://github.com/Waizusora/ONWFS), image construction to [Wicofe-Image](https://github.com/Waizusora/Wicofe-Image), and canonical cross-repository test suites to [Wicofe-Tests](https://github.com/Waizusora/Wicofe-Tests).

## Tool requirements
Document inputs, outputs, supported platforms, exit codes, failure modes, side effects, and tests. Tools must be deterministic where possible and must not silently modify user data.

- [Central documentation index](https://github.com/Waizusora/Wicofe-Docs/blob/main/INDEX.md)
- [Repository documentation map](https://github.com/Waizusora/Wicofe-Docs/blob/main/REPOSITORY_DOCUMENTATION_MAP.md)
