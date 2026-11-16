# Tooling Documentation Index

This directory documents project-wide development, maintenance, validation, and release tooling.

## Scope
- Repository metadata and policy validation.
- Shared developer scripts and CI helpers.
- Release, packaging, and artifact inspection utilities.
- Dependency, license, and provenance audit helpers.

## Ownership
Component-specific tools should remain with their component when they require private implementation details. Wicofe-Tools owns shared project automation consumed by multiple repositories. Whole-system build orchestration belongs to [Wicofe-Build](https://github.com/Waizusora/Wicofe-Build).

## Tool requirements
Document inputs, outputs, supported platforms, exit codes, failure modes, side effects, and tests. Tools must be deterministic where possible and must not silently modify user data.

- [Central documentation index](https://github.com/Waizusora/Wicofe-Docs/blob/main/INDEX.md)
- [Repository documentation map](https://github.com/Waizusora/Wicofe-Docs/blob/main/REPOSITORY_DOCUMENTATION_MAP.md)
