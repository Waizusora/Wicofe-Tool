# Wicofe-Tools

Development, maintenance, and release tools for the Wicofe OS project.

## Scope

This repository contains project-owned tooling that supports development and maintenance across Wicofe repositories, including repository validation, build orchestration helpers, release and artifact inspection, dependency/license/provenance auditing, and CI support utilities.

## Boundaries

Component-specific build logic remains with its owning repository where practical. Kernel build and boot validation belong to Wicofe-Kernel; package-management implementation belongs to its dedicated component. Shared project automation may live here when multiple repositories consume it.

Tools must not silently modify source repositories, overwrite user data, or perform destructive operations without explicit confirmation.

## Requirements

- Document supported platforms, inputs, outputs, and failure modes.
- Prefer reproducible and deterministic behavior.
- Validate external input and report actionable errors.
- Keep dependencies minimal and enforce the [Wicofe dependency license policy](https://github.com/Waizusora/Wicofe-ThirdParty/blob/main/policies/DEPENDENCY_LICENSE_POLICY_0.2.md).
- Add automated tests for non-trivial behavior.

## License

Original Wicofe code targets MPL-2.0. Third-party dependencies retain their own licenses and notices.

## Existing tooling

- [Project metadata checker](scripts/check_project_metadata.py) checks README.md and LICENSE presence.
- [Documentation validator](scripts/validate_repository_docs.py) checks local Markdown links, heading fragments, workspace path escapes and configured forbidden terms.
- [Repository inventory validator](scripts/validate_repository_inventory.py) compares local checkouts with the canonical 29-repository inventory in config/repository_inventory.txt.
- [Dependency License Auditor](scripts/audit_dependencies.py) inventories resolved Cargo graphs, GitHub Actions, build commands, system packages and known assets, then applies Wicofe Policy 0.2 with fail-closed human-review gates. See [auditor documentation](docs/DEPENDENCY_LICENSE_AUDITOR.md) and [CI enforcement](docs/DEPENDENCY_LICENSE_CI_ENFORCEMENT.md).\n- [Dependency License Auditor](scripts/audit_dependencies.py) inventories resolved Cargo graphs, GitHub Actions, workflow runners, apt packages, build scripts, downloaded artifacts, vendored assets and submodules. [Debian package license inventory](scripts/audit_dpkg_packages.py) records CI system-package deltas from copyright metadata. Upstream evidence is separate from human approvals. Non-Cargo resolvers and final-image inventories remain pending.

Run from a local checkout:

```sh
python3 scripts/validate_repository_inventory.py ../workspace
python3 scripts/validate_repository_docs.py ../workspace --forbid-term MYPK
python3 -m unittest discover -s tests -v
```

The validators are read-only and use the Python standard library. They do not query GitHub, inspect dependency lockfiles, determine legal compatibility or certify repository implementation status.

## Documentation

See [docs/INDEX.md](docs/INDEX.md) for technical documentation. The [central repository documentation map](https://github.com/Waizusora/Wicofe-Docs/blob/main/REPOSITORY_DOCUMENTATION_MAP.md) identifies canonical ownership and cross-repository boundaries.
