# Wicofe-Tools

Development, maintenance, and release tools for the Wicofe OS project.

## Scope

This repository contains project-owned tooling that supports development and maintenance across Wicofe repositories, including:

- Repository validation and metadata checks.
- Build orchestration helpers that complement, but do not replace, component build systems.
- Release, packaging, and artifact inspection utilities.
- Dependency, license, and provenance audit helpers.
- Developer scripts and CI support utilities.

## Boundaries

Component-specific build logic remains with its owning repository where practical. Kernel build and boot validation belong to Wicofe-Kernel; package-management implementation belongs to its dedicated component. Shared project automation may live here when multiple repositories consume it.

Tools must not silently modify source repositories, overwrite user data, or perform destructive operations without explicit confirmation.

## Requirements

- Document supported platforms, inputs, outputs, and failure modes.
- Prefer reproducible and deterministic behavior.
- Validate external input and report actionable errors.
- Keep dependencies minimal and audit their licenses.
- Add automated tests for non-trivial behavior.

## Status

Initial repository baseline. No complete tool suite is claimed.

## License

Original Wicofe code is intended to use MPL-2.0. Third-party dependencies retain their own licenses and notices.

## Initial tooling

- [Project metadata checker](scripts/check_project_metadata.py) verifies that supplied local repository directories contain non-empty `README.md` and `LICENSE` files.

Run it from a local checkout:

```sh
python3 scripts/check_project_metadata.py ../Wicofe-Kernel ../Wicofe-ABI ../Wicofe-Lib
```

This is a baseline check only. It does not validate SPDX expressions, transitive dependency licenses, CI configuration, or legal compatibility.

## Documentation

See [docs/INDEX.md](docs/INDEX.md) for this repository's technical documentation. The [central repository documentation map](https://github.com/Waizusora/Wicofe-Docs/blob/main/REPOSITORY_DOCUMENTATION_MAP.md) identifies canonical ownership and cross-repository boundaries.

## Repository documentation validation

- [Documentation validator](scripts/validate_repository_docs.py) checks local Markdown links, heading fragments, workspace path escapes, and optional forbidden terms.
- [Validator guide](docs/REPOSITORY_DOCUMENTATION_VALIDATOR.md) documents workspace layout, command usage, exit codes, and limitations.
- [Unit tests](tests/test_validate_repository_docs.py) cover valid links, missing targets, missing anchors, forbidden terms, and workspace escapes.
- [GitHub Actions workflow](.github/workflows/repository-docs-validator.yml) runs the unit tests on relevant pushes and pull requests.

Example:

```sh
python3 scripts/validate_repository_docs.py ../workspace --forbid-term MYPK
python3 -m unittest discover -s tests -v
```

The validator is read-only. It checks local links only; it does not verify remote HTTP links, license compatibility, dependency trees, or repository implementation status.
