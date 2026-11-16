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
