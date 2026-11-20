# Repository Dependency Manifest Coverage Review

**Review date:** 2026-11-20  
**Scope:** canonical 29 repositories on their `main` branches  
**Purpose:** identify dependency/build manifests and prevent a missing manifest from being mistaken for a dependency-free repository.

## Main-branch tree review

A recursive Git tree inspection of all 29 repositories found supported manifest/build descriptor paths in four repositories:

| Repository | Discovered paths | Review status |
|---|---:|---|
| Wicofe-Kernel | 3 | Cargo workspace manifests and Rust toolchain |
| Frenit | 1 | Cargo manifest |
| WDE | 12 | Cargo workspace manifests and Rust toolchain |
| Mysh | 3 | Cargo manifest, lockfile, and Rust toolchain |
| Other 25 repositories | 0 | No supported manifest filename found |

The 25 repositories without a supported manifest filename are:

Wicofe, Wicofe-Doc, Wicofe-Spec, Wicofe-Test, Wicofe-Tool,
Wicofe-ThirdParty, Wicofe-ABI, Wicofe-Driver, Wicofe-Storage,
ONWFS, Wicofe-Lib, WLibc, Wicofe-Service, Wicofe-Network,
Wicofe-Input, Wicofe-Graphic, Wicofe-Audio, WPM, Wicofe-Build,
Wicofe-Image, Wicofe-Installer, Wicofe-Update, Wicofe-Recovery,
Wicofe-SDK, and Wicofe-Port.

This is a filename-based discovery result, not proof that these repositories
have no dependencies. In particular, Wicofe-Tool has Python scripts and CI
workflows despite having no recognized Python package manifest. Its build
and workflow dependencies are therefore discovered by the separate
build-script/CI scanner.

## Manifest discovery improvements

The dependency auditor now additionally recognizes:

- Python `requirements*.txt` and `requirements*.in` files
- Python `constraints*.txt` and `constraints*.in` files
- Conda environment and lock files
- Nix `flake.nix` and `flake.lock`
- Bazel `MODULE.bazel`, workspace, and lock files
- Local GitHub Actions `action.yml` and `action.yaml` definitions

The scanner excludes generated or vendored build output directories such as
`.git`, `target`, `node_modules`, `.venv`, `.gradle`, `dist`, and `build`.

Discovery does not resolve non-Cargo ecosystems. A discovered non-Cargo
manifest remains unresolved until a dedicated resolver and license-evidence
path exist. Cargo manifests continue to be resolved by Cargo metadata in
default and all-features modes.

## Automated reporting

The cross-repository dependency audit now runs
`scripts/report_manifest_coverage.py` after cloning and validating the
canonical repository set. It publishes:

- `reports/manifest-coverage.json`
- `reports/manifest-coverage.md`

The report lists each repository, manifest count, and exact discovered
manifest paths. A repository with no supported manifest is labeled
`NO_SUPPORTED_MANIFEST_FOUND`, never `reviewed_no_dependencies`.

## Required follow-up

1. Add a supported resolver before treating npm, Python, Gradle, Go, Maven,
   Nix, Bazel, or other ecosystem manifests as resolved.
2. Review workflow actions, runner images, build scripts, downloaded
   artifacts, submodules, vendored code, fonts, codecs, and binary assets
   separately from package manifests.
3. Do not create no-dependency attestations for the 25 repositories based
   solely on this filename scan.
4. Keep missing license documents and GPL/AGPL policy findings as separate
   governance and compatibility issues.

## Acceptance criteria

- All 29 repositories are present in the coverage report.
- Each discovered manifest path is included in the report.
- Repositories with no recognized manifest remain explicitly unreviewed.
- Cross-repository CI fails closed for unresolved dependencies and
  non-approved license evidence.
