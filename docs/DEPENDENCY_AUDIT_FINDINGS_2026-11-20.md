# Cross-Repository Dependency Audit Findings — 2026-11-20

## Scope and evidence

This report records the result of the 29-repository audit run
[44710193967](https://github.com/Waizusora/Wicofe-Tool/actions/runs/44710193967)
and the repository baseline checked in the same workflow.

The audit is technical evidence, not legal approval. No license, dependency,
or distribution policy has been changed by this report.

## Coverage status

Four repositories produced resolved manifest inventories:

| Repository | Dependency records | Build-command matches | Other inventory |
|---|---:|---:|---|
| Wicofe-Kernel | 70 | 60 | 2 asset/vendor records |
| Frenit | 7 | 4 | — |
| WDE | 239 | 9 | — |
| Mysh | 32 | 19 | — |

The following 25 repositories returned `coverage=UNKNOWN` because the audit
did not find a supported dependency manifest or an approved coverage attestation:

- Wicofe
- Wicofe-Doc
- Wicofe-Spec
- Wicofe-Test
- Wicofe-Tool
- Wicofe-ThirdParty
- Wicofe-ABI
- Wicofe-Driver
- Wicofe-Storage
- ONWFS
- Wicofe-Lib
- WLibc
- Wicofe-Service
- Wicofe-Network
- Wicofe-Input
- Wicofe-Graphic
- Wicofe-Audio
- WPM
- Wicofe-Build
- Wicofe-Image
- Wicofe-Installer
- Wicofe-Update
- Wicofe-Recovery
- Wicofe-SDK
- Wicofe-Port

This status does not mean that these repositories have no dependencies.
Each repository requires a scoped review of manifests, build scripts,
workflow actions, downloaded artifacts, assets, and submodules. Only after
that review may an authorized reviewer add a `reviewed_no_dependencies`
attestation where it is factually applicable.

## Missing repository license documents

The baseline reported 17 repositories with a missing or empty root
`LICENSE` file:

- Wicofe
- Wicofe-Storage
- ONWFS
- Wicofe-Lib
- Wicofe-Service
- Wicofe-Network
- Wicofe-Input
- Wicofe-Graphic
- Wicofe-Audio
- WPM
- Wicofe-Build
- Wicofe-Image
- Wicofe-Installer
- Wicofe-Update
- Wicofe-Recovery
- Wicofe-SDK
- Wicofe-Port

A missing file is a governance/documentation gap; it is not evidence that
the repository is unlicensed or that a particular license may be inferred.
Do not copy a license into these repositories until the project owner has
confirmed the intended license and its compatibility with existing content.

## Confirmed GPL build-tool findings

The Wicofe-Kernel workflow installs pinned CI host packages including:

- `qemu-system-x86=1:10.2.1+ds-1ubuntu3.3` — upstream evidence records
  `GPL-2.0-or-later`.
- `xorriso=1:1.5.6-1.1ubuntu4` — upstream evidence records
  `GPL-2.0-or-later`.

They are used by kernel CI for QEMU boot tests and ISO creation. They are
identified as build-time host tools; the audit does not establish that either
is included in the final Wicofe image. The current project policy still
rejects GPL/AGPL records, so this distinction is evidence for a policy-owner
decision, not an automatic exception or approval.

The Limine release artifact is separately pinned and has recorded checksum,
upstream license evidence, and bundled third-party notices. Its evidence
must not be conflated with the QEMU/xorriso host-tool findings.

## Required follow-up

1. Review the 25 unknown-coverage repositories individually. Record only
   evidence-backed coverage decisions; do not bulk-attest them as dependency-free.
2. Obtain owner confirmation for the intended root license of each of the
   17 repositories missing `LICENSE`.
3. Decide explicitly whether the GPL/AGPL prohibition applies equally to
   CI-only host tools. Until policy is changed by its owner, retain the
   current strict rejection.
4. Re-run the cross-repository audit and review the generated JSON/Markdown
   evidence before changing dependency decisions.
5. Preserve unresolved findings as blockers rather than suppressing them.

## CI result at report creation

- Cross-Repository Baseline: success; 29 repositories checked, 0 failures,
  17 warnings.
- Dependency license audit: failed closed due to unknown coverage and
  unapproved/rejected dependency records.
- Repository link validation: 164 Markdown files scanned, 0 findings.

