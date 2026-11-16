# Dependency License CI Enforcement

**Policy:** Wicofe Dependency License Policy 0.2.0  
**Implementation owner:** Wicofe-Tools  
**Compliance record owner:** Wicofe-ThirdParty

## Workflows

- `.github/workflows/dependency-license-audit.yml` runs unit tests and produces a local informational inventory on push, pull request and manual dispatch.
- `.github/workflows/cross-repository-dependency-audit.yml` checks out the canonical 29-repository set, resolves discovered Cargo manifests, inventories GitHub Actions, known assets, vendored directories and submodules, then runs strict enforcement. It runs on push, manual dispatch and weekly schedule.
- Cross-repository JSON/Markdown reports and transient Cargo lockfiles are uploaded as workflow artifacts even when enforcement fails.

## Release gate semantics

Strict mode blocks on:
- GPL or AGPL dependencies (REJECTED).
- Unknown or missing license metadata (UNKNOWN).
- Dependencies without scoped human approval (NEEDS_REVIEW).
- LGPL without explicit approval and verified conditions.
- Non-Cargo manifests without an ecosystem resolver.
- Repositories with no dependency manifests and no human-reviewed coverage attestation.
- Unresolved vendored assets, generated assets, firmware, fonts, codecs, schemas, binary assets or submodules.
- Unreviewed hosted runner images, apt/system packages, downloaded release archives and host build tools.
- GitHub Actions references without verified license/source evidence.

The scanner never creates legal approval. Decision records and no-manifest coverage attestations must be reviewed and supplied by authorized humans.

## Current integration boundary

Wicofe-Build now provides `.github/workflows/release-dependency-license-gate.yml`, a reusable/tag-triggered gate pinned to an immutable Wicofe-Tools commit. It calls the strict cross-repository workflow. However, Wicofe-Build still has no complete end-to-end build/release pipeline, and final-image publication is not yet wired to this gate. A successful individual repository informational workflow must not be treated as release authorization.

Before release integration, Wicofe-Build must consume the strict cross-repository audit result and fail if it is unsuccessful. Wicofe-Image must also provide a final image/SBOM inventory that is reconciled against the audited dependency and asset set.

## Required release evidence

1. Immutable repository commit SHAs and build configuration.
2. Resolved dependency graphs for every supported feature and target configuration.
3. Human-reviewed license decisions and no-manifest coverage records.
4. Vendored source, submodule, firmware, font, codec, schema and generated-code provenance.
5. Build-time tool and GitHub Actions source/license review.
6. Final image SBOM and notices/attribution package.
7. Successful strict audit and image reconciliation tied to the exact release commit.
