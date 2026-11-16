# Repository Documentation Validator

**Status:** Implemented initial local CLI; external-link and repository-metadata checks are not included.

## Purpose

`scripts/validate_repository_docs.py` checks Markdown documentation across one or more local repository checkouts. It is read-only and uses only the Python standard library.

## Workspace layout

Place the repositories that should be checked under one common directory:

```text
workspace/
├── Wicofe/
├── Wicofe-Docs/
├── Wicofe-Specs/
├── Wicofe-Tools/
└── ...
```

Relative links can then resolve between sibling repositories, provided the relative path in the Markdown file is correct.

## Usage

Run from a Wicofe-Tools checkout:

```sh
python3 scripts/validate_repository_docs.py ../workspace
```

Check that a legacy term is absent from Markdown prose:

```sh
python3 scripts/validate_repository_docs.py ../workspace --forbid-term MYPK
```

Multiple terms and exclusions are supported:

```sh
python3 scripts/validate_repository_docs.py ../workspace \
  --forbid-term MYPK \
  --forbid-term ANOTHER_LEGACY_NAME \
  --exclude 'Wicofe-Docs/docs/archive/**'
```

## Checks

- Local Markdown file links.
- Local Markdown heading fragments.
- Directory links that have a `README.md`, `INDEX.md`, or `index.md`.
- Links that resolve outside the declared workspace.
- Optional case-insensitive forbidden terms in Markdown prose.

Exit code is 0 when no findings are detected and 1 when one or more findings exist. Invalid workspace arguments are rejected by the CLI.

## Limitations

- HTTP(S) links are not requested; this tool does not detect remote 404 responses.
- Reference-style Markdown links, raw HTML links, and complex nested-parenthesis destinations are not fully parsed.
- Heading slug generation covers common GitHub Markdown headings, not every extension or renderer.
- It does not validate repository inventory, SPDX expressions, dependency trees, license compatibility, requirement IDs, test IDs, or CI status.
- It does not modify files or automatically fix links.

These checks should be extended only with fixtures and explicit behavior tests. A clean run means only that the supported local checks found no issues; it is not a full documentation or legal compliance certification.

## Tests

Run the unit tests:

```sh
python3 -m unittest discover -s tests -v
```
