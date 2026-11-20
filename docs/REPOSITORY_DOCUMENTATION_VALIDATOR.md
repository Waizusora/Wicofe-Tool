# Repository Documentation Validator

**Status:** Local Markdown and canonical Waizusora cross-repository link checks are implemented; arbitrary external HTTP links and repository metadata checks are not included.

## Purpose

`scripts/validate_repository_docs.py` checks Markdown documentation across one or more local repository checkouts. It is read-only and uses only the Python standard library.

## Workspace layout

Place repositories under one common directory. The canonical expected set of 29 repositories is maintained in `config/repository_inventory.txt`.

## Usage

```sh
python3 scripts/validate_repository_docs.py ../workspace
python3 scripts/validate_repository_docs.py ../workspace --forbid-term MYPK
python3 scripts/validate_repository_docs.py ../workspace --forbid-term MYPK --exclude 'Wicofe-Doc/docs/archive/**'
```

## Checks

- Local Markdown file links and heading fragments.
- Directory links with README.md, INDEX.md or index.md.
- Links escaping the declared workspace.
- Optional case-insensitive forbidden terms in Markdown prose.

Exit code is 0 when no findings are detected and 1 when findings exist.

## Limitations

- HTTP(S) links are not requested.
- Reference-style Markdown links, raw HTML links and complex nested-parenthesis destinations are not fully parsed.
- Heading slug generation covers common GitHub Markdown headings, not every renderer.
- This tool does not validate dependency trees, SPDX expressions, legal compatibility, requirement IDs, test IDs or CI status.
- It does not modify files or automatically fix links.

A clean run means only that supported local checks found no issues; it is not a full documentation or legal compliance certification.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
