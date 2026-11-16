# Repository Inventory Validator

**Status:** Initial local validator implemented; no GitHub API or remote repository existence checks.

## Purpose

`scripts/validate_repository_inventory.py` checks whether a local workspace contains the canonical repository checkout set. The expected list is maintained in `config/repository_inventory.txt` and currently contains 29 Wicofe repositories.

## Usage

```sh
python3 scripts/validate_repository_inventory.py ../workspace
```

Use a different inventory file:

```sh
python3 scripts/validate_repository_inventory.py ../workspace --expected ./my-inventory.txt
```

Ignore additional directories:

```sh
python3 scripts/validate_repository_inventory.py ../workspace --allow-extra
```

## Results

- `MISSING_CHECKOUT`: an expected repository directory is absent locally.
- `UNLISTED_DIRECTORY`: an unexpected non-hidden directory exists in the workspace.
- Exit code 0: inventory matches the selected policy.
- Exit code 1: one or more findings.

A missing checkout does not mean the remote GitHub repository is missing. This tool is read-only, uses the Python standard library, and does not fetch, clone, delete or modify repositories.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests cover exact matches, missing checkouts, unlisted directories, optional extra-directory handling and duplicate inventory entries.
