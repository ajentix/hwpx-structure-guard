# Publication boundary

## Intended repository

- Organization: `ajentix`
- Repository: `hwpx-structure-guard`
- Intended visibility: public
- License: MIT
- Runtime dependencies: Python standard library only
- Build dependency: setuptools

## Included files

Only the following files belong to the initial publication:

```text
.gitignore
LICENSE
PUBLICATION.md
README.md
SECURITY.md
pyproject.toml
src/hwpx_guard/__init__.py
src/hwpx_guard/__main__.py
src/hwpx_guard/cli.py
src/hwpx_guard/core.py
tests/test_guard.py
tests/test_independent.py
```

This package is a standalone implementation of generic ZIP/XML checks. It is not a copy of a product repository, a product repository's Git history or its raw QA output. No customer names, templates, documents, credentials, account IDs, database snapshots, communication archives, screenshots or production endpoints belong in this repository. Fixtures are generated from literal synthetic XML in tests.

## Release checks

Before any push, review the exact allowlisted file set, run tests, inspect the built wheel contents, scan staged source for credentials and customer identifiers, and record the target and visibility. Never use a recursive copy from a product repository or a wildcard `git add` from a customer worktree.

The initial public release requires confirming that the named publisher can license this newly written utility. The MIT grant covers this repository only, not third-party specifications, applications or customer templates. No third-party renderer, converter, font or binary dependency is vendored.
