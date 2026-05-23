# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-22

### Added

- Public documentation site built with MkDocs Material, deployed to GitHub Pages via `.github/workflows/pages.yml` (enable **Settings → Pages → GitHub Actions** on first use).
- Official **Docker Hub** image `tsjnsn/scpz`: release workflow pushes tags on
  each GitHub release (`<release tag>` plus `latest` for stable releases).
- CI job **Equivalence golden regression** runs `tests/test_golden_regression.py`:
  every `examples/*.json` and the NotAction fixtures in that module are
  optimized then checked with `check_permission_equivalence` so merges block on
  accidental permission broadening.
- `scpz check-equivalence before.json after.json` — catalog-backed check that
  the optimized (or other) policy did not broaden permissions versus a
  baseline: ``Deny`` coverage must not shrink and ``Allow`` carve-outs must not
  grow, grouped by effect, condition fingerprint, and resources.
- `split_if_needed(..., catalog=...)` expands oversized `Deny` + `NotAction`
  statements using the action catalog: denied atoms are re-encoded as chunked
  `Deny` + `Action` lists so split output is permission-equivalent (no list
  partitioning of exemptions, which would broaden denies).
- Opt-in `redundancyEliminate` pass: when a non-empty action catalog is
  configured, wholly redundant ``Deny`` + ``NotAction`` statements are removed
  using the same catalog-backed exemption model as ``NotAction`` compression
  (*exempt(B) ⊆ exempt(A)* in the catalog universe).
- `spec.validation` in `scpz.yaml` with per-rule severities (`error`, `warn`,
  `ignore`) for wildcard actions, broad `Resource: "*"`, missing `Sid`, and
  unknown service prefixes. Wildcard actions use `onWildcardAction`: the
  service-specific part after `:` must contain `*` or `?` to match; the bare
  action `*` is excluded. The optimizer and `scpz validate` honour these
  settings from the discovered config file.
- `scpz validate` (and pre-optimize validation) cross-checks literal
  `Action` / `NotAction` strings against the configured AWS action catalog.
  Unknown actions for a catalogued service use `spec.validation.onUnknownCatalogAction`
  (default `warn`; set to `error` for strict mode, or `ignore` to skip).
- `actionCompress` applies catalog-safe wildcard compression to ``NotAction``
  lists when a non-empty action catalog is configured (same conservative trie
  and ``catalog.covers`` proofs as ``Action``; aggressive shortening is not
  used for ``NotAction`` because wildcards would exempt additional APIs).

### Changed

- **CLI redesign (breaking):** flat verb-first commands with hyphenated multi-word names.
  - `optimize-cmd` → `optimize`
  - `schema` → `print-schema`
  - `validate` and `check-equivalence` unchanged
  - No backward-compatibility aliases for removed command names
  - Normalized `--help` / `--version` messaging and option help text
  - `--output` is deterministic: only paths ending in `.json` name a single file
    (existing directories always use directory semantics); otherwise `--output`
    is a directory (`<output>/<input>` or split shards); when PATH is a
    directory, `--output` must be a directory
- `optimize` applies the same validation rules as `validate`, checks the
  optimized document (and each split shard) before any write, exits non-zero
  when any issue is elevated to `error`, and skips backups, in-place writes,
  `--output`, and split file writes in that case.
- `validate` loads project config per file so it honours `spec.validation`
  (invalid `scpz.yaml` prints a config error and counts as failure for that
  path without aborting the whole command).

## [0.2.7] - 2026-05-16

### Fixed
- Resolved ruff lint violations (UP037, SIM109, E501) in `actions.py` and tests introduced in v0.2.6.

## [0.2.6] - 2026-05-16

### Changed
- Refactored `actions.py` internals: extracted `_bare_prefix` helper,
  improved `_try_shorten_across_verbs` with incremental LCP narrowing,
  hoisted `has_catalog` guard, fixed type narrowing for mypy/pyright strict mode.
- Fixed inaccurate docstring example in `_shorten_verb_prefix`.

## [0.2.5] - 2026-05-16

### Added
- `actionCompress` aggressive mode now performs shortest-prefix trimming when
  a catalog is provided. Each verb-level wildcard is shortened to the minimum
  prefix at which the catalog confirms no other verb families exist
  (e.g. `guardduty:Delete*` → `guardduty:Del*`, `iam:Update*` → `iam:Upd*`).
  A second cross-verb pass then collapses adjacent shortened wildcards when
  the catalog confirms the merged prefix is still safe
  (e.g. `svc:Del*` + `svc:Det*` → `svc:De*`).

### Fixed
- `scpz validate` was emitting every constraint warning (statement count,
  size) twice because `validate_file` already runs `validate_document`
  internally, but `validate_cmd` called it a second time.

## [0.2.3] - 2026-05-16

### Fixed
- `scpz --version` now reports the correct installed version; previously always showed `0.1.0` due to a hardcoded string in `__init__.py`

## [0.2.2] - 2026-05-16

### Changed
- README: fix installation instructions to show `pip install scpz` / `uv tool install scpz` for consumers
- README: add Python 3.13+ requirements section
- README: clarify `.bak` backup filename in optimize comment
- README: move developer-only commands (`uv sync --dev`, schema regeneration) to Development section

## [0.2.1] - 2026-05-16

### Changed
- Updated AWS SCP limits to match new quotas announced May 2026:
  - `MAX_SCP_SIZE_BYTES`: 5,120 → 10,240 bytes
  - `MAX_SCPS_PER_TARGET`: 5 → 10 SCPs per node
- README: document `redundancyEliminate`, `fixpoint`, catalog config, and `schema` command
- `examples/scpz.yaml`: add `fixpoint` pass to reference config

## [0.1.0] - 2026-05-16

### Added
- Initial release
- `optimize-cmd` — optimize SCP JSON files in-place or to a specified output path
- `validate` — validate SCP JSON files without modifying them
- `schema` — print or write the JSON Schema for `scpz.yaml`
- Optimization passes: statement merging, action wildcard compression, condition merging, resource ARN optimization, redundancy elimination, and auto-splitting
- Bundled AWS action catalog refreshed weekly from the AWS Service Reference API
- `scpz.yaml` project config following the Kubernetes object model (`apiVersion / kind / metadata / spec`)
- Dry-run and summary-only modes
- Rich terminal output with diffs and optimization summaries

[Unreleased]: https://github.com/tsjnsn/scpz/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/tsjnsn/scpz/compare/v0.2.7...v0.3.0
[0.2.7]: https://github.com/tsjnsn/scpz/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/tsjnsn/scpz/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/tsjnsn/scpz/compare/v0.2.3...v0.2.5
[0.2.3]: https://github.com/tsjnsn/scpz/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tsjnsn/scpz/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tsjnsn/scpz/compare/v0.1.0...v0.2.1
[0.1.0]: https://github.com/tsjnsn/scpz/releases/tag/v0.1.0
