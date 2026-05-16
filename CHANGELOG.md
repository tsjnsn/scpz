# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/tsjnsn/scpz/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/tsjnsn/scpz/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tsjnsn/scpz/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tsjnsn/scpz/compare/v0.1.0...v0.2.1
[0.1.0]: https://github.com/tsjnsn/scpz/releases/tag/v0.1.0
