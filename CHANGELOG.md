# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/tsjnsn/scpz/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tsjnsn/scpz/releases/tag/v0.1.0
