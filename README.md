# scpz

[![CI](https://github.com/tsjnsn/scpz/actions/workflows/ci.yml/badge.svg)](https://github.com/tsjnsn/scpz/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/scpz)](https://pypi.org/project/scpz/)
[![Python](https://img.shields.io/pypi/pyversions/scpz)](https://pypi.org/project/scpz/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Intelligently optimize AWS Service Control Policy (SCP) JSONs to fit within AWS's strict limits.

## AWS SCP Limits

| Constraint | Limit |
|---|---|
| Policy size | 5,120 bytes |
| Statements per SCP | 5 |
| SCPs per target (account/OU) | 5 |

## Installation

```bash
uv pip install -e .
```

Or for development:

```bash
uv sync --dev
```

## Usage

### Optimize

```bash
# Optimize a single file (in-place with .bak backup)
scpz optimize-cmd policy.json

# Optimize all JSON files in a directory
scpz optimize-cmd policies/

# Dry run — show diff + summary without writing
scpz optimize-cmd policy.json --dry-run

# Summary only — just show what would change
scpz optimize-cmd policy.json --summary-only

# Write to a different file
scpz optimize-cmd policy.json --output optimized.json

# Error instead of auto-splitting
scpz optimize-cmd policy.json --no-split
```

### Validate

```bash
# Validate a single file
scpz validate policy.json

# Validate all JSON files in a directory
scpz validate policies/
```

## Optimization Passes

scpz runs the following optimizations in order:

1. **Statement merging** — Combines statements that share the same Effect, Condition, and Resource into a single statement with a unioned Action list.
2. **Action wildcard compression** — Replaces groups of actions sharing a common prefix with wildcard patterns (e.g. `s3:GetObject` + `s3:GetBucketPolicy` → `s3:Get*`).
3. **Condition merging** — Deduplicates condition values and merges equivalent condition blocks.
4. **Resource ARN optimization** — Collapses multiple specific ARNs into wildcard patterns (e.g. `role/Admin` + `role/ReadOnly` → `role/*`).

When a policy still exceeds limits after optimization, scpz automatically splits it into multiple SCP documents (up to 5 per target).

## Development

```bash
# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=scpz

# Run a specific test file
uv run pytest tests/test_actions.py -v
```

## License

MIT