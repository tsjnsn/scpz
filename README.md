# scpz

[![CI](https://github.com/tsjnsn/scpz/actions/workflows/ci.yml/badge.svg)](https://github.com/tsjnsn/scpz/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/scpz)](https://pypi.org/project/scpz/)
[![Python](https://img.shields.io/pypi/pyversions/scpz)](https://pypi.org/project/scpz/)
[![Downloads](https://img.shields.io/pypi/dm/scpz)](https://pypi.org/project/scpz/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/tsjnsn/scpz/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-0366d6)](https://tsjnsn.github.io/scpz/)

Intelligently optimize AWS Service Control Policy (SCP) JSONs to fit within AWS's strict limits.

## AWS SCP Limits

| Constraint | Limit |
|---|---|
| Policy size | 10,240 bytes |
| Statements per SCP | 5 |
| SCPs per target (account/OU) | 10 |

## Requirements

Python 3.13 or later.

## Installation

```bash
pip install scpz
```

Or with [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv tool install scpz
```

### Container images

Images are built from this repository’s `Dockerfile` (compatible with Docker and Podman) and published when a [GitHub Release](https://github.com/tsjnsn/scpz/releases) is published.

**Tagging (both registries):** each release tag (for example `v0.3.0`) is always published; `latest` is updated only for **stable** releases (not GitHub pre-releases).

- **`ghcr.io/tsjnsn/scpz:<release-tag>`** and **`ghcr.io/tsjnsn/scpz:latest`** (GHCR)
- **`tsjnsn/scpz:<release-tag>`** and **`tsjnsn/scpz:latest`** (Docker Hub)

#### GitHub Container Registry

Published to [GitHub Container Registry](https://github.com/tsjnsn/scpz/pkgs/container/scpz) as `ghcr.io/tsjnsn/scpz`.

Example (optimize a policy file in the current directory):

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/tsjnsn/scpz:latest optimize policy.json
```

With Podman:

```bash
podman run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:z" ghcr.io/tsjnsn/scpz:latest optimize policy.json
```

#### Docker Hub

Published to [Docker Hub](https://hub.docker.com/r/tsjnsn/scpz) as `tsjnsn/scpz`.

```bash
# Pin to a release (recommended in production)
docker pull tsjnsn/scpz:v0.3.0

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" tsjnsn/scpz:v0.3.0 optimize policy.json --dry-run
```

#### Build locally

```bash
docker build -t scpz:local .
docker run --rm scpz:local --version
```

#### Maintainer credentials

The [Publish release](https://github.com/tsjnsn/scpz/blob/main/.github/workflows/publish.yml) workflow pushes to GHCR (via `GITHUB_TOKEN`) and Docker Hub (via repository secrets). Container jobs run only after PyPI publish succeeds so a failed package release does not leave tagged images for an incomplete release. If `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` are unset, the Docker Hub job skips with a workflow notice instead of failing the release.

| Secret | Purpose |
| --- | --- |
| `DOCKERHUB_USERNAME` | Docker Hub account with push access to **`tsjnsn/scpz`** (must be `tsjnsn` today; the workflow image name is fixed, not derived from this secret) |
| `DOCKERHUB_TOKEN` | Docker Hub [access token](https://docs.docker.com/security/for-admins/access-tokens/) with **Read & Write** scope for that account |

Ensure the Docker Hub repository **`tsjnsn/scpz`** exists before the first push.

## Usage

### Optimize

```bash
# Optimize a single file in-place (original saved as policy.json.bak)
scpz optimize policy.json

# Optimize all JSON files in a directory
scpz optimize policies/

# Dry run — show diff + summary without writing
scpz optimize policy.json --dry-run

# Summary only — just show what would change
scpz optimize policy.json --summary-only

# Write to a different file
scpz optimize policy.json --output optimized.json

# Error instead of auto-splitting
scpz optimize policy.json --no-split
```

### Validate

```bash
# Validate a single file
scpz validate policy.json

# Validate all JSON files in a directory
scpz validate policies/

# Machine-readable JSON for CI (stdout only; exit code unchanged)
scpz validate policy.json --json
```

Exit codes for `validate`:

| Code | Meaning |
|------|---------|
| `0` | Every file passed validation (warnings are allowed). |
| `1` | Path missing, no `*.json` files found, or at least one file has a validation error. |

### Check equivalence

```bash
# Ensure optimized output did not broaden permissions (catalog model)
scpz check-equivalence policy.json policy.optimized.json

# Machine-readable JSON for CI
scpz check-equivalence policy.json policy.optimized.json --json
```

Exit codes for `check-equivalence`:

| Code | Meaning |
|------|---------|
| `0` | Both files validate and `after` is same or stricter than `before`. |
| `1` | Missing file, config error, validation failure, or equivalence failure. |

### Automation (`--json`)

`validate` and `check-equivalence` accept `--json` to emit a stable JSON document on **stdout** (human-oriented Rich output is suppressed). Parse the payload and use `exit_code` / `status` together with the process exit code:

```bash
# Fail the job when validation errors exist
scpz validate policies/ --json | tee result.json
test "$(jq -r .exit_code result.json)" -eq 0

# Gate deploy on equivalence
scpz check-equivalence before.json after.json --json > equiv.json
jq -e '.equivalence.ok' equiv.json
```

Top-level fields are consistent across both commands: `command`, `version`, `status` (`ok` | `error`), and `exit_code` (mirrors the process exit code). Command-specific details live under `files` / `summary` (`validate`) or `before`, `after`, and `equivalence` (`check-equivalence`). On failure, an `error` string summarizes the primary reason.

## Optimization Passes

scpz runs the following optimizations in order, repeating until the output stops changing (up to 5 rounds):

1. **Statement merging** — Combines statements that share the same Effect, Condition, and Resource into a single statement with a unioned Action list.
2. **Action wildcard compression** — Replaces groups of actions sharing a common prefix with wildcard patterns (e.g. `s3:GetObject` + `s3:GetBucketPolicy` → `s3:Get*`). Uses the bundled AWS action catalog in conservative mode to avoid scope broadening.
3. **Condition merging** — Deduplicates condition values and merges equivalent condition blocks.
4. **Resource ARN optimization** — Collapses multiple specific ARNs into wildcard patterns (e.g. `role/Admin` + `role/ReadOnly` → `role/*`).
5. **Redundancy elimination** _(opt-in)_ — Removes statements wholly subsumed by another statement in the same policy (`Action` via wildcards; `NotAction` only when a non-empty action catalog is configured, mirroring catalog safety for `NotAction` compression). Enable with `redundancyEliminate.enabled: true` in `scpz.yaml`.

When a policy still exceeds limits after optimization, scpz automatically splits it into multiple SCP documents (up to 10 per target).

## Configuration

Place a `scpz.yaml` in your project root (scpz walks up from the input file to find it). See `examples/scpz.yaml` for a fully-annotated reference.

```yaml
apiVersion: scpz.io/v1alpha1
kind: OptimizerConfig
metadata:
  name: default
spec:
  optimizer:
    actionCompress:
      mode: conservative  # conservative | aggressive
    redundancyEliminate:
      enabled: true       # opt-in
```

```bash
# Print the JSON Schema for editor validation
scpz print-schema
```

## Development

```bash
# Install with dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=scpz

# Run a specific test file
uv run pytest tests/test_actions.py -v

# Regenerate the committed schema after model changes
uv run scpz print-schema -o schema/OptimizerConfig.json
```

## License

MIT