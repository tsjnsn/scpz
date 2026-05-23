---
name: scpz
description: >
  Optimize, validate, and split AWS Service Control Policy (SCP) JSON files to fit
  within AWS's strict limits using scpz. Use this skill whenever the user is working
  with AWS SCPs, AWS Organizations policies, needs to shrink SCP JSON to fit size or
  statement limits, wants to validate SCP structure, or mentions SCP optimization,
  policy merging, action wildcarding, or SCP splitting. Also use when the user
  references scpz by name, or is troubleshooting SCP limit errors from AWS
  Organizations.
---

# scpz — AWS SCP Optimizer

scpz is a Python CLI that intelligently optimizes AWS Service Control Policy (SCP) JSON
files to fit within AWS's hard limits:

- **Policy size:** 10,240 bytes
- **Statements per SCP:** 5
- **SCPs per target (account/OU):** 10

## Installation

Requires Python 3.13+ and `uv`:

```bash
uv pip install scpz
```

For local development from source:

```bash
uv sync --dev
```

## Commands

### Optimize

Shrink an SCP to fit within AWS limits. Runs all optimization passes in order,
then auto-splits if the policy still exceeds limits.

```bash
# Optimize in-place (creates .bak backup)
scpz optimize policy.json

# Optimize a whole directory
scpz optimize policies/

# Preview changes without writing
scpz optimize policy.json --dry-run

# Just show the byte/statement summary
scpz optimize policy.json --summary-only

# Write to a different file
scpz optimize policy.json --output optimized.json

# Error instead of auto-splitting
scpz optimize policy.json --no-split
```

### Validate

Check SCP JSON for structural and limit issues without modifying anything.

```bash
scpz validate policy.json
scpz validate policies/
```

### Schema

Emit the JSON Schema for scpz.yaml config files:

```bash
scpz print-schema
scpz print-schema -o schema/OptimizerConfig.json
```

## Optimization Passes

Passes run in this fixed order:

1. **statement-merge** — Combines statements sharing the same Effect, Condition,
   and Resource into one statement with a unioned Action list. Most impactful for
   policies near the 5-statement limit.
2. **action-compress** — Replaces groups of actions sharing a common prefix with
   wildcards (e.g. `s3:GetObject` + `s3:GetBucketPolicy` → `s3:Get*`). Conservative
   mode uses the bundled AWS action catalog to guarantee zero scope broadening;
   aggressive mode wildcards at the verb level for more savings.
3. **condition-merge** — Deduplicates condition values and merges equivalent
   condition blocks within each statement.
4. **resource-optimize** — Collapses multiple ARNs into wildcard patterns when
   they share a common prefix (e.g. `role/Admin` + `role/ReadOnly` → `role/*`).
5. **redundancy-eliminate** (opt-in, disabled by default) — Removes statements
   wholly subsumed by another statement in the same policy. Wildcard-aware.
6. **split** — When the policy still exceeds limits after all other passes,
   splits it into multiple SCP documents (up to 10 per target).

## Configuration

scpz discovers a `scpz.yaml` config by walking up from the input file. If none is
found, all defaults apply. The config follows the Kubernetes object model:

```yaml
apiVersion: scpz.io/v1alpha1
kind: OptimizerConfig
metadata:
  name: default
spec:
  catalog:
    source: bundled          # bundled | file | none
  optimizer:
    statementMerge:
      enabled: true
      sidOnMerge: first      # drop | first | join | joinTruncate
    actionCompress:
      enabled: true
      mode: conservative     # conservative | aggressive
    conditionMerge:
      enabled: true
    resourceOptimize:
      enabled: true
    redundancyEliminate:
      enabled: false         # opt-in
    split:
      enabled: true
      strategy: auto         # auto | never
  output:
    backupSuffix: ".bak"
```

Disable any pass by setting `enabled: false`. Pass-specific args belong inside their
pass block under `spec.optimizer`, not at the `spec` level.

## Typical Workflow

1. **Validate** the raw SCP to catch structural issues early:
   `scpz validate policy.json`
2. **Dry-run** optimization to preview what changes:
   `scpz optimize policy.json --dry-run`
3. **Optimize** once satisfied:
   `scpz optimize policy.json`
4. If the policy was split, review each `policy_N.json` output file.
5. Deploy the optimized SCP(s) via your IaC pipeline (Terraform, CloudFormation, etc.).

## Development

```bash
uv run ruff format src/ tests/
uv run ruff check src/ tests/
uv run mypy src/
uv run pytest -q
```

Always run all four checks after any code change. If `src/scpz/config.py` changes,
also regenerate the schema: `uv run scpz print-schema -o schema/OptimizerConfig.json`.
