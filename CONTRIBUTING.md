# Contributing to scpz

Thanks for your interest in contributing! This document covers how to get set up, run tests, and submit changes.

## Development setup

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/tsjnsn/scpz.git
cd scpz
uv sync --dev
uv run pre-commit install
```

## Running checks

Run all checks before opening a pull request:

```bash
uv run ruff format src/ tests/
uv run ruff check src/ tests/
uv run mypy src/
uv run pytest -q
```

To run only the optimize + equivalence golden regression suite (same checks as the
**Equivalence golden regression** CI job):

```bash
uv run pytest tests/test_golden_regression.py -v
```

### Equivalence golden regression

`tests/test_golden_regression.py` loads every `examples/*.json` plus the NotAction
fixtures listed in `NOT_ACTION_REGRESSION_FILES`, runs the optimizer with
`OptimizerConfig.load` (so `examples/scpz.yaml` applies to example policies), and
requires `check_permission_equivalence` in `scpz.equivalence` to pass — the
optimized policy must not be **broader** than the input under the catalog-backed
model.

Expectations are **semantic** (equivalence), not committed JSON snapshots, so
formatting-only changes or a refreshed bundled catalog do not require updating
golden files.

When CI fails on this suite:

- **Unintended optimizer regression (permissions broadened):** fix the optimizer
  (or validation) so equivalence holds again.
- **Intentional change to equivalence rules:** update `src/scpz/equivalence.py`
  and extend or adjust `tests/test_equivalence.py` and this golden module as
  needed.
- **Fixture or example policy should change:** edit the JSON under `examples/` or
  `tests/fixtures/`.
- **New example SCP:** add `examples/<name>.json` — it is picked up automatically.
- **New NotAction regression fixture:** add the JSON under `tests/fixtures/` and
  append its filename to `NOT_ACTION_REGRESSION_FILES` in
  `tests/test_golden_regression.py`.

If you modify `src/scpz/config.py` (Pydantic models), also regenerate the committed schema:

```bash
uv run scpz print-schema -o schema/OptimizerConfig.json
```

## Adding a new optimization pass

1. Create `src/scpz/optimizations/<pass_name>.py` with a top-level function that takes and returns `list[Statement]`.
2. Add a corresponding args model and field to `PassesConfig` in `src/scpz/config.py` with an `enabled: bool` (default `True`, or `False` for opt-in passes).
3. Wire the pass into `optimize()` in `src/scpz/optimizer.py`.
4. Add a test file at `tests/test_<pass_name>.py`.
5. Regenerate the schema.

## `dev-ai` and Copilot

Agent work targets the `dev-ai` branch; releases merge **`dev-ai` → `main`**. If Copilot
cannot push review fixes (GH006 / required status checks on `dev-ai`), see
[`.github/DEV_AI.md`](https://github.com/tsjnsn/scpz/blob/main/.github/DEV_AI.md) for branch ruleset setup—do not open a second PR
just to land Copilot commits.

## Pull request guidelines

- Keep PRs focused — one feature or fix per PR.
- Include tests for new behaviour.
- Update `CHANGELOG.md` under `[Unreleased]`.
- All CI checks must pass.

## Reporting bugs

Open an issue using the **Bug report** template. Include the input SCP JSON, the `scpz` version (`scpz --version`), and the full error output.

## Suggesting features

Open an issue using the **Feature request** template with a clear description of the problem and your proposed solution.
