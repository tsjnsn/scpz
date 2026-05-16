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

If you modify `src/scpz/config.py` (Pydantic models), also regenerate the committed schema:

```bash
uv run scpz schema -o schema/OptimizerConfig.json
```

## Adding a new optimization pass

1. Create `src/scpz/optimizations/<pass_name>.py` with a top-level function that takes and returns `list[Statement]`.
2. Add a corresponding args model and field to `PassesConfig` in `src/scpz/config.py` with an `enabled: bool` (default `True`, or `False` for opt-in passes).
3. Wire the pass into `optimize()` in `src/scpz/optimizer.py`.
4. Add a test file at `tests/test_<pass_name>.py`.
5. Regenerate the schema.

## Pull request guidelines

- Keep PRs focused — one feature or fix per PR.
- Include tests for new behaviour.
- Update `CHANGELOG.md` under `[Unreleased]`.
- All CI checks must pass.

## Reporting bugs

Open an issue using the **Bug report** template. Include the input SCP JSON, the `scpz` version (`scpz --version`), and the full error output.

## Suggesting features

Open an issue using the **Feature request** template with a clear description of the problem and your proposed solution.
