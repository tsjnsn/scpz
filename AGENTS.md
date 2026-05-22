# scpz — Agent Rules

## Project overview
scpz is a Python CLI tool that optimizes AWS Service Control Policy (SCP) JSON
files to fit within AWS Organizations Service Control Policy limits
(10,240 bytes per SCP, 5 statements per SCP, up to 10 SCPs attached per account or OU).

- **Package manager:** `uv` (never use `pip` directly)
- **Python:** 3.13+, strict typing enforced via mypy
- **Formatter/linter:** ruff
- **Tests:** pytest with coverage

## After every code change

Run all of the following and fix any failures before considering the task done:

```bash
uv run ruff format src/ tests/
uv run ruff check src/ tests/
uv run mypy src/
uv run pytest -q
```

If you change `src/scpz/config.py` (Pydantic models), also regenerate the
committed schema file:

```bash
uv run scpz schema -o schema/OptimizerConfig.json
```

## Code conventions

- No `any` types except where unavoidable for third-party compatibility
- Explicit return types on all functions
- `extra="forbid"` on every Pydantic model
- All new optimization passes must be wired into `PassesConfig` in `config.py`
  with an `enabled: bool` field (defaulting to `True`, or `False` for opt-in passes)
  and into the `optimize()` function in `optimizer.py`
- New passes require a corresponding test file `tests/test_<pass>.py`

## Config schema (scpz.yaml)

The config format follows the Kubernetes object model:
`apiVersion / kind / metadata / spec`. Do not add flat top-level keys outside
`spec`. Pass-specific args belong inside the pass block under `spec.optimizer`,
not at the `spec` level.

## Never commit

- `.bak` files (optimizer backups)
- `__pycache__` / `.pyc` files
- Modified `examples/*.json` files (they are reference inputs, not outputs)
