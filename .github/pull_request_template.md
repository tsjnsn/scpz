## Summary

<!-- What does this PR do and why? -->

## Changes

<!-- List the key changes made. -->

## Testing

<!-- How was this tested? New tests added? -->

## Checklist

- [ ] Tests pass (`uv run pytest -q`)
- [ ] Linting passes (`uv run ruff check src/ tests/`)
- [ ] Type checking passes (`uv run mypy src/`)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Schema regenerated if `config.py` was modified (`uv run scpz print-schema -o schema/OptimizerConfig.json`)
