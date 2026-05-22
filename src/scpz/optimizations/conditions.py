"""Condition key merging and deduplication.

Merges duplicate condition keys within the same operator block and
deduplicates identical condition blocks across statements.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scpz.models import Statement


def merge_conditions(statements: list[Statement]) -> list[Statement]:
    """Deduplicate and merge condition blocks within each statement."""
    return [_merge_statement_conditions(s) for s in statements]


def _merge_statement_conditions(stmt: Statement) -> Statement:
    """Merge condition entries within a single statement."""
    if stmt.condition is None:
        return stmt

    merged: dict[str, dict[str, Any]] = {}
    for operator, keys in stmt.condition.items():
        if not isinstance(keys, dict):  # defensive for malformed JSON
            merged[operator] = keys  # type: ignore[unreachable]
            continue
        if operator not in merged:
            merged[operator] = {}
        for key, value in keys.items():
            if key in merged[operator]:
                merged[operator][key] = _merge_values(merged[operator][key], value)
            else:
                merged[operator][key] = _dedup_value(value)

    # Remove empty operators
    merged = {op: keys for op, keys in merged.items() if keys}

    if not merged:
        return stmt.model_copy(update={"condition": None})

    return stmt.model_copy(update={"condition": merged})


def _merge_values(existing: Any, new: Any) -> Any:
    """Merge two condition values, combining lists and deduplicating."""
    existing_list = _to_list(existing)
    new_list = _to_list(new)

    # Deduplicate while preserving order
    seen: set[str] = set()
    combined: list[str] = []
    for v in existing_list + new_list:
        v_str = str(v)
        if v_str not in seen:
            seen.add(v_str)
            combined.append(v)

    if len(combined) == 1:
        return combined[0]
    return combined


def _dedup_value(value: Any) -> Any:
    """Deduplicate a single condition value (list or scalar)."""
    if not isinstance(value, list):
        return value
    seen: set[str] = set()
    deduped: list[Any] = []
    for v in value:
        v_str = str(v)
        if v_str not in seen:
            seen.add(v_str)
            deduped.append(v)
    if len(deduped) == 1:
        return deduped[0]
    return deduped


def _to_list(value: Any) -> list[Any]:
    """Normalise a value to a list."""
    if isinstance(value, list):
        return value
    return [value]


def conditions_equal(
    a: dict[str, dict[str, Any]] | None,
    b: dict[str, dict[str, Any]] | None,
) -> bool:
    """Check whether two condition blocks are semantically equal."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return _normalise_condition(a) == _normalise_condition(b)


def condition_fingerprint(cond: dict[str, dict[str, Any]] | None) -> str:
    """Return a stable string key for partitioning statements by condition semantics."""
    if cond is None:
        return ""
    return _normalise_condition(cond)


def _normalise_condition(cond: dict[str, dict[str, Any]]) -> str:
    """Produce a canonical JSON string for comparison."""
    normalised: dict[str, dict[str, Any]] = {}
    for op in sorted(cond):
        normalised[op] = {}
        if not isinstance(cond[op], dict):
            normalised[op] = cond[op]
            continue
        for key in sorted(cond[op]):
            val = cond[op][key]
            if isinstance(val, list):
                normalised[op][key] = sorted(str(v) for v in val)
            else:
                normalised[op][key] = val
    return json.dumps(normalised, sort_keys=True)
