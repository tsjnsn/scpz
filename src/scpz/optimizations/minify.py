"""Canonical minification pass.

Ensures every statement field is in its smallest valid JSON shape:

- Single-element ``Action``, ``NotAction``, or ``Resource`` lists become
  scalars (saves 2 bytes per field: the ``[`` and ``]``).
- Duplicate entries in list fields are removed (preserving insertion order).

This pass is always applied last in the optimizer pipeline and is not
controlled by a separate config flag — it is semantics-preserving and has
no trade-offs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scpz.models import Statement


def canonicalize_statement(stmt: Statement) -> Statement:
    """Return *stmt* with each list field collapsed to its minimal shape.

    - A single-element list becomes a scalar string.
    - Duplicate entries are removed (first occurrence is kept).
    - Multi-element lists with no duplicates are returned unchanged.
    - Scalar fields are returned as-is.
    """
    updates: dict[str, Any] = {}

    if stmt.not_action is None:
        action_field = stmt.action
        if isinstance(action_field, list):
            normalized = _normalize_list(action_field)
            if normalized != action_field:
                updates["action"] = normalized
    else:
        not_action_field = stmt.not_action
        if isinstance(not_action_field, list):
            normalized = _normalize_list(not_action_field)
            if normalized != not_action_field:
                updates["not_action"] = normalized

    resource_field = stmt.resource
    if isinstance(resource_field, list):
        normalized = _normalize_list(resource_field)
        if normalized != resource_field:
            updates["resource"] = normalized

    if updates:
        return stmt.model_copy(update=updates)
    return stmt


def _normalize_list(values: list[str]) -> str | list[str]:
    """Deduplicate *values* and collapse to a scalar when only one entry remains.

    A single-element list is always returned as a scalar string (saves the
    ``[`` / ``]`` brackets in JSON).  Lists with no duplicates and more than
    one element are returned unchanged as a list.
    """
    seen: set[str] = set()
    deduped: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped[0] if len(deduped) == 1 else deduped
