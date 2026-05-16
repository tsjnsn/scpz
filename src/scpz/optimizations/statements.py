"""Statement merging — combine statements with matching Effect + Condition.

Two Deny statements with the same Condition can be merged by unioning their
Action and Resource lists.  This reduces statement count, which is critical
for staying within the 5-statement limit.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from scpz.optimizations.conditions import conditions_equal

if TYPE_CHECKING:
    from scpz.models import Statement


class SidMergeMode(StrEnum):
    """Controls what happens to Sid fields when statements are merged."""

    DROP = "drop"  # omit Sid entirely — fewest bytes
    FIRST = "first"  # keep the Sid of the first statement in the group
    JOIN = "join"  # concatenate all Sids with a separator
    JOIN_TRUNCATE = "joinTruncate"  # join then truncate to a maximum length


def merge_statements(
    statements: list[Statement],
    *,
    sid_merge_mode: SidMergeMode = SidMergeMode.FIRST,
    sid_join_separator: str = "+",
    sid_join_max_length: int = 64,
) -> list[Statement]:
    """Merge compatible statements.

    Two statements are merged when they share Effect and Condition and one
    of the following is true:

    - **Same Resource, different Actions** → union the Action lists.
    - **Same Action, different Resources** → union the Resource lists.

    When both Action *and* Resource differ, the statements are kept
    separate: merging them would create a cross-product that broadens
    the effective policy beyond the original intent.

    Sids are handled according to *sid_merge_mode*.
    """
    if len(statements) <= 1:
        return statements

    merged: list[Statement] = []
    used: set[int] = set()

    for i, a in enumerate(statements):
        if i in used:
            continue
        current = a
        for j in range(i + 1, len(statements)):
            if j in used:
                continue
            b = statements[j]
            combined = _try_merge(
                current,
                b,
                sid_merge_mode=sid_merge_mode,
                sid_join_separator=sid_join_separator,
                sid_join_max_length=sid_join_max_length,
            )
            if combined is not None:
                current = combined
                used.add(j)
        used.add(i)
        merged.append(current)

    return merged


def _try_merge(
    a: Statement,
    b: Statement,
    *,
    sid_merge_mode: SidMergeMode,
    sid_join_separator: str,
    sid_join_max_length: int,
) -> Statement | None:
    """Attempt to merge two statements. Returns merged statement or None."""
    # Must have same Effect
    if a.effect != b.effect:
        return None

    # Must both use Action or both use NotAction
    a_uses_not = a.not_action is not None
    b_uses_not = b.not_action is not None
    if a_uses_not != b_uses_not:
        return None

    # Must have same Condition
    if not conditions_equal(a.condition, b.condition):
        return None

    new_sid = _merge_sids(
        a.sid,
        b.sid,
        mode=sid_merge_mode,
        separator=sid_join_separator,
        max_length=sid_join_max_length,
    )

    same_resource = _normalise_field(a.resource) == _normalise_field(b.resource)
    # Compare the relevant action field (Action or NotAction) as a frozenset.
    a_action_set = frozenset(a.not_action_list if a_uses_not else a.action_list)
    b_action_set = frozenset(b.not_action_list if b_uses_not else b.action_list)
    same_action = a_action_set == b_action_set

    if same_resource:
        # Union action lists (original behaviour).
        if a_uses_not:
            combined = _union_lists(a.not_action_list, b.not_action_list)
            new_not_action = combined if len(combined) > 1 else combined[0]
            return a.model_copy(update={"not_action": new_not_action, "sid": new_sid})
        combined = _union_lists(a.action_list, b.action_list)
        return a.model_copy(
            update={
                "action": combined if len(combined) > 1 else combined[0],
                "sid": new_sid,
            }
        )

    if same_action:
        # Union resource lists (symmetric case).
        combined_resources = _union_lists(a.resource_list, b.resource_list)
        new_resource: list[str] | str = (
            combined_resources if len(combined_resources) > 1 else combined_resources[0]
        )
        return a.model_copy(update={"resource": new_resource, "sid": new_sid})

    # Both Action and Resource differ — merging would create a cross-product.
    return None


def _normalise_field(val: list[str] | str) -> frozenset[str]:
    """Normalise a Resource or Action field for comparison."""
    if isinstance(val, str):
        return frozenset({val})
    return frozenset(val)


def _union_lists(a: list[str], b: list[str]) -> list[str]:
    """Union two lists, preserving order and deduplicating."""
    seen: set[str] = set()
    result: list[str] = []
    for item in a + b:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _merge_sids(
    a: str | None,
    b: str | None,
    *,
    mode: SidMergeMode,
    separator: str,
    max_length: int,
) -> str | None:
    """Combine Sids from two statements according to *mode*.

    drop         — always return None (fewest bytes).
    first        — keep *a* (the first statement's Sid).
    join         — concatenate both Sids with *separator*.
    joinTruncate — join then truncate to *max_length* characters.
    """
    if mode is SidMergeMode.DROP:
        return None
    if mode is SidMergeMode.FIRST:
        return a
    # join / joinTruncate
    parts = [s for s in (a, b) if s is not None]
    if not parts:
        return None
    joined = separator.join(parts)
    if mode is SidMergeMode.JOIN_TRUNCATE:
        joined = joined[:max_length]
    return joined or None
