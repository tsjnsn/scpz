"""Redundancy elimination — remove statements wholly subsumed by others.

A statement A is *redundant* when another statement B in the same policy
already covers everything A covers:

  - Same Effect
  - Same Condition (semantically equal)
  - Same Resource set (exact match)
  - Every action in A is covered by at least one action in B

Wildcard awareness (no catalog required):

  - ``*`` covers every action.
  - ``svc:Verb*`` covers any action that starts with ``svc:Verb``, including
    other wildcard patterns such as ``svc:VerbFoo*``.

NotAction statements are skipped — subsumption logic inverts for NotAction
and safely handling it requires a full action catalog.

Example::

    # B subsumes A: s3:* covers s3:GetObject
    A: Deny s3:GetObject on * (no condition)
    B: Deny s3:*         on * (no condition)
    → A is removed.

    # Not subsumed: different conditions
    A: Deny s3:* on * if PrincipalArn == admin
    B: Deny s3:* on * (no condition)
    → both kept (different scope).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scpeasy.optimizations.conditions import conditions_equal

if TYPE_CHECKING:
    from scpeasy.models import Statement


def eliminate_redundancy(statements: list[Statement]) -> list[Statement]:
    """Remove statements wholly subsumed by another statement in *statements*.

    Runs in O(n²) over the statement list — acceptable given the AWS limit of
    5 statements per SCP.  When two statements are identical both are compared
    against each other; the algorithm keeps the later one and discards the
    earlier, leaving exactly one copy.
    """
    if len(statements) <= 1:
        return statements

    redundant: set[int] = set()

    for i, a in enumerate(statements):
        if i in redundant:
            continue
        # Skip NotAction — subsumption logic inverts and requires a catalog.
        if a.not_action is not None:
            continue
        for j, b in enumerate(statements):
            if i == j or j in redundant:
                continue
            if b.not_action is not None:
                continue
            if _is_subsumed_by(a, b):
                redundant.add(i)
                break

    return [s for idx, s in enumerate(statements) if idx not in redundant]


# ── Internal helpers ──────────────────────────────────────────────────


def _is_subsumed_by(a: Statement, b: Statement) -> bool:
    """Return True if statement *a* is wholly subsumed by statement *b*."""
    if a.effect != b.effect:
        return False
    if not conditions_equal(a.condition, b.condition):
        return False
    if _normalise_resource(a.resource) != _normalise_resource(b.resource):
        return False
    # Every action in A must be covered by at least one action in B.
    return all(
        any(_covers(b_action, a_action) for b_action in b.action_list) for a_action in a.action_list
    )


def _covers(covering: str, action: str) -> bool:
    """Return True if *covering* covers *action*.

    ``*``            covers everything.
    ``svc:Verb*``    covers ``svc:VerbFoo``, ``svc:VerbFoo*``, etc.
    ``svc:VerbFoo``  covers only ``svc:VerbFoo`` exactly.
    """
    if covering == "*":
        return True
    if covering == action:
        return True
    if covering.endswith("*"):
        return action.startswith(covering[:-1])
    return False


def _normalise_resource(resource: list[str] | str) -> frozenset[str]:
    if isinstance(resource, str):
        return frozenset({resource})
    return frozenset(resource)
