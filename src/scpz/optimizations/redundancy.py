"""Redundancy elimination — remove statements wholly subsumed by others.

A statement A is *redundant* when another statement B in the same policy
already covers everything A covers:

  - Same Effect
  - Same Condition (semantically equal)
  - Same Resource set (exact match)
  - Every action in A is covered by at least one action in B
    (for ``Action`` statements)

Wildcard awareness for ``Action`` (no catalog required):

  - ``*`` covers every action.
  - ``svc:Verb*`` covers any action that starts with ``svc:Verb``, including
    other wildcard patterns such as ``svc:VerbFoo*``.

``NotAction`` (Deny-with-exemptions)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For ``Deny`` + ``NotAction``, an action is *not* denied when it matches any
exemption pattern; otherwise it is denied.  Let *exempt(S)* be the set of IAM
actions matched by statement S's ``NotAction`` list.

Statement A (``NotAction``) is subsumed by statement B (``NotAction``) when
*exempt(B) ⊆ exempt(A)* — equivalently *denied(A) ⊆ denied(B)*: every action
denied by A is already denied by B.  Intuitively B has the same or tighter
exemptions, so B's deny is the same or stronger.

Because wildcards in ``NotAction`` expand exemption sets in non-obvious ways,
``NotAction`` subsumption is evaluated only against a **non-empty**
:class:`~scpz.catalog.ActionCatalog`: for every catalog action that B exempts,
the catalog must show that A exempts it too.  Without a catalog, ``NotAction``
pairs are never removed (same conservative stance as ``actionCompress`` on
``NotAction``).

``Action`` and ``NotAction`` statements are never compared to each other for
subsumption.

Example::

    # B subsumes A: s3:* covers s3:GetObject
    A: Deny s3:GetObject on * (no condition)
    B: Deny s3:*         on * (no condition)
    → A is removed.

    # Not subsumed: different conditions
    A: Deny s3:* on * if PrincipalArn == admin
    B: Deny s3:* on * (no condition)
    → both kept (different scope).

``NotAction`` example (catalog must list the named actions)::

    A: Deny NotAction [s3:GetObject, s3:PutObject] on *
    B: Deny NotAction [s3:GetObject]             on *
    → A is removed (B exempts only GetObject; A exempts that and more, so
       everything A denies is already denied by B).
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from scpz.optimizations.conditions import conditions_equal

if TYPE_CHECKING:
    from scpz.catalog import ActionCatalog
    from scpz.models import Statement


def eliminate_redundancy(
    statements: list[Statement],
    *,
    catalog: ActionCatalog | None = None,
) -> list[Statement]:
    """Remove statements wholly subsumed by another statement in *statements*.

    Runs in O(n²) over the statement list for ``Action`` statements. With a
    non-empty *catalog*, each ``NotAction``-pair comparison also scans the
    catalog and the pair's exemption patterns, so the worst case becomes
    O(n² × c × p), where *c* is the number of catalog actions and *p* is the
    number of ``NotAction`` patterns checked for the pair. This remains
    acceptable given the AWS limit of 5 statements per SCP. When two
    statements are identical both are compared against each other; the
    algorithm keeps the later one and discards the earlier, leaving exactly
    one copy.

    When *catalog* is non-empty, ``NotAction`` statements participate: see
    module docstring.  With no catalog (or an empty one), ``NotAction`` pairs
    are never eliminated.
    """
    if len(statements) <= 1:
        return statements

    catalog_ok = catalog is not None and not catalog.is_empty()

    redundant: set[int] = set()

    for i, a in enumerate(statements):
        if i in redundant:
            continue
        for j, b in enumerate(statements):
            if i == j or j in redundant:
                continue
            if a.not_action is None and b.not_action is not None:
                continue
            if a.not_action is not None and b.not_action is None:
                continue
            if a.not_action is None and b.not_action is None:
                if _is_subsumed_by(a, b):
                    redundant.add(i)
                    break
            else:
                if catalog_ok and catalog is not None and _not_action_subsumed_by(a, b, catalog):
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


def _not_action_subsumed_by(a: Statement, b: Statement, catalog: ActionCatalog) -> bool:
    """Return True if ``NotAction`` *a* is wholly subsumed by ``NotAction`` *b*.

    Requires *exempt(b) ⊆ exempt(a)* for every action in *catalog* (see module
    docstring).  Call only when *catalog* is non-empty and both statements use
    ``NotAction``.
    """
    if a.effect != b.effect:
        return False
    if not conditions_equal(a.condition, b.condition):
        return False
    if _normalise_resource(a.resource) != _normalise_resource(b.resource):
        return False
    na_a = _normalize_action_patterns(a.not_action_list)
    na_b = _normalize_action_patterns(b.not_action_list)
    for full in catalog.iter_full_actions():
        if _exempted_by_not_action_list(full, na_b) and not _exempted_by_not_action_list(
            full, na_a
        ):
            return False
    return True


def _exempted_by_not_action_list(full_action: str, patterns: list[str]) -> bool:
    """True when *full_action* matches any ``NotAction`` exemption *patterns*."""
    normalized_action = _normalize_action_match_term(full_action)
    return any(fnmatchcase(normalized_action, pattern) for pattern in patterns)


def _normalize_action_patterns(patterns: list[str]) -> list[str]:
    """Normalize IAM action patterns for catalog-backed matching."""
    return [_normalize_action_match_term(pattern) for pattern in patterns]


def _normalize_action_match_term(action: str) -> str:
    """Normalize an IAM action string for catalog-backed matching."""
    if action == "*" or ":" not in action:
        return action
    service, _, name = action.partition(":")
    return f"{service.lower()}:{name}"


def _covers(covering: str, action: str) -> bool:
    """Return True if *covering* covers *action*.

    Used for ``Action`` subsumption checks. Catalog-backed ``NotAction`` checks
    use glob-style matching against literal catalog actions instead.

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
