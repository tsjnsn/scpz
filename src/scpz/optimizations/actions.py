"""Action wildcard compression.

Replaces groups of actions sharing a common prefix with a single wildcard
pattern, but only when the longest common prefix (LCP) of the action names
extends *beyond* the verb prefix.  This keeps wildcards semantically tight:

  iam:DeleteRole + iam:DeleteRolePolicy  -> iam:DeleteRole*   (LCP > verb)
  iam:UpdateRole + iam:UpdateAssumeRolePolicy -> kept explicit (LCP == verb)
  logs:DeleteLogGroup + logs:DeleteLogStream  -> logs:DeleteLog* (LCP > verb)
  guardduty:DeleteDetector + guardduty:DeleteMembers -> kept explicit

Catalog safety in conservative mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When a catalog is provided, it is used to guard *both* wildcard levels:

- LCP wildcard (``svc:LCP*``): emitted only when the catalog confirms that
  no action starting with LCP exists beyond those already in the statement.
  Without a catalog the LCP heuristic is trusted as-is.
- Verb wildcard (``svc:Verb*``): emitted only when the catalog confirms full
  verb-level coverage (every ``Verb*`` catalog action is in the statement).
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scpz.catalog import ActionCatalog
    from scpz.models import Statement


def compress_actions(
    statements: list[Statement],
    *,
    mode: str = "conservative",
    catalog: ActionCatalog | None = None,
) -> list[Statement]:
    """Apply action wildcard compression to each statement.

    *mode* controls aggressiveness:

    conservative
        Wildcard only when the LCP of action names extends beyond the verb
        prefix, producing tight patterns like ``iam:DeleteRole*``.
        When *catalog* is provided, also wildcards at verb level when the
        catalog confirms that every matching action is already in the
        statement (``iam:Delete*`` is safe if all Delete* actions are listed).
    aggressive
        Wildcard at verb level (pre-LCP behaviour), e.g. ``iam:Delete*``.
        Saves more bytes but may broaden policy scope.  *catalog* has no
        effect in aggressive mode.
    """
    return [_compress_statement_actions(s, mode=mode, catalog=catalog) for s in statements]


def _compress_statement_actions(
    stmt: Statement,
    *,
    mode: str,
    catalog: ActionCatalog | None,
) -> Statement:
    """Compress actions within a single statement."""
    # Only compress Action, not NotAction (wildcards in NotAction are risky)
    if stmt.not_action is not None:
        return stmt

    actions = stmt.action_list
    if len(actions) <= 1 or actions == ["*"]:
        return stmt

    compressed = _compress_action_list(actions, mode=mode, catalog=catalog)

    new_action: list[str] | str = compressed
    if len(compressed) == 1:
        new_action = compressed[0]

    return stmt.model_copy(update={"action": new_action})


def _compress_action_list(
    actions: list[str],
    *,
    mode: str,
    catalog: ActionCatalog | None,
) -> list[str]:
    """Find common prefixes among actions and replace with wildcards.

    Strategy:
    1. Group actions by service (prefix before ':').
    2. Within each service, find common prefixes among the action names.
    3. If a wildcard pattern is shorter and covers >= 2 actions, use it.
    """
    # Group by service
    by_service: dict[str, list[str]] = defaultdict(list)
    wildcards: list[str] = []

    for action in actions:
        if "*" in action or "?" in action:
            wildcards.append(action)
            continue
        if ":" not in action:
            wildcards.append(action)
            continue
        svc, name = action.split(":", 1)
        by_service[svc].append(name)

    result: list[str] = list(wildcards)

    for svc, names in sorted(by_service.items()):
        result.extend(_compress_service_actions(svc, names, mode=mode, catalog=catalog))

    result = _remove_subsumed_actions(result)
    return sorted(set(result))


def _compress_service_actions(
    service: str,
    names: list[str],
    *,
    mode: str,
    catalog: ActionCatalog | None,
) -> list[str]:
    """Compress action names within a single service.

    conservative mode: wildcard only when LCP extends beyond the verb prefix
                       AND (no catalog is present OR the catalog confirms the
                       LCP wildcard matches no additional actions).  When the
                       LCP wildcard is blocked by the catalog, falls back to a
                       verb-level wildcard if the catalog confirms full
                       verb-level coverage.
    aggressive mode:   wildcard at verb level (``service:Verb*``).
    """
    if len(names) <= 1:
        return [f"{service}:{n}" for n in names]

    # Group by verb prefix (first CamelCase word)
    by_prefix: dict[str, list[str]] = defaultdict(list)
    for name in names:
        prefix = _extract_verb_prefix(name)
        by_prefix[prefix].append(name)

    result: list[str] = []
    for verb, group in sorted(by_prefix.items()):
        expanded = [f"{service}:{n}" for n in group]
        if len(group) >= 2 and verb:
            if mode == "aggressive":
                # Verb-level wildcard regardless of sub-prefix commonality
                wildcard = f"{service}:{verb}*"
                expanded_len = sum(len(a) for a in expanded) + len(expanded) - 1
                if len(wildcard) < expanded_len:
                    result.append(wildcard)
                    continue
            else:
                # conservative: require LCP beyond the verb
                lcp = find_longest_common_prefix(group)
                if len(lcp) > len(verb):
                    wildcard = f"{service}:{lcp}*"
                    expanded_len = sum(len(a) for a in expanded) + len(expanded) - 1
                    if len(wildcard) < expanded_len:
                        # Safety check: when the catalog is available, confirm
                        # that every catalog action matching the LCP pattern is
                        # already present in the statement.  Without a catalog
                        # the LCP heuristic is trusted as-is.
                        if catalog is None or catalog.covers(
                            service, lcp, frozenset(names)
                        ):
                            result.append(wildcard)
                            continue
                        # Catalog signals the LCP wildcard would broaden scope;
                        # fall through to the verb-level catalog check below.
                # catalog fallback: verb-level wildcard is safe when the
                # catalog confirms every matching action is already present
                if catalog is not None and catalog.covers(service, verb, frozenset(names)):
                    wildcard = f"{service}:{verb}*"
                    expanded_len = sum(len(a) for a in expanded) + len(expanded) - 1
                    if len(wildcard) < expanded_len:
                        result.append(wildcard)
                        continue
        result.extend(expanded)

    return result


def _extract_verb_prefix(action_name: str) -> str:
    """Extract the verb/prefix portion of an action name.

    Uses CamelCase boundaries to find the first 'word', which is typically
    the verb (Get, Put, List, Delete, Create, Describe, etc.).
    """
    prefix = []
    for i, ch in enumerate(action_name):
        if i > 0 and ch.isupper():
            break
        prefix.append(ch)
    return "".join(prefix)


def find_longest_common_prefix(strings: list[str]) -> str:
    """Find the longest common prefix among a list of strings."""
    if not strings:
        return ""
    return os.path.commonprefix(strings)


def _covers_action(covering: str, covered: str) -> bool:
    """Return True if *covering* covers *covered*.

    Exact string equality returns False so that an action is not considered
    to cover itself — callers that need to handle self-coverage should guard
    with an index check.

    ``*``            covers everything.
    ``svc:Verb*``    covers ``svc:VerbFoo``, ``svc:VerbFoo*``, etc.
    ``svc:VerbFoo``  does not cover ``svc:VerbFoo`` (exact match excluded).
    """
    if covering == covered:
        return False
    if covering == "*":
        return True
    if covering.endswith("*"):
        return covered.startswith(covering[:-1])
    return False


def _remove_subsumed_actions(actions: list[str]) -> list[str]:
    """Remove actions (including tighter wildcards) that are already covered
    by a broader action or wildcard in the same list.

    Examples::

        ["*", "iam:GetRole"]            -> ["*"]
        ["s3:Get*", "s3:GetObject"]     -> ["s3:Get*"]
        ["s3:Get*", "s3:GetObject*"]    -> ["s3:Get*"]
        ["s3:Get*", "iam:GetRole"]      -> ["s3:Get*", "iam:GetRole"]  (unchanged)

    Runs in O(n²) over the action list — acceptable given the small size of
    SCP action lists in practice.
    """
    if len(actions) <= 1:
        return actions
    # Fast path: no wildcards present, nothing can be subsumed.
    if not any("*" in a or "?" in a for a in actions):
        return actions

    return [
        action
        for i, action in enumerate(actions)
        if not any(_covers_action(other, action) for j, other in enumerate(actions) if i != j)
    ]
