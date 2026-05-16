"""Action wildcard compression.

Replaces groups of actions sharing a common prefix with a single wildcard
pattern, but only when the longest common prefix (LCP) of the action names
extends *beyond* the verb prefix.  This keeps wildcards semantically tight:

  iam:DeleteRole + iam:DeleteRolePolicy  -> iam:DeleteRole*   (LCP > verb)
  iam:UpdateRole + iam:UpdateAssumeRolePolicy -> kept explicit (LCP == verb)
  logs:DeleteLogGroup + logs:DeleteLogStream  -> logs:DeleteLog* (LCP > verb)
  guardduty:DeleteDetector + guardduty:DeleteMembers -> kept explicit
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

    return sorted(set(result))


def _compress_service_actions(
    service: str,
    names: list[str],
    *,
    mode: str,
    catalog: ActionCatalog | None,
) -> list[str]:
    """Compress action names within a single service.

    conservative mode: wildcard only when LCP extends beyond the verb prefix,
                       OR when the catalog confirms full verb-level coverage.
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
                        result.append(wildcard)
                        continue
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
