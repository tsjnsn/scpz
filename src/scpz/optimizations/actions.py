"""Action wildcard compression.

Replaces groups of actions sharing a common prefix with a single wildcard
pattern using a trie-based recursive algorithm:

1. Group actions by service prefix.
2. Within each service, group by CamelCase verb (first word).
3. For each verb group, recursively search for sub-groups that share a
   longer common prefix and can be safely wildcarded.

Examples::

  iam:CreatePolicy + iam:CreatePolicyVersion + iam:CreateRole
      -> iam:CreatePolicy*  +  iam:CreateRole       (sub-group found)

  iam:DeleteRole + iam:DeleteRolePolicy
      -> iam:DeleteRole*                             (LCP > verb)

  guardduty:DeleteDetector + guardduty:DeleteMembers
      -> kept explicit                               (sub-groups are singletons)

Catalog safety
~~~~~~~~~~~~~~
Conservative mode: a wildcard ``svc:prefix*`` is emitted only when the
catalog confirms that every catalog action starting with *prefix* is already
in the statement (or sub-group).  Without a catalog the LCP heuristic is
trusted as-is.

``NotAction`` uses the same conservative + ``catalog.covers`` proofs only: a
wildcard in ``NotAction`` would exempt more IAM actions, so compression runs
only when a catalog is configured and non-empty (mirroring the Action path
with catalog).  Aggressive shortening for ``NotAction`` is not supported.

Aggressive mode with catalog: two additional passes run after the verb-level
wildcards are produced.

1. *Individual shortening* — each ``svc:Verb*`` wildcard is shortened to the
   minimum prefix at which the catalog confirms no other verb families exist.
   For example ``guardduty:Delete*`` → ``guardduty:Del*`` when the catalog
   has no ``Del``-prefixed action outside the Delete family.

2. *Cross-verb collapse* — adjacent shortened wildcards whose bare prefixes
   share a common prefix are collapsed further when ``catalog.covers``
   confirms full coverage at that shorter prefix.

Byte-cost formula
~~~~~~~~~~~~~~~~~
Wildcard acceptance uses JSON-accurate byte counts: each string contributes
``len + 2`` bytes (the surrounding quotes), so the formula is

    wildcard_bytes = len(wildcard) + 2
    expanded_bytes = sum(len(a) + 2 for a in expanded) + (n - 1)   # commas

This is more accurate than a raw character count and catches marginal cases
the simpler formula misses.
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

    Statements that use ``NotAction`` are compressed only when *catalog* is
    non-empty, using conservative rules (same ``catalog.covers`` proofs as
    ``Action`` with a catalog).  *mode* applies only to ``Action`` and does
    not enable aggressive passes on ``NotAction``.

    conservative
        Trie-based recursive compression.  A wildcard is emitted for any
        sub-group of actions sharing a prefix longer than their verb prefix.
        When *catalog* is provided, wildcards are only emitted when the
        catalog confirms no additional actions would be covered.
    aggressive
        Verb-level wildcard for each verb group, e.g. ``iam:Delete*``.
        When *catalog* is also provided, two additional passes run:

        1. Each verb wildcard is shortened to the minimum safe prefix —
           e.g. ``guardduty:Delete*`` → ``guardduty:Del*`` when the catalog
           has no ``Del``-prefixed action outside the Delete family.
        2. Adjacent shortened wildcards are collapsed further when
           ``catalog.covers`` confirms a shared shorter prefix is safe.
    """
    return [_compress_statement_actions(s, mode=mode, catalog=catalog) for s in statements]


def _compress_not_action_statement(
    stmt: Statement,
    *,
    catalog: ActionCatalog | None,
) -> Statement:
    """Compress ``NotAction`` entries when a catalog proves no new exemptions.

    Wildcards in ``NotAction`` exempt *more* actions than explicit entries, so
    the no-catalog LCP heuristic used for ``Action`` is not applied here.
    When *catalog* is missing or empty, the statement is returned unchanged.
    """
    items = stmt.not_action_list
    if len(items) <= 1 or items == ["*"]:
        return stmt
    if catalog is None or catalog.is_empty():
        return stmt

    compressed = _compress_action_list(
        items,
        mode="conservative",
        catalog=catalog,
    )
    new_not_action: list[str] | str = compressed
    if len(compressed) == 1:
        new_not_action = compressed[0]

    return stmt.model_copy(update={"not_action": new_not_action})


def _compress_statement_actions(
    stmt: Statement,
    *,
    mode: str,
    catalog: ActionCatalog | None,
) -> Statement:
    """Compress actions within a single statement."""
    if stmt.not_action is not None:
        return _compress_not_action_statement(stmt, catalog=catalog)

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

    conservative mode: trie-based recursive sub-group compression (see
                       ``_compress_name_group``).
    aggressive mode:   verb-level wildcard (``service:Verb*``) for each
                       verb group when shorter than the expanded form.
    """
    if len(names) <= 1:
        return [f"{service}:{n}" for n in names]

    # Group by verb prefix (first CamelCase word)
    by_prefix: dict[str, list[str]] = defaultdict(list)
    for name in names:
        prefix = _extract_verb_prefix(name)
        by_prefix[prefix].append(name)

    has_catalog = catalog is not None and not catalog.is_empty()
    result: list[str] = []
    for verb, group in sorted(by_prefix.items()):
        expanded = [f"{service}:{n}" for n in group]
        if len(group) >= 2 and verb and mode == "aggressive":
            if has_catalog and catalog is not None:
                effective_verb = _shorten_verb_prefix(service, verb, catalog)
            else:
                effective_verb = verb
            wildcard = f"{service}:{effective_verb}*"
            if _wildcard_saves_bytes(wildcard, expanded):
                result.append(wildcard)
                continue
        result.extend(_compress_name_group(service, group, verb, mode=mode, catalog=catalog))

    if mode == "aggressive" and has_catalog and catalog is not None:
        result = _try_shorten_across_verbs(service, names, result, catalog)

    return result


def _compress_name_group(
    service: str,
    names: list[str],
    base_prefix: str,
    *,
    mode: str,
    catalog: ActionCatalog | None,
) -> list[str]:
    """Recursively compress a group of action names sharing *base_prefix*.

    At each level the algorithm:

    1. Computes the longest common prefix (LCP) of *names*.
    2. If LCP extends beyond *base_prefix*, attempts a ``service:LCP*``
       wildcard (safety-checked via catalog when available).
    3. If LCP equals *base_prefix* and a catalog is present, attempts a
       ``service:base_prefix*`` wildcard confirmed by the catalog.
    4. When no single wildcard covers the whole group, splits by the next
       character after LCP and recurses into each sub-group independently.

    The recursion terminates because each recursive call either has a
    strictly longer *base_prefix* or fewer names.
    """
    if len(names) <= 1:
        return [f"{service}:{n}" for n in names]

    lcp = find_longest_common_prefix(names)
    expanded = [f"{service}:{n}" for n in names]

    if len(lcp) > len(base_prefix):
        wildcard = f"{service}:{lcp}*"
        if _wildcard_saves_bytes(wildcard, expanded) and (
            catalog is None or catalog.covers(service, lcp, frozenset(names))
        ):
            return [wildcard]

    # Only when names diverge immediately (lcp == base_prefix) — the path
    # above did not fire — try a catalog-confirmed verb-level wildcard.
    if lcp == base_prefix and catalog is not None:
        wildcard = f"{service}:{base_prefix}*"
        if _wildcard_saves_bytes(wildcard, expanded) and catalog.covers(
            service, base_prefix, frozenset(names)
        ):
            return [wildcard]

    split_at = len(lcp)
    groups: dict[str, list[str]] = {}
    for name in names:
        key = name[split_at] if split_at < len(name) else ""
        groups.setdefault(key, []).append(name)

    result: list[str] = []
    for _, group in sorted(groups.items()):
        result.extend(_compress_name_group(service, group, lcp, mode=mode, catalog=catalog))
    return result


def _shorten_verb_prefix(
    service: str,
    verb: str,
    catalog: ActionCatalog,
) -> str:
    """Find the shortest prefix p where ``service:p*`` is scope-equivalent to ``service:verb*``.

    A prefix *p* (a strict prefix of *verb*) is safe when every catalog action
    for *service* that starts with *p* also starts with *verb* — meaning ``p*``
    adds no new verb families beyond ``verb*``.

    Scans from length 1 upward and returns the first safe prefix; returns
    *verb* unchanged when no shorter prefix qualifies or the catalog has no
    data for this service.

    Example::

        # catalog "Del*" actions are exclusively "Delete*" — "Del" is safe
        _shorten_verb_prefix("guardduty", "Delete", catalog) -> "Del"

        # catalog "Pu*" includes non-Put actions (e.g. PublishRecord) — no safe short prefix
        _shorten_verb_prefix("example", "Put", catalog) -> "Put"  (unchanged)
    """
    known = catalog.get_service(service)
    if not known:
        return verb

    for length in range(1, len(verb)):
        prefix = verb[:length]
        prefix_actions = [n for n in known if n.startswith(prefix)]
        if not prefix_actions:
            continue  # no catalog data at this prefix length — skip
        if all(n.startswith(verb) for n in prefix_actions):
            return prefix

    return verb


def _bare_prefix(item: str, service: str) -> str:
    """Strip ``service:`` and trailing ``*`` from a compressed action item."""
    return item[len(service) + 1 :].rstrip("*")


def _try_shorten_across_verbs(
    service: str,
    all_names: list[str],
    items: list[str],
    catalog: ActionCatalog,
) -> list[str]:
    """Replace verb-level results with shorter catalog-safe prefixes where possible.

    Iteratively finds runs of 2+ sorted items whose bare prefixes share a
    common prefix *shorter* than any individual item's prefix, then attempts
    ``service:lcp*`` — emitting it only when the catalog confirms no
    additional actions would be covered.  Repeats until no progress is made.

    Example::

        items   = ["svc:Delete*", "svc:DetachFoo"]
        catalog = {"svc": ["DeleteA", "DeleteB", "DetachFoo"]}
        result  = ["svc:De*"]   # lcp="De", catalog confirms full coverage
    """
    result = list(items)
    improved = True

    while improved:
        improved = False
        sorted_result = sorted(result)
        n = len(sorted_result)

        i = 0
        while i < n - 1:
            # Grow a window of consecutive items whose bare prefixes share a
            # common prefix strictly shorter than any individual bare prefix.
            window = [sorted_result[i]]
            lcp = _bare_prefix(sorted_result[i], service)

            for j in range(i + 1, n):
                next_bare = _bare_prefix(sorted_result[j], service)
                # Incrementally narrow the LCP instead of recomputing from scratch.
                new_lcp = os.path.commonprefix([lcp, next_bare])
                # Stop if lcp vanishes or equals any item's bare prefix (no gain).
                if not new_lcp or new_lcp in (lcp, next_bare):
                    break
                lcp = new_lcp
                window.append(sorted_result[j])

            if len(window) < 2:
                i += 1
                continue

            lcp_names = frozenset(name for name in all_names if name.startswith(lcp))
            candidate = f"{service}:{lcp}*"

            if _wildcard_saves_bytes(candidate, window) and catalog.covers(service, lcp, lcp_names):
                for item in window:
                    result.remove(item)
                result.append(candidate)
                improved = True
                break

            i += 1

    return result


def _wildcard_saves_bytes(wildcard: str, expanded: list[str]) -> bool:
    """Return True if *wildcard* produces fewer JSON bytes than *expanded*.

    Uses JSON-accurate accounting: each string in an array costs
    ``len + 2`` bytes (surrounding quotes), and n elements need n-1 commas.
    """
    wildcard_bytes = len(wildcard) + 2
    expanded_bytes = sum(len(a) + 2 for a in expanded) + len(expanded) - 1
    return wildcard_bytes < expanded_bytes


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
