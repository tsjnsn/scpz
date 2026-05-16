"""Resource ARN pattern optimization.

Collapses multiple specific ARNs into wildcard patterns where safe, and
deduplicates resource lists.

ARNs are only collapsed when the resource names within a type share a
non-empty longest common prefix (LCP).  This prevents semantically broad
patterns like ``role/*`` from replacing a list of unrelated named roles.
For example:

  role/app-prod-1, role/app-prod-2  -> role/app-prod-*   (LCP = 'app-prod-')
  role/SecurityAdmin, role/IncidentResponse -> kept explicit (LCP = '')
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scpz.models import Statement


def optimize_resources(statements: list[Statement]) -> list[Statement]:
    """Optimize resource lists across all statements."""
    return [_optimize_statement_resources(s) for s in statements]


def _optimize_statement_resources(stmt: Statement) -> Statement:
    """Optimize the Resource field within a single statement."""
    resources = stmt.resource_list
    if len(resources) <= 1:
        return stmt

    # Deduplicate
    seen: set[str] = set()
    deduped: list[str] = []
    for r in resources:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    # If '*' is present, everything else is redundant
    if "*" in seen:
        return stmt.model_copy(update={"resource": "*"})

    optimized = _collapse_arns(deduped)

    new_resource: list[str] | str = optimized
    if len(optimized) == 1:
        new_resource = optimized[0]

    return stmt.model_copy(update={"resource": new_resource})


def _collapse_arns(arns: list[str]) -> list[str]:
    """Collapse ARNs sharing a common prefix into wildcard patterns.

    Groups ARNs by their first 5 colon-separated segments (partition, service,
    region, account) and collapses the resource portion with wildcards.
    """
    # Separate non-ARN resources
    non_arns: list[str] = []
    arn_groups: dict[str, list[str]] = defaultdict(list)

    for arn in arns:
        if not arn.startswith("arn:"):
            non_arns.append(arn)
            continue
        parts = arn.split(":", 5)
        if len(parts) < 6:
            non_arns.append(arn)
            continue
        # Key = partition:service:region:account
        key = ":".join(parts[:5])
        arn_groups[key].append(parts[5])  # resource portion

    result: list[str] = list(non_arns)

    for prefix, resource_parts in sorted(arn_groups.items()):
        if len(resource_parts) == 1:
            result.append(f"{prefix}:{resource_parts[0]}")
            continue

        # Try to collapse by resource type
        collapsed = _collapse_resource_parts(prefix, resource_parts)
        result.extend(collapsed)

    return sorted(set(result))


def _collapse_resource_parts(arn_prefix: str, parts: list[str]) -> list[str]:
    """Collapse resource parts sharing a type prefix.

    Only collapses a ``type/name`` group when the resource names share a
    non-empty LCP, emitting ``type/LCP*`` instead of the unsafe ``type/*``.
    Groups whose names share no common prefix are kept explicit.
    """
    import os

    by_type: dict[str, list[str]] = defaultdict(list)
    no_type: list[str] = []

    for part in parts:
        if "/" in part:
            rtype, rest = part.split("/", 1)
            by_type[rtype].append(rest)
        else:
            no_type.append(part)

    result: list[str] = [f"{arn_prefix}:{p}" for p in no_type]

    for rtype, resources in sorted(by_type.items()):
        expanded = [f"{arn_prefix}:{rtype}/{r}" for r in resources]
        if len(resources) >= 2:
            lcp = os.path.commonprefix(resources)
            # Only wildcard when the names share a non-empty common prefix,
            # producing a tighter pattern than the blanket type/*.
            if lcp:
                wildcard = f"{arn_prefix}:{rtype}/{lcp}*"
                expanded_size = sum(len(a) for a in expanded) + len(expanded) - 1
                if len(wildcard) < expanded_size:
                    result.append(wildcard)
                    continue
        result.extend(expanded)

    return result
