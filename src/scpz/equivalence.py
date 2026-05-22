"""Semantic permission comparison for SCP documents (catalog-backed).

``check_permission_equivalence`` answers whether an *after* policy is the same
or **stricter** than *before* for member-account effective permissions under a
deliberately narrow model:

- Only ``Effect`` ``Deny`` / ``Allow`` statements are analysed (the common SCP
  case).  Other effects would fail validation elsewhere.
- Statements are grouped by ``(Effect, condition fingerprint, Resource set)``.
  Optimizer output is expected to keep those axes stable for merged statements.
- ``Deny`` + ``Action`` — denied IAM actions are expanded on the **catalog**
  universe using the same wildcard rules as :func:`scpz.optimizations.redundancy._covers`.
- ``Deny`` + ``NotAction`` — denied actions are ``catalog universe`` minus exemptions,
  where exemptions are expanded from ``NotAction`` entries (requires a
  non-empty catalog).
- ``Allow`` (SCP carve-outs for inherited denies) — **stricter** means *fewer*
  actions receive the carve-out: ``carve(after)`` is a subset of ``carve(before)``.
- ``Allow`` statements must use ``Action`` (``NotAction`` on ``Allow`` is
  rejected as unsupported).

This is **not** a full Organizations attachment simulator; it is a
machine-checkable best effort aligned with how scpz reasons about actions.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scpz.optimizations.conditions import condition_fingerprint

if TYPE_CHECKING:
    from scpz.catalog import ActionCatalog
    from scpz.models import ScpDocument, Statement


@dataclass(frozen=True)
class EquivalenceResult:
    """Outcome of :func:`check_permission_equivalence`."""

    ok: bool
    messages: tuple[str, ...] = ()


def _pattern_covers_action(pattern: str, full_action: str) -> bool:
    """True when IAM action pattern *pattern* covers concrete action *full_action*."""
    if pattern == "*":
        return True
    if pattern == full_action:
        return True
    if pattern.endswith("*"):
        return full_action.startswith(pattern[:-1])
    return False


def _full_catalog_atoms(catalog: ActionCatalog) -> frozenset[str]:
    """Every ``service:name`` string in the catalog."""
    return catalog.all_full_actions()


def _normalize_action_pattern(pattern: str) -> str:
    """Normalize action patterns by lowercasing only the service prefix."""
    if ":" not in pattern:
        return pattern
    service, _, remainder = pattern.partition(":")
    return f"{service.lower()}:{remainder}"


def _expand_action_patterns_to_atoms(patterns: list[str], catalog: ActionCatalog) -> set[str]:
    """Expand ``Action`` / ``NotAction`` patterns to a set of ``svc:name`` atoms."""
    out: set[str] = set()
    universe: frozenset[str] | None = None

    for pattern in patterns:
        normalized_pattern = _normalize_action_pattern(pattern)
        if normalized_pattern == "*":
            if catalog.is_empty():
                msg = "Expanding bare Action '*' requires a non-empty action catalog."
                raise ValueError(msg)
            if universe is None:
                universe = _full_catalog_atoms(catalog)
            out.update(universe)
            continue
        if ":" not in normalized_pattern:
            out.add(normalized_pattern)
            continue
        service = normalized_pattern.partition(":")[0]
        if "*" not in normalized_pattern and "?" not in normalized_pattern:
            out.add(normalized_pattern)
            continue
        known = catalog.get_service(service)
        if not known:
            # Unknown service — treat pattern as a single opaque atom if exact
            if "*" not in normalized_pattern and "?" not in normalized_pattern:
                out.add(normalized_pattern)
            else:
                msg = (
                    f"Cannot expand wildcard action '{normalized_pattern}' — service '{service}' "
                    "is absent from the action catalog. Use a bundled or file catalog."
                )
                raise ValueError(msg)
            continue
        for name in known:
            full = f"{service}:{name}"
            if _pattern_covers_action(normalized_pattern, full):
                out.add(full)
    return out


def _deny_action_statement_atoms(stmt: Statement, catalog: ActionCatalog) -> set[str]:
    """Denied atoms for a ``Deny`` statement that uses ``Action``."""
    return _expand_action_patterns_to_atoms(stmt.action_list, catalog)


def _deny_not_action_statement_atoms(stmt: Statement, catalog: ActionCatalog) -> set[str]:
    """Denied atoms for a ``Deny`` statement that uses ``NotAction``."""
    if catalog.is_empty():
        msg = (
            "Deny statements with NotAction require a non-empty action catalog "
            "to prove equivalence."
        )
        raise ValueError(msg)
    universe = set(_full_catalog_atoms(catalog))
    exempt = _expand_action_patterns_to_atoms(stmt.not_action_list, catalog)
    return universe - exempt


def _allow_carve_atoms(stmt: Statement, catalog: ActionCatalog) -> set[str]:
    """Atoms carved out by an ``Allow`` statement (SCP inheritance exception)."""
    if stmt.not_action is not None:
        msg = "Allow statements with NotAction are not supported for equivalence checks."
        raise ValueError(msg)
    return _expand_action_patterns_to_atoms(stmt.action_list, catalog)


def _statement_partition_key(stmt: Statement) -> tuple[str, str, frozenset[str]]:
    return (
        stmt.effect,
        condition_fingerprint(stmt.condition),
        frozenset(stmt.resource_list),
    )


def _partition_by_key(doc: ScpDocument) -> dict[tuple[str, str, frozenset[str]], list[Statement]]:
    groups: dict[tuple[str, str, frozenset[str]], list[Statement]] = defaultdict(list)
    for stmt in doc.statement:
        groups[_statement_partition_key(stmt)].append(stmt)
    return dict(groups)


def _union_deny_atoms_for_statements(stmts: list[Statement], catalog: ActionCatalog) -> set[str]:
    denied: set[str] = set()
    for stmt in stmts:
        if stmt.effect != "Deny":
            continue
        if stmt.not_action is not None:
            denied |= _deny_not_action_statement_atoms(stmt, catalog)
        else:
            denied |= _deny_action_statement_atoms(stmt, catalog)
    return denied


def _union_allow_carve_for_statements(stmts: list[Statement], catalog: ActionCatalog) -> set[str]:
    carved: set[str] = set()
    for stmt in stmts:
        if stmt.effect != "Allow":
            continue
        carved |= _allow_carve_atoms(stmt, catalog)
    return carved


def check_permission_equivalence(
    before: ScpDocument,
    after: ScpDocument,
    catalog: ActionCatalog,
) -> EquivalenceResult:
    """Return whether *after* is the same or stricter than *before* (not broader).

    Stricter means: at least as much ``Deny`` coverage and no additional
    ``Allow`` carve-outs within each ``(Effect, Condition, Resource)`` slice.
    """
    errors: list[str] = []

    try:
        before_g = _partition_by_key(before)
        after_g = _partition_by_key(after)

        # --- Deny: every atom denied before must still be denied after (per key).
        for key, stmts_b in before_g.items():
            if key[0] != "Deny":
                continue
            denied_before = _union_deny_atoms_for_statements(stmts_b, catalog)
            if not denied_before:
                continue
            stmts_a = after_g.get(key, [])
            denied_after = _union_deny_atoms_for_statements(stmts_a, catalog)
            if not denied_before <= denied_after:
                witness = next(iter(sorted(denied_before - denied_after)))
                errors.append(
                    "Deny coverage shrank (broader permissions): "
                    f"action '{witness}' was denied before but not after "
                    f"(partition Effect={key[0]!r}, resources={sorted(key[2])!r})."
                )

        # --- Allow: carve-outs must not grow (per key).
        for key, stmts_b in before_g.items():
            if key[0] != "Allow":
                continue
            carve_before = _union_allow_carve_for_statements(stmts_b, catalog)
            if not carve_before:
                continue
            stmts_a = after_g.get(key, [])
            carve_after = _union_allow_carve_for_statements(stmts_a, catalog)
            if not carve_after <= carve_before:
                witness = next(iter(sorted(carve_after - carve_before)))
                errors.append(
                    "Allow carve-out grew (broader permissions): "
                    f"action '{witness}' is newly or more strongly allowed to bypass "
                    "inherited denies "
                    f"(partition resources={sorted(key[2])!r})."
                )

        # --- Brand-new Allow partitions in after (non-empty carve) broaden.
        for key, stmts_a in after_g.items():
            if key[0] != "Allow" or key in before_g:
                continue
            carve_after = _union_allow_carve_for_statements(stmts_a, catalog)
            if carve_after:
                errors.append(
                    "New Allow statement group in 'after' introduces carve-outs "
                    f"({len(carve_after)} catalog actions) that were absent before "
                    f"(resources={sorted(key[2])!r})."
                )
    except ValueError as exc:
        errors.append(str(exc))

    if errors:
        return EquivalenceResult(ok=False, messages=tuple(errors))
    return EquivalenceResult(ok=True, messages=())
