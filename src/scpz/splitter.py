"""SCP splitter — split oversized policies into multiple SCP documents.

When a single SCP cannot fit within AWS limits even after optimization,
this module splits it into multiple documents while respecting the
10-SCP-per-target constraint.

Splitting strategy
~~~~~~~~~~~~~~~~~~
1. **Expand oversized statements** — any statement that is individually
   too large to fit in a single SCP is first split on its largest list
   field (``Action`` takes priority, then ``Deny`` + ``NotAction`` when a
   non-empty :class:`~scpz.catalog.ActionCatalog` is supplied — see below,
   then ``Resource``).
2. **First-fit decreasing (FFD) packing** — the expanded statement list
   is sorted by descending byte weight, then each statement is placed
   into the first existing SCP document where it fits (both byte limit
   and 5-statement limit), opening a new document only when necessary.
   FFD typically produces fewer documents than sequential greedy packing.

``Deny`` + ``NotAction`` cannot be split by *partitioning* the exemption
list across statements: under AWS semantics the union of denies would
change.  When a catalog is available, an oversized ``NotAction`` deny is
instead expanded to the finite set of denied catalog atoms
(``universe - exemptions``) and greedily re-chunked as ``Deny`` +
``Action`` lists — union semantics match the original statement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from scpz.constants import (
    MAX_SCP_SIZE_BYTES,
    MAX_SCPS_PER_TARGET,
    MAX_STATEMENTS_PER_SCP,
)
from scpz.equivalence import _deny_not_action_statement_atoms
from scpz.models import ScpDocument, Statement

if TYPE_CHECKING:
    from scpz.catalog import ActionCatalog


class SplitError(Exception):
    """Raised when a policy cannot be split to fit within AWS limits."""


@dataclass
class SplitResult:
    """Result of splitting an SCP document."""

    documents: list[ScpDocument]

    @property
    def count(self) -> int:
        return len(self.documents)

    @property
    def fits(self) -> bool:
        return self.count <= MAX_SCPS_PER_TARGET and all(
            doc.size_bytes <= MAX_SCP_SIZE_BYTES and len(doc.statement) <= MAX_STATEMENTS_PER_SCP
            for doc in self.documents
        )


def split_if_needed(doc: ScpDocument, *, catalog: ActionCatalog | None = None) -> SplitResult:
    """Split an SCP document if it exceeds AWS limits.

    Returns a ``SplitResult`` with one or more documents.  Raises
    ``SplitError`` if the policy cannot fit within ``MAX_SCPS_PER_TARGET``
    documents even after splitting, or if a single action/resource item
    is itself too large to fit in any SCP.

    *catalog*
        When non-empty, ``Deny`` statements that use ``NotAction`` and
        exceed the per-SCP byte limit alone can be split safely by
        re-encoding the implied deny set as chunked ``Action`` lists
        (catalog-backed).  When omitted or empty, those statements fall back
        to ``Resource`` splitting only (same as historical behaviour).
    """
    if _fits_single(doc):
        return SplitResult(documents=[doc])

    # Step 1: expand any statements that are individually over the size limit.
    stmts = _expand_oversized_statements(list(doc.statement), doc.version, catalog)

    # Step 2: pack using first-fit decreasing.
    documents = _pack_statements_ffd(doc.version, stmts)

    if len(documents) > MAX_SCPS_PER_TARGET:
        raise SplitError(
            f"Policy requires {len(documents)} SCPs, but the maximum is "
            f"{MAX_SCPS_PER_TARGET} per target. "
            "Consider reducing the number of statements or actions."
        )

    return SplitResult(documents=documents)


def _fits_single(doc: ScpDocument) -> bool:
    """Check if a document fits within a single SCP."""
    return doc.size_bytes <= MAX_SCP_SIZE_BYTES and len(doc.statement) <= MAX_STATEMENTS_PER_SCP


def _expand_oversized_statements(
    stmts: list[Statement],
    version: str,
    catalog: ActionCatalog | None,
) -> list[Statement]:
    """Replace any statement too large to fit alone with a list of smaller chunks."""
    result: list[Statement] = []
    for stmt in stmts:
        single = ScpDocument(version=version, statement=[stmt])
        if single.size_bytes > MAX_SCP_SIZE_BYTES:
            chunks = _split_oversized_statement(stmt, version, catalog)
            for chunk_doc in chunks:
                result.extend(chunk_doc.statement)
        else:
            result.append(stmt)
    return result


def _split_oversized_statement(
    stmt: Statement,
    version: str,
    catalog: ActionCatalog | None,
) -> list[ScpDocument]:
    """Split a single statement that is too large to fit in one SCP.

    Attempts to split the ``Action`` list first (when ``Action`` is used,
    not ``NotAction``), then — when *catalog* is non-empty — a ``Deny`` +
    ``NotAction`` statement by expanding to denied catalog atoms and
    chunking as ``Action`` lists, then falls back to splitting the
    ``Resource`` list.

    Raises ``SplitError`` when no strategy applies or a single list element
    still exceeds the byte limit.
    """
    if stmt.not_action is None and len(stmt.action_list) > 1:
        return _split_by_field(stmt, "action", stmt.action_list, version)
    if (
        stmt.effect == "Deny"
        and stmt.not_action is not None
        and catalog is not None
        and not catalog.is_empty()
    ):
        not_action_chunks = _split_oversized_deny_not_action_via_catalog(stmt, version, catalog)
        if not_action_chunks is not None:
            return not_action_chunks
    if len(stmt.resource_list) > 1:
        return _split_by_field(stmt, "resource", stmt.resource_list, version)
    raise SplitError(
        f"Statement cannot be split further: no splittable Action / NotAction(catalog) / "
        f"Resource list, yet the statement still exceeds {MAX_SCP_SIZE_BYTES:,} bytes."
    )


def _split_oversized_deny_not_action_via_catalog(
    stmt: Statement,
    version: str,
    catalog: ActionCatalog,
) -> list[ScpDocument] | None:
    """If *stmt* is ``Deny`` + ``NotAction`` and too large, split using catalog denied atoms.

    Returns ``None`` when this strategy does not apply (caller tries
    ``Resource`` splitting).  Raises :class:`SplitError` when the statement is
    clearly oversized but the implied deny set cannot be materialised
    (expansion error, or every catalog action is exempt while JSON remains
    oversized).
    """
    single = ScpDocument(version=version, statement=[stmt])
    if single.size_bytes <= MAX_SCP_SIZE_BYTES:
        return None

    try:
        denied_sorted = sorted(_deny_not_action_statement_atoms(stmt, catalog))
    except ValueError as exc:
        raise SplitError(str(exc)) from exc

    if not denied_sorted:
        raise SplitError(
            "This Deny+NotAction statement is larger than the SCP byte limit, but under "
            "the configured action catalog it exempts every action — the remaining bulk "
            "cannot be reduced by catalog-backed splitting. Add Resource list splitting, "
            "use a smaller exemption list, or supply a wider catalog."
        )

    return _split_by_denied_action_atoms(stmt, version, denied_sorted)


def _split_by_denied_action_atoms(
    stmt: Statement,
    version: str,
    denied_sorted: list[str],
) -> list[ScpDocument]:
    """Greedy-chunk *denied_sorted* into ``Deny`` + ``Action`` statements (clears ``NotAction``)."""
    docs: list[ScpDocument] = []
    remaining = list(denied_sorted)

    while remaining:
        chunk: list[str] = []
        for item in remaining:
            trial = [*chunk, item]
            trial_val: list[str] | str = trial[0] if len(trial) == 1 else trial
            trial_stmt = stmt.model_copy(update={"action": trial_val, "not_action": None})
            trial_doc = ScpDocument(version=version, statement=[trial_stmt])
            if trial_doc.size_bytes <= MAX_SCP_SIZE_BYTES:
                chunk = trial
            else:
                break

        if not chunk:
            raise SplitError(
                "A single catalog action in this Deny+NotAction expansion produces a "
                f"statement that exceeds {MAX_SCP_SIZE_BYTES:,} bytes and cannot be split "
                "further."
            )

        chunk_val: list[str] | str = chunk[0] if len(chunk) == 1 else chunk
        chunk_stmt = stmt.model_copy(update={"action": chunk_val, "not_action": None})
        docs.append(ScpDocument(version=version, statement=[chunk_stmt]))
        remaining = remaining[len(chunk) :]

    return docs


def _split_by_field(
    stmt: Statement,
    field_name: str,
    items: list[str],
    version: str,
) -> list[ScpDocument]:
    """Greedily chunk a statement's list field so each chunk fits in one SCP.

    All other statement fields (Effect, Condition, and the non-split list
    field) are preserved unchanged in every chunk.
    """
    docs: list[ScpDocument] = []
    remaining = list(items)

    while remaining:
        chunk: list[str] = []
        for item in remaining:
            trial = [*chunk, item]
            trial_val: list[str] | str = trial[0] if len(trial) == 1 else trial
            trial_stmt = stmt.model_copy(update={field_name: trial_val})
            trial_doc = ScpDocument(version=version, statement=[trial_stmt])
            if trial_doc.size_bytes <= MAX_SCP_SIZE_BYTES:
                chunk = trial
            else:
                break  # item doesn't fit; seal the current chunk

        if not chunk:
            raise SplitError(
                f"A single '{field_name}' item produces a statement that "
                f"exceeds {MAX_SCP_SIZE_BYTES:,} bytes and cannot be split further."
            )

        chunk_val: list[str] | str = chunk[0] if len(chunk) == 1 else chunk
        chunk_stmt = stmt.model_copy(update={field_name: chunk_val})
        docs.append(ScpDocument(version=version, statement=[chunk_stmt]))
        remaining = remaining[len(chunk) :]

    return docs


def _pack_statements_ffd(version: str, stmts: list[Statement]) -> list[ScpDocument]:
    """Pack statements into documents using first-fit decreasing.

    Statements are sorted by descending byte weight (size when alone in a
    document).  Each statement is placed into the first existing document
    where it fits; a new document is opened only when no existing one can
    accommodate it.  Both the per-SCP byte limit and the 5-statement limit
    are respected.
    """
    if not stmts:
        return []

    sorted_stmts = sorted(
        stmts,
        key=lambda s: ScpDocument(version=version, statement=[s]).size_bytes,
        reverse=True,
    )

    bins: list[list[Statement]] = []

    for stmt in sorted_stmts:
        placed = False
        for bin_stmts in bins:
            if len(bin_stmts) >= MAX_STATEMENTS_PER_SCP:
                continue
            candidate_doc = ScpDocument(version=version, statement=[*bin_stmts, stmt])
            if candidate_doc.size_bytes <= MAX_SCP_SIZE_BYTES:
                bin_stmts.append(stmt)
                placed = True
                break
        if not placed:
            bins.append([stmt])

    return [ScpDocument(version=version, statement=b) for b in bins]
