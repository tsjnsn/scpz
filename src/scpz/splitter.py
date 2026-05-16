"""SCP splitter — split oversized policies into multiple SCP documents.

When a single SCP cannot fit within AWS limits even after optimization,
this module splits it into multiple documents while respecting the
10-SCP-per-target constraint.

Splitting strategy
~~~~~~~~~~~~~~~~~~
1. **Expand oversized statements** — any statement that is individually
   too large to fit in a single SCP is first split on its largest list
   field (``Action`` takes priority, then ``Resource``).
2. **First-fit decreasing (FFD) packing** — the expanded statement list
   is sorted by descending byte weight, then each statement is placed
   into the first existing SCP document where it fits (both byte limit
   and 5-statement limit), opening a new document only when necessary.
   FFD typically produces fewer documents than sequential greedy packing.
"""

from __future__ import annotations

from dataclasses import dataclass

from scpz.constants import (
    MAX_SCP_SIZE_BYTES,
    MAX_SCPS_PER_TARGET,
    MAX_STATEMENTS_PER_SCP,
)
from scpz.models import ScpDocument, Statement


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


def split_if_needed(doc: ScpDocument) -> SplitResult:
    """Split an SCP document if it exceeds AWS limits.

    Returns a ``SplitResult`` with one or more documents.  Raises
    ``SplitError`` if the policy cannot fit within ``MAX_SCPS_PER_TARGET``
    documents even after splitting, or if a single action/resource item
    is itself too large to fit in any SCP.
    """
    if _fits_single(doc):
        return SplitResult(documents=[doc])

    # Step 1: expand any statements that are individually over the size limit.
    stmts = _expand_oversized_statements(list(doc.statement), doc.version)

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
    stmts: list[Statement], version: str
) -> list[Statement]:
    """Replace any statement too large to fit alone with a list of smaller chunks."""
    result: list[Statement] = []
    for stmt in stmts:
        single = ScpDocument(version=version, statement=[stmt])
        if single.size_bytes > MAX_SCP_SIZE_BYTES:
            chunks = _split_oversized_statement(stmt, version)
            for chunk_doc in chunks:
                result.extend(chunk_doc.statement)
        else:
            result.append(stmt)
    return result


def _split_oversized_statement(stmt: Statement, version: str) -> list[ScpDocument]:
    """Split a single statement that is too large to fit in one SCP.

    Attempts to split the ``Action`` list first (when ``Action`` is used,
    not ``NotAction``), then falls back to splitting the ``Resource`` list.
    Raises ``SplitError`` when neither list can be split further.
    """
    # Prefer splitting Action (not NotAction — semantic inversion makes it unsafe).
    if stmt.not_action is None and len(stmt.action_list) > 1:
        return _split_by_field(stmt, "action", stmt.action_list, version)
    # Fallback: split Resource.
    if len(stmt.resource_list) > 1:
        return _split_by_field(stmt, "resource", stmt.resource_list, version)
    raise SplitError(
        f"Statement cannot be split further: Action and Resource are both "
        f"scalars but the statement still exceeds {MAX_SCP_SIZE_BYTES:,} bytes."
    )


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
            trial = chunk + [item]
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
        remaining = remaining[len(chunk):]

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
            candidate_doc = ScpDocument(version=version, statement=bin_stmts + [stmt])
            if candidate_doc.size_bytes <= MAX_SCP_SIZE_BYTES:
                bin_stmts.append(stmt)
                placed = True
                break
        if not placed:
            bins.append([stmt])

    return [ScpDocument(version=version, statement=b) for b in bins]
