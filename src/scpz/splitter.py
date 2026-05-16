"""SCP splitter — split oversized policies into multiple SCP documents.

When a single SCP cannot fit within AWS limits even after optimization,
this module splits it into multiple documents while respecting the
5-SCP-per-target constraint.
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

    Returns a SplitResult with one or more documents.
    Raises SplitError if the policy cannot fit even after splitting.
    """
    if _fits_single(doc):
        return SplitResult(documents=[doc])

    documents = _split_by_statements(doc)

    # Verify all documents fit
    for i, d in enumerate(documents):
        if d.size_bytes > MAX_SCP_SIZE_BYTES:
            # Try further splitting individual large statements
            # This is a hard case — a single statement that's too big
            raise SplitError(
                f"Split document {i + 1} is {d.size_bytes:,} bytes, "
                f"which exceeds the {MAX_SCP_SIZE_BYTES:,} byte limit. "
                "A single statement may be too large to fit in any SCP."
            )

    if len(documents) > MAX_SCPS_PER_TARGET:
        raise SplitError(
            f"Policy requires {len(documents)} SCPs, but the maximum is "
            f"{MAX_SCPS_PER_TARGET} per target. "
            f"Consider reducing the number of statements or actions."
        )

    return SplitResult(documents=documents)


def _fits_single(doc: ScpDocument) -> bool:
    """Check if a document fits within a single SCP."""
    return doc.size_bytes <= MAX_SCP_SIZE_BYTES and len(doc.statement) <= MAX_STATEMENTS_PER_SCP


def _split_by_statements(doc: ScpDocument) -> list[ScpDocument]:
    """Split statements across multiple SCP documents.

    Uses a greedy bin-packing approach: add statements to the current
    document until adding the next one would exceed a limit, then start
    a new document.
    """
    documents: list[ScpDocument] = []
    current_stmts: list[Statement] = []

    for stmt in doc.statement:
        # Check if adding this statement would exceed limits
        candidate = [*current_stmts, stmt]
        candidate_doc = ScpDocument(version=doc.version, statement=candidate)

        if len(candidate) > MAX_STATEMENTS_PER_SCP or (
            candidate_doc.size_bytes > MAX_SCP_SIZE_BYTES and len(current_stmts) > 0
        ):
            # Flush current batch
            if current_stmts:
                documents.append(ScpDocument(version=doc.version, statement=current_stmts))
            current_stmts = [stmt]
        else:
            current_stmts = candidate

    # Flush remaining
    if current_stmts:
        documents.append(ScpDocument(version=doc.version, statement=current_stmts))

    return documents
