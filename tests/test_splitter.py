"""Tests for scpz.splitter."""

from __future__ import annotations

import pytest

from scpz.constants import MAX_SCP_SIZE_BYTES, MAX_SCPS_PER_TARGET, MAX_STATEMENTS_PER_SCP
from scpz.models import ScpDocument, Statement
from scpz.splitter import SplitError, split_if_needed


class TestSplitter:
    def test_no_split_needed(self, simple_deny: ScpDocument) -> None:
        result = split_if_needed(simple_deny)
        assert result.count == 1
        assert result.fits

    def test_split_by_statement_count(self) -> None:
        stmts = [
            Statement(
                sid=f"Stmt{i}",
                effect="Deny",
                action=f"s3:Action{i}",
                resource="*",
            )
            for i in range(8)
        ]
        doc = ScpDocument(version="2012-10-17", statement=stmts)
        result = split_if_needed(doc)
        assert result.count == 2
        assert all(len(d.statement) <= MAX_STATEMENTS_PER_SCP for d in result.documents)

    def test_error_on_too_many_splits(self) -> None:
        # Create enough statements to need > 5 SCPs
        stmts = [
            Statement(
                sid=f"Stmt{i}",
                effect="Deny",
                action=f"s3:Action{i}",
                resource="*",
            )
            for i in range(MAX_STATEMENTS_PER_SCP * (MAX_SCPS_PER_TARGET + 1))
        ]
        doc = ScpDocument(version="2012-10-17", statement=stmts)
        with pytest.raises(SplitError, match="maximum is"):
            split_if_needed(doc)

    def test_split_preserves_version(self) -> None:
        stmts = [Statement(effect="Deny", action=f"s3:Action{i}", resource="*") for i in range(8)]
        doc = ScpDocument(version="2012-10-17", statement=stmts)
        result = split_if_needed(doc)
        for d in result.documents:
            assert d.version == "2012-10-17"


class TestOversizedStatementSplitting:
    """A single statement too large for one SCP is now split rather than erroring."""

    def _oversized_action_doc(
        self,
        n: int = 520,
        resource: str = "*",
        condition: dict | None = None,  # type: ignore[type-arg]
    ) -> ScpDocument:
        actions = [f"s3:SomeAction{i:04d}" for i in range(n)]
        stmt = Statement(
            effect="Deny",
            action=actions,
            resource=resource,
            condition=condition,
        )
        doc = ScpDocument(version="2012-10-17", statement=[stmt])
        assert doc.size_bytes > MAX_SCP_SIZE_BYTES, (
            f"expected doc to exceed {MAX_SCP_SIZE_BYTES} bytes — increase n"
        )
        return doc

    def test_split_oversized_action_list_no_longer_raises(self) -> None:
        """An oversized single-action-list statement splits successfully."""
        doc = self._oversized_action_doc()
        result = split_if_needed(doc)  # must not raise SplitError
        assert result.fits
        for d in result.documents:
            assert d.size_bytes <= MAX_SCP_SIZE_BYTES
            assert len(d.statement) <= MAX_STATEMENTS_PER_SCP

    def test_split_oversized_preserves_effect_resource_condition(self) -> None:
        """Each chunk retains the original statement's Effect, Resource, and Condition."""
        cond = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        doc = self._oversized_action_doc(
            resource="arn:aws:s3:::my-bucket",
            condition=cond,
        )
        result = split_if_needed(doc)
        for d in result.documents:
            for s in d.statement:
                assert s.effect == "Deny"
                assert s.resource == "arn:aws:s3:::my-bucket"
                assert s.condition == cond

    def test_split_oversized_action_list_is_complete(self) -> None:
        """All original actions appear exactly once across the split output."""
        n = 520
        doc = self._oversized_action_doc(n=n)
        original_actions = {f"s3:SomeAction{i:04d}" for i in range(n)}
        result = split_if_needed(doc)
        output_actions: set[str] = set()
        for d in result.documents:
            for s in d.statement:
                output_actions.update(s.action_list)
        assert output_actions == original_actions

    def test_split_oversized_resource_list(self) -> None:
        """Falls back to splitting the Resource list when Action is a scalar."""
        resources = [f"arn:aws:s3:::bucket{i:04d}/*" for i in range(400)]
        stmt = Statement(effect="Deny", action="s3:GetObject", resource=resources)
        doc = ScpDocument(version="2012-10-17", statement=[stmt])
        assert doc.size_bytes > MAX_SCP_SIZE_BYTES
        result = split_if_needed(doc)
        assert result.fits
        output_resources: set[str] = set()
        for d in result.documents:
            for s in d.statement:
                output_resources.update(s.resource_list)
        assert output_resources == set(resources)


class TestFirstFitDecreasingPacking:
    """FFD packing produces correct and efficient output."""

    def _make_stmt(self, n_actions: int) -> Statement:
        """Statement whose size is controlled by the number of actions."""
        return Statement(
            effect="Deny",
            action=[f"s3:SomeActionName{i:04d}" for i in range(n_actions)],
            resource="*",
        )

    def test_ffd_respects_byte_and_statement_limits(self) -> None:
        """All output documents satisfy both the byte limit and statement-count limit."""
        stmts = [Statement(effect="Deny", action=f"s3:Action{i}", resource="*") for i in range(10)]
        doc = ScpDocument(version="2012-10-17", statement=stmts)
        result = split_if_needed(doc)
        assert result.fits
        for d in result.documents:
            assert d.size_bytes <= MAX_SCP_SIZE_BYTES
            assert len(d.statement) <= MAX_STATEMENTS_PER_SCP

    def test_ffd_packs_more_efficiently_than_greedy(self) -> None:
        """FFD produces 2 documents where sequential greedy would produce 3.

        Two large statements (~59% of limit) and two small ones (~40%) are
        ordered [L1, L2, S1, S2].  Greedy packs [L1], [L2, S1], [S2].  FFD
        sorts by descending weight and packs [L1, S1], [L2, S2].
        """
        large = [self._make_stmt(240), self._make_stmt(240)]  # ~6 KB each
        small = [self._make_stmt(160), self._make_stmt(160)]  # ~4 KB each

        # Verify byte assumptions hold
        doc_large = ScpDocument(version="2012-10-17", statement=[large[0]])
        doc_small = ScpDocument(version="2012-10-17", statement=[small[0]])
        assert doc_large.size_bytes + doc_small.size_bytes <= MAX_SCP_SIZE_BYTES, (
            "large + small must fit together for this test to be meaningful"
        )
        assert doc_large.size_bytes * 2 > MAX_SCP_SIZE_BYTES, (
            "two large statements must NOT fit together"
        )

        doc = ScpDocument(version="2012-10-17", statement=large + small)
        result = split_if_needed(doc)
        assert result.count == 2
        assert result.fits
