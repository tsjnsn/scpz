"""Tests for scpz.splitter."""

from __future__ import annotations

import pytest

from scpz.constants import MAX_SCPS_PER_TARGET, MAX_STATEMENTS_PER_SCP
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
