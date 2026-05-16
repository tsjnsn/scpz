"""Tests for scpz.optimizations.conditions."""

from __future__ import annotations

from scpz.models import Statement
from scpz.optimizations.conditions import (
    _dedup_value,
    _merge_statement_conditions,
    _merge_values,
    _normalise_condition,
    _to_list,
    conditions_equal,
    merge_conditions,
)


class TestConditionsEqual:
    def test_both_none(self) -> None:
        assert conditions_equal(None, None)

    def test_one_none(self) -> None:
        assert not conditions_equal(None, {"StringEquals": {"aws:PrincipalArn": "foo"}})

    def test_equal(self) -> None:
        cond = {"StringEquals": {"aws:PrincipalArn": "foo"}}
        assert conditions_equal(cond, cond)

    def test_different_values(self) -> None:
        a = {"StringEquals": {"aws:PrincipalArn": "foo"}}
        b = {"StringEquals": {"aws:PrincipalArn": "bar"}}
        assert not conditions_equal(a, b)

    def test_order_independent(self) -> None:
        a = {"StringEquals": {"aws:PrincipalArn": ["a", "b"]}}
        b = {"StringEquals": {"aws:PrincipalArn": ["b", "a"]}}
        assert conditions_equal(a, b)


class TestMergeConditions:
    def test_no_condition(self) -> None:
        stmt = Statement(effect="Deny", action="s3:*", resource="*")
        result = merge_conditions([stmt])
        assert result[0].condition is None

    def test_dedup_values(self) -> None:
        stmt = Statement(
            effect="Deny",
            action="s3:*",
            resource="*",
            condition={
                "StringEquals": {"aws:RequestedRegion": ["us-east-1", "us-east-1", "us-west-2"]}
            },
        )
        result = merge_conditions([stmt])
        vals = result[0].condition["StringEquals"]["aws:RequestedRegion"]  # type: ignore[index]
        # Should be deduplicated
        assert len(vals) == 2

    def test_dedup_list_collapses_to_scalar(self) -> None:
        """A list that deduplicates to one item should become a scalar (line 79)."""
        stmt = Statement(
            effect="Deny",
            action="s3:*",
            resource="*",
            condition={"StringEquals": {"aws:RequestedRegion": ["us-east-1", "us-east-1"]}},
        )
        result = merge_conditions([stmt])
        val = result[0].condition["StringEquals"]["aws:RequestedRegion"]  # type: ignore[index]
        assert val == "us-east-1"

    def test_empty_operator_dict_becomes_none(self) -> None:
        """An operator whose keys are all removed should make condition None (line 43)."""
        stmt = Statement.model_construct(
            sid=None,
            effect="Deny",
            action="s3:*",
            not_action=None,
            resource="*",
            condition={"StringEquals": {}},
        )
        result = _merge_statement_conditions(stmt)
        assert result.condition is None

    def test_malformed_operator_value_passthrough(self) -> None:
        """Non-dict operator value passes through unchanged (lines 29-30)."""
        stmt = Statement.model_construct(
            sid=None,
            effect="Deny",
            action="s3:*",
            not_action=None,
            resource="*",
            condition={"StringEquals": "not-a-dict"},  # type: ignore[arg-type]
        )
        result = _merge_statement_conditions(stmt)
        assert result.condition == {"StringEquals": "not-a-dict"}


class TestPrivateHelpers:
    """Unit tests for private helpers in conditions.py."""

    def test_to_list_with_scalar(self) -> None:
        assert _to_list("a") == ["a"]

    def test_to_list_with_list(self) -> None:
        """Lines 85-86: list input is returned as-is."""
        assert _to_list(["a", "b"]) == ["a", "b"]

    def test_merge_values_combines_two_scalars(self) -> None:
        assert _merge_values("a", "b") == ["a", "b"]

    def test_merge_values_deduplicates_to_scalar(self) -> None:
        """Lines 62-63: combined list of one item → scalar."""
        assert _merge_values("a", "a") == "a"

    def test_merge_values_scalar_and_list(self) -> None:
        assert _merge_values("a", ["a", "b"]) == ["a", "b"]

    def test_merge_values_two_lists(self) -> None:
        assert _merge_values(["a", "b"], ["b", "c"]) == ["a", "b", "c"]

    def test_dedup_value_scalar_passthrough(self) -> None:
        assert _dedup_value("x") == "x"

    def test_dedup_value_list_to_scalar(self) -> None:
        """Line 79: list that deduplicates to one item → scalar."""
        assert _dedup_value(["x", "x"]) == "x"

    def test_dedup_value_list_preserved(self) -> None:
        assert _dedup_value(["a", "b"]) == ["a", "b"]

    def test_normalise_condition_non_dict_operator(self) -> None:
        """Lines 108-109: malformed operator value is carried through as-is."""
        cond = {"StringEquals": "not-a-dict"}  # type: ignore[dict-item]
        result = _normalise_condition(cond)  # type: ignore[arg-type]
        import json

        parsed = json.loads(result)
        assert parsed["StringEquals"] == "not-a-dict"
