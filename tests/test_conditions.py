"""Tests for scpz.optimizations.conditions."""

from __future__ import annotations

from scpz.models import Statement
from scpz.optimizations.conditions import conditions_equal, merge_conditions


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
