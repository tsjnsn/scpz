"""Tests for scpz.optimizations.redundancy."""

from __future__ import annotations

import pytest

from scpz.models import Statement
from scpz.optimizations.redundancy import _covers, eliminate_redundancy

# ── Helpers ───────────────────────────────────────────────────────────


def deny(action: str | list[str], resource: str = "*", condition: dict | None = None) -> Statement:
    return Statement(effect="Deny", action=action, resource=resource, condition=condition)


def allow(action: str | list[str], resource: str = "*") -> Statement:
    return Statement(effect="Allow", action=action, resource=resource)


# ── _covers unit tests ────────────────────────────────────────────────


class TestCovers:
    def test_star_covers_everything(self) -> None:
        assert _covers("*", "s3:GetObject")
        assert _covers("*", "iam:DeleteRole")
        assert _covers("*", "anything")

    def test_exact_match(self) -> None:
        assert _covers("s3:GetObject", "s3:GetObject")

    def test_no_match(self) -> None:
        assert not _covers("s3:GetObject", "s3:PutObject")

    def test_service_wildcard_covers_specific(self) -> None:
        assert _covers("s3:*", "s3:GetObject")
        assert _covers("s3:*", "s3:PutBucketPolicy")

    def test_service_wildcard_does_not_cross_service(self) -> None:
        assert not _covers("s3:*", "ec2:RunInstances")

    def test_verb_wildcard_covers_action(self) -> None:
        assert _covers("iam:Delete*", "iam:DeleteRole")
        assert _covers("iam:Delete*", "iam:DeleteRolePolicy")

    def test_verb_wildcard_covers_narrower_wildcard(self) -> None:
        # iam:DeleteRole* starts with iam:Delete
        assert _covers("iam:Delete*", "iam:DeleteRole*")

    def test_verb_wildcard_does_not_cover_other_verb(self) -> None:
        assert not _covers("iam:Delete*", "iam:UpdateRole")


# ── eliminate_redundancy ──────────────────────────────────────────────


class TestEliminateRedundancy:
    def test_subset_actions_removed(self) -> None:
        """Statement with subset of actions is removed when superset exists."""
        broad = deny(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"])
        narrow = deny("s3:GetObject")
        result = eliminate_redundancy([narrow, broad])
        assert len(result) == 1
        assert result[0] is broad

    def test_wildcard_subsumes_specific(self) -> None:
        """s3:* subsumes s3:GetObject."""
        broad = deny("s3:*")
        narrow = deny("s3:GetObject")
        result = eliminate_redundancy([narrow, broad])
        assert len(result) == 1
        assert result[0] is broad

    def test_verb_wildcard_subsumes_specific(self) -> None:
        """iam:Delete* subsumes iam:DeleteRole."""
        broad = deny("iam:Delete*")
        narrow = deny("iam:DeleteRole")
        result = eliminate_redundancy([narrow, broad])
        assert len(result) == 1
        assert result[0] is broad

    def test_star_subsumes_all(self) -> None:
        """* subsumes everything."""
        broad = deny("*")
        narrow = deny(["s3:GetObject", "iam:DeleteRole", "ec2:RunInstances"])
        result = eliminate_redundancy([narrow, broad])
        assert len(result) == 1
        assert result[0] is broad

    def test_identical_statements_deduped(self) -> None:
        """Two identical statements collapse to one."""
        a = deny("s3:GetObject")
        b = deny("s3:GetObject")
        result = eliminate_redundancy([a, b])
        assert len(result) == 1

    def test_different_condition_not_removed(self) -> None:
        """Same actions but different conditions → both kept."""
        conditioned = deny("s3:*", condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        unconditioned = deny("s3:*")
        result = eliminate_redundancy([conditioned, unconditioned])
        assert len(result) == 2

    def test_different_resource_not_removed(self) -> None:
        """Same actions but different resources → both kept."""
        specific = deny("s3:GetObject", resource="arn:aws:s3:::my-bucket")
        broad = deny("s3:GetObject", resource="*")
        result = eliminate_redundancy([specific, broad])
        assert len(result) == 2

    def test_different_effect_not_removed(self) -> None:
        """Allow and Deny with same actions → both kept."""
        a = allow("s3:GetObject")
        d = deny("s3:GetObject")
        result = eliminate_redundancy([a, d])
        assert len(result) == 2

    def test_non_redundant_statements_preserved(self) -> None:
        """Disjoint action sets → both kept."""
        s3 = deny("s3:GetObject")
        iam = deny("iam:DeleteRole")
        result = eliminate_redundancy([s3, iam])
        assert len(result) == 2

    def test_not_action_skipped(self) -> None:
        """NotAction statements are not analysed and always kept."""
        not_action = Statement(effect="Deny", not_action="s3:GetObject", resource="*")
        regular = Statement(effect="Deny", action="*", resource="*")
        result = eliminate_redundancy([not_action, regular])
        # NotAction stmt is kept even though regular Deny * subsumes it logically
        assert len(result) == 2

    def test_single_statement_unchanged(self) -> None:
        result = eliminate_redundancy([deny("s3:GetObject")])
        assert len(result) == 1

    def test_empty_list_unchanged(self) -> None:
        assert eliminate_redundancy([]) == []

    def test_partial_overlap_not_removed(self) -> None:
        """A has actions not covered by B → A is kept."""
        a = deny(["s3:GetObject", "ec2:RunInstances"])
        b = deny("s3:*")  # covers s3:GetObject but not ec2:RunInstances
        result = eliminate_redundancy([a, b])
        assert len(result) == 2

    def test_order_independent(self) -> None:
        """Broader statement first or last — same result."""
        broad = deny("s3:*")
        narrow = deny("s3:GetObject")
        assert len(eliminate_redundancy([broad, narrow])) == 1
        assert len(eliminate_redundancy([narrow, broad])) == 1

    def test_chain_elimination(self) -> None:
        """Three statements where each subsumes the next."""
        star = deny("*")
        s3_star = deny("s3:*")
        s3_get = deny("s3:GetObject")
        result = eliminate_redundancy([s3_get, s3_star, star])
        assert len(result) == 1
        assert result[0] is star

    @pytest.mark.parametrize("n", [1, 2, 3, 5])
    def test_n_identical_statements_collapse_to_one(self, n: int) -> None:
        stmts = [deny("iam:DeleteRole") for _ in range(n)]
        result = eliminate_redundancy(stmts)
        assert len(result) == 1
