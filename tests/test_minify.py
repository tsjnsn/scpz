"""Tests for scpz.optimizations.minify."""

from __future__ import annotations

from scpz.models import Statement
from scpz.optimizations.minify import canonicalize_statement


class TestCanonicalize:
    """canonicalize_statement produces the minimal byte-shape for each field."""

    def test_single_action_list_becomes_scalar(self) -> None:
        stmt = Statement(effect="Deny", action=["iam:GetRole"], resource="*")
        result = canonicalize_statement(stmt)
        assert result.action == "iam:GetRole"
        assert isinstance(result.action, str)

    def test_single_resource_list_becomes_scalar(self) -> None:
        stmt = Statement(effect="Deny", action="iam:GetRole", resource=["arn:aws:s3:::bucket"])
        result = canonicalize_statement(stmt)
        assert result.resource == "arn:aws:s3:::bucket"
        assert isinstance(result.resource, str)

    def test_single_not_action_list_becomes_scalar(self) -> None:
        stmt = Statement(effect="Deny", not_action=["iam:CreateUser"], resource="*")
        result = canonicalize_statement(stmt)
        assert result.not_action == "iam:CreateUser"
        assert isinstance(result.not_action, str)

    def test_duplicate_actions_deduped_preserving_order(self) -> None:
        stmt = Statement(
            effect="Deny",
            action=["s3:GetObject", "s3:GetObject", "s3:PutObject"],
            resource="*",
        )
        result = canonicalize_statement(stmt)
        assert result.action_list == ["s3:GetObject", "s3:PutObject"]

    def test_duplicate_actions_reduce_to_scalar(self) -> None:
        stmt = Statement(
            effect="Deny",
            action=["s3:GetObject", "s3:GetObject"],
            resource="*",
        )
        result = canonicalize_statement(stmt)
        assert result.action == "s3:GetObject"
        assert isinstance(result.action, str)

    def test_duplicate_resources_deduped(self) -> None:
        stmt = Statement(effect="Deny", action="iam:GetRole", resource=["*", "*"])
        result = canonicalize_statement(stmt)
        assert result.resource == "*"
        assert isinstance(result.resource, str)

    def test_multi_element_action_list_unchanged(self) -> None:
        stmt = Statement(
            effect="Deny",
            action=["iam:GetRole", "iam:CreateRole"],
            resource="*",
        )
        result = canonicalize_statement(stmt)
        assert isinstance(result.action, list)
        assert len(result.action_list) == 2

    def test_already_scalar_action_unchanged(self) -> None:
        stmt = Statement(effect="Deny", action="iam:GetRole", resource="*")
        result = canonicalize_statement(stmt)
        assert result.action == "iam:GetRole"
        assert isinstance(result.action, str)

    def test_already_scalar_resource_unchanged(self) -> None:
        stmt = Statement(effect="Deny", action="iam:GetRole", resource="*")
        result = canonicalize_statement(stmt)
        assert result.resource == "*"
        assert isinstance(result.resource, str)

    def test_condition_preserved_unchanged(self) -> None:
        cond = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        stmt = Statement(effect="Deny", action="iam:GetRole", resource="*", condition=cond)
        result = canonicalize_statement(stmt)
        assert result.condition == cond

    def test_idempotent(self) -> None:
        """Applying canonicalize twice gives the same result as applying once."""
        stmt = Statement(
            effect="Deny",
            action=["iam:GetRole", "s3:GetObject"],
            resource=["*"],
        )
        once = canonicalize_statement(stmt)
        twice = canonicalize_statement(once)
        assert once.to_policy_dict() == twice.to_policy_dict()
