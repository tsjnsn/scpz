"""Tests for scpz.optimizations.statements."""

from __future__ import annotations

from scpz.models import ScpDocument, Statement
from scpz.optimizations.statements import merge_statements


class TestStatementMerging:
    def test_merge_same_effect_condition_resource(self) -> None:
        stmts = [
            Statement(
                effect="Deny",
                action="s3:DeleteBucket",
                resource="*",
                condition={"StringNotEquals": {"aws:PrincipalOrgID": "o-123"}},
            ),
            Statement(
                effect="Deny",
                action="s3:PutBucketPolicy",
                resource="*",
                condition={"StringNotEquals": {"aws:PrincipalOrgID": "o-123"}},
            ),
        ]
        result = merge_statements(stmts)
        assert len(result) == 1
        assert set(result[0].action_list) == {"s3:DeleteBucket", "s3:PutBucketPolicy"}

    def test_no_merge_different_effect(self) -> None:
        stmts = [
            Statement(effect="Deny", action="s3:DeleteBucket", resource="*"),
            Statement(effect="Allow", action="s3:GetObject", resource="*"),
        ]
        result = merge_statements(stmts)
        assert len(result) == 2

    def test_no_merge_different_condition(self) -> None:
        stmts = [
            Statement(
                effect="Deny",
                action="s3:DeleteBucket",
                resource="*",
                condition={"StringEquals": {"aws:PrincipalArn": "a"}},
            ),
            Statement(
                effect="Deny",
                action="s3:PutBucketPolicy",
                resource="*",
                condition={"StringEquals": {"aws:PrincipalArn": "b"}},
            ),
        ]
        result = merge_statements(stmts)
        assert len(result) == 2

    def test_no_merge_different_resource(self) -> None:
        stmts = [
            Statement(effect="Deny", action="s3:DeleteBucket", resource="*"),
            Statement(effect="Deny", action="s3:PutBucketPolicy", resource="arn:aws:s3:::mybucket"),
        ]
        result = merge_statements(stmts)
        assert len(result) == 2

    def test_merge_three_statements(self) -> None:
        stmts = [
            Statement(effect="Deny", action="s3:DeleteBucket", resource="*"),
            Statement(effect="Deny", action="s3:PutBucketPolicy", resource="*"),
            Statement(effect="Deny", action="ec2:TerminateInstances", resource="*"),
        ]
        result = merge_statements(stmts)
        assert len(result) == 1
        assert len(result[0].action_list) == 3

    def test_single_statement_unchanged(self) -> None:
        stmts = [Statement(effect="Deny", action="s3:*", resource="*")]
        result = merge_statements(stmts)
        assert len(result) == 1

    def test_merge_fixture(self, mergeable: ScpDocument) -> None:
        result = merge_statements(list(mergeable.statement))
        # 3 Deny statements with same condition+resource should merge into 1
        # Plus 1 Allow statement
        assert len(result) == 2


class TestSymmetricResourceMerging:
    """Same Effect + Action + Condition but different Resources → union Resources."""

    def test_merge_same_action_different_resources(self) -> None:
        """Two statements with identical Action and Condition merge by unioning Resources."""
        stmts = [
            Statement(effect="Deny", action="s3:GetObject", resource="arn:aws:s3:::bucket-a/*"),
            Statement(effect="Deny", action="s3:GetObject", resource="arn:aws:s3:::bucket-b/*"),
        ]
        result = merge_statements(stmts)
        assert len(result) == 1
        assert result[0].action == "s3:GetObject"
        assert set(result[0].resource_list) == {
            "arn:aws:s3:::bucket-a/*",
            "arn:aws:s3:::bucket-b/*",
        }

    def test_merge_same_action_list_different_resources(self) -> None:
        """Works when Action is a list too, not just a scalar."""
        stmts = [
            Statement(
                effect="Deny",
                action=["s3:GetObject", "s3:PutObject"],
                resource="arn:aws:s3:::bucket-a/*",
            ),
            Statement(
                effect="Deny",
                action=["s3:GetObject", "s3:PutObject"],
                resource="arn:aws:s3:::bucket-b/*",
            ),
        ]
        result = merge_statements(stmts)
        assert len(result) == 1
        assert set(result[0].resource_list) == {
            "arn:aws:s3:::bucket-a/*",
            "arn:aws:s3:::bucket-b/*",
        }

    def test_no_merge_when_both_action_and_resource_differ(self) -> None:
        """Cannot merge when both Action and Resource differ — would create cross-product."""
        stmts = [
            Statement(effect="Deny", action="s3:GetObject", resource="arn:aws:s3:::bucket-a/*"),
            Statement(effect="Deny", action="s3:PutObject", resource="arn:aws:s3:::bucket-b/*"),
        ]
        result = merge_statements(stmts)
        assert len(result) == 2

    def test_symmetric_merge_not_action_different_resources(self) -> None:
        """Symmetric merge also applies when both statements use NotAction."""
        stmts = [
            Statement(
                effect="Deny",
                not_action="iam:CreateUser",
                resource="arn:aws:s3:::bucket-a/*",
            ),
            Statement(
                effect="Deny",
                not_action="iam:CreateUser",
                resource="arn:aws:s3:::bucket-b/*",
            ),
        ]
        result = merge_statements(stmts)
        assert len(result) == 1
        assert set(result[0].resource_list) == {
            "arn:aws:s3:::bucket-a/*",
            "arn:aws:s3:::bucket-b/*",
        }
        assert result[0].not_action == "iam:CreateUser"

    def test_symmetric_merge_with_matching_condition(self) -> None:
        """Resource union only fires when Conditions also match."""
        cond = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        stmts = [
            Statement(
                effect="Deny",
                action="s3:GetObject",
                resource="arn:aws:s3:::bucket-a/*",
                condition=cond,
            ),
            Statement(
                effect="Deny",
                action="s3:GetObject",
                resource="arn:aws:s3:::bucket-b/*",
                condition=cond,
            ),
        ]
        result = merge_statements(stmts)
        assert len(result) == 1

    def test_no_symmetric_merge_different_conditions(self) -> None:
        """Different Conditions block the resource union even when Action matches."""
        stmts = [
            Statement(
                effect="Deny",
                action="s3:GetObject",
                resource="arn:aws:s3:::bucket-a/*",
                condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            ),
            Statement(
                effect="Deny",
                action="s3:GetObject",
                resource="arn:aws:s3:::bucket-b/*",
                condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
            ),
        ]
        result = merge_statements(stmts)
        assert len(result) == 2
