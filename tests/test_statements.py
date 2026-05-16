"""Tests for scpeasy.optimizations.statements."""

from __future__ import annotations

from scpeasy.models import ScpDocument, Statement
from scpeasy.optimizations.statements import merge_statements


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
