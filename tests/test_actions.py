"""Tests for scpeasy.optimizations.actions."""

from __future__ import annotations

from scpeasy.models import Statement
from scpeasy.optimizations.actions import _extract_verb_prefix, compress_actions


class TestVerbPrefixExtraction:
    def test_get_prefix(self) -> None:
        assert _extract_verb_prefix("GetObject") == "Get"

    def test_put_prefix(self) -> None:
        assert _extract_verb_prefix("PutBucketPolicy") == "Put"

    def test_single_word(self) -> None:
        assert _extract_verb_prefix("Describe") == "Describe"

    def test_lowercase_start(self) -> None:
        assert _extract_verb_prefix("getObject") == "get"


class TestActionCompression:
    def test_no_compress_same_verb_only(self) -> None:
        """Actions sharing only the verb with no further common prefix stay explicit."""
        stmt = Statement(
            effect="Deny",
            action=["s3:GetObject", "s3:GetBucketPolicy", "s3:GetBucketAcl"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        # LCP of GetObject/GetBucketPolicy/GetBucketAcl is 'Get' == verb -> no wildcard
        assert "s3:Get*" not in actions
        assert set(actions) == {"s3:GetObject", "s3:GetBucketPolicy", "s3:GetBucketAcl"}

    def test_compress_shared_sub_prefix(self) -> None:
        """Actions whose LCP exceeds the verb get a tight wildcard."""
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteRolePolicy"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        # LCP = 'DeleteRole' > verb 'Delete' -> wildcard iam:DeleteRole*
        assert "iam:DeleteRole*" in actions
        assert "iam:Delete*" not in actions

    def test_compress_logs_delete_log(self) -> None:
        """logs:DeleteLogGroup + logs:DeleteLogStream share 'DeleteLog'."""
        stmt = Statement(
            effect="Deny",
            action=["logs:DeleteLogGroup", "logs:DeleteLogStream"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "logs:DeleteLog*" in actions
        assert "logs:Delete*" not in actions

    def test_no_compress_guardduty_delete(self) -> None:
        """guardduty:DeleteDetector + guardduty:DeleteMembers share only the verb."""
        stmt = Statement(
            effect="Deny",
            action=["guardduty:DeleteDetector", "guardduty:DeleteMembers"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "guardduty:Delete*" not in actions
        assert set(actions) == {"guardduty:DeleteDetector", "guardduty:DeleteMembers"}

    def test_no_compress_iam_update(self) -> None:
        """iam:UpdateRole + iam:UpdateAssumeRolePolicy share only the verb."""
        stmt = Statement(
            effect="Deny",
            action=["iam:UpdateRole", "iam:UpdateAssumeRolePolicy"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "iam:Update*" not in actions
        assert set(actions) == {"iam:UpdateRole", "iam:UpdateAssumeRolePolicy"}

    def test_no_compress_single_action(self) -> None:
        stmt = Statement(
            effect="Deny",
            action="s3:GetObject",
            resource="*",
        )
        result = compress_actions([stmt])
        assert result[0].action == "s3:GetObject"

    def test_skip_not_action(self) -> None:
        stmt = Statement(
            effect="Deny",
            not_action=["iam:CreateUser", "iam:CreateRole"],
            resource="*",
        )
        result = compress_actions([stmt])
        # NotAction should not be compressed
        assert result[0].not_action == ["iam:CreateUser", "iam:CreateRole"]

    def test_mixed_services_no_broad_wildcard(self) -> None:
        """Cross-service statement: only compress where LCP > verb."""
        stmt = Statement(
            effect="Deny",
            action=[
                "s3:GetObject",
                "s3:GetBucketPolicy",
                "ec2:RunInstances",
                "ec2:StartInstances",
            ],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        # s3: Get* LCP == verb only -> stays explicit
        assert "s3:Get*" not in actions
        # ec2: Run/Start share only verb letter 'R'/'S' actually different verbs,
        # so they stay as-is in separate verb buckets
        assert "ec2:Run*" not in actions
        assert "ec2:Start*" not in actions

    def test_preserve_existing_wildcards(self) -> None:
        stmt = Statement(
            effect="Deny",
            action=["s3:Get*", "ec2:Describe*"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "s3:Get*" in actions
        assert "ec2:Describe*" in actions
