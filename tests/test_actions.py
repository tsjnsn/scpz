"""Tests for scpz.optimizations.actions."""

from __future__ import annotations

from scpz.catalog import ActionCatalog
from scpz.models import Statement
from scpz.optimizations.actions import _extract_verb_prefix, compress_actions


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
    def test_trie_compresses_subgroup_within_verb_group(self) -> None:
        """Actions that share a common prefix longer than the verb are now compressed
        as a sub-group, even when the full verb group's LCP only equals the verb.

        GetBucketPolicy and GetBucketAcl share 'GetBucket' (> verb 'Get'),
        so they are compressed to s3:GetBucket*.  GetObject is in a different
        trie branch and stays explicit.
        """
        stmt = Statement(
            effect="Deny",
            action=["s3:GetObject", "s3:GetBucketPolicy", "s3:GetBucketAcl"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "s3:GetBucket*" in actions
        assert "s3:GetObject" in actions
        assert "s3:Get*" not in actions
        assert "s3:GetBucketPolicy" not in actions
        assert "s3:GetBucketAcl" not in actions

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


class TestTrieBasedCompression:
    """Recursive sub-group compression: verb groups are split by trie structure."""

    def test_subgroup_of_verb_group_gets_own_wildcard(self) -> None:
        """When the full verb group's LCP equals the verb, sub-groups are
        examined independently.  A sub-group with a longer shared prefix
        gets a tighter wildcard while other branches stay explicit.
        """
        stmt = Statement(
            effect="Deny",
            action=[
                "iam:CreatePolicy",
                "iam:CreatePolicyVersion",
                "iam:CreateRole",
            ],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        # CreatePolicy + CreatePolicyVersion share 'CreatePolicy' > 'Create'
        assert "iam:CreatePolicy*" in actions
        # CreateRole stays explicit (no sibling to form a sub-group)
        assert "iam:CreateRole" in actions
        # Verb-level wildcard must NOT be emitted in conservative mode
        assert "iam:Create*" not in actions

    def test_trie_three_level_nesting(self) -> None:
        """Compression works correctly when names nest three levels deep."""
        stmt = Statement(
            effect="Deny",
            action=[
                "s3:DeleteObject",
                "s3:DeleteObjectAcl",
                "s3:DeleteObjectVersion",
                "s3:DeleteBucket",
            ],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        # DeleteObject + DeleteObjectAcl + DeleteObjectVersion share 'DeleteObject'
        assert "s3:DeleteObject*" in actions
        # DeleteBucket stays explicit
        assert "s3:DeleteBucket" in actions
        assert "s3:Delete*" not in actions

    def test_trie_does_not_compress_truly_divergent_groups(self) -> None:
        """Actions whose sub-branches are all singletons remain explicit."""
        stmt = Statement(
            effect="Deny",
            action=["guardduty:DeleteDetector", "guardduty:DeleteMembers"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        # D-branch → DeleteDetector (single), M-branch → DeleteMembers (single)
        assert "guardduty:Delete*" not in actions
        assert set(actions) == {"guardduty:DeleteDetector", "guardduty:DeleteMembers"}


class TestCatalogAwareCompression:
    """conservative mode with catalog: verb-level wildcard when fully covered."""

    def _catalog_with(self, svc: str, action_names: list[str]) -> ActionCatalog:
        return ActionCatalog.from_dict({svc: action_names})

    def test_catalog_enables_verb_wildcard_when_fully_covered(self) -> None:
        """All Delete* actions present + catalog → iam:Delete* is emitted."""
        catalog = self._catalog_with(
            "iam",
            ["DeleteRole", "DeleteUser"],
        )
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteUser"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        assert "iam:Delete*" in actions

    def test_catalog_suppressed_when_not_fully_covered(self) -> None:
        """Catalog has a Delete* action that is NOT in the statement → no wildcard."""
        catalog = self._catalog_with(
            "iam",
            ["DeleteRole", "DeleteUser", "DeletePolicy"],  # DeletePolicy not in stmt
        )
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteUser"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        assert "iam:Delete*" not in actions
        assert set(actions) == {"iam:DeleteRole", "iam:DeleteUser"}

    def test_no_catalog_still_conservative(self) -> None:
        """Without a catalog the old conservative behaviour is unchanged."""
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteUser"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=None)
        actions = result[0].action_list
        # LCP('DeleteRole','DeleteUser') == 'Delete' == verb → no wildcard without catalog
        assert "iam:Delete*" not in actions

    def test_catalog_does_not_affect_aggressive_mode(self) -> None:
        """aggressive mode ignores the catalog (it always wildcards at verb level)."""
        catalog = self._catalog_with(
            "iam",
            ["DeleteRole", "DeleteUser", "DeletePolicy"],  # partial — would block conservative
        )
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteUser"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # aggressive always uses verb wildcard when shorter
        assert "iam:Delete*" in actions

    def test_catalog_unknown_service_no_wildcard(self) -> None:
        """Service not in catalog → catalog cannot confirm coverage → no verb wildcard."""
        catalog = self._catalog_with("s3", ["GetObject"])  # no guardduty
        stmt = Statement(
            effect="Deny",
            action=["guardduty:DeleteDetector", "guardduty:DeleteMembers"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        assert "guardduty:Delete*" not in actions

    def test_lcp_wildcard_still_takes_precedence(self) -> None:
        """LCP path fires before catalog check; tight wildcard is preferred."""
        catalog = self._catalog_with(
            "iam",
            ["DeleteRole", "DeleteRolePolicy"],
        )
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteRolePolicy"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        # LCP = 'DeleteRole' > verb 'Delete' → iam:DeleteRole* not iam:Delete*
        assert "iam:DeleteRole*" in actions
        assert "iam:Delete*" not in actions

    def test_lcp_wildcard_blocked_when_catalog_has_additional_matching_action(self) -> None:
        """LCP > verb but catalog contains an action matching the LCP wildcard
        that is NOT in the statement — the wildcard must be suppressed."""
        catalog = self._catalog_with(
            "s3",
            ["DeleteObject", "DeleteObjects", "DeleteObjectTagging"],
        )
        stmt = Statement(
            effect="Deny",
            action=["s3:DeleteObject", "s3:DeleteObjects"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        # s3:DeleteObject* would also cover DeleteObjectTagging (not in stmt)
        assert "s3:DeleteObject*" not in actions
        assert set(actions) == {"s3:DeleteObject", "s3:DeleteObjects"}

    def test_lcp_wildcard_allowed_when_catalog_confirms_full_lcp_coverage(self) -> None:
        """LCP > verb and catalog contains no additional actions matching the
        LCP wildcard — the tight wildcard is safe to emit."""
        catalog = self._catalog_with(
            "s3",
            ["DeleteObject", "DeleteObjects", "DeleteBucket"],
        )
        stmt = Statement(
            effect="Deny",
            action=["s3:DeleteObject", "s3:DeleteObjects"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        # Only DeleteObject and DeleteObjects start with 'DeleteObject' in
        # the catalog — both are present in the statement, so s3:DeleteObject*
        # is safe.
        assert "s3:DeleteObject*" in actions

    def test_lcp_wildcard_without_catalog_still_emits(self) -> None:
        """Without a catalog the LCP heuristic is trusted as-is; the tight
        wildcard is emitted even though we cannot verify full coverage."""
        stmt = Statement(
            effect="Deny",
            action=["s3:DeleteObject", "s3:DeleteObjects"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=None)
        actions = result[0].action_list
        assert "s3:DeleteObject*" in actions


class TestIntraStatementSubsumption:
    """Explicit actions covered by a wildcard in the same statement are removed."""

    def test_global_wildcard_subsumes_explicit_action(self) -> None:
        """'*' subsumes any explicit action in the same statement."""
        stmt = Statement(
            effect="Deny",
            action=["*", "iam:GetRole", "s3:GetObject"],
            resource="*",
        )
        result = compress_actions([stmt])
        assert result[0].action == "*"

    def test_global_wildcard_subsumes_service_wildcard(self) -> None:
        """'*' subsumes service-level wildcards like 's3:Get*'."""
        stmt = Statement(
            effect="Deny",
            action=["*", "s3:Get*", "iam:CreateRole"],
            resource="*",
        )
        result = compress_actions([stmt])
        assert result[0].action == "*"

    def test_service_wildcard_subsumes_explicit_action(self) -> None:
        """'s3:Get*' subsumes 's3:GetObject' and other Get-prefixed actions."""
        stmt = Statement(
            effect="Deny",
            action=["s3:Get*", "s3:GetObject", "s3:GetBucketPolicy"],
            resource="*",
        )
        result = compress_actions([stmt])
        assert result[0].action == "s3:Get*"

    def test_broader_wildcard_subsumes_tighter_wildcard(self) -> None:
        """'s3:Get*' subsumes the tighter 's3:GetObject*'."""
        stmt = Statement(
            effect="Deny",
            action=["s3:Get*", "s3:GetObject*"],
            resource="*",
        )
        result = compress_actions([stmt])
        assert result[0].action == "s3:Get*"

    def test_cross_service_wildcard_not_subsumed(self) -> None:
        """'s3:Get*' must not subsume 'iam:GetRole' from a different service."""
        stmt = Statement(
            effect="Deny",
            action=["s3:Get*", "iam:GetRole"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "s3:Get*" in actions
        assert "iam:GetRole" in actions

    def test_no_wildcards_no_subsumption(self) -> None:
        """With no wildcards present, all explicit actions are kept unchanged."""
        stmt = Statement(
            effect="Deny",
            action=["iam:GetRole", "iam:CreateRole"],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "iam:GetRole" in actions
        assert "iam:CreateRole" in actions

    def test_multiple_wildcards_each_subsume_own_actions(self) -> None:
        """Multiple wildcards each subsume their own matching explicit actions."""
        stmt = Statement(
            effect="Deny",
            action=[
                "s3:Get*",
                "s3:Put*",
                "s3:GetObject",
                "s3:PutObject",
                "ec2:RunInstances",
            ],
            resource="*",
        )
        result = compress_actions([stmt])
        actions = result[0].action_list
        assert "s3:Get*" in actions
        assert "s3:Put*" in actions
        assert "s3:GetObject" not in actions
        assert "s3:PutObject" not in actions
        assert "ec2:RunInstances" in actions  # not covered by any wildcard

    def test_not_action_not_subsumed(self) -> None:
        """compress_actions skips NotAction statements entirely."""
        original: list[str] = ["iam:GetRole", "iam:CreateRole"]
        stmt = Statement(effect="Deny", not_action=original, resource="*")
        result = compress_actions([stmt])
        assert result[0].not_action == original
