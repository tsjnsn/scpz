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

    def test_partial_catalog_does_not_suppress_aggressive_wildcard(self) -> None:
        """Partial catalog coverage still produces a wildcard in aggressive mode.

        Conservative mode would suppress iam:Delete* because DeletePolicy is in
        the catalog but not the statement.  Aggressive mode still emits a
        wildcard — and since all catalog "D*" iam actions start with "Delete"
        in this minimal catalog, the prefix is further shortened to D*.
        """
        catalog = self._catalog_with(
            "iam",
            ["DeleteRole", "DeleteUser", "DeletePolicy"],
        )
        stmt = Statement(
            effect="Deny",
            action=["iam:DeleteRole", "iam:DeleteUser"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # A wildcard must be emitted — the exact prefix depends on catalog data.
        # With this minimal catalog where every "D*" action starts with "Delete",
        # the prefix shortens all the way to "D".
        assert "iam:D*" in actions

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


class TestAggressiveIndividualVerbShortening:
    """aggressive + catalog: verb-level wildcard is shortened as far as catalog allows."""

    def _catalog(self, svc: str, action_names: list[str]) -> ActionCatalog:
        return ActionCatalog.from_dict({svc: action_names})

    # ── Basic behaviour ───────────────────────────────────────────────

    def test_basic_shortening_to_first_unique_prefix(self) -> None:
        """Delete* shortens to D* when all catalog D* actions start with Delete.

        CreateThing starts with C, not D, so the only catalog D* actions are
        Delete*.  The shortest safe prefix is therefore D (length 1).
        """
        catalog = self._catalog("svc", ["DeleteFoo", "DeleteBar", "CreateThing"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:D*" in actions
        assert "svc:Delete*" not in actions

    def test_single_char_prefix_safe(self) -> None:
        """When all catalog G* actions start with Get, Get* shortens all the way to G*."""
        catalog = self._catalog("svc", ["GetFoo", "GetBar", "GetBaz"])
        stmt = Statement(
            effect="Deny",
            action=["svc:GetFoo", "svc:GetBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:G*" in actions

    def test_shortening_blocked_at_d_but_safe_at_del(self) -> None:
        """D* blocked (Deploy* exists), De* blocked (Describe* exists), Del* safe."""
        catalog = self._catalog(
            "svc",
            ["DeleteFoo", "DeleteBar", "DeployApp", "DescribeThings"],
        )
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:D*" not in actions  # DeployApp and DescribeThings block D*
        assert "svc:De*" not in actions  # DeployApp and DescribeThings block De*
        assert "svc:Del*" in actions  # all Del* actions start with Delete
        assert "svc:Delete*" not in actions

    def test_shortening_stops_before_interfering_prefix(self) -> None:
        """Del* is blocked by DelimitedFoo, but Dele* is safe and emitted instead.

        DelimitedFoo: D-e-l-i vs Delete: D-e-l-e-t → they diverge at position 3
        (index 3 is 'i' vs 'e'), so 'Del' captures both but 'Dele' captures only
        Delete*.
        """
        catalog = self._catalog("svc", ["DeleteFoo", "DeleteBar", "DelimitedFoo"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:Del*" not in actions  # DelimitedFoo starts with Del but not Delete
        assert "svc:Dele*" in actions  # all catalog Dele* actions start with Delete
        assert "svc:Delete*" not in actions

    def test_shortening_finds_safe_prefix_after_gap_in_catalog_data(self) -> None:
        """Catalog has no actions at D or De, but has actions at Del that are all Delete*.

        The function skips prefix lengths with no catalog data and finds the
        first length where catalog data exists and is fully within the verb.
        """
        catalog = self._catalog("svc", ["DeleteFoo", "DeleteBar"])
        # No other "D" or "De" prefixed actions exist in the catalog.
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # "D" prefix: catalog D* = {DeleteFoo, DeleteBar}, all start with Delete → D* is safe
        assert "svc:D*" in actions

    def test_shortening_finds_deepest_safe_prefix(self) -> None:
        """Each blocking action narrows the safe prefix one level deeper.

        D*    blocked — DenyAccess starts with D but not Delete
        De*   blocked — DescribeThing starts with De but not Delete
        Del*  blocked — DelimitedObj (Deli) and DelegateRole (Dele) start with Del but not Delete
        Dele* blocked — DelegateRole starts with Dele but not Delete
        Delet* safe   — DelegateRole starts with Dele NOT Delet; DeleteFoo/Bar do start with Delet
        """
        catalog = self._catalog(
            "svc",
            [
                "DeleteFoo",
                "DeleteBar",
                "DenyAccess",
                "DescribeThing",
                "DelimitedObj",
                "DelegateRole",
            ],
        )
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:Delet*" in actions
        assert "svc:Delete*" not in actions

    # ── Interaction between two verb groups ───────────────────────────

    def test_two_groups_shorten_independently(self) -> None:
        """Each verb group finds its own shortest safe prefix independently."""
        catalog = self._catalog(
            "svc",
            ["DeleteFoo", "DeleteBar", "CreateThing", "CreateOther", "DeployApp"],
        )
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar", "svc:CreateThing", "svc:CreateOther"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # Delete group: D* blocked (DeployApp), De* blocked (DeployApp), Del* safe
        assert "svc:Del*" in actions
        # Create group: C* — only Create* actions exist for C → C* is safe
        assert "svc:C*" in actions

    def test_individual_shortening_then_cross_verb_collapses_to_de(self) -> None:
        """Delete → Del*, Deploy → Dep*, then cross-verb pass collapses both to De*.

        Individual pass: D* blocked (Deploy* ∉ Delete*), De* blocked same reason,
        Del* safe for Delete group, Dep* safe for Deploy group.
        Cross-verb pass: LCP(Del, Dep) = De; catalog De* = all four actions, all
        covered → De* is emitted.
        """
        catalog = self._catalog(
            "svc",
            ["DeleteFoo", "DeleteBar", "DeployApp", "DeployOther"],
        )
        stmt = Statement(
            effect="Deny",
            action=[
                "svc:DeleteFoo",
                "svc:DeleteBar",
                "svc:DeployApp",
                "svc:DeployOther",
            ],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert actions == ["svc:De*"]

    # ── Conservative mode unaffected ──────────────────────────────────

    def test_conservative_mode_does_not_shorten_verb_prefix(self) -> None:
        """Individual verb prefix shortening is aggressive-only; conservative is unchanged."""
        catalog = self._catalog("svc", ["DeleteFoo", "DeleteBar"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="conservative", catalog=catalog)
        actions = result[0].action_list
        # Conservative: LCP("DeleteFoo","DeleteBar")="Delete" > verb → DeleteFoo* ... wait
        # Actually LCP = "DeleteF" ... no: Delete-Foo vs Delete-Bar → LCP = "Delete"
        # LCP("DeleteFoo","DeleteBar") = "Delete" (D-e-l-e-t-e, then F vs B → stop)
        # LCP == verb → no trie wildcard without catalog; catalog.covers("svc","Delete",{F,B})
        # = all catalog Delete* ∈ {F,B} → True → iam:Delete* emitted in conservative mode
        # But NOT shortened to Del* or D*.
        assert "svc:Delete*" in actions
        assert "svc:Del*" not in actions
        assert "svc:D*" not in actions

    # ── No catalog ────────────────────────────────────────────────────

    def test_no_catalog_stays_at_verb_level(self) -> None:
        """Without catalog, aggressive mode never shortens below verb level."""
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=None)
        actions = result[0].action_list
        assert "svc:Delete*" in actions
        assert "svc:Del*" not in actions

    def test_unknown_service_in_catalog_stays_at_verb_level(self) -> None:
        """Catalog has data for a different service — unknown service → no shortening."""
        catalog = self._catalog("other", ["DeleteFoo", "DeleteBar"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:Delete*" in actions
        assert "svc:Del*" not in actions

    # ── Interaction with cross-verb pass ──────────────────────────────

    def test_individual_shortening_then_cross_verb_merge(self) -> None:
        """Individual shortening to Del*/Det*, then cross-verb pass merges to De*."""
        catalog = self._catalog(
            "svc",
            ["DeleteFoo", "DeleteBar", "DetachX", "DetachY"],
        )
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar", "svc:DetachX", "svc:DetachY"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # Individual: Delete → Del* (safe), Detach → Det* (safe)
        # Cross-verb: LCP(Del, Det) = De; catalog De* = all four actions → De* safe
        assert actions == ["svc:De*"]

    def test_individual_shortening_then_cross_verb_blocked(self) -> None:
        """Individual shortening works but cross-verb merge is blocked by catalog."""
        catalog = self._catalog(
            "svc",
            ["DeleteFoo", "DeleteBar", "DetachX", "DetachY", "DescribeAll"],
        )
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteFoo", "svc:DeleteBar", "svc:DetachX", "svc:DetachY"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # Individual: Delete → Del* (safe), Detach → Det* (safe)
        # Cross-verb: LCP(Del, Det) = De; catalog De* includes DescribeAll → blocked
        assert "svc:De*" not in actions
        assert "svc:Del*" in actions
        assert "svc:Det*" in actions


class TestAggressiveCrossVerbShortening:
    """aggressive + catalog: shorter cross-verb prefix when catalog confirms safety."""

    def _catalog(self, svc: str, action_names: list[str]) -> ActionCatalog:
        return ActionCatalog.from_dict({svc: action_names})

    def test_verb_wildcard_and_singleton_collapse_to_shorter_prefix(self) -> None:
        """Delete* + singleton DetachFoo → De* when catalog lists only those three."""
        catalog = self._catalog("svc", ["DeleteA", "DeleteB", "DetachFoo"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteA", "svc:DeleteB", "svc:DetachFoo"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert actions == ["svc:De*"]

    def test_two_verb_wildcards_collapse_to_shorter_prefix(self) -> None:
        """Delete* + Detach* → De* when catalog lists only those actions."""
        catalog = self._catalog("svc", ["DeleteA", "DeleteB", "DetachX", "DetachY"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteA", "svc:DeleteB", "svc:DetachX", "svc:DetachY"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert actions == ["svc:De*"]

    def test_catalog_blocks_cross_verb_prefix_when_uncovered_action_exists(self) -> None:
        """DescribeThings starts with De but not Delete or Detach → De* is blocked.

        However, Del* is still safe for the Delete group (no catalog action
        starts with Del without also starting with Delete), so Del* replaces
        Delete*.  DetachFoo stays as a singleton — Dis/Det shortening depends
        on whether catalog has other Det* actions; here it has none, so Det*
        is also safe, but DetachFoo is a singleton group and individual
        shortening only applies to multi-item verb groups.
        """
        catalog = self._catalog("svc", ["DeleteA", "DeleteB", "DetachFoo", "DescribeThings"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteA", "svc:DeleteB", "svc:DetachFoo"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # De* blocked — DescribeThings starts with De but is not in stmt
        assert "svc:De*" not in actions
        # Delete group (2 items) → Del* (all catalog Del* actions start with Delete)
        assert "svc:Del*" in actions
        # DetachFoo is a singleton → stays explicit
        assert "svc:DetachFoo" in actions

    def test_no_catalog_no_cross_verb_shortening(self) -> None:
        """Without a catalog, aggressive mode stops at verb level."""
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteA", "svc:DeleteB", "svc:DetachFoo"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=None)
        actions = result[0].action_list
        assert "svc:De*" not in actions
        assert "svc:Delete*" in actions

    def test_unrelated_verbs_not_collapsed(self) -> None:
        """Verbs sharing no common prefix are left at verb level."""
        catalog = self._catalog("svc", ["CreateFoo", "UpdateBar"])
        stmt = Statement(
            effect="Deny",
            action=["svc:CreateFoo", "svc:UpdateBar"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        assert "svc:De*" not in actions
        assert "svc:CreateFoo" in actions
        assert "svc:UpdateBar" in actions

    def test_iterative_shortening(self) -> None:
        """Two rounds of shortening: first De*, then D* if catalog allows."""
        catalog = self._catalog("svc", ["DeleteA", "DetachB", "DisableFoo"])
        stmt = Statement(
            effect="Deny",
            action=["svc:DeleteA", "svc:DetachB", "svc:DisableFoo"],
            resource="*",
        )
        result = compress_actions([stmt], mode="aggressive", catalog=catalog)
        actions = result[0].action_list
        # All three share "D"; De* would cover Delete+Detach but not Disable.
        # D* covers all three and catalog confirms full coverage.
        assert actions == ["svc:D*"]
