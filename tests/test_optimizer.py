"""Tests for scpz.optimizer — fixpoint loop and canonical minification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scpz.config import SUPPORTED_API_VERSION, SUPPORTED_KIND, OptimizerConfig
from scpz.models import ScpDocument, Statement
from scpz.optimizer import optimize
from scpz.validator import validate_document

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _make_config(**spec: Any) -> OptimizerConfig:
    """Construct an OptimizerConfig with the given spec overrides."""
    return OptimizerConfig.model_validate(
        {
            "apiVersion": SUPPORTED_API_VERSION,
            "kind": SUPPORTED_KIND,
            "spec": spec,
        }
    )


def _condition_dupe_doc() -> ScpDocument:
    """Two statements with semantically equal conditions, but one has a duplicate
    list value that prevents statement-merge until condition-merge cleans it up."""
    return ScpDocument(
        version="2012-10-17",
        statement=[
            Statement(
                effect="Deny",
                action="s3:GetObject",
                resource="*",
                condition={
                    "StringEquals": {
                        "aws:RequestedRegion": ["us-east-1", "us-east-1"],
                    }
                },
            ),
            Statement(
                effect="Deny",
                action="s3:PutObject",
                resource="*",
                condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            ),
        ],
    )


class TestFixpointLoop:
    """The fixpoint loop re-runs passes until the document stops shrinking."""

    def test_fixpoint_merges_after_condition_normalization(self) -> None:
        """Key motivating case: condition-merge in round 1 normalises a duplicate
        value, making two statements mergeable in round 2.

        Pass order is: statement-merge → … → condition-merge.  In a single pass
        statement-merge sees unequal conditions and skips.  condition-merge then
        deduplicates the value.  In the next round statement-merge succeeds.
        """
        doc = _condition_dupe_doc()

        # Single pass: statement-merge runs before condition-merge fixes the dupe
        no_fp = _make_config(optimizer={"fixpoint": {"enabled": False}})
        no_fp_result = optimize(doc, config=no_fp)
        assert no_fp_result.optimized_statement_count == 2

        # Fixpoint: round 2 can now merge after round 1 cleaned the condition
        result = optimize(doc)  # fixpoint enabled by default
        assert result.optimized_statement_count == 1

    def test_fixpoint_disabled_runs_single_pass_only(self) -> None:
        """With fixpoint disabled the condition-dupe case stays at 2 statements."""
        doc = _condition_dupe_doc()
        config = _make_config(optimizer={"fixpoint": {"enabled": False}})
        result = optimize(doc, config=config)
        assert result.optimized_statement_count == 2

    def test_fixpoint_max_rounds_limits_iterations(self) -> None:
        """maxRounds=1 prevents the second-round merge, same as fixpoint disabled."""
        doc = _condition_dupe_doc()
        config = _make_config(optimizer={"fixpoint": {"enabled": True, "maxRounds": 1}})
        result = optimize(doc, config=config)
        assert result.optimized_statement_count == 2

    def test_fixpoint_sufficient_rounds_allows_merge(self) -> None:
        """maxRounds >= 2 is enough for the condition-dupe case to merge."""
        doc = _condition_dupe_doc()
        config = _make_config(optimizer={"fixpoint": {"enabled": True, "maxRounds": 3}})
        result = optimize(doc, config=config)
        assert result.optimized_statement_count == 1

    def test_fixpoint_terminates_without_regression(self) -> None:
        """An already-optimal document is returned unchanged (no size increase)."""
        doc = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action="iam:GetRole", resource="*")],
        )
        result = optimize(doc)
        assert result.bytes_saved >= 0
        assert result.optimized_statement_count == 1


class TestCanonicalMinification:
    """The optimizer always emits canonically shaped statements."""

    def test_single_element_action_list_becomes_scalar(self) -> None:
        doc = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action=["iam:GetRole"], resource="*")],
        )
        result = optimize(doc)
        stmt = result.optimized.statement[0]
        assert isinstance(stmt.action, str), "single-element action list must become scalar"

    def test_single_element_resource_list_becomes_scalar(self) -> None:
        doc = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action="iam:GetRole", resource=["*"])],
        )
        result = optimize(doc)
        stmt = result.optimized.statement[0]
        assert isinstance(stmt.resource, str), "single-element resource list must become scalar"

    def test_both_fields_canonicalized(self) -> None:
        doc = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action=["iam:GetRole"], resource=["*"])],
        )
        result = optimize(doc)
        stmt = result.optimized.statement[0]
        assert isinstance(stmt.action, str)
        assert isinstance(stmt.resource, str)


class TestOptimizerNotActionRedundancy:
    """End-to-end: redundancy eliminate receives the loaded action catalog."""

    def test_not_action_subsumed_statement_dropped_with_bundled_catalog(self) -> None:
        cfg = _make_config(
            catalog={"source": "bundled"},
            optimizer={
                "statementMerge": {"enabled": False},
                "actionCompress": {"enabled": False},
                "conditionMerge": {"enabled": False},
                "resourceOptimize": {"enabled": False},
                "redundancyEliminate": {"enabled": True},
                "fixpoint": {"enabled": False},
            },
        )
        doc = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    not_action=["s3:GetObject", "s3:PutObject"],
                    resource="*",
                ),
                Statement(effect="Deny", not_action="s3:GetObject", resource="*"),
            ],
        )
        result = optimize(doc, config=cfg)
        assert len(result.optimized.statement) == 1
        assert "redundancy-eliminate" in result.passes_applied


class TestNotActionFixtureOptimize:
    """Shared NotAction corpus fixture optimizes without validation errors."""

    def test_not_action_allowlist_fixture_stays_valid(self) -> None:
        path = FIXTURES_DIR / "not_action_allowlist.json"
        doc = ScpDocument.from_file(str(path))
        result = optimize(doc)
        v = validate_document(result.optimized)
        assert v.is_valid, v.errors
