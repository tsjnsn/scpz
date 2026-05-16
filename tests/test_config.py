"""Tests for scpz.config."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

from scpz.config import (
    SUPPORTED_API_VERSION,
    SUPPORTED_KIND,
    OptimizerConfig,
    PassesConfig,
    StatementMergeArgs,
)
from scpz.models import Statement
from scpz.optimizations.statements import SidMergeMode, merge_statements

if TYPE_CHECKING:
    from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────


def write_config(tmp_path: Path, content: str) -> Path:
    cfg = tmp_path / "scpz.yaml"
    cfg.write_text(textwrap.dedent(content), encoding="utf-8")
    return cfg


def make_stmts(sids: list[str | None]) -> list[Statement]:
    """Two deny-all statements with given Sids that are mergeable."""
    return [
        Statement(sid=sid, effect="Deny", action="s3:DeleteBucket", resource="*") for sid in sids
    ]


# ── Discovery ─────────────────────────────────────────────────────────


class TestConfigDiscovery:
    def test_no_file_returns_default(self, tmp_path: Path) -> None:
        cfg = OptimizerConfig.load(tmp_path / "policy.json")
        assert cfg.apiVersion == SUPPORTED_API_VERSION
        assert cfg.kind == SUPPORTED_KIND
        # All passes enabled by default
        assert cfg.spec.optimizer.statementMerge is not None
        assert cfg.spec.optimizer.split is not None

    def test_file_in_same_dir(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            metadata:
              name: test
            spec:
              optimizer:
                statementMerge:
                  sidOnMerge: drop
            """,
        )
        cfg = OptimizerConfig.load(tmp_path / "policy.json")
        assert cfg.spec.optimizer.statementMerge is not None
        assert cfg.spec.optimizer.statementMerge.sidOnMerge == "drop"

    def test_file_discovered_in_parent(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            metadata:
              name: root
            """,
        )
        subdir = tmp_path / "policies"
        subdir.mkdir()
        cfg = OptimizerConfig.load(subdir / "policy.json")
        assert cfg.metadata.name == "root"

    def test_partial_spec_gets_defaults(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                statementMerge:
                  sidOnMerge: join
            """,
        )
        cfg = OptimizerConfig.load(tmp_path / "p.json")
        optimizer = cfg.spec.optimizer
        # Explicitly set
        assert optimizer.statementMerge is not None
        assert optimizer.statementMerge.sidOnMerge == "join"
        # Others default to enabled
        assert optimizer.actionCompress is not None
        assert optimizer.actionCompress.mode == "conservative"
        assert optimizer.conditionMerge is not None
        assert optimizer.split is not None
        assert optimizer.split.strategy == "auto"
        # output defaults
        assert cfg.spec.output.backupSuffix == ".bak"


# ── Validation ────────────────────────────────────────────────────────


class TestConfigValidation:
    def test_wrong_api_version_raises(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: scpz.io/v99
            kind: {SUPPORTED_KIND}
            """,
        )
        with pytest.raises(ValueError, match="apiVersion"):
            OptimizerConfig.load(tmp_path / "p.json")

    def test_wrong_kind_raises(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: WrongKind
            """,
        )
        with pytest.raises(ValueError, match="kind"):
            OptimizerConfig.load(tmp_path / "p.json")

    def test_unknown_pass_field_raises(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                unknownPass: {{}}
            """,
        )
        with pytest.raises(ValueError, match=r"Extra inputs are not permitted|unknownPass"):
            OptimizerConfig.load(tmp_path / "p.json")

    def test_unknown_arg_field_raises(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                statementMerge:
                  typoArg: yes
            """,
        )
        with pytest.raises(ValueError, match=r"Extra inputs are not permitted|typoArg"):
            OptimizerConfig.load(tmp_path / "p.json")

    def test_invalid_sid_on_merge_value_raises(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                statementMerge:
                  sidOnMerge: concat
            """,
        )
        with pytest.raises(ValueError, match=r"sidOnMerge"):
            OptimizerConfig.load(tmp_path / "p.json")

    def test_empty_dict_enables_pass_with_defaults(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                conditionMerge: {{}}
            """,
        )
        cfg = OptimizerConfig.load(tmp_path / "p.json")
        assert cfg.spec.optimizer.conditionMerge is not None

    def test_null_coerced_to_disabled(self, tmp_path: Path) -> None:
        """null is still accepted for backward compat but coerced to enabled: false."""
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                actionCompress: null
            """,
        )
        cfg = OptimizerConfig.load(tmp_path / "p.json")
        assert cfg.spec.optimizer.actionCompress.enabled is False

    def test_enabled_false_disables_pass(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            f"""
            apiVersion: {SUPPORTED_API_VERSION}
            kind: {SUPPORTED_KIND}
            spec:
              optimizer:
                actionCompress:
                  enabled: false
            """,
        )
        cfg = OptimizerConfig.load(tmp_path / "p.json")
        assert cfg.spec.optimizer.actionCompress.enabled is False
        # Other args should still be at their defaults
        assert cfg.spec.optimizer.actionCompress.mode == "conservative"


# ── SidMergeMode end-to-end ───────────────────────────────────────────


class TestSidMergeModeEndToEnd:
    def test_drop_removes_sid(self) -> None:
        stmts = make_stmts(["DenyA", "DenyB"])
        merged = merge_statements(stmts, sid_merge_mode=SidMergeMode.DROP)
        assert len(merged) == 1
        assert merged[0].sid is None

    def test_first_keeps_first_sid(self) -> None:
        stmts = make_stmts(["DenyA", "DenyB"])
        merged = merge_statements(stmts, sid_merge_mode=SidMergeMode.FIRST)
        assert len(merged) == 1
        assert merged[0].sid == "DenyA"

    def test_join_concatenates_sids(self) -> None:
        stmts = make_stmts(["DenyA", "DenyB"])
        merged = merge_statements(stmts, sid_merge_mode=SidMergeMode.JOIN, sid_join_separator="+")
        assert len(merged) == 1
        assert merged[0].sid == "DenyA+DenyB"

    def test_join_truncate_respects_max_length(self) -> None:
        stmts = make_stmts(["DenyA", "DenyB"])
        merged = merge_statements(
            stmts,
            sid_merge_mode=SidMergeMode.JOIN_TRUNCATE,
            sid_join_separator="+",
            sid_join_max_length=5,
        )
        assert len(merged) == 1
        assert merged[0].sid == "DenyA"  # "DenyA+DenyB"[:5]

    def test_first_with_none_sid_returns_none(self) -> None:
        stmts = make_stmts([None, None])
        merged = merge_statements(stmts, sid_merge_mode=SidMergeMode.FIRST)
        assert merged[0].sid is None

    def test_join_with_none_sids_returns_none(self) -> None:
        stmts = make_stmts([None, None])
        merged = merge_statements(stmts, sid_merge_mode=SidMergeMode.JOIN)
        assert merged[0].sid is None


# ── PassesConfig defaults ─────────────────────────────────────────────


class TestPassesConfigDefaults:
    def test_default_passes_enabled_state(self) -> None:
        cfg = PassesConfig()
        assert cfg.statementMerge.enabled is True
        assert cfg.actionCompress.enabled is True
        assert cfg.conditionMerge.enabled is True
        assert cfg.resourceOptimize.enabled is True
        assert cfg.split.enabled is True
        # redundancyEliminate is opt-in
        assert cfg.redundancyEliminate.enabled is False

    def test_statement_merge_defaults(self) -> None:
        args = StatementMergeArgs()
        assert args.enabled is True
        assert args.sidOnMerge == "first"
        assert args.sidJoinSeparator == "+"
        assert args.sidJoinMaxLength == 64
