"""Optimization pipeline orchestrator.

Runs all optimisation passes in order and produces the final optimised SCP.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from scpeasy.config import OptimizerConfig
from scpeasy.constants import MAX_SCP_SIZE_BYTES, MAX_STATEMENTS_PER_SCP
from scpeasy.models import ScpDocument, Statement
from scpeasy.optimizations.actions import compress_actions
from scpeasy.optimizations.conditions import merge_conditions
from scpeasy.optimizations.redundancy import eliminate_redundancy
from scpeasy.optimizations.resources import optimize_resources
from scpeasy.optimizations.statements import SidMergeMode, merge_statements


@dataclass
class OptimizationResult:
    """Result of running the optimization pipeline."""

    original: ScpDocument
    optimized: ScpDocument
    passes_applied: list[str] = field(default_factory=list)

    @property
    def original_size(self) -> int:
        return self.original.size_bytes

    @property
    def optimized_size(self) -> int:
        return self.optimized.size_bytes

    @property
    def bytes_saved(self) -> int:
        return self.original_size - self.optimized_size

    @property
    def original_statement_count(self) -> int:
        return len(self.original.statement)

    @property
    def optimized_statement_count(self) -> int:
        return len(self.optimized.statement)

    @property
    def fits_single_scp(self) -> bool:
        return (
            self.optimized_size <= MAX_SCP_SIZE_BYTES
            and self.optimized_statement_count <= MAX_STATEMENTS_PER_SCP
        )

    def summary(self) -> str:
        """Human-readable optimization summary."""
        lines = [
            f"Size: {self.original_size:,} → {self.optimized_size:,} bytes "
            f"({self.bytes_saved:,} saved)",
            f"Statements: {self.original_statement_count} → {self.optimized_statement_count}",
            f"Passes: {', '.join(self.passes_applied)}",
        ]
        if not self.fits_single_scp:
            if self.optimized_size > MAX_SCP_SIZE_BYTES:
                lines.append(f"⚠ Still exceeds size limit ({MAX_SCP_SIZE_BYTES:,} bytes)")
            if self.optimized_statement_count > MAX_STATEMENTS_PER_SCP:
                lines.append(f"⚠ Still exceeds statement limit ({MAX_STATEMENTS_PER_SCP})")
        return "\n".join(lines)


def optimize(
    doc: ScpDocument,
    *,
    config: OptimizerConfig | None = None,
) -> OptimizationResult:
    """Run the full optimization pipeline on an SCP document."""
    if config is None:
        config = OptimizerConfig.default()

    passes_cfg = config.spec.optimizer
    passes_applied: list[str] = []
    stmts = list(doc.statement)

    # 1. Statement merging
    if passes_cfg.statementMerge.enabled:
        sm_args = passes_cfg.statementMerge
        before = len(stmts)
        stmts = merge_statements(
            stmts,
            sid_merge_mode=SidMergeMode(sm_args.sidOnMerge),
            sid_join_separator=sm_args.sidJoinSeparator,
            sid_join_max_length=sm_args.sidJoinMaxLength,
        )
        if len(stmts) < before:
            passes_applied.append("statement-merge")

    # 2. Action wildcard compression
    if passes_cfg.actionCompress.enabled:
        prev = _serialise_stmts(stmts)
        stmts = compress_actions(stmts, mode=passes_cfg.actionCompress.mode)
        if _serialise_stmts(stmts) != prev:
            passes_applied.append("action-compress")

    # 3. Condition merging
    if passes_cfg.conditionMerge.enabled:
        prev = _serialise_stmts(stmts)
        stmts = merge_conditions(stmts)
        if _serialise_stmts(stmts) != prev:
            passes_applied.append("condition-merge")

    # 4. Resource ARN optimization
    if passes_cfg.resourceOptimize.enabled:
        prev = _serialise_stmts(stmts)
        stmts = optimize_resources(stmts)
        if _serialise_stmts(stmts) != prev:
            passes_applied.append("resource-optimize")

    # 5. Redundancy elimination
    if passes_cfg.redundancyEliminate.enabled:
        before = len(stmts)
        stmts = eliminate_redundancy(stmts)
        if len(stmts) < before:
            passes_applied.append("redundancy-eliminate")

    # Build optimised document
    optimized = ScpDocument(
        version=doc.version,
        statement=stmts,
    )

    if not passes_applied:
        passes_applied.append("none (already optimal)")

    return OptimizationResult(
        original=doc,
        optimized=optimized,
        passes_applied=passes_applied,
    )


def _serialise_stmts(stmts: list[Statement]) -> str:
    """Quick serialisation for change detection."""
    return json.dumps(
        [s.to_policy_dict() for s in stmts],
        separators=(",", ":"),
        sort_keys=True,
    )
