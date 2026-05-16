"""Project configuration for scpeasy.

Follows the Kubernetes object model: apiVersion / kind / metadata / spec.
Discovered by walking up the directory tree from the input file, looking for
``scpeasy.yaml``.  Falls back to defaults when no file is found.

Example config::

    apiVersion: scpeasy.io/v1alpha1
    kind: OptimizerConfig
    metadata:
      name: default
    spec:
      optimizer:
        statementMerge:
          sidOnMerge: first
          sidJoinSeparator: "+"
          sidJoinMaxLength: 64
        actionCompress:
          mode: conservative
        conditionMerge: {}
        resourceOptimize: {}
        split:
          strategy: auto
      output:
        backupSuffix: ".bak"
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


# ── Supported API version / kind ─────────────────────────────────────

SUPPORTED_API_VERSION = "scpeasy.io/v1alpha1"
SUPPORTED_KIND = "OptimizerConfig"
CONFIG_FILENAME = "scpeasy.yaml"


# ── Per-pass arg models ───────────────────────────────────────────────


class StatementMergeArgs(BaseModel):
    """Args for the statementMerge pass."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    sidOnMerge: Literal["drop", "first", "join", "joinTruncate"] = "first"
    sidJoinSeparator: str = "+"
    sidJoinMaxLength: int = Field(default=64, ge=1)


class ActionCompressArgs(BaseModel):
    """Args for the actionCompress pass."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    mode: Literal["conservative", "aggressive"] = "conservative"


class ConditionMergeArgs(BaseModel):
    """Args for the conditionMerge pass."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ResourceOptimizeArgs(BaseModel):
    """Args for the resourceOptimize pass."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class RedundancyEliminateArgs(BaseModel):
    """Args for the redundancyEliminate pass.

    Defaults to ``enabled: false`` — opt-in because it is more aggressive
    than the other passes and may require user review of the results.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False


class SplitArgs(BaseModel):
    """Args for the split pass."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    strategy: Literal["auto", "never"] = "auto"


# ── Passes map ────────────────────────────────────────────────────────


class PassesConfig(BaseModel):
    """Map of optimizer passes.

    Each pass field always has an ``enabled`` key.  Set ``enabled: false`` to
    disable a pass while keeping its other args in place.  Omitting a pass key
    entirely uses that pass's defaults (which includes its default ``enabled``
    value — ``true`` for most passes, ``false`` for ``redundancyEliminate``).
    """

    model_config = ConfigDict(extra="forbid")

    statementMerge: StatementMergeArgs = Field(default_factory=StatementMergeArgs)
    actionCompress: ActionCompressArgs = Field(default_factory=ActionCompressArgs)
    conditionMerge: ConditionMergeArgs = Field(default_factory=ConditionMergeArgs)
    resourceOptimize: ResourceOptimizeArgs = Field(default_factory=ResourceOptimizeArgs)
    redundancyEliminate: RedundancyEliminateArgs = Field(default_factory=RedundancyEliminateArgs)
    split: SplitArgs = Field(default_factory=SplitArgs)

    @model_validator(mode="before")
    @classmethod
    def _coerce_nulls(cls, values: Any) -> Any:
        """Coerce ``pass: null`` → ``pass: {enabled: false}`` for a clear error path.

        Null is no longer the canonical way to disable a pass (use
        ``enabled: false`` instead), but we accept it gracefully so that old
        configs don't break silently.
        """
        if not isinstance(values, dict):
            return values
        for field_name in (
            "statementMerge",
            "actionCompress",
            "conditionMerge",
            "resourceOptimize",
            "redundancyEliminate",
            "split",
        ):
            if field_name in values and values[field_name] is None:
                values[field_name] = {"enabled": False}
        return values


# ── Top-level spec sections ───────────────────────────────────────────


class OutputConfig(BaseModel):
    """spec.output — controls how files are written."""

    model_config = ConfigDict(extra="forbid")

    backupSuffix: str = ".bak"


class ConfigSpec(BaseModel):
    """The full spec block."""

    model_config = ConfigDict(extra="forbid")

    optimizer: PassesConfig = Field(default_factory=PassesConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


# ── Metadata ──────────────────────────────────────────────────────────


class ConfigMetadata(BaseModel):
    """Standard Kubernetes-style metadata block."""

    model_config = ConfigDict(extra="allow")  # forward-compat: ignore extra labels/annotations

    name: str = "default"


# ── Root object ───────────────────────────────────────────────────────


class OptimizerConfig(BaseModel):
    """Root config object, following the Kubernetes object model."""

    model_config = ConfigDict(extra="forbid")

    apiVersion: str
    kind: str
    metadata: ConfigMetadata = Field(default_factory=ConfigMetadata)
    spec: ConfigSpec = Field(default_factory=ConfigSpec)

    @model_validator(mode="after")
    def _validate_gvk(self) -> OptimizerConfig:
        if self.apiVersion != SUPPORTED_API_VERSION:
            msg = (
                f"Unsupported apiVersion '{self.apiVersion}'. "
                f"Expected '{SUPPORTED_API_VERSION}'."
            )
            raise ValueError(msg)
        if self.kind != SUPPORTED_KIND:
            msg = f"Unsupported kind '{self.kind}'. Expected '{SUPPORTED_KIND}'."
            raise ValueError(msg)
        return self

    # ── Factory methods ───────────────────────────────────────────────

    @classmethod
    def default(cls) -> OptimizerConfig:
        """Return an OptimizerConfig with all defaults."""
        return cls(
            apiVersion=SUPPORTED_API_VERSION,
            kind=SUPPORTED_KIND,
        )

    @classmethod
    def load(cls, start_path: Path) -> OptimizerConfig:
        """Discover and load ``scpeasy.yaml`` by walking up from *start_path*.

        *start_path* may be a file or directory.  The search starts from the
        file's parent directory (or the directory itself).  Returns
        ``OptimizerConfig.default()`` if no config file is found.

        Raises ``ValueError`` with a clear message if the file exists but is
        invalid.
        """
        search_dir = start_path if start_path.is_dir() else start_path.parent

        for directory in (search_dir, *search_dir.parents):
            candidate = directory / CONFIG_FILENAME
            if candidate.is_file():
                return cls._parse_file(candidate)

        return cls.default()

    @classmethod
    def _parse_file(cls, path: Path) -> OptimizerConfig:
        """Parse and validate a ``scpeasy.yaml`` file."""
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            msg = f"{path}: invalid YAML — {exc}"
            raise ValueError(msg) from exc

        if not isinstance(raw, dict):
            msg = f"{path}: expected a YAML mapping at the top level"
            raise ValueError(msg)

        try:
            return cls.model_validate(raw)
        except Exception as exc:
            msg = f"{path}: {exc}"
            raise ValueError(msg) from exc
