"""Pydantic models for AWS SCP documents."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator

from scpeasy.constants import REQUIRED_SCP_VERSION, VALID_EFFECTS


class Statement(BaseModel):
    """A single SCP policy statement."""

    sid: str | None = Field(default=None, alias="Sid")
    effect: str = Field(alias="Effect")
    action: list[str] | str = Field(default="*", alias="Action")
    not_action: list[str] | str | None = Field(default=None, alias="NotAction")
    resource: list[str] | str = Field(default="*", alias="Resource")
    condition: dict[str, dict[str, Any]] | None = Field(default=None, alias="Condition")

    model_config = {"populate_by_name": True}

    @field_validator("effect")
    @classmethod
    def validate_effect(cls, v: str) -> str:
        if v not in VALID_EFFECTS:
            raise ValueError(f"Effect must be one of {VALID_EFFECTS}, got '{v}'")
        return v

    @property
    def action_list(self) -> list[str]:
        """Return actions as a normalised list."""
        if self.not_action is not None:
            return []
        if isinstance(self.action, str):
            return [self.action]
        return list(self.action)

    @property
    def not_action_list(self) -> list[str]:
        """Return NotAction as a normalised list."""
        if self.not_action is None:
            return []
        if isinstance(self.not_action, str):
            return [self.not_action]
        return list(self.not_action)

    @property
    def resource_list(self) -> list[str]:
        """Return resources as a normalised list."""
        if isinstance(self.resource, str):
            return [self.resource]
        return list(self.resource)

    def to_policy_dict(self) -> dict[str, Any]:
        """Serialize to the AWS JSON policy format."""
        d: dict[str, Any] = {}
        if self.sid is not None:
            d["Sid"] = self.sid
        d["Effect"] = self.effect
        if self.not_action is not None:
            d["NotAction"] = self.not_action
        else:
            d["Action"] = self.action
        d["Resource"] = self.resource
        if self.condition is not None:
            d["Condition"] = self.condition
        return d


class ScpDocument(BaseModel):
    """A complete SCP policy document."""

    version: str = Field(default=REQUIRED_SCP_VERSION, alias="Version")
    statement: list[Statement] = Field(alias="Statement")

    model_config = {"populate_by_name": True}

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if v != REQUIRED_SCP_VERSION:
            raise ValueError(f"SCP Version must be '{REQUIRED_SCP_VERSION}', got '{v}'")
        return v

    def to_policy_dict(self) -> dict[str, Any]:
        """Serialize to the AWS JSON policy format."""
        return {
            "Version": self.version,
            "Statement": [s.to_policy_dict() for s in self.statement],
        }

    def to_json(self, *, minify: bool = False) -> str:
        """Serialize to a JSON string."""
        d = self.to_policy_dict()
        if minify:
            return json.dumps(d, separators=(",", ":"), sort_keys=False)
        return json.dumps(d, indent=2, sort_keys=False)

    @property
    def size_bytes(self) -> int:
        """Size of the minified JSON representation in bytes."""
        return len(self.to_json(minify=True).encode("utf-8"))

    @classmethod
    def from_json(cls, text: str) -> ScpDocument:
        """Parse an SCP document from a JSON string."""
        data = json.loads(text)
        return cls.model_validate(data)

    @classmethod
    def from_file(cls, path: str) -> ScpDocument:
        """Parse an SCP document from a JSON file."""
        with open(path, encoding="utf-8") as f:
            return cls.from_json(f.read())
