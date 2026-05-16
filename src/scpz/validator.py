"""SCP validation — structure, actions, conditions, and constraint checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from scpz.constants import (
    CONDITION_OPERATORS,
    GLOBAL_CONDITION_KEYS,
    MAX_SCP_SIZE_BYTES,
    MAX_STATEMENTS_PER_SCP,
    SERVICE_PREFIXES,
)
from scpz.models import ScpDocument, Statement


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass
class ValidationIssue:
    severity: Severity
    message: str
    path: str = ""  # JSONPath-style location, e.g. "Statement[0].Action[2]"


@dataclass
class ValidationResult:
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not any(i.severity is Severity.ERROR for i in self.issues)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity is Severity.WARNING]

    def add_error(self, message: str, path: str = "") -> None:
        self.issues.append(ValidationIssue(Severity.ERROR, message, path))

    def add_warning(self, message: str, path: str = "") -> None:
        self.issues.append(ValidationIssue(Severity.WARNING, message, path))


# ── Public API ───────────────────────────────────────────────────────


def validate_json_syntax(text: str) -> tuple[dict[str, Any] | None, ValidationResult]:
    """Validate that the input is well-formed JSON and has the top-level SCP shape."""
    result = ValidationResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.add_error(f"Invalid JSON: {exc}")
        return None, result

    if not isinstance(data, dict):
        result.add_error("SCP must be a JSON object at the top level")
        return None, result

    if "Version" not in data:
        result.add_error("Missing required field 'Version'")
    elif data["Version"] != "2012-10-17":
        result.add_error(f"Version must be '2012-10-17', got '{data['Version']}'", path="Version")

    if "Statement" not in data:
        result.add_error("Missing required field 'Statement'")
    elif not isinstance(data["Statement"], list):
        result.add_error("'Statement' must be an array", path="Statement")
    elif len(data["Statement"]) == 0:
        result.add_error("'Statement' array must not be empty", path="Statement")

    return data, result


def validate_document(doc: ScpDocument) -> ValidationResult:
    """Run all validation checks on a parsed SCP document."""
    result = ValidationResult()
    _check_constraints(doc, result)
    for idx, stmt in enumerate(doc.statement):
        prefix = f"Statement[{idx}]"
        _check_actions(stmt, prefix, result)
        _check_conditions(stmt, prefix, result)
        _check_resources(stmt, prefix, result)
    return result


def validate_file(path: str | Path) -> tuple[ScpDocument | None, ValidationResult]:
    """Validate an SCP JSON file end-to-end.

    Returns the parsed document (if parseable) and all validation issues.
    """
    text = Path(path).read_text(encoding="utf-8")
    data, result = validate_json_syntax(text)
    if not result.is_valid:
        return None, result

    assert data is not None
    try:
        doc = ScpDocument.model_validate(data)
    except Exception as exc:
        result.add_error(f"Failed to parse SCP document: {exc}")
        return None, result

    doc_result = validate_document(doc)
    result.issues.extend(doc_result.issues)
    return doc, result


# ── Internal checks ──────────────────────────────────────────────────

_ACTION_RE = re.compile(r"^[a-zA-Z0-9\-]+:[a-zA-Z0-9\*\?]+$")


def _check_constraints(doc: ScpDocument, result: ValidationResult) -> None:
    """Check hard limits (size, statement count)."""
    if len(doc.statement) > MAX_STATEMENTS_PER_SCP:
        result.add_warning(
            f"SCP has {len(doc.statement)} statements (limit is {MAX_STATEMENTS_PER_SCP})",
        )
    if doc.size_bytes > MAX_SCP_SIZE_BYTES:
        result.add_warning(
            f"SCP is {doc.size_bytes:,} bytes (limit is {MAX_SCP_SIZE_BYTES:,} bytes)",
        )


def _check_actions(stmt: Statement, prefix: str, result: ValidationResult) -> None:
    """Validate action strings."""
    actions = stmt.action_list or stmt.not_action_list
    action_field = "NotAction" if stmt.not_action is not None else "Action"
    for i, action in enumerate(actions):
        if action == "*":
            continue
        if not _ACTION_RE.match(action):
            result.add_error(
                f"Malformed action '{action}'",
                path=f"{prefix}.{action_field}[{i}]",
            )
            continue
        svc = action.split(":")[0].lower()
        if svc not in SERVICE_PREFIXES:
            result.add_warning(
                f"Unknown service prefix '{svc}' in action '{action}'",
                path=f"{prefix}.{action_field}[{i}]",
            )


def _check_conditions(stmt: Statement, prefix: str, result: ValidationResult) -> None:
    """Validate condition operators and keys."""
    if stmt.condition is None:
        return
    for operator, keys in stmt.condition.items():
        # Allow "...IfExists" variants
        base_op = operator.removesuffix("IfExists")
        if base_op not in CONDITION_OPERATORS:
            result.add_warning(
                f"Unknown condition operator '{operator}'",
                path=f"{prefix}.Condition.{operator}",
            )
        if not isinstance(keys, dict):  # defensive for malformed JSON
            result.add_error(  # type: ignore[unreachable]
                f"Condition operator '{operator}' value must be an object",
                path=f"{prefix}.Condition.{operator}",
            )
            continue
        for key in keys:
            _check_condition_key(key, f"{prefix}.Condition.{operator}", result)


def _check_condition_key(key: str, prefix: str, result: ValidationResult) -> None:
    """Warn on unrecognised global condition keys."""
    if not key.startswith("aws:"):
        # Service-specific keys — we don't validate these exhaustively
        return
    # Handle tag keys like aws:PrincipalTag/Department
    base_key = key.split("/")[0]
    if base_key not in GLOBAL_CONDITION_KEYS:
        result.add_warning(
            f"Unknown global condition key '{key}'",
            path=f"{prefix}.{key}",
        )


def _check_resources(stmt: Statement, prefix: str, result: ValidationResult) -> None:
    """Basic resource validation."""
    for i, resource in enumerate(stmt.resource_list):
        if resource == "*":
            continue
        if not resource.startswith("arn:"):
            result.add_warning(
                f"Resource '{resource}' does not look like an ARN",
                path=f"{prefix}.Resource[{i}]",
            )
