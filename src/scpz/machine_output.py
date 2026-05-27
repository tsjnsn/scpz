"""Machine-readable CLI result payloads for validation-style commands."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path  # noqa: TC003 — used at runtime in payload builders
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from scpz.validator import ValidationIssue, ValidationResult

SCHEMA_VERSION = 1

CommandStatus = Literal["ok", "error"]


class OutputFormat(StrEnum):
    """CLI output format for commands that support machine-readable results."""

    HUMAN = "human"
    JSON = "json"


def issue_to_dict(issue: ValidationIssue) -> dict[str, str]:
    return {
        "severity": issue.severity.value,
        "message": issue.message,
        "path": issue.path,
    }


def validation_result_to_dict(result: ValidationResult) -> dict[str, Any]:
    return {
        "valid": result.is_valid,
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
        "issues": [issue_to_dict(i) for i in result.issues],
    }


def build_validate_payload(
    *,
    files: list[dict[str, Any]],
    status: CommandStatus,
    exit_code: int,
    error: str | None = None,
) -> dict[str, Any]:
    """Build the JSON document for ``scpz validate --format json``."""
    error_count = sum(f["validation"]["error_count"] for f in files)
    warning_count = sum(f["validation"]["warning_count"] for f in files)
    files_valid = sum(1 for f in files if f["validation"]["valid"])
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "command": "validate",
        "status": status,
        "exit_code": exit_code,
        "summary": {
            "files_checked": len(files),
            "files_valid": files_valid,
            "error_count": error_count,
            "warning_count": warning_count,
        },
        "files": files,
    }
    if error is not None:
        payload["error"] = error
    return payload


def build_check_equivalence_payload(
    *,
    before: Path,
    after: Path,
    status: CommandStatus,
    exit_code: int,
    equivalent: bool | None,
    messages: list[str],
    before_validation: ValidationResult | None = None,
    after_validation: ValidationResult | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Build the JSON document for ``scpz check-equivalence --format json``."""
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "command": "check-equivalence",
        "status": status,
        "exit_code": exit_code,
        "before": str(before),
        "after": str(after),
        "equivalent": equivalent,
        "messages": messages,
    }
    if before_validation is not None:
        payload["before_validation"] = validation_result_to_dict(before_validation)
    if after_validation is not None:
        payload["after_validation"] = validation_result_to_dict(after_validation)
    if error is not None:
        payload["error"] = error
    return payload


def emit_json(payload: dict[str, Any]) -> None:
    """Write a single JSON object to stdout (no Rich styling)."""
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    sys.stdout.write("\n")


def file_validation_entry(path: Path, result: ValidationResult) -> dict[str, Any]:
    return {
        "path": str(path),
        "validation": validation_result_to_dict(result),
    }
