"""Stable machine-readable JSON payloads for validation-style CLI commands."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any, Literal

from scpz import __version__

if TYPE_CHECKING:
    from pathlib import Path

    from scpz.validator import ValidationIssue, ValidationResult

CommandName = Literal["validate", "check-equivalence"]
Status = Literal["ok", "error"]


def issue_to_dict(issue: ValidationIssue) -> dict[str, str]:
    return {
        "severity": issue.severity.value,
        "message": issue.message,
        "path": issue.path,
    }


def file_validation_to_dict(file_path: Path, result: ValidationResult) -> dict[str, Any]:
    errors = result.errors
    warnings = result.warnings
    return {
        "path": str(file_path),
        "valid": result.is_valid,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "issues": [issue_to_dict(i) for i in result.issues],
    }


def _envelope(
    *,
    command: CommandName,
    status: Status,
    exit_code: int,
    body: dict[str, Any],
    error: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "command": command,
        "version": __version__,
        "status": status,
        "exit_code": exit_code,
    }
    if error is not None:
        payload["error"] = error
    payload.update(body)
    return payload


def build_validate_payload(
    *,
    files: list[dict[str, Any]],
    exit_code: int,
    error: str | None = None,
) -> dict[str, Any]:
    valid_count = sum(1 for f in files if f.get("valid"))
    invalid_count = len(files) - valid_count
    status: Status = "ok" if exit_code == 0 else "error"
    return _envelope(
        command="validate",
        status=status,
        exit_code=exit_code,
        error=error,
        body={
            "files": files,
            "summary": {
                "file_count": len(files),
                "valid_count": valid_count,
                "invalid_count": invalid_count,
            },
        },
    )


def build_check_equivalence_payload(
    *,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    equivalence: dict[str, Any] | None,
    exit_code: int,
    error: str | None = None,
) -> dict[str, Any]:
    status: Status = "ok" if exit_code == 0 else "error"
    body: dict[str, Any] = {}
    if before is not None:
        body["before"] = before
    if after is not None:
        body["after"] = after
    if equivalence is not None:
        body["equivalence"] = equivalence
    return _envelope(
        command="check-equivalence",
        status=status,
        exit_code=exit_code,
        error=error,
        body=body,
    )


def emit_json(payload: dict[str, Any]) -> None:
    """Write a JSON document to stdout (single trailing newline)."""
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
