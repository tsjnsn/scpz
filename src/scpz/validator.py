"""SCP validation — structure, actions, conditions, and constraint checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from scpz.catalog import ActionCatalog
from scpz.config import OptimizerConfig, ValidationConfig, ValidationSeverity
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


def validate_document(
    doc: ScpDocument,
    *,
    validation: ValidationConfig | None = None,
    action_catalog: ActionCatalog | None = None,
) -> ValidationResult:
    """Run all validation checks on a parsed SCP document.

    When *action_catalog* is non-empty, literal ``Action`` / ``NotAction`` strings
    are cross-checked against the catalog. Unknown literals for a catalogued
    service use ``validation.onUnknownCatalogAction``.
    """
    result = ValidationResult()
    vcfg = validation if validation is not None else ValidationConfig()
    _check_constraints(doc, result)
    catalog = (
        action_catalog if (action_catalog is not None and not action_catalog.is_empty()) else None
    )
    for idx, stmt in enumerate(doc.statement):
        prefix = f"Statement[{idx}]"
        _check_missing_sid(stmt, prefix, vcfg, result)
        _check_actions(stmt, prefix, vcfg, result, catalog=catalog)
        _check_conditions(stmt, prefix, result)
        _check_resources(stmt, prefix, vcfg, result)
    return result


def parse_scp_file(path: str | Path) -> tuple[ScpDocument | None, ValidationResult]:
    """Parse an SCP JSON file (syntax and document model only).

    Does not run constraint, action, or catalog checks. Use ``validate_document``
    or ``validate_file`` for full validation.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    data, result = validate_json_syntax(text)
    if not result.is_valid:
        return None, result

    assert data is not None
    try:
        doc = ScpDocument.model_validate(data)
    except Exception as exc:
        result.add_error(f"Failed to parse SCP document: {exc}")
        return None, result

    return doc, result


def validate_file(
    path: str | Path,
    *,
    config: OptimizerConfig | None = None,
    action_catalog: ActionCatalog | None = None,
) -> tuple[ScpDocument | None, ValidationResult]:
    """Validate an SCP JSON file end-to-end.

    Loads ``scpz.yaml`` from the file's directory tree (same discovery as
    ``optimize``) unless *config* is provided. When *action_catalog* is given,
    it is used instead of loading the catalog again (for callers that already
    loaded it). Returns the parsed document (if parseable) and all validation
    issues.
    """
    doc, result = parse_scp_file(path)
    if doc is None:
        return None, result

    p = Path(path)
    try:
        cfg = config if config is not None else OptimizerConfig.load(p)
    except ValueError as exc:
        result.add_error(f"Invalid scpz.yaml: {exc}")
        return None, result

    if action_catalog is not None:
        catalog = action_catalog
    else:
        try:
            catalog = ActionCatalog.load(cfg.spec.catalog)
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            result.add_error(f"Could not load action catalog ({cfg.spec.catalog.source}): {exc}")
            return None, result

    doc_result = validate_document(
        doc,
        validation=cfg.spec.validation,
        action_catalog=catalog,
    )
    result.issues.extend(doc_result.issues)
    return doc, result


# ── Internal checks ──────────────────────────────────────────────────

_ACTION_RE = re.compile(r"^[a-zA-Z0-9\-]+:[a-zA-Z0-9\*\?]+$")


def _emit_rule(
    result: ValidationResult,
    severity: ValidationSeverity,
    message: str,
    path: str = "",
) -> None:
    if severity == "ignore":
        return
    if severity == "error":
        result.add_error(message, path)
    else:
        result.add_warning(message, path)


def _action_verb_has_wildcard(action: str) -> bool:
    """True when the action is not bare ``*`` but the verb part contains ``*`` or ``?``."""
    if action == "*":
        return False
    _svc, sep, verb = action.partition(":")
    if not sep:
        return "*" in action or "?" in action
    return "*" in verb or "?" in verb


def _check_missing_sid(
    stmt: Statement, prefix: str, vcfg: ValidationConfig, result: ValidationResult
) -> None:
    if stmt.sid is None:
        _emit_rule(
            result,
            vcfg.onMissingSid,
            "Statement has no Sid",
            path=f"{prefix}.Sid",
        )


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


def _check_actions(
    stmt: Statement,
    prefix: str,
    vcfg: ValidationConfig,
    result: ValidationResult,
    *,
    catalog: ActionCatalog | None,
) -> None:
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
        if stmt.not_action is None and _action_verb_has_wildcard(action):
            _emit_rule(
                result,
                vcfg.onWildcardAction,
                f"Action '{action}' contains a wildcard in the action name",
                path=f"{prefix}.{action_field}[{i}]",
            )
        svc = action.split(":")[0].lower()
        name_part = action.split(":", 1)[1]
        if catalog is not None:
            known = catalog.literal_action_known(svc, name_part)
            if known is False:
                msg = f"Unknown action '{action}' (not in the AWS action catalog)"
                path = f"{prefix}.{action_field}[{i}]"
                _emit_rule(result, vcfg.onUnknownCatalogAction, msg, path)
        if svc not in SERVICE_PREFIXES:
            _emit_rule(
                result,
                vcfg.onUnknownService,
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


def _check_resources(
    stmt: Statement, prefix: str, vcfg: ValidationConfig, result: ValidationResult
) -> None:
    """Basic resource validation."""
    if stmt.condition is None:
        for i, resource in enumerate(stmt.resource_list):
            if resource == "*":
                _emit_rule(
                    result,
                    vcfg.onBroadResource,
                    "Resource '*' with no Condition is very broad",
                    path=f"{prefix}.Resource[{i}]",
                )
    for i, resource in enumerate(stmt.resource_list):
        if resource == "*":
            continue
        if not resource.startswith("arn:"):
            result.add_warning(
                f"Resource '{resource}' does not look like an ARN",
                path=f"{prefix}.Resource[{i}]",
            )
