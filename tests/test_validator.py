"""Tests for scpz.validator."""

from __future__ import annotations

from typing import TYPE_CHECKING

from scpz.models import ScpDocument
from scpz.validator import (
    Severity,
    validate_document,
    validate_file,
    validate_json_syntax,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestJsonSyntaxValidation:
    def test_valid_json(self) -> None:
        text = (
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}'
        )
        data, result = validate_json_syntax(text)
        assert result.is_valid
        assert data is not None

    def test_invalid_json(self) -> None:
        _, result = validate_json_syntax("{not json}")
        assert not result.is_valid

    def test_missing_version(self) -> None:
        _, result = validate_json_syntax('{"Statement": []}')
        assert not result.is_valid

    def test_missing_statement(self) -> None:
        _, result = validate_json_syntax('{"Version": "2012-10-17"}')
        assert not result.is_valid

    def test_wrong_version(self) -> None:
        _, result = validate_json_syntax(
            '{"Version": "2023-01-01", '
            '"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}'
        )
        assert not result.is_valid

    def test_empty_statement_array(self) -> None:
        _, result = validate_json_syntax('{"Version": "2012-10-17", "Statement": []}')
        assert not result.is_valid


class TestDocumentValidation:
    def test_valid_simple(self, simple_deny: ScpDocument) -> None:
        result = validate_document(simple_deny)
        assert result.is_valid

    def test_oversized_warnings(self, oversized: ScpDocument) -> None:
        result = validate_document(oversized)
        # Should warn about statement count
        warnings = [i for i in result.issues if i.severity is Severity.WARNING]
        stmt_warnings = [w for w in warnings if "statement" in w.message.lower()]
        assert len(stmt_warnings) > 0

    def test_unknown_service_prefix(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", '
            '"Action": "fakeservice:DoSomething", "Resource": "*"}]}'
        )
        result = validate_document(doc)
        warnings = [i for i in result.issues if "Unknown service prefix" in i.message]
        assert len(warnings) == 1


class TestFileValidation:
    def test_validate_file(self, fixtures_dir: Path) -> None:
        doc, result = validate_file(fixtures_dir / "simple_deny.json")
        assert doc is not None
        assert result.is_valid

    def test_validate_complex(self, fixtures_dir: Path) -> None:
        doc, _result = validate_file(fixtures_dir / "complex_multi.json")
        assert doc is not None
