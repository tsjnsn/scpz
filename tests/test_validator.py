"""Tests for scpz.validator."""

from __future__ import annotations

from typing import TYPE_CHECKING

from scpz.config import ValidationConfig
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

    def test_on_unknown_service_ignore(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "fakeservice:DoSomething", "Resource": "*"}]}'
        )
        vcfg = ValidationConfig(onUnknownService="ignore")
        result = validate_document(doc, validation=vcfg)
        assert not any("Unknown service prefix" in i.message for i in result.issues)

    def test_on_unknown_service_error(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "fakeservice:DoSomething", "Resource": "*"}]}'
        )
        vcfg = ValidationConfig(onUnknownService="error")
        result = validate_document(doc, validation=vcfg)
        assert not result.is_valid
        assert any("Unknown service prefix" in i.message for i in result.errors)

    def test_on_wildcard_action_in_verb(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "iam:Get*", "Resource": "*"}]}'
        )
        result = validate_document(doc)
        assert any("wildcard" in i.message.lower() for i in result.warnings)

    def test_on_wildcard_action_ignore(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "iam:Get*", "Resource": "*"}]}'
        )
        vcfg = ValidationConfig(onWildcardAction="ignore")
        result = validate_document(doc, validation=vcfg)
        assert not any("wildcard" in i.message.lower() for i in result.issues)

    def test_bare_star_action_not_wildcard_rule(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "*", "Resource": "*", '
            '"Condition": {"StringEquals": {"aws:PrincipalAccount": "123"}}}]}'
        )
        result = validate_document(doc)
        assert not any("wildcard" in i.message.lower() for i in result.issues)

    def test_on_broad_resource_warn(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "s3:GetObject", "Resource": "*"}]}'
        )
        result = validate_document(doc)
        assert any("very broad" in i.message for i in result.warnings)

    def test_on_broad_resource_suppressed_when_condition(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "s3:GetObject", "Resource": "*", '
            '"Condition": {"StringEquals": {"aws:PrincipalAccount": "123"}}}]}'
        )
        result = validate_document(doc)
        assert not any("very broad" in i.message for i in result.issues)

    def test_on_missing_sid_respects_severity(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", '
            '"Action": "s3:GetObject", "Resource": "arn:aws:s3:::mybucket"}]}'
        )
        assert not any("no Sid" in i.message for i in validate_document(doc).issues)
        warn_result = validate_document(doc, validation=ValidationConfig(onMissingSid="warn"))
        assert any("no Sid" in i.message for i in warn_result.warnings)
        err_result = validate_document(doc, validation=ValidationConfig(onMissingSid="error"))
        assert not err_result.is_valid


class TestFileValidation:
    def test_validate_file(self, fixtures_dir: Path) -> None:
        doc, result = validate_file(fixtures_dir / "simple_deny.json")
        assert doc is not None
        assert result.is_valid

    def test_validate_complex(self, fixtures_dir: Path) -> None:
        doc, _result = validate_file(fixtures_dir / "complex_multi.json")
        assert doc is not None
