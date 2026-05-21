"""Tests for scpz.validator."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from scpz.catalog import ActionCatalog
from scpz.config import SUPPORTED_API_VERSION, SUPPORTED_KIND, ValidationConfig
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


class TestValidationRuleSeverities:
    def test_on_wildcard_action_error(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Sid": "S", "Effect": "Deny", '
            '"Action": "iam:Get*", "Resource": "*"}]}'
        )
        rules = ValidationConfig(onWildcardAction="error")
        result = validate_document(doc, validation=rules)
        assert not result.is_valid
        assert any("wildcard" in i.message.lower() for i in result.errors)


class TestCatalogActionValidation:
    def test_known_bundled_actions_clean(self, simple_deny: ScpDocument) -> None:
        cat = ActionCatalog.bundled()
        result = validate_document(
            simple_deny,
            validation=ValidationConfig(),
            action_catalog=cat,
        )
        catalog_msgs = [i for i in result.issues if "not in the AWS action catalog" in i.message]
        assert catalog_msgs == []

    def test_unknown_action_warns_when_service_is_catalogued(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", "Action": "iam:GetFunctoin", "Resource": "*"}]}'
        )
        cat = ActionCatalog.from_dict({"iam": ["GetRole", "GetUser"]})
        result = validate_document(
            doc,
            validation=ValidationConfig(),
            action_catalog=cat,
        )
        assert result.is_valid
        warns = [i for i in result.warnings if "not in the AWS action catalog" in i.message]
        assert len(warns) == 1

    def test_unknown_action_errors_in_strict_mode(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", "Action": "iam:GetFunctoin", "Resource": "*"}]}'
        )
        cat = ActionCatalog.from_dict({"iam": ["GetRole"]})
        result = validate_document(
            doc,
            validation=ValidationConfig(onUnknownCatalogAction="error"),
            action_catalog=cat,
        )
        assert not result.is_valid
        errs = [i for i in result.errors if "not in the AWS action catalog" in i.message]
        assert len(errs) == 1

    def test_wildcard_not_catalog_checked(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", "Action": "iam:Get*", "Resource": "*"}]}'
        )
        cat = ActionCatalog.from_dict({"iam": ["GetRole"]})
        result = validate_document(
            doc,
            validation=ValidationConfig(onUnknownCatalogAction="error"),
            action_catalog=cat,
        )
        cat_issues = [i for i in result.issues if "not in the AWS action catalog" in i.message]
        assert cat_issues == []

    def test_not_action_unknown_warns(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", "NotAction": "s3:GetObjet", "Resource": "*"}]}'
        )
        cat = ActionCatalog.from_dict({"s3": ["GetObject"]})
        result = validate_document(
            doc,
            validation=ValidationConfig(),
            action_catalog=cat,
        )
        assert result.is_valid
        assert any("not in the AWS action catalog" in i.message for i in result.warnings)

    def test_on_unknown_catalog_action_ignore(self) -> None:
        doc = ScpDocument.from_json(
            '{"Version": "2012-10-17", '
            '"Statement": [{"Effect": "Deny", "Action": "iam:GetFunctoin", "Resource": "*"}]}'
        )
        cat = ActionCatalog.from_dict({"iam": ["GetRole"]})
        result = validate_document(
            doc,
            validation=ValidationConfig(onUnknownCatalogAction="ignore"),
            action_catalog=cat,
        )
        assert not any("not in the AWS action catalog" in i.message for i in result.issues)


class TestValidateFileConfig:
    def test_invalid_scpz_yaml_returns_no_doc(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text("not: [broken", encoding="utf-8")
        pol = tmp_path / "p.json"
        pol.write_text(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
            encoding="utf-8",
        )
        doc, result = validate_file(pol)
        assert doc is None
        assert not result.is_valid
        assert any("Invalid scpz.yaml" in i.message for i in result.errors)

    def test_validate_file_missing_catalog_path(self, tmp_path: Path) -> None:
        missing = tmp_path / "nope.json"
        (tmp_path / "scpz.yaml").write_text(
            textwrap.dedent(
                f"""
                apiVersion: {SUPPORTED_API_VERSION}
                kind: {SUPPORTED_KIND}
                spec:
                  catalog:
                    source: file
                    path: {missing.as_posix()}
                """
            ),
            encoding="utf-8",
        )
        pol = tmp_path / "p.json"
        pol.write_text(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
            encoding="utf-8",
        )
        doc, result = validate_file(pol)
        assert doc is None
        assert not result.is_valid
        assert any("Could not load action catalog" in i.message for i in result.errors)

    def test_validate_file_malformed_catalog_json(self, tmp_path: Path) -> None:
        bad_cat = tmp_path / "bad.json"
        bad_cat.write_text("{not json", encoding="utf-8")
        (tmp_path / "scpz.yaml").write_text(
            textwrap.dedent(
                f"""
                apiVersion: {SUPPORTED_API_VERSION}
                kind: {SUPPORTED_KIND}
                spec:
                  catalog:
                    source: file
                    path: {bad_cat.as_posix()}
                """
            ),
            encoding="utf-8",
        )
        pol = tmp_path / "p.json"
        pol.write_text(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
            encoding="utf-8",
        )
        doc, result = validate_file(pol)
        assert doc is None
        assert not result.is_valid
        assert any("Could not load action catalog" in i.message for i in result.errors)

    def test_strict_unknown_action_via_scpz_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text(
            textwrap.dedent(
                f"""
                apiVersion: {SUPPORTED_API_VERSION}
                kind: {SUPPORTED_KIND}
                spec:
                  validation:
                    onUnknownCatalogAction: error
                """
            ),
            encoding="utf-8",
        )
        pol = tmp_path / "p.json"
        pol.write_text(
            '{"Version":"2012-10-17","Statement":['
            '{"Effect":"Deny","Action":"iam:GetRol","Resource":"*"}]}',
            encoding="utf-8",
        )
        doc, result = validate_file(pol)
        assert doc is not None
        assert not result.is_valid
        assert any("not in the AWS action catalog" in i.message for i in result.errors)

    def test_validate_file(self, fixtures_dir: Path) -> None:
        doc, result = validate_file(fixtures_dir / "simple_deny.json")
        assert doc is not None
        assert result.is_valid

    def test_validate_complex(self, fixtures_dir: Path) -> None:
        doc, _result = validate_file(fixtures_dir / "complex_multi.json")
        assert doc is not None
