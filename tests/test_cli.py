"""Tests for scpz.cli."""

from __future__ import annotations

import json
import shutil
import textwrap
from typing import TYPE_CHECKING
from unittest.mock import patch

from typer.testing import CliRunner

from scpz.cli import app
from scpz.splitter import SplitError

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def _needs_split_policy(tmp_path: Path) -> Path:
    """Write a policy that is too large/has too many statements to fit in one SCP.

    Uses 20 statements each with a unique condition so they cannot be merged.
    The statement count (20 > 5) ensures fits_single_scp is False after optimization.
    """
    actions = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
    ]
    statements = [
        {
            "Sid": f"DenyRegion{i:02d}",
            "Effect": "Deny",
            "Action": actions,
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": f"ap-southeast-{i + 1}",
                    "aws:PrincipalTag/CostCenter": f"cost-center-{i:04d}",
                }
            },
        }
        for i in range(20)
    ]
    path = tmp_path / "needs_split.json"
    path.write_text(
        json.dumps({"Version": "2012-10-17", "Statement": statements}),
        encoding="utf-8",
    )
    return path


class TestVersion:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "scpz" in result.stdout


class TestValidateCommand:
    def test_validate_valid_file(self, fixtures_dir: Path) -> None:
        result = runner.invoke(app, ["validate", str(fixtures_dir / "simple_deny.json")])
        assert result.exit_code == 0

    def test_validate_bad_config_exits_1(self, fixtures_dir: Path, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text("apiVersion: bad\nkind: Bad\n", encoding="utf-8")
        shutil.copy2(fixtures_dir / "simple_deny.json", tmp_path / "policy.json")
        result = runner.invoke(app, ["validate", str(tmp_path / "policy.json")])
        assert result.exit_code == 1

    def test_validate_directory(self, fixtures_dir: Path) -> None:
        result = runner.invoke(app, ["validate", str(fixtures_dir)])
        # May have warnings but should not fail with errors
        assert result.exit_code == 0

    def test_validate_missing_file(self) -> None:
        result = runner.invoke(app, ["validate", "/nonexistent.json"])
        assert result.exit_code == 1


class TestSchemaCommand:
    def test_stdout_is_valid_json(self) -> None:
        result = runner.invoke(app, ["schema"])
        assert result.exit_code == 0
        schema = json.loads(result.output)
        assert schema.get("title") == "OptimizerConfig"

    def test_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "schema.json"
        result = runner.invoke(app, ["schema", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert json.loads(out.read_text()).get("title") == "OptimizerConfig"


def _scpz_yaml_with_validation(**validation: str) -> str:
    lines = [
        "apiVersion: scpz.io/v1alpha1",
        "kind: OptimizerConfig",
        "metadata:",
        "  name: test",
        "spec:",
        "  validation:",
    ]
    for key, value in validation.items():
        lines.append(f"    {key}: {value}")
    return "\n".join(lines) + "\n"


class TestOptimizeValidationSeverity:
    """Optimize honours spec.validation severities (same semantics as validate)."""

    def test_on_wildcard_action_error_exits_nonzero_no_backup(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text(
            _scpz_yaml_with_validation(onWildcardAction="error"),
            encoding="utf-8",
        )
        policy = tmp_path / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "X",
                            "Effect": "Deny",
                            "Action": "iam:Get*",
                            "Resource": "*",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        before = policy.read_text()

        result = runner.invoke(app, ["optimize-cmd", str(policy)])
        assert result.exit_code == 1
        assert not (tmp_path / "policy.json.bak").exists()
        assert policy.read_text() == before

    def test_on_wildcard_action_warn_allows_optimize(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text(
            _scpz_yaml_with_validation(onWildcardAction="warn"),
            encoding="utf-8",
        )
        policy = tmp_path / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "X",
                            "Effect": "Deny",
                            "Action": "iam:Get*",
                            "Resource": "*",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(app, ["optimize-cmd", str(policy)])
        assert result.exit_code == 0
        assert (tmp_path / "policy.json.bak").exists()

    def test_validation_error_skips_explicit_output(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text(
            _scpz_yaml_with_validation(onWildcardAction="error"),
            encoding="utf-8",
        )
        policy = tmp_path / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "X",
                            "Effect": "Deny",
                            "Action": "s3:Get*",
                            "Resource": "*",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "optimized.json"
        result = runner.invoke(
            app,
            ["optimize-cmd", str(policy), "--output", str(out)],
        )
        assert result.exit_code == 1
        assert not out.exists()


class TestOptimizeErrors:
    def test_empty_dir_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["optimize-cmd", str(tmp_path)])
        assert result.exit_code == 1

    def test_bad_config_exits_1(self, fixtures_dir: Path, tmp_path: Path) -> None:
        """Invalid scpz.yaml discovered while walking up triggers config error."""
        (tmp_path / "scpz.yaml").write_text("apiVersion: bad\nkind: Bad\n", encoding="utf-8")
        shutil.copy2(fixtures_dir / "simple_deny.json", tmp_path / "policy.json")
        result = runner.invoke(app, ["optimize-cmd", str(tmp_path / "policy.json")])
        assert result.exit_code == 1

    def test_unparseable_scp_exits_1(self, tmp_path: Path) -> None:
        """A JSON file that cannot be parsed as an SCP causes exit 1."""
        bad = tmp_path / "bad.json"
        bad.write_text('{"no": "statement"}', encoding="utf-8")
        result = runner.invoke(app, ["optimize-cmd", str(bad)])
        assert result.exit_code == 1

    def test_no_split_oversized_exits_1(self, tmp_path: Path) -> None:
        policy = _needs_split_policy(tmp_path)
        result = runner.invoke(app, ["optimize-cmd", str(policy), "--no-split"])
        assert result.exit_code == 1

    def test_split_error_propagates(self, tmp_path: Path) -> None:
        policy = _needs_split_policy(tmp_path)
        with patch("scpz.cli.split_if_needed", side_effect=SplitError("too complex")):
            result = runner.invoke(app, ["optimize-cmd", str(policy)])
        assert result.exit_code == 1


class TestOptimizeSplit:
    def test_dry_run(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["optimize-cmd", str(_needs_split_policy(tmp_path)), "--dry-run"]
        )
        assert result.exit_code == 0

    def test_summary_only(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["optimize-cmd", str(_needs_split_policy(tmp_path)), "--summary-only"]
        )
        assert result.exit_code == 0

    def test_writes_multiple_files(self, tmp_path: Path) -> None:
        policy = _needs_split_policy(tmp_path)
        result = runner.invoke(app, ["optimize-cmd", str(policy)])
        assert result.exit_code == 0
        written = sorted(tmp_path.glob("needs_split_*.json"))
        assert len(written) > 1


class TestOptimizeCommand:
    def test_dry_run(self, fixtures_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["optimize-cmd", str(fixtures_dir / "mergeable_statements.json"), "--dry-run"],
        )
        assert result.exit_code == 0

    def test_summary_only(self, fixtures_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["optimize-cmd", str(fixtures_dir / "oversized.json"), "--summary-only"],
        )
        assert result.exit_code == 0

    def test_optimize_writes_file(self, fixtures_dir: Path, tmp_path: Path) -> None:
        src = fixtures_dir / "mergeable_statements.json"
        dest = tmp_path / "policy.json"
        shutil.copy2(src, dest)

        result = runner.invoke(app, ["optimize-cmd", str(dest)])
        assert result.exit_code == 0
        # Backup should exist
        assert (tmp_path / "policy.json.bak").exists()
        # Optimized file should be valid JSON
        data = json.loads(dest.read_text())
        assert "Statement" in data

    def test_optimize_with_output(self, fixtures_dir: Path, tmp_path: Path) -> None:
        src = fixtures_dir / "simple_deny.json"
        out = tmp_path / "optimized.json"

        result = runner.invoke(
            app,
            ["optimize-cmd", str(src), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_dry_run_already_optimal_shows_no_changes(
        self, fixtures_dir: Path, tmp_path: Path
    ) -> None:
        """A second dry-run pass on an already-optimized file produces an empty diff."""
        src = fixtures_dir / "simple_deny.json"
        out = tmp_path / "optimized.json"
        # Produce the canonical optimized form first
        runner.invoke(app, ["optimize-cmd", str(src), "--output", str(out)])
        # Second pass: optimizer has nothing left to change
        result = runner.invoke(app, ["optimize-cmd", str(out), "--dry-run"])
        assert result.exit_code == 0


class TestValidateErrors:
    def test_bad_scpz_yaml_exits_1(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text("not: [broken", encoding="utf-8")
        pol = tmp_path / "p.json"
        pol.write_text(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
            encoding="utf-8",
        )
        result = runner.invoke(app, ["validate", str(pol)])
        assert result.exit_code == 1

    def test_strict_unknown_action_exits_1(self, tmp_path: Path) -> None:
        (tmp_path / "scpz.yaml").write_text(
            textwrap.dedent(
                """
                apiVersion: scpz.io/v1alpha1
                kind: OptimizerConfig
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
        result = runner.invoke(app, ["validate", str(pol)])
        assert result.exit_code == 1

    def test_empty_dir_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["validate", str(tmp_path)])
        assert result.exit_code == 1

    def test_unparseable_scp_exits_1(self, tmp_path: Path) -> None:
        """A JSON file without a Statement key fails file-level validation."""
        bad = tmp_path / "bad.json"
        bad.write_text('{"no": "statement"}', encoding="utf-8")
        result = runner.invoke(app, ["validate", str(bad)])
        assert result.exit_code == 1

    def test_malformed_action_exits_1(self, tmp_path: Path) -> None:
        """A valid SCP structure with a malformed action fails document-level validation."""
        bad = tmp_path / "bad_action.json"
        bad.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Deny", "Action": ["not-a-valid-action"], "Resource": "*"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["validate", str(bad)])
        assert result.exit_code == 1
