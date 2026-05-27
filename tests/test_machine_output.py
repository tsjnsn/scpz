"""Tests for machine-readable CLI output (--format json)."""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from typer.testing import CliRunner

from scpz.cli import app
from scpz.machine_output import SCHEMA_VERSION

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def _parse_json(stdout: str) -> dict[str, Any]:
    return json.loads(stdout)


class TestValidateJsonOutput:
    def test_valid_file_shape(self, fixtures_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["validate", "--format", "json", str(fixtures_dir / "simple_deny.json")],
        )
        assert result.exit_code == 0
        payload = _parse_json(result.stdout)
        assert payload["schema_version"] == SCHEMA_VERSION
        assert payload["command"] == "validate"
        assert payload["status"] == "ok"
        assert payload["exit_code"] == 0
        assert payload["summary"]["files_checked"] == 1
        assert payload["summary"]["files_valid"] == 1
        assert len(payload["files"]) == 1
        file_entry = payload["files"][0]
        assert file_entry["validation"]["valid"] is True
        assert file_entry["validation"]["issues"] == []

    def test_invalid_file_reports_issues(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text('{"no": "statement"}', encoding="utf-8")
        result = runner.invoke(app, ["validate", "-f", "json", str(bad)])
        assert result.exit_code == 1
        payload = _parse_json(result.stdout)
        assert payload["status"] == "error"
        assert payload["exit_code"] == 1
        assert payload["summary"]["files_valid"] == 0
        issues = payload["files"][0]["validation"]["issues"]
        assert issues
        assert issues[0]["severity"] == "error"

    def test_missing_path_error_payload(self) -> None:
        result = runner.invoke(app, ["validate", "--format", "json", "/nonexistent.json"])
        assert result.exit_code == 1
        payload = _parse_json(result.stdout)
        assert payload["status"] == "error"
        assert payload["files"] == []
        assert "Path not found" in payload["error"]

    def test_missing_path_human_single_message(self) -> None:
        result = runner.invoke(app, ["validate", "/nonexistent/path.json"])
        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert combined.count("Path not found") == 1
        assert "No JSON files found" not in combined

    def test_empty_dir_human_message(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(app, ["validate", str(empty)])
        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "No JSON files found" in combined
        assert "Path not found" not in combined

    def test_json_stdout_only(self, fixtures_dir: Path) -> None:
        result = runner.invoke(
            app,
            ["validate", "-f", "json", str(fixtures_dir / "simple_deny.json")],
        )
        assert result.exit_code == 0
        assert result.stdout.strip().startswith("{")
        assert "✓" not in result.stdout


class TestCheckEquivalenceJsonOutput:
    def test_equivalent_files(self, fixtures_dir: Path, tmp_path: Path) -> None:
        src = fixtures_dir / "simple_deny.json"
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        shutil.copy2(src, a)
        shutil.copy2(src, b)
        result = runner.invoke(
            app,
            ["check-equivalence", "--format", "json", str(a), str(b)],
        )
        assert result.exit_code == 0
        payload = _parse_json(result.stdout)
        assert payload["command"] == "check-equivalence"
        assert payload["status"] == "ok"
        assert payload["equivalent"] is True
        assert payload["before_validation"]["valid"] is True
        assert payload["after_validation"]["valid"] is True

    def test_broadened_policy(self, tmp_path: Path) -> None:
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        before.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": "*",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        after.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["check-equivalence", "-f", "json", str(before), str(after)],
        )
        assert result.exit_code == 1
        payload = _parse_json(result.stdout)
        assert payload["status"] == "error"
        assert payload["equivalent"] is False
        assert payload["messages"]
        assert any("PutObject" in msg for msg in payload["messages"])

    def test_missing_file_error(self, tmp_path: Path) -> None:
        before = tmp_path / "before.json"
        before.write_text(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["check-equivalence", "--format", "json", str(before), str(tmp_path / "nope.json")],
        )
        assert result.exit_code == 1
        payload = _parse_json(result.stdout)
        assert payload["equivalent"] is None
        assert "not found" in payload["error"].lower()

    def test_loads_catalog_once(self, fixtures_dir: Path, tmp_path: Path) -> None:
        src = fixtures_dir / "simple_deny.json"
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        shutil.copy2(src, a)
        shutil.copy2(src, b)
        from scpz.catalog import ActionCatalog

        with patch("scpz.cli.ActionCatalog.load", wraps=ActionCatalog.load) as load_mock:
            result = runner.invoke(app, ["check-equivalence", str(a), str(b)])
        assert result.exit_code == 0
        assert load_mock.call_count == 1
