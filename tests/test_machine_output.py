"""Tests for machine-readable JSON CLI output."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from scpz.cli import app

runner = CliRunner()

VALIDATE_TOP_KEYS = frozenset({"command", "version", "status", "exit_code", "files", "summary"})
VALIDATE_FILE_KEYS = frozenset({"path", "valid", "error_count", "warning_count", "issues"})
VALIDATE_ISSUE_KEYS = frozenset({"severity", "message", "path"})
VALIDATE_SUMMARY_KEYS = frozenset({"file_count", "valid_count", "invalid_count"})

EQUIV_TOP_KEYS = frozenset(
    {"command", "version", "status", "exit_code", "before", "after", "equivalence"}
)
EQUIV_FILE_KEYS = VALIDATE_FILE_KEYS
EQUIV_EQUIV_KEYS = frozenset({"ok", "messages"})


def _parse_json_output(result: Any) -> dict[str, Any]:
    assert result.stdout.strip(), "expected JSON on stdout"
    return json.loads(result.stdout)


class TestValidateJsonOutput:
    def test_valid_file_shape_and_exit_code(self, fixtures_dir: Path) -> None:
        path = fixtures_dir / "simple_deny.json"
        result = runner.invoke(app, ["validate", "--json", str(path)])
        assert result.exit_code == 0
        payload = _parse_json_output(result)
        assert payload["command"] == "validate"
        assert set(payload) == VALIDATE_TOP_KEYS
        assert payload["status"] == "ok"
        assert payload["exit_code"] == 0
        assert set(payload["summary"]) == VALIDATE_SUMMARY_KEYS
        assert payload["summary"]["file_count"] == 1
        assert payload["summary"]["valid_count"] == 1
        assert payload["summary"]["invalid_count"] == 0
        file_entry = payload["files"][0]
        assert set(file_entry) == VALIDATE_FILE_KEYS
        assert file_entry["valid"] is True
        assert file_entry["path"] == str(path)
        assert file_entry["issues"] == []

    def test_invalid_file_reports_errors(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text('{"no": "statement"}', encoding="utf-8")
        result = runner.invoke(app, ["validate", "--json", str(bad)])
        assert result.exit_code == 1
        payload = _parse_json_output(result)
        assert payload["status"] == "error"
        assert payload["exit_code"] == 1
        file_entry = payload["files"][0]
        assert file_entry["valid"] is False
        assert file_entry["error_count"] >= 1
        issue = file_entry["issues"][0]
        assert set(issue) == VALIDATE_ISSUE_KEYS
        assert issue["severity"] == "error"

    def test_missing_path_includes_error_field(self) -> None:
        result = runner.invoke(app, ["validate", "--json", "/nonexistent.json"])
        assert result.exit_code == 1
        payload = _parse_json_output(result)
        assert payload["status"] == "error"
        assert "error" in payload
        assert "not found" in payload["error"].lower()
        assert payload["files"] == []

    def test_json_mode_suppresses_human_success_message(self, fixtures_dir: Path) -> None:
        path = fixtures_dir / "simple_deny.json"
        result = runner.invoke(app, ["validate", "--json", str(path)])
        assert "All files are valid" not in result.stdout
        assert "✓" not in result.stdout


class TestCheckEquivalenceJsonOutput:
    def test_identical_files_ok(self, fixtures_dir: Path, tmp_path: Path) -> None:
        src = fixtures_dir / "simple_deny.json"
        before = tmp_path / "before.json"
        after = tmp_path / "after.json"
        shutil.copy2(src, before)
        shutil.copy2(src, after)
        result = runner.invoke(
            app,
            ["check-equivalence", "--json", str(before), str(after)],
        )
        assert result.exit_code == 0
        payload = _parse_json_output(result)
        assert set(payload) == EQUIV_TOP_KEYS
        assert payload["command"] == "check-equivalence"
        assert payload["status"] == "ok"
        assert payload["exit_code"] == 0
        assert set(payload["before"]) == EQUIV_FILE_KEYS
        assert set(payload["after"]) == EQUIV_FILE_KEYS
        assert set(payload["equivalence"]) == EQUIV_EQUIV_KEYS
        assert payload["equivalence"]["ok"] is True
        assert payload["equivalence"]["messages"] == []

    def test_broadened_policy_fails_with_messages(self, tmp_path: Path) -> None:
        examples_dir = Path(__file__).resolve().parents[1] / "examples"
        shutil.copy2(examples_dir / "scpz.yaml", tmp_path / "scpz.yaml")
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
            ["check-equivalence", "--json", str(before), str(after)],
        )
        assert result.exit_code == 1
        payload = _parse_json_output(result)
        assert payload["status"] == "error"
        assert payload["exit_code"] == 1
        assert payload["equivalence"]["ok"] is False
        assert payload["equivalence"]["messages"]
        assert "error" in payload

    def test_missing_file_error_payload(self) -> None:
        result = runner.invoke(
            app,
            ["check-equivalence", "--json", "/no/before.json", "/no/after.json"],
        )
        assert result.exit_code == 1
        payload = _parse_json_output(result)
        assert payload["status"] == "error"
        assert "error" in payload
        assert "not found" in payload["error"].lower()
