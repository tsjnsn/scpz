"""Tests for scpeasy.cli."""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from scpeasy.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


class TestVersion:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "scpeasy" in result.stdout


class TestValidateCommand:
    def test_validate_valid_file(self, fixtures_dir: Path) -> None:
        result = runner.invoke(app, ["validate", str(fixtures_dir / "simple_deny.json")])
        assert result.exit_code == 0

    def test_validate_directory(self, fixtures_dir: Path) -> None:
        result = runner.invoke(app, ["validate", str(fixtures_dir)])
        # May have warnings but should not fail with errors
        assert result.exit_code == 0

    def test_validate_missing_file(self) -> None:
        result = runner.invoke(app, ["validate", "/nonexistent.json"])
        assert result.exit_code == 1


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
