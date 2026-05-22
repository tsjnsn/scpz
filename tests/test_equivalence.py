"""Tests for scpz.equivalence — catalog-backed permission refinement checks."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scpz.catalog import ActionCatalog
from scpz.cli import app
from scpz.config import OptimizerConfig
from scpz.equivalence import _expand_action_patterns_to_atoms, check_permission_equivalence
from scpz.models import ScpDocument, Statement
from scpz.optimizer import optimize

runner = CliRunner()
EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"


def _tiny_catalog() -> ActionCatalog:
    return ActionCatalog.from_dict(
        {
            "s3": ["GetObject", "PutObject", "DeleteObject"],
            "iam": ["CreateUser", "DeleteUser"],
        }
    )


class TestCheckPermissionEquivalence:
    def test_identical_policies_ok(self) -> None:
        doc = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(effect="Deny", action="s3:GetObject", resource="*"),
            ],
        )
        cat = _tiny_catalog()
        r = check_permission_equivalence(doc, doc, cat)
        assert r.ok

    def test_stricter_more_denies_ok(self) -> None:
        before = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action="s3:GetObject", resource="*")],
        )
        after = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["s3:GetObject", "s3:PutObject"],
                    resource="*",
                ),
            ],
        )
        r = check_permission_equivalence(before, after, _tiny_catalog())
        assert r.ok

    def test_broadened_fewer_denies_fails(self) -> None:
        before = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["s3:GetObject", "s3:PutObject"],
                    resource="*",
                ),
            ],
        )
        after = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action="s3:GetObject", resource="*")],
        )
        r = check_permission_equivalence(before, after, _tiny_catalog())
        assert not r.ok
        assert any("s3:PutObject" in m for m in r.messages)

    def test_not_action_requires_catalog(self) -> None:
        doc = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    not_action=["s3:GetObject"],
                    resource="*",
                ),
            ],
        )
        r = check_permission_equivalence(doc, doc, ActionCatalog.empty())
        assert not r.ok
        assert any("NotAction" in m and "catalog" in m for m in r.messages)

    def test_not_action_same_ok_with_catalog(self) -> None:
        doc = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    not_action=["s3:GetObject"],
                    resource="*",
                ),
            ],
        )
        cat = _tiny_catalog()
        r = check_permission_equivalence(doc, doc, cat)
        assert r.ok

    def test_allow_carve_growth_fails(self) -> None:
        before = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(effect="Allow", action="s3:GetObject", resource="*"),
            ],
        )
        after = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Allow", action="*", resource="*")],
        )
        r = check_permission_equivalence(before, after, _tiny_catalog())
        assert not r.ok
        assert any("carve" in m.lower() for m in r.messages)

    def test_wildcard_subsumption_with_catalog(self) -> None:
        """After replaces explicit names with a catalog-backed wildcard that covers them."""
        before = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    resource="*",
                ),
            ],
        )
        after = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action="s3:*", resource="*")],
        )
        r = check_permission_equivalence(before, after, _tiny_catalog())
        assert r.ok

    def test_mixed_case_service_prefix_wildcard_expands(self) -> None:
        before = ScpDocument(
            version="2012-10-17",
            statement=[
                Statement(
                    effect="Deny",
                    action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    resource="*",
                ),
            ],
        )
        after = ScpDocument(
            version="2012-10-17",
            statement=[Statement(effect="Deny", action="S3:*", resource="*")],
        )
        r = check_permission_equivalence(before, after, _tiny_catalog())
        assert r.ok

    def test_explicit_actions_do_not_require_catalog_universe(self) -> None:
        class CatalogWithoutUniverse(ActionCatalog):
            def all_full_actions(self) -> frozenset[str]:
                msg = "catalog universe should not be requested"
                raise AssertionError(msg)

        catalog = CatalogWithoutUniverse.from_dict({"s3": ["GetObject"]})
        expanded = _expand_action_patterns_to_atoms(["s3:GetObject"], catalog)
        assert expanded == {"s3:GetObject"}

    def test_bare_star_loads_catalog_universe_lazily(self) -> None:
        class CountingCatalog(ActionCatalog):
            def __init__(self, data: dict[str, frozenset[str]]) -> None:
                super().__init__(data)
                self.calls = 0

            def all_full_actions(self) -> frozenset[str]:
                self.calls += 1
                return super().all_full_actions()

        catalog = CountingCatalog({"s3": frozenset({"GetObject"})})
        expanded = _expand_action_patterns_to_atoms(["*"], catalog)
        assert expanded == {"s3:GetObject"}
        assert catalog.calls == 1


class TestExamplesOptimizedEquivalence:
    @pytest.mark.parametrize(
        "name",
        ["bloated_deny", "data_protection", "region_lockdown", "security_guardrails"],
    )
    def test_example_passes_versus_default_optimize(self, name: str) -> None:
        path = EXAMPLES_DIR / f"{name}.json"
        cfg = OptimizerConfig.load(path)
        catalog = ActionCatalog.load(cfg.spec.catalog)
        doc = ScpDocument.from_file(str(path))
        result = optimize(doc, config=cfg)
        eq = check_permission_equivalence(doc, result.optimized, catalog)
        assert eq.ok, eq.messages


class TestOptimizeFixturesEquivalence:
    def test_mergeable_statements_fixture(self, fixtures_dir: Path) -> None:
        path = fixtures_dir / "mergeable_statements.json"
        cfg = OptimizerConfig.load(path)
        catalog = ActionCatalog.load(cfg.spec.catalog)
        doc = ScpDocument.from_file(str(path))
        result = optimize(doc, config=cfg)
        eq = check_permission_equivalence(doc, result.optimized, catalog)
        assert eq.ok, eq.messages


class TestCheckEquivalenceCli:
    def test_cli_ok_on_identical_files(self, fixtures_dir: Path, tmp_path: Path) -> None:
        src = fixtures_dir / "simple_deny.json"
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        shutil.copy2(src, a)
        shutil.copy2(src, b)
        result = runner.invoke(app, ["check-equivalence", str(a), str(b)])
        assert result.exit_code == 0

    def test_cli_fails_on_broadened_policy(self, tmp_path: Path) -> None:
        shutil.copy2(EXAMPLES_DIR / "scpz.yaml", tmp_path / "scpz.yaml")
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
        result = runner.invoke(app, ["check-equivalence", str(before), str(after)])
        assert result.exit_code == 1
        assert "PutObject" in result.stderr or "PutObject" in result.stdout
