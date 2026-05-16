"""Tests for scpeasy.catalog.ActionCatalog."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from scpeasy.catalog import ActionCatalog
from scpeasy.config import CatalogConfig

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _mini_catalog() -> ActionCatalog:
    """A small deterministic catalog for unit tests."""
    return ActionCatalog.from_dict(
        {
            "iam": [
                "DeleteRole",
                "DeleteRolePermissionsBoundary",
                "DeleteRolePolicy",
                "DeleteUser",
                "DeleteUserPermissionsBoundary",
                "DeleteUserPolicy",
                "GetRole",
                "GetUser",
            ],
            "s3": [
                "GetObject",
                "GetObjectAcl",
                "GetObjectTagging",
                "PutObject",
                "PutObjectAcl",
            ],
        }
    )


# ── ActionCatalog.empty ───────────────────────────────────────────────────────


class TestEmptyCatalog:
    def test_is_empty(self) -> None:
        assert ActionCatalog.empty().is_empty()

    def test_covers_always_false(self) -> None:
        cat = ActionCatalog.empty()
        assert not cat.covers("iam", "Delete", frozenset(["DeleteRole", "DeleteUser"]))

    def test_get_service_returns_empty_frozenset(self) -> None:
        assert ActionCatalog.empty().get_service("iam") == frozenset()


# ── ActionCatalog.covers ──────────────────────────────────────────────────────


class TestCovers:
    def test_full_coverage_returns_true(self) -> None:
        """All Delete* actions in catalog are present → safe to wildcard."""
        cat = _mini_catalog()
        candidate = frozenset(
            [
                "DeleteRole",
                "DeleteRolePermissionsBoundary",
                "DeleteRolePolicy",
                "DeleteUser",
                "DeleteUserPermissionsBoundary",
                "DeleteUserPolicy",
            ]
        )
        assert cat.covers("iam", "Delete", candidate)

    def test_partial_coverage_returns_false(self) -> None:
        """Only some Delete* actions present → wildcard would add scope."""
        cat = _mini_catalog()
        candidate = frozenset(["DeleteRole", "DeleteUser"])
        assert not cat.covers("iam", "Delete", candidate)

    def test_unknown_service_returns_false(self) -> None:
        """Service not in catalog → cannot confirm coverage."""
        cat = _mini_catalog()
        assert not cat.covers("guardduty", "Delete", frozenset(["DeleteDetector"]))

    def test_unknown_verb_returns_false(self) -> None:
        """Verb that has no catalog entries → False (can't confirm safety)."""
        cat = _mini_catalog()
        # "Create" has no entries in the mini catalog
        assert not cat.covers("iam", "Create", frozenset(["CreateRole"]))

    def test_superset_candidate_still_true(self) -> None:
        """Candidate may contain extra actions beyond the verb — still covered."""
        cat = _mini_catalog()
        candidate = frozenset(
            [
                "DeleteRole",
                "DeleteRolePermissionsBoundary",
                "DeleteRolePolicy",
                "DeleteUser",
                "DeleteUserPermissionsBoundary",
                "DeleteUserPolicy",
                "GetRole",  # extra — irrelevant to Delete coverage
            ]
        )
        assert cat.covers("iam", "Delete", candidate)

    def test_get_verb_full_coverage(self) -> None:
        cat = _mini_catalog()
        candidate = frozenset(["GetRole", "GetUser"])
        assert cat.covers("iam", "Get", candidate)

    def test_s3_get_partial(self) -> None:
        cat = _mini_catalog()
        candidate = frozenset(["GetObject"])  # missing GetObjectAcl, GetObjectTagging
        assert not cat.covers("s3", "Get", candidate)

    def test_s3_get_full(self) -> None:
        cat = _mini_catalog()
        candidate = frozenset(["GetObject", "GetObjectAcl", "GetObjectTagging"])
        assert cat.covers("s3", "Get", candidate)

    def test_empty_candidate_returns_false(self) -> None:
        cat = _mini_catalog()
        assert not cat.covers("iam", "Delete", frozenset())


# ── ActionCatalog.from_file / load ────────────────────────────────────────────


class TestLoadFromFile:
    def test_round_trip(self) -> None:
        """Write catalog to a temp file and load it back correctly."""
        raw = {"iam": ["DeleteRole", "GetRole"], "s3": ["GetObject"]}
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump(raw, f)
            tmp_path = Path(f.name)

        try:
            cat = ActionCatalog.from_file(tmp_path)
            assert cat.get_service("iam") == frozenset(["DeleteRole", "GetRole"])
            assert cat.get_service("s3") == frozenset(["GetObject"])
        finally:
            tmp_path.unlink()

    def test_load_with_file_source(self) -> None:
        raw = {"ec2": ["DescribeInstances", "RunInstances"]}
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump(raw, f)
            tmp_path = Path(f.name)

        try:
            cfg = CatalogConfig(source="file", path=tmp_path)
            cat = ActionCatalog.load(cfg)
            assert cat.get_service("ec2") == frozenset(["DescribeInstances", "RunInstances"])
        finally:
            tmp_path.unlink()

    def test_file_source_requires_path(self) -> None:
        with pytest.raises(ValueError, match="path is required"):
            CatalogConfig(source="file", path=None)


# ── source: none ──────────────────────────────────────────────────────────────


class TestSourceNone:
    def test_load_none_returns_empty(self) -> None:
        cfg = CatalogConfig(source="none")
        cat = ActionCatalog.load(cfg)
        assert cat.is_empty()

    def test_none_covers_always_false(self) -> None:
        cfg = CatalogConfig(source="none")
        cat = ActionCatalog.load(cfg)
        assert not cat.covers("iam", "Delete", frozenset(["DeleteRole"]))


# ── source: bundled ───────────────────────────────────────────────────────────


class TestBundledCatalog:
    def test_bundled_loads_without_error(self) -> None:
        cat = ActionCatalog.bundled()
        assert not cat.is_empty()

    def test_bundled_contains_iam(self) -> None:
        cat = ActionCatalog.bundled()
        iam_actions = cat.get_service("iam")
        assert len(iam_actions) > 50

    def test_bundled_iam_has_delete_role(self) -> None:
        cat = ActionCatalog.bundled()
        assert "DeleteRole" in cat.get_service("iam")

    def test_bundled_s3_has_get_object(self) -> None:
        cat = ActionCatalog.bundled()
        assert "GetObject" in cat.get_service("s3")

    def test_load_default_config_returns_bundled(self) -> None:
        cfg = CatalogConfig()  # default: source="bundled"
        cat = ActionCatalog.load(cfg)
        assert not cat.is_empty()
