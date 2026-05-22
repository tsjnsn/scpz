"""Golden regression: optimize curated examples and NotAction fixtures, then assert equivalence.

Each input is run through ``optimize`` from ``scpz.optimizer`` with config discovered
via ``OptimizerConfig.load``, then ``check_permission_equivalence`` must report that the
optimized document did not broaden permissions versus the original.

This suite is intentionally **semantic** (equivalence), not byte-for-byte JSON
snapshots, so harmless formatting changes or catalog refreshes do not require
updating checked-in golden blobs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scpz.catalog import ActionCatalog
from scpz.config import OptimizerConfig
from scpz.equivalence import check_permission_equivalence
from scpz.models import ScpDocument
from scpz.optimizer import optimize

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

# NotAction-focused fixtures (conservative compression / catalog coverage — TSJ-5).
NOT_ACTION_REGRESSION_FILES = (
    "not_action_allowlist.json",
    "complex_multi.json",
)


def _example_json_paths() -> tuple[Path, ...]:
    return tuple(sorted(p for p in EXAMPLES_DIR.glob("*.json") if p.is_file()))


EXAMPLE_JSON_PATHS = _example_json_paths()


def test_example_corpus_is_non_empty() -> None:
    assert EXAMPLE_JSON_PATHS, f"expected at least one *.json under {EXAMPLES_DIR}"


@pytest.mark.parametrize("path", EXAMPLE_JSON_PATHS, ids=lambda p: p.stem)
def test_example_optimize_semantically_equivalent(path: Path) -> None:
    cfg = OptimizerConfig.load(path)
    catalog = ActionCatalog.load(cfg.spec.catalog)
    doc = ScpDocument.from_file(str(path))
    result = optimize(doc, config=cfg)
    eq = check_permission_equivalence(doc, result.optimized, catalog)
    assert eq.ok, eq.messages


@pytest.mark.parametrize(
    "path",
    [FIXTURES_DIR / name for name in NOT_ACTION_REGRESSION_FILES],
    ids=lambda p: p.name,
)
def test_not_action_fixture_optimize_semantically_equivalent(path: Path) -> None:
    assert path.is_file(), f"missing fixture: {path}"
    cfg = OptimizerConfig.load(path)
    catalog = ActionCatalog.load(cfg.spec.catalog)
    doc = ScpDocument.from_file(str(path))
    result = optimize(doc, config=cfg)
    eq = check_permission_equivalence(doc, result.optimized, catalog)
    assert eq.ok, eq.messages
