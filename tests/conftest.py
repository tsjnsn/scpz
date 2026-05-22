"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from scpz.models import ScpDocument

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def simple_deny() -> ScpDocument:
    return ScpDocument.from_file(str(FIXTURES_DIR / "simple_deny.json"))


@pytest.fixture
def oversized() -> ScpDocument:
    return ScpDocument.from_file(str(FIXTURES_DIR / "oversized.json"))


@pytest.fixture
def mergeable() -> ScpDocument:
    return ScpDocument.from_file(str(FIXTURES_DIR / "mergeable_statements.json"))


@pytest.fixture
def complex_multi() -> ScpDocument:
    return ScpDocument.from_file(str(FIXTURES_DIR / "complex_multi.json"))


@pytest.fixture
def oversized_not_action_deny() -> ScpDocument:
    """Single Deny+NotAction statement whose minified JSON exceeds the SCP byte limit."""
    return ScpDocument.from_file(str(FIXTURES_DIR / "oversized_not_action_deny.json"))
