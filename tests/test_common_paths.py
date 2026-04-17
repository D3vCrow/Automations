"""Tests for tools._common.paths — repo-layout constants."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools._common.paths import (  # noqa: E402
    AUDITS_DIR,
    COMMON_DIR,
    PLANS_DIR,
    PORTABLE_DIR,
    REPO_ROOT,
    TESTS_DIR,
    TOOLS_DIR,
)


# ── Derivation sanity ────────────────────────────────────────────────

def test_repo_root_points_at_project_root():
    """REPO_ROOT matches the conftest-level project root."""
    assert REPO_ROOT == PROJECT_ROOT


def test_repo_root_contains_expected_markers():
    """CLAUDE.md and the tools package live at the repo root."""
    assert (REPO_ROOT / "CLAUDE.md").is_file()
    assert (REPO_ROOT / "tools").is_dir()


def test_all_constants_are_absolute_paths():
    """Every exported constant is an absolute Path (no relative leakage)."""
    for p in (
        AUDITS_DIR,
        COMMON_DIR,
        PLANS_DIR,
        PORTABLE_DIR,
        REPO_ROOT,
        TESTS_DIR,
        TOOLS_DIR,
    ):
        assert isinstance(p, Path)
        assert p.is_absolute()


def test_directory_relationships():
    """Nested constants resolve inside their parent constants."""
    assert TOOLS_DIR.parent == REPO_ROOT
    assert COMMON_DIR.parent == TOOLS_DIR
    assert TESTS_DIR.parent == REPO_ROOT
    assert PLANS_DIR.parent == REPO_ROOT
    assert AUDITS_DIR.parent == REPO_ROOT
    assert PORTABLE_DIR.parent == REPO_ROOT


def test_existing_dirs_are_present_on_disk():
    """Dirs we know exist today pass is_dir(). Plans/audits may be
    user-local, so we don't require them."""
    assert TOOLS_DIR.is_dir()
    assert COMMON_DIR.is_dir()
    assert TESTS_DIR.is_dir()
    assert PORTABLE_DIR.is_dir()
