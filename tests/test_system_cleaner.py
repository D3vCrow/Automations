"""Tests for tools/system_cleaner.py safe-delete refactor (Plan A / Task A1).

Covers:
    * DRY_RUN does not touch disk.
    * Symlink entries at the top level are skipped, not followed.
    * Directory entries whose tree contains a nested symlink are
      refused entirely (stricter than rmtree's built-in stop-at-link).
    * Successful deletions emit a structured log line per outcome.
    * Missing %TEMP% env var resolves to a non-existent path that
      ``_delete_dir_contents`` handles gracefully (no crash, no deletes).

Tests use ``tmp_path`` exclusively -- never touch real user dirs.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.system_cleaner import (  # noqa: E402
    DeleteMode,
    _delete_dir_contents,
    _delete_glob_files,
    _tree_has_symlink,
    main,
)


# ---------- helpers ----------

def _silent_log(_msg: str) -> None:
    """Log callback that discards messages (test noise control)."""


def _make_sample_tree(root: Path) -> tuple[Path, Path]:
    """Populate ``root`` with one file and one nested directory of files.

    Returns ``(file, subdir)`` so callers can assert on them.
    """
    f = root / "a.txt"
    f.write_text("hello" * 100, encoding="utf-8")
    sub = root / "sub"
    sub.mkdir()
    (sub / "b.bin").write_bytes(b"\x00" * 1024)
    (sub / "c.log").write_text("log\n" * 50, encoding="utf-8")
    return f, sub


# ---------- (a) DRY_RUN does not touch disk ----------

def test_dry_run_reports_size_without_touching_disk(tmp_path):
    f, sub = _make_sample_tree(tmp_path)
    files_before = sorted(p.name for p in tmp_path.iterdir())
    sub_before = sorted(p.name for p in sub.iterdir())

    freed = _delete_dir_contents(str(tmp_path), _silent_log, DeleteMode.DRY_RUN)

    # Non-zero "would free" reported
    assert freed > 0, "DRY_RUN should report would-free bytes"

    # Disk untouched
    assert sorted(p.name for p in tmp_path.iterdir()) == files_before
    assert sub.is_dir()
    assert sorted(p.name for p in sub.iterdir()) == sub_before
    assert f.read_text(encoding="utf-8") == "hello" * 100


def test_dry_run_glob_does_not_delete(tmp_path):
    for n in ("x.tmp", "y.tmp", "z.tmp"):
        (tmp_path / n).write_bytes(b"12345")
    pattern = str(tmp_path / "*.tmp")

    freed = _delete_glob_files(pattern, _silent_log, DeleteMode.DRY_RUN)

    assert freed == 15, "DRY_RUN should report sum of file sizes"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.tmp", "y.tmp", "z.tmp"]


# ---------- (b) symlink is skipped, not followed ----------

def test_symlink_entry_is_skipped_not_followed(tmp_path):
    """Symlinks inside the target dir must never be traversed or deleted."""
    # Isolated "outside" tree whose contents we must NOT touch.
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "precious.txt"
    protected.write_text("do-not-delete", encoding="utf-8")

    # Target dir with one real file plus a symlink pointing at 'outside'.
    target = tmp_path / "target"
    target.mkdir()
    (target / "real.txt").write_text("ok", encoding="utf-8")
    link = target / "link_to_outside"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation not permitted in this env: {exc}")

    # Run PERMANENT mode so there is no send2trash dependency in the test.
    freed = _delete_dir_contents(str(target), _silent_log, DeleteMode.PERMANENT)

    # The real file was deleted; the symlink and its target are untouched.
    assert not (target / "real.txt").exists(), "real file should be deleted"
    assert link.exists() or link.is_symlink(), "symlink should be preserved"
    assert outside.is_dir(), "symlink target directory must not be followed"
    assert protected.exists(), "file referenced via symlink must NOT be deleted"
    assert protected.read_text(encoding="utf-8") == "do-not-delete"
    # The reported 'freed' must only account for the real file, not outside content.
    assert freed == len("ok")


# ---------- (c) %TEMP% unset fallback ----------

def test_temp_unset_falls_back_gracefully(tmp_path, monkeypatch):
    """A path that resolves to a non-existent location returns 0 without crashing.

    Emulates ``%TEMP%`` being unset: ``os.path.expandvars('%TEMP%')`` yields
    the literal string '%TEMP%' which is not a directory. The helper must
    log and return 0 cleanly.
    """
    monkeypatch.delenv("TEMP", raising=False)
    monkeypatch.delenv("TMP", raising=False)
    unresolved = os.path.expandvars("%TEMP%")  # typically stays '%TEMP%' when unset
    # Defensive: if the test runner's OS expands to something else, force a missing dir.
    if os.path.isdir(unresolved):
        unresolved = str(tmp_path / "does_not_exist")

    messages: list[str] = []

    def capture(msg: str) -> None:
        messages.append(msg)

    freed = _delete_dir_contents(unresolved, capture, DeleteMode.DRY_RUN)

    assert freed == 0
    assert any("Not found" in m for m in messages), messages


# ---------- (d) CLI safeguards ----------

def test_permanent_without_yes_exits_2(capsys):
    """--permanent without --yes exits with code 2 and error message."""
    exit_code = main(argv=["--permanent"])
    assert exit_code == 2
    _, stderr = capsys.readouterr()
    assert "requires --yes" in stderr


def test_permanent_without_categories_exits_2(capsys):
    """--permanent without --categories exits with code 2 and error message."""
    exit_code = main(argv=["--permanent", "--yes"])
    assert exit_code == 2
    _, stderr = capsys.readouterr()
    assert "requires --categories" in stderr


# ---------- (e) nested-symlink refusal ----------

def test_nested_symlink_refuses_whole_directory(tmp_path, capsys):
    """A dir entry whose tree contains a symlink must be refused entirely.

    Stricter than rmtree's "stop at the link" — we refuse the whole
    directory and emit a ``symlink_in_tree_refused`` structured log so
    ops can audit the refusal.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "precious.txt"
    protected.write_text("do-not-delete", encoding="utf-8")

    target = tmp_path / "target"
    target.mkdir()
    # Directory entry with a NESTED symlink (not the top entry itself)
    nested = target / "nested"
    nested.mkdir()
    (nested / "plain.txt").write_text("would-be-deleted", encoding="utf-8")
    link = nested / "link_inside"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation not permitted in this env: {exc}")

    freed = _delete_dir_contents(str(target), _silent_log, DeleteMode.PERMANENT)

    # The whole nested dir was refused -> nothing inside it was deleted.
    assert nested.is_dir(), "refused directory must remain"
    assert (nested / "plain.txt").exists(), "sibling of symlink must not be deleted"
    assert link.is_symlink(), "symlink must remain"
    assert protected.exists() and protected.read_text(encoding="utf-8") == "do-not-delete"
    assert freed == 0, "nothing should have been freed"

    _, stderr = capsys.readouterr()
    refusal_events = [
        line for line in stderr.splitlines()
        if line.strip().startswith("{") and '"symlink_in_tree_refused"' in line
    ]
    assert refusal_events, f"expected symlink_in_tree_refused log, got: {stderr!r}"
    payload = json.loads(refusal_events[0])
    assert payload["event"] == "symlink_in_tree_refused"
    assert Path(payload["path"]).name == "nested"
    assert Path(payload["symlink"]).name == "link_inside"


def test_tree_has_symlink_returns_offender(tmp_path):
    """Unit test for the pre-walk helper: returns first symlink path, None otherwise."""
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.txt").write_text("x", encoding="utf-8")
    assert _tree_has_symlink(str(clean)) is None

    dirty = tmp_path / "dirty"
    dirty.mkdir()
    sub = dirty / "sub"
    sub.mkdir()
    link = sub / "ln"
    try:
        link.symlink_to(clean, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation not permitted in this env: {exc}")

    offender = _tree_has_symlink(str(dirty))
    assert offender is not None
    assert Path(offender).name == "ln"


# ---------- (f) structured success log ----------

def test_permanent_delete_emits_structured_success_log(tmp_path, capsys):
    """Each successful PERMANENT delete emits a ``permanent_deleted`` line
    with path + byte count so operators can audit what a run actually touched."""
    (tmp_path / "a.txt").write_bytes(b"1234567890")
    freed = _delete_dir_contents(str(tmp_path), _silent_log, DeleteMode.PERMANENT)
    assert freed == 10

    _, stderr = capsys.readouterr()
    events = [
        json.loads(line) for line in stderr.splitlines()
        if line.strip().startswith("{") and '"permanent_deleted"' in line
    ]
    assert events, f"expected permanent_deleted log, got: {stderr!r}"
    assert events[0]["event"] == "permanent_deleted"
    assert Path(events[0]["path"]).name == "a.txt"
    assert events[0]["bytes"] == 10
