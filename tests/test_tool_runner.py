"""Tests for the subprocess-based tool runner and AST discovery."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


# ── AST discovery tests ──────────────────────────────────────────────────────


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_discover_tools_extracts_name_and_docstring(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    # Import here so the log env var is picked up.
    from Main import discover_tools  # noqa: WPS433

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    _write(
        tools_dir / "sample.py",
        '"""First line is the description.\n\nMore detail here."""\n'
        "TOOL_NAME = 'Sample Tool'\n"
        "def run_tool():\n"
        "    pass\n",
    )

    tools, failures = discover_tools(tools_dir)
    assert failures == []
    assert len(tools) == 1
    t = tools[0]
    assert t["name"] == "Sample Tool"
    assert t["description"] == "First line is the description."
    assert t["filename"] == "sample.py"
    assert Path(t["path"]) == tools_dir / "sample.py"


def test_discover_tools_prefers_tool_desc_over_docstring(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    from Main import discover_tools

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    _write(
        tools_dir / "withdesc.py",
        '"""Docstring description."""\n'
        "TOOL_NAME = 'Named'\n"
        "TOOL_DESC = 'Explicit desc'\n"
        "def run_tool(): pass\n",
    )

    tools, _ = discover_tools(tools_dir)
    assert tools[0]["description"] == "Explicit desc"


def test_discover_tools_accepts_tool_description_alias(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    from Main import discover_tools

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    _write(
        tools_dir / "alias.py",
        "TOOL_NAME = 'Aliased'\n"
        "TOOL_DESCRIPTION = 'Long-form desc'\n"
        "def run_tool(): pass\n",
    )

    tools, _ = discover_tools(tools_dir)
    assert tools[0]["description"] == "Long-form desc"


def test_discover_tools_skips_underscore_files(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    from Main import discover_tools

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    _write(
        tools_dir / "_private.py",
        "TOOL_NAME = 'Should Skip'\ndef run_tool(): pass\n",
    )
    _write(
        tools_dir / "__init__.py",
        "",
    )

    tools, failures = discover_tools(tools_dir)
    assert tools == []
    assert failures == []


def test_discover_tools_reports_syntax_error(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    from Main import discover_tools

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    _write(tools_dir / "broken.py", "TOOL_NAME = 'X'\ndef run_tool(: pass\n")

    tools, failures = discover_tools(tools_dir)
    assert tools == []
    assert len(failures) == 1
    assert failures[0]["filename"] == "broken.py"
    assert "SyntaxError" in failures[0]["error"]


def test_discover_tools_does_not_execute_module(tmp_path, monkeypatch):
    """AST discovery must NOT run top-level code."""
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    from Main import discover_tools

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    marker = tmp_path / "marker.txt"
    _write(
        tools_dir / "sideeffect.py",
        "from pathlib import Path\n"
        f"Path(r'{marker}').write_text('side effect ran')\n"
        "TOOL_NAME = 'With side effect'\n"
        "def run_tool(): pass\n",
    )

    tools, _ = discover_tools(tools_dir)
    assert len(tools) == 1
    assert not marker.exists(), "AST discovery must not execute module code"


def test_discover_tools_skips_module_without_run_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "logs"))
    from Main import discover_tools

    tools_dir = tmp_path / "mytools"
    tools_dir.mkdir()
    _write(
        tools_dir / "helper.py",
        "TOOL_NAME = 'Helper'\ndef some_function(): pass\n",
    )

    tools, failures = discover_tools(tools_dir)
    assert tools == []
    assert failures == []


# ── _runner subprocess tests ─────────────────────────────────────────────────


def _run_runner(arg: str, cwd: Path) -> subprocess.CompletedProcess:
    """Invoke ``python -m tools._runner <arg>`` and return the result."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "tools._runner", arg],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture
def make_tool_file():
    """Create a .py file inside ``tools/`` for the test's duration.

    The runner's path-containment guard refuses paths outside ``tools/``, so
    subprocess tests that exercise the file-load branch must place their
    fixtures under ``tools/``. Files are underscore-prefixed so
    ``Main.discover_tools`` skips any stragglers if cleanup fails.
    """
    created: list[Path] = []
    tools_dir = PROJECT_ROOT / "tools"

    def _factory(body: str, name: str | None = None) -> Path:
        if name is None:
            name = f"_test_{uuid.uuid4().hex[:8]}.py"
        path = tools_dir / name
        path.write_text(body, encoding="utf-8")
        created.append(path)
        return path

    yield _factory

    for p in created:
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def test_runner_exits_with_usage_when_no_args():
    r = subprocess.run(
        [sys.executable, "-m", "tools._runner"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2
    assert "usage" in r.stderr.lower()


def test_runner_executes_run_tool_from_file_path(make_tool_file):
    tool_file = make_tool_file("def run_tool():\n    print('OK')\n")

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "OK"


def test_runner_reports_nonzero_on_tool_exception(make_tool_file):
    tool_file = make_tool_file(
        "def run_tool():\n    raise RuntimeError('boom')\n",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode != 0
    assert "RuntimeError" in r.stderr
    assert "boom" in r.stderr


def test_runner_propagates_sys_exit_code(make_tool_file):
    tool_file = make_tool_file(
        "import sys\n"
        "def run_tool():\n    sys.exit(7)\n",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 7


def test_runner_handles_spaces_in_filename(make_tool_file):
    """Runner must accept file paths containing spaces (e.g., NETWORK STABILITY MONITOR.py)."""
    tool_file = make_tool_file(
        "def run_tool():\n    print('spaced OK')\n",
        name="_test with spaces.py",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "spaced OK"


def test_runner_runs_module_without_run_tool(make_tool_file):
    """If a module has no run_tool(), the runner still exits 0 after import."""
    tool_file = make_tool_file("print('top level ran')\n")

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr
    assert "top level ran" in r.stdout


def test_runner_accepts_dotted_module_name():
    """When given a dotted name, the runner must import it via importlib."""
    # tools._common.logging exists and has no run_tool() — a safe import target.
    r = _run_runner("tools._common.logging", cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr


def test_runner_returns_exit_code_3_on_import_failure(make_tool_file):
    """Runner must return exit code 3 when a tool fails to import (e.g., syntax error)."""
    tool_file = make_tool_file("raise ImportError('broken module')\n")

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 3
    assert "ImportError" in r.stderr
    assert "broken module" in r.stderr


# ── Path-containment guard (A8) ──────────────────────────────────────────────


def test_runner_refuses_path_outside_tools_dir(tmp_path):
    """Runner must refuse to load a .py file that lives outside tools/."""
    outside = tmp_path / "outside_tool.py"
    outside.write_text(
        "def run_tool():\n    print('should not run')\n",
        encoding="utf-8",
    )

    r = _run_runner(str(outside), cwd=PROJECT_ROOT)
    assert r.returncode == 3
    assert "refusing to load" in r.stderr
    assert "should not run" not in r.stdout


def test_runner_refuses_nonexistent_py_path(tmp_path):
    """A .py path that does not exist must be rejected by the strict-resolve guard."""
    missing = tmp_path / "does_not_exist.py"

    r = _run_runner(str(missing), cwd=PROJECT_ROOT)
    assert r.returncode == 3
    stderr_lower = r.stderr.lower()
    assert (
        "filenotfounderror" in stderr_lower
        or "no such file" in stderr_lower
        or "cannot find the file" in stderr_lower
    )


def test_runner_refuses_symlink_escape_from_tools(tmp_path):
    """A symlink inside tools/ pointing outside must be refused after resolve()."""
    outside = tmp_path / "external_tool.py"
    outside.write_text(
        "def run_tool():\n    print('escaped!')\n",
        encoding="utf-8",
    )

    link = PROJECT_ROOT / "tools" / "_test_escape_link.py"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    try:
        r = _run_runner(str(link), cwd=PROJECT_ROOT)
        assert r.returncode == 3
        assert "refusing to load" in r.stderr
        assert "escaped!" not in r.stdout
    finally:
        try:
            link.unlink()
        except FileNotFoundError:
            pass
