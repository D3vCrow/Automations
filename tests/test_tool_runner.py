"""Tests for the subprocess-based tool runner and AST discovery."""

from __future__ import annotations

import os
import subprocess
import sys
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


def test_runner_exits_with_usage_when_no_args():
    r = subprocess.run(
        [sys.executable, "-m", "tools._runner"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2
    assert "usage" in r.stderr.lower()


def test_runner_executes_run_tool_from_file_path(tmp_path):
    tool_file = tmp_path / "test_tool.py"
    tool_file.write_text(
        "def run_tool():\n    print('OK')\n",
        encoding="utf-8",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "OK"


def test_runner_reports_nonzero_on_tool_exception(tmp_path):
    tool_file = tmp_path / "crashy.py"
    tool_file.write_text(
        "def run_tool():\n    raise RuntimeError('boom')\n",
        encoding="utf-8",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode != 0
    assert "RuntimeError" in r.stderr
    assert "boom" in r.stderr


def test_runner_propagates_sys_exit_code(tmp_path):
    tool_file = tmp_path / "exit_code.py"
    tool_file.write_text(
        "import sys\n"
        "def run_tool():\n    sys.exit(7)\n",
        encoding="utf-8",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 7


def test_runner_handles_spaces_in_filename(tmp_path):
    """Runner must accept file paths containing spaces (e.g., NETWORK STABILITY MONITOR.py)."""
    spaced_dir = tmp_path / "with spaces"
    spaced_dir.mkdir()
    tool_file = spaced_dir / "My Tool.py"
    tool_file.write_text(
        "def run_tool():\n    print('spaced OK')\n",
        encoding="utf-8",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "spaced OK"


def test_runner_runs_module_without_run_tool(tmp_path):
    """If a module has no run_tool(), the runner still exits 0 after import."""
    tool_file = tmp_path / "no_entry.py"
    tool_file.write_text(
        "print('top level ran')\n",
        encoding="utf-8",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr
    assert "top level ran" in r.stdout


def test_runner_accepts_dotted_module_name():
    """When given a dotted name, the runner must import it via importlib."""
    # tools._common.logging exists and has no run_tool() — a safe import target.
    r = _run_runner("tools._common.logging", cwd=PROJECT_ROOT)
    assert r.returncode == 0, r.stderr


def test_runner_returns_exit_code_3_on_import_failure(tmp_path):
    """Runner must return exit code 3 when a tool fails to import (e.g., syntax error)."""
    tool_file = tmp_path / "broken_import.py"
    tool_file.write_text(
        "raise ImportError('broken module')\n",
        encoding="utf-8",
    )

    r = _run_runner(str(tool_file), cwd=PROJECT_ROOT)
    assert r.returncode == 3
    assert "ImportError" in r.stderr
    assert "broken module" in r.stderr
