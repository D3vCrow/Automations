"""Subprocess entry point for tool launches.

Invoked by ``Main.py`` as::

    python -m tools._runner <module-or-path>

The argument can be either:

* A dotted module path (e.g. ``tools.decision_dice``) — imported via
  ``importlib.import_module``.
* A filesystem path to a ``.py`` file — loaded via
  ``importlib.util.spec_from_file_location``. This path is required
  for tool filenames that are not valid Python identifiers (e.g.
  ``NETWORK STABILITY MONITOR.py`` contains spaces).

Behavior:

* If the loaded module defines ``run_tool()``, it is called.
* Otherwise, the module's top-level code is considered its entry point
  (it already ran during import).

Exit codes:

* ``0`` — normal completion.
* ``1`` — the tool raised an unhandled exception. The traceback is
  written to stderr so the launcher's reader thread captures it.
* ``2`` — argument error (missing or invalid module/path).
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import traceback
from pathlib import Path
from types import ModuleType
from typing import Optional


def _load_by_path(path: Path) -> ModuleType:
    """Load a module from an explicit file path.

    Args:
        path: Absolute or relative path to a ``.py`` file.

    Returns:
        The loaded module.

    Raises:
        ImportError: If the spec or loader cannot be built.
    """
    mod_name = path.stem.replace(" ", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot build module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules so imports inside the tool resolve correctly.
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def _load(target: str) -> ModuleType:
    """Load *target* as either a dotted module name or a file path."""
    path_candidate = Path(target)
    if path_candidate.suffix == ".py" or path_candidate.exists():
        return _load_by_path(path_candidate)
    return importlib.import_module(target)


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point. Returns an exit code.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m tools._runner <module-or-path>", file=sys.stderr)
        return 2

    target = args[0]
    try:
        module = _load(target)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return 1

    run_tool = getattr(module, "run_tool", None)
    if callable(run_tool):
        try:
            run_tool()
        except SystemExit:
            raise
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
