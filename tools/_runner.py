"""Subprocess entry point for tool launches.

Invoked by ``Main.py`` as::

    python -m tools._runner <module-or-path>

The argument can be either:

* A dotted module path (e.g. ``tools.decision_dice``) — imported via
  ``importlib.import_module``.
* A filesystem path to a ``.py`` file — loaded via
  ``importlib.util.spec_from_file_location``. This path is useful for
  tool filenames that are not valid Python identifiers (e.g. files
  containing spaces).

Behavior:

* If the loaded module defines ``run_tool()``, it is called.
* Otherwise, the module's top-level code is considered its entry point
  (it already ran during import).
* After ``run_tool()`` returns, if a Tk default root exists with visible
  windows, the runner enters ``mainloop()`` and exits when the last
  window is closed. This lets tools written for the embedded pattern
  (create Toplevel, return, rely on launcher's mainloop) also work as
  standalone subprocesses without modification.

Exit codes:

* ``0`` — normal completion.
* ``1`` — the tool raised an unhandled exception at runtime. The traceback is
  written to stderr so the launcher's reader thread captures it.
* ``2`` — argument error (missing or invalid module/path).
* ``3`` — the tool failed to load (import or syntax error). The traceback is
  written to stderr so the launcher's reader thread captures it.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import traceback
from pathlib import Path
from types import ModuleType
from typing import Optional


TOOLS_DIR = Path(__file__).resolve().parent


def _validate_under_tools(path: Path) -> Path:
    """Resolve *path* and ensure it lives under ``tools/``.

    Collapses symlinks and ``..`` segments via ``resolve(strict=True)`` so that
    a symlink inside ``tools/`` pointing outside is refused alongside a plain
    external path.

    Args:
        path: The candidate path (absolute or relative).

    Returns:
        The resolved absolute path, guaranteed to be under ``tools/``.

    Raises:
        FileNotFoundError: If *path* does not exist.
        PermissionError: If the resolved path is outside ``tools/``.
    """
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(TOOLS_DIR):
        raise PermissionError(
            f"refusing to load {resolved}: outside {TOOLS_DIR}"
        )
    return resolved


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
    """Load *target* as either a dotted module name or a file path.

    File-path targets are gated by :func:`_validate_under_tools` so that the
    runner refuses to execute arbitrary ``.py`` files from outside ``tools/``.
    """
    path_candidate = Path(target)
    if path_candidate.suffix == ".py" or path_candidate.exists():
        safe_path = _validate_under_tools(path_candidate)
        return _load_by_path(safe_path)
    return importlib.import_module(target)


def _apply_ctk_theme() -> None:
    """Match the launcher's appearance so subprocess windows render dark.

    Safe no-op when customtkinter is not installed.
    """
    try:
        import customtkinter as ctk  # noqa: WPS433
    except Exception:
        return
    try:
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
    except Exception:
        # Theming is cosmetic — never fail the launch on this.
        pass


def _ensure_hidden_root() -> None:
    """Pre-create a withdrawn root so CTkToplevel tools don't spawn a visible blank window.

    When ``CTkToplevel()`` is instantiated and ``tk._default_root`` is ``None``,
    tkinter auto-creates a plain ``Tk()`` root that appears as a blank window.
    By pre-creating a withdrawn ``CTk`` root here, ``CTkToplevel`` attaches to it
    and no blank window appears.

    Side-effect: tools like ``network_stability_monitor`` that only call
    ``mainloop()`` when ``tk._default_root is None`` will skip their own
    ``mainloop()`` call, letting ``_wait_for_gui()`` manage the event loop.
    """
    try:
        import tkinter as tk  # noqa: WPS433
        if tk._default_root is not None:
            return
    except Exception:
        return
    try:
        import customtkinter as ctk  # noqa: WPS433
        root = ctk.CTk()
        root.withdraw()
    except Exception:
        try:
            import tkinter as tk  # noqa: WPS433
            root = tk.Tk()
            root.withdraw()
        except Exception:
            pass


def _wait_for_gui() -> None:
    """If the tool created Tk windows but didn't enter mainloop, do it here.

    Most tools' ``run_tool()`` was written assuming the launcher is already
    running ``mainloop()``: they create a ``CTk``/``CTkToplevel``, wire
    callbacks, and return. As subprocesses they have no enclosing loop,
    so the process would exit immediately and the window would vanish.
    This helper drives the loop until every visible window is closed.

    Detection rules:

    * Skip entirely if no ``tk._default_root`` exists or it has no
      child widgets (CLI-style tool that only imported tkinter).
    * Otherwise enter ``mainloop()`` and poll for live windows.
    * Quit only after first observing at least one visible window —
      avoids racing the initial map (the root is briefly ``withdrawn``
      until the event loop processes geometry events).
    """
    try:
        import tkinter as tk  # noqa: WPS433
    except Exception:
        return

    root = tk._default_root
    if root is None:
        return

    try:
        has_children = bool(root.winfo_children())
    except tk.TclError:
        has_children = False
    if not has_children:
        return  # Tool imported tk but never built UI.

    # Tools that use CTkToplevel leave an invisible CTk root as a container.
    # Withdraw it now so it doesn't appear as a blank extra window.
    # (Tools that use CTk() directly as their main window won't have Toplevel
    # children yet at this point, so they are unaffected.)
    try:
        if any(isinstance(w, tk.Toplevel) for w in root.winfo_children()):
            root.withdraw()
    except tk.TclError:
        pass

    def _has_active_window() -> bool:
        try:
            if not root.winfo_exists():
                return False
        except tk.TclError:
            return False
        # Visible root window counts (CTk/Tk-style tools).
        try:
            if root.state() != "withdrawn":
                return True
        except tk.TclError:
            pass
        # Otherwise count Toplevels (embedded-tool pattern).
        try:
            for w in root.winfo_children():
                if isinstance(w, tk.Toplevel):
                    try:
                        if w.winfo_exists():
                            return True
                    except tk.TclError:
                        continue
        except tk.TclError:
            pass
        return False

    armed = {"flag": False}

    def _watchdog() -> None:
        if _has_active_window():
            armed["flag"] = True
        elif armed["flag"]:
            # We saw a window earlier, now they're all gone — exit.
            try:
                root.quit()
            except Exception:
                pass
            return
        # Not yet seen any window — keep waiting (window may still be mapping).
        try:
            root.after(500, _watchdog)
        except tk.TclError:
            pass

    try:
        root.after(500, _watchdog)
        root.mainloop()
    finally:
        try:
            if root.winfo_exists():
                root.destroy()
        except Exception:
            pass


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point. Returns an exit code.

    Args:
        argv: Command-line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (0=success, 1=runtime error, 2=arg error, 3=import error).
    """
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m tools._runner <module-or-path>", file=sys.stderr)
        return 2

    target = args[0]
    _apply_ctk_theme()
    _ensure_hidden_root()

    try:
        module = _load(target)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return 3

    run_tool = getattr(module, "run_tool", None)
    if callable(run_tool):
        try:
            run_tool()
        except SystemExit:
            raise
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return 1

    _wait_for_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
