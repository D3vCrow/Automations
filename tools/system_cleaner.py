# -*- coding: utf-8 -*-
"""
system_cleaner.py
─────────────────
System Resource Cleaner Pro

Safely frees disk space and optimises RAM.
- Preview sizes before deleting anything
- Checkbox selection per category
- Live log with bytes freed
- RAM working-set trim + standby memory purge
- Explorer restart to free leaked RAM & unlock caches
- System uptime warning for long-running sessions

Dependencies (already in venv): customtkinter, psutil
"""

import argparse
import ctypes
import ctypes.wintypes
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import timedelta
from enum import Enum
from pathlib import Path
from tkinter import messagebox
from typing import Callable, List, Optional

import customtkinter as ctk
import psutil

try:  # send2trash is the default (safe) delete path; optional at import time
    from send2trash import send2trash as _send2trash  # type: ignore
    _HAS_SEND2TRASH = True
except ImportError:
    _send2trash = None  # type: ignore
    _HAS_SEND2TRASH = False

from tools._common.exceptions import narrow_excepts
from tools._common.logging import get_logger

# ──────────────────────────────────────────────
TOOL_NAME = "System Cleaner Pro"
TOOL_DESC = "Safely free disk space and optimise RAM — preview sizes before deleting"
log = get_logger(__name__)

_CREATE_NO_WINDOW = 0x08000000


# ──────────────────────────────────────────────
# Deletion mode
# ──────────────────────────────────────────────
class DeleteMode(Enum):
    """Controls how `_delete_dir_contents` and `_delete_glob_files` touch disk.

    Attributes:
        DRY_RUN: Accumulate size only; do not touch disk.
        TRASH: Move entries to the OS recycle bin via send2trash (default).
        PERMANENT: Unlink/rmtree with narrow error handling (legacy behavior).
    """

    DRY_RUN = "dry_run"
    TRASH = "trash"
    PERMANENT = "permanent"


DEFAULT_DELETE_MODE = DeleteMode.TRASH


def _log_struct(event: str, **fields) -> None:
    """Emit a structured JSON log line to stderr (pre-A4 shared logger)."""
    try:
        payload = {"event": event, **fields}
        print(json.dumps(payload, default=str), file=sys.stderr)
    except (OSError, TypeError, ValueError):
        # Never let logging raise.
        pass


def _tree_has_symlink(root_path: str) -> Optional[str]:
    """Return the first symlink found anywhere under ``root_path``, or None.

    Uses ``os.walk(followlinks=False)`` so the walk never crosses a symlink.
    We check both directory and file entries at every level because a
    symlink that points outside ``root_path`` would otherwise allow an
    ``rmtree``/``send2trash`` call to affect state beyond the intended
    target. Returns the absolute path of the first offender for logging.
    """
    try:
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    return full
    except OSError:
        pass
    return None


# ──────────────────────────────────────────────
# ctypes struct for Recycle Bin query
# ──────────────────────────────────────────────
class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize",      ctypes.c_ulong),
        ("i64Size",     ctypes.c_longlong),
        ("i64NumItems", ctypes.c_longlong),
    ]


# ──────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────
@narrow_excepts(AttributeError, OSError, default=False)
def is_admin() -> bool:
    """Return True when the current process has Windows admin rights.

    Caught: ``AttributeError`` (``ctypes.windll`` absent on non-Windows),
    ``OSError`` (shell32 call failure).
    """
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def format_size(n: int) -> str:
    if n <= 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def _dir_size(path: str) -> int:
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _delete_dir_contents(
    path: str,
    log_cb: Callable[[str], None],
    mode: DeleteMode = DEFAULT_DELETE_MODE,
) -> int:
    """Delete everything inside ``path`` (not the folder itself).

    Symlink-at-top entries are skipped (never followed). Directory entries
    are additionally tree-walked via ``os.walk(followlinks=False)`` and
    **refused entirely** if any symlink is present anywhere below — this
    is stricter than ``rmtree``'s built-in "stop at the link" behavior and
    emits a structured ``symlink_in_tree_refused`` log entry.

    Behavior branches on ``mode``:

    * ``DRY_RUN``  — accumulate size only, do not touch disk.
    * ``TRASH``    — move each entry to the recycle bin via ``send2trash``.
    * ``PERMANENT`` — unlink/rmtree with narrow per-entry error handling.

    Args:
        path: Absolute directory whose contents should be removed.
        log_cb: Callback that receives human-readable status lines.
        mode: Delete strategy (see :class:`DeleteMode`).

    Returns:
        Total bytes "freed" (in DRY_RUN, bytes that *would* be freed).
    """
    if not path or not os.path.isdir(path):
        log_cb(f"  Not found: {path}")
        return 0

    if mode is DeleteMode.TRASH and not _HAS_SEND2TRASH:
        log_cb("  send2trash not installed -- nothing deleted (install: pip install send2trash)")
        _log_struct("send2trash_missing", path=path)
        return 0

    freed = 0
    skipped = 0
    try:
        entries = os.listdir(path)
    except OSError as exc:
        log_cb(f"  Error listing {path}: {exc}")
        _log_struct("listdir_failed", path=path, errno=getattr(exc, "errno", None), error=str(exc))
        return 0

    for entry in entries:
        full = os.path.join(path, entry)

        # Symlink safety: never follow, never delete.
        if os.path.islink(full):
            log_cb(f"  Skipped symlink: {entry}")
            _log_struct("symlink_skipped", path=full)
            continue

        try:
            size = _dir_size(full) if os.path.isdir(full) else os.path.getsize(full)
        except OSError as exc:
            skipped += 1
            _log_struct("stat_failed", path=full, errno=getattr(exc, "errno", None))
            continue

        if mode is DeleteMode.DRY_RUN:
            freed += size
            continue

        # Refuse to touch any directory entry whose tree contains a symlink.
        # rmtree/send2trash stop at the link itself, but pre-refusal gives a
        # louder, auditable signal and matches the Plan A/A1 stance.
        if os.path.isdir(full):
            offender = _tree_has_symlink(full)
            if offender is not None:
                skipped += 1
                log_cb(f"  Refused (symlink inside tree): {entry}")
                _log_struct("symlink_in_tree_refused", path=full, symlink=offender)
                continue

        if mode is DeleteMode.TRASH:
            try:
                _send2trash(full)
                freed += size
                _log_struct("trashed", path=full, bytes=size)
            except OSError as exc:  # send2trash.TrashPermissionError subclasses OSError
                skipped += 1
                _log_struct(
                    "trash_failed",
                    path=full,
                    error=str(exc),
                    errno=getattr(exc, "errno", None),
                )
            continue

        # PERMANENT
        try:
            if os.path.isdir(full):
                shutil.rmtree(full)
            else:
                os.remove(full)
            freed += size
            _log_struct("permanent_deleted", path=full, bytes=size)
        except (OSError, PermissionError) as exc:
            skipped += 1
            _log_struct(
                "permanent_delete_failed",
                path=full,
                errno=getattr(exc, "errno", None),
                error=str(exc),
            )

    if skipped:
        log_cb(f"  Skipped {skipped} locked/protected entry(ies)")
    return freed


def _delete_glob_files(
    pattern: str,
    log_cb: Callable[[str], None],
    mode: DeleteMode = DEFAULT_DELETE_MODE,
) -> int:
    """Delete files matching ``pattern`` (symlinks skipped).

    Args:
        pattern: Glob pattern expanded via :mod:`glob`.
        log_cb: Callback for human-readable status lines.
        mode: See :class:`DeleteMode`.

    Returns:
        Total bytes freed (or that would be freed in DRY_RUN).
    """
    if mode is DeleteMode.TRASH and not _HAS_SEND2TRASH:
        log_cb("  send2trash not installed -- nothing deleted (install: pip install send2trash)")
        _log_struct("send2trash_missing", pattern=pattern)
        return 0

    freed = 0
    skipped = 0
    for fp in glob.glob(pattern):
        if os.path.islink(fp):
            log_cb(f"  Skipped symlink: {os.path.basename(fp)}")
            _log_struct("symlink_skipped", path=fp)
            continue
        try:
            size = os.path.getsize(fp)
        except OSError as exc:
            skipped += 1
            _log_struct("stat_failed", path=fp, errno=getattr(exc, "errno", None))
            continue

        if mode is DeleteMode.DRY_RUN:
            freed += size
            continue

        if mode is DeleteMode.TRASH:
            try:
                _send2trash(fp)
                freed += size
                _log_struct("trashed", path=fp, bytes=size)
            except OSError as exc:  # send2trash.TrashPermissionError subclasses OSError
                skipped += 1
                _log_struct(
                    "trash_failed",
                    path=fp,
                    error=str(exc),
                    errno=getattr(exc, "errno", None),
                )
            continue

        # PERMANENT
        try:
            os.remove(fp)
            freed += size
            _log_struct("permanent_deleted", path=fp, bytes=size)
        except (OSError, PermissionError) as exc:
            skipped += 1
            _log_struct(
                "permanent_delete_failed",
                path=fp,
                errno=getattr(exc, "errno", None),
                error=str(exc),
            )

    if skipped:
        log_cb(f"  Skipped {skipped} locked file(s)")
    return freed


def _resolve_firefox_cache_paths() -> list:
    pattern = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles\*\cache2")
    return glob.glob(pattern)


def _query_recycle_bin_size() -> int:
    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
    try:
        ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        return max(0, info.i64Size)
    except (AttributeError, OSError):
        # AttributeError: ctypes.windll missing on non-Windows. OSError: shell32 call failure.
        return 0


@narrow_excepts(psutil.Error, OSError, default=timedelta(0))
def _get_system_uptime() -> timedelta:
    """Return system uptime as a timedelta.

    Caught: ``psutil.Error`` (boot_time unavailable), ``OSError`` (clock read
    failure). Returns ``timedelta(0)`` on failure so callers can still render.
    """
    boot = psutil.boot_time()
    return timedelta(seconds=time.time() - boot)


def _format_uptime(td: timedelta) -> str:
    total_secs = int(td.total_seconds())
    days  = total_secs // 86400
    hours = (total_secs % 86400) // 3600
    mins  = (total_secs % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    if hours > 0:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def _resolve_gpu_shader_paths() -> list:
    """Return list of existing GPU shader cache directories."""
    candidates = [
        # NVIDIA
        os.path.expandvars(r"%LOCALAPPDATA%\NVIDIA\DXCache"),
        os.path.expandvars(r"%LOCALAPPDATA%\NVIDIA\GLCache"),
        os.path.expandvars(r"%LOCALAPPDATA%\NVIDIA Corporation\NV_Cache"),
        # AMD
        os.path.expandvars(r"%LOCALAPPDATA%\AMD\DxCache"),
        os.path.expandvars(r"%LOCALAPPDATA%\AMD\GLCache"),
        # Intel
        os.path.expandvars(r"%LOCALAPPDATA%\Intel\ShaderCache"),
        # D3D pipeline cache (common)
        os.path.expandvars(r"%LOCALAPPDATA%\D3DSCache"),
    ]
    return [p for p in candidates if os.path.isdir(p)]


@narrow_excepts(AttributeError, OSError, default=False)
def _enable_privilege(privilege_name: str) -> bool:
    """Enable a Windows privilege (e.g. SeProfileSingleProcessPrivilege). Needs admin.

    Caught: ``AttributeError`` (``ctypes.windll`` absent on non-Windows),
    ``OSError`` (advapi32/kernel32 call failure). Returns ``False`` on failure.
    """
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.wintypes.DWORD),
                    ("HighPart", ctypes.wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID),
                    ("Attributes", ctypes.wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    token = ctypes.wintypes.HANDLE()
    advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    )

    luid = LUID()
    advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid))

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    kernel32.CloseHandle(token)
    return True


# ──────────────────────────────────────────────
# Category definitions
# ──────────────────────────────────────────────
CATEGORIES = [
    # ── Temp & Junk ──
    {
        "key":     "user_temp",
        "label":   "User TEMP Folder",
        "path":    os.path.expandvars("%TEMP%"),
        "type":    "dir_contents",
        "admin":   False,
        "desc":    "Temporary files created by apps and Windows",
        "section": "Temp & Junk Files",
    },
    {
        "key":     "win_temp",
        "label":   "Windows TEMP",
        "path":    os.path.expandvars(r"%SystemRoot%\Temp"),
        "type":    "dir_contents",
        "admin":   True,
        "desc":    "System-wide temp files -- requires Administrator",
        "section": None,
    },
    {
        "key":     "recycle_bin",
        "label":   "Recycle Bin",
        "path":    None,
        "type":    "recycle_bin",
        "admin":   False,
        "desc":    "Empties the Recycle Bin for all drives",
        "section": None,
    },
    {
        "key":     "wer",
        "label":   "Windows Error Reports",
        "path":    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\WER"),
        "type":    "dir_contents",
        "admin":   False,
        "desc":    "Crash dumps and error reports -- safe to delete",
        "section": None,
    },
    {
        "key":     "prefetch",
        "label":   "Windows Prefetch",
        "path":    os.path.expandvars(r"%SystemRoot%\Prefetch"),
        "type":    "dir_contents",
        "admin":   True,
        "desc":    "App launch optimisation files -- stale ones slow things down",
        "section": None,
    },
    # ── Windows System Caches ──
    {
        "key":     "win_update",
        "label":   "Windows Update Cache",
        "path":    os.path.expandvars(r"%SystemRoot%\SoftwareDistribution\Download"),
        "type":    "dir_contents",
        "admin":   True,
        "desc":    "Downloaded update files -- already installed, safe to remove",
        "section": "Windows System Caches",
    },
    {
        "key":     "delivery_opt",
        "label":   "Delivery Optimisation Cache",
        "path":    None,
        "type":    "delivery_opt",
        "admin":   True,
        "desc":    "Windows P2P update sharing files -- can grow to several GB",
        "section": None,
    },
    {
        "key":     "event_logs",
        "label":   "Windows Event Logs",
        "path":    None,
        "type":    "event_logs",
        "admin":   True,
        "desc":    "Application, System, Security logs -- clears with wevtutil",
        "section": None,
    },
    # ── Browser & App Caches ──
    {
        "key":     "chrome_cache",
        "label":   "Chrome Cache",
        "path":    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache"),
        "type":    "dir_contents",
        "admin":   False,
        "desc":    "Cached web data -- cookies and history are NOT touched",
        "section": "Browser & App Caches",
    },
    {
        "key":     "edge_cache",
        "label":   "Edge Cache",
        "path":    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache"),
        "type":    "dir_contents",
        "admin":   False,
        "desc":    "Cached web data -- cookies and history are NOT touched",
        "section": None,
    },
    {
        "key":     "firefox_cache",
        "label":   "Firefox Cache",
        "path":    None,
        "type":    "firefox_cache",
        "admin":   False,
        "desc":    "Cached web data -- cookies and history are NOT touched",
        "section": None,
    },
    {
        "key":     "gpu_shader",
        "label":   "GPU Shader Cache",
        "path":    None,
        "type":    "gpu_shader",
        "admin":   False,
        "desc":    "NVIDIA / AMD / Intel shader caches -- apps rebuild as needed",
        "section": None,
    },
    {
        "key":     "thumbcache",
        "label":   "Thumbnail Cache",
        "path":    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
        "type":    "thumbcache",
        "admin":   False,
        "desc":    "thumbcache_*.db files -- Windows regenerates them automatically",
        "section": None,
    },
    # ── Quick Actions ──
    {
        "key":     "clipboard",
        "label":   "Clear Clipboard",
        "path":    None,
        "type":    "clipboard",
        "admin":   False,
        "desc":    "Wipes whatever is currently on the clipboard",
        "section": "Quick Actions",
    },
    {
        "key":     "dns_cache",
        "label":   "Flush DNS Cache",
        "path":    None,
        "type":    "dns_flush",
        "admin":   False,
        "desc":    "Runs ipconfig /flushdns -- clears the DNS resolver cache",
        "section": None,
    },
]

_NO_SIZE_TYPES = {"clipboard", "dns_flush", "event_logs", "delivery_opt"}


# ======================================================
# App class
# ======================================================
class App(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("System Cleaner Pro")
        parent.geometry("960x750")
        parent.minsize(860, 650)

        self._is_admin        = is_admin()
        self._is_scanning     = False
        self._is_cleaning     = False
        self._is_ram_opt      = False
        self._check_vars:   dict = {}
        self._size_cache:   dict = {}
        self._size_labels:  dict = {}
        self._total_freed       = 0
        self._cancel_flag     = threading.Event()

        self._build_ui()
        self.after(300, self._start_size_scan)
        self.after(500, self._start_ram_update_loop)
        self.after(600, self._update_uptime)

    # ──────────────────────────────────────────
    # UI construction
    # ──────────────────────────────────────────
    def _build_ui(self):
        self.pack(fill="both", expand=True, padx=8, pady=8)

        # == Header bar ==
        hdr = ctk.CTkFrame(self, height=52, corner_radius=8, fg_color="#1e2940")
        hdr.pack(fill="x", pady=(0, 8))
        hdr.pack_propagate(False)

        ctk.CTkLabel(
            hdr, text="System Cleaner Pro",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#4fc3f7",
        ).pack(side="left", padx=14)

        # Uptime badge
        self._uptime_label = ctk.CTkLabel(
            hdr, text="Uptime: ...",
            font=ctk.CTkFont(size=11),
            text_color="#aaaaaa",
        )
        self._uptime_label.pack(side="left", padx=(20, 0))

        # Admin badge
        admin_color = "#4caf50" if self._is_admin else "#ff9800"
        admin_text  = "Admin: YES" if self._is_admin else "Admin: NO (some items disabled)"
        ctk.CTkLabel(
            hdr, text=admin_text,
            font=ctk.CTkFont(size=11),
            text_color=admin_color,
        ).pack(side="right", padx=14)

        # == Body: two columns ==
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        left  = ctk.CTkFrame(body, width=460, corner_radius=8)
        right = ctk.CTkFrame(body, corner_radius=8)
        left.pack(side="left", fill="y", padx=(0, 6))
        right.pack(side="left", fill="both", expand=True)
        left.pack_propagate(False)

        # == Left: scrollable categories ==
        ctk.CTkLabel(
            left, text="Select items to clean:",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        scroll = ctk.CTkScrollableFrame(left, corner_radius=6)
        scroll.pack(fill="both", padx=8, expand=True)

        current_section = None
        for cat in CATEGORIES:
            # Section header
            section = cat.get("section")
            if section and section != current_section:
                current_section = section
                sec_frm = ctk.CTkFrame(scroll, fg_color="transparent", height=24)
                sec_frm.pack(fill="x", pady=(8 if current_section else 2, 2))
                ctk.CTkLabel(
                    sec_frm,
                    text=f"  {section}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color="#6688bb",
                    anchor="w",
                ).pack(side="left")

            key  = cat["key"]
            bvar = tk.BooleanVar(value=True)
            self._check_vars[key] = bvar

            row = ctk.CTkFrame(scroll, corner_radius=6, fg_color="#1e1e2e")
            row.pack(fill="x", pady=2, padx=2)

            top = ctk.CTkFrame(row, fg_color="transparent")
            top.pack(fill="x", padx=6, pady=(4, 0))

            disabled = cat["admin"] and not self._is_admin
            cb = ctk.CTkCheckBox(
                top, text=cat["label"],
                variable=bvar,
                font=ctk.CTkFont(size=12),
                state="disabled" if disabled else "normal",
            )
            cb.pack(side="left")
            if disabled:
                bvar.set(False)

            lbl = ctk.CTkLabel(
                top, text="...",
                font=ctk.CTkFont(size=11),
                text_color="#aaaaaa",
                width=80,
                anchor="e",
            )
            lbl.pack(side="right")
            self._size_labels[key] = lbl

            desc_color = "#888888" if not disabled else "#555555"
            ctk.CTkLabel(
                row,
                text=f"  {cat['desc']}",
                font=ctk.CTkFont(size=10),
                text_color=desc_color,
                anchor="w",
            ).pack(anchor="w", padx=6, pady=(0, 4))

        # == Left: action buttons ==
        btn_row = ctk.CTkFrame(left, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=(6, 0))

        ctk.CTkButton(
            btn_row, text="Rescan", width=80,
            command=self._start_size_scan,
            fg_color="#2b4a6f",
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            btn_row, text="All", width=55,
            command=lambda: self._select_all(True),
            fg_color="#333355",
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            btn_row, text="None", width=55,
            command=lambda: self._select_all(False),
            fg_color="#333355",
        ).pack(side="left")

        self._clean_btn = ctk.CTkButton(
            left, text="Clean Selected",
            height=38,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2e7d32", hover_color="#1b5e20",
            command=self._clean_selected,
        )
        self._clean_btn.pack(fill="x", padx=8, pady=(6, 0))

        # Preview (dry-run) + Cancel
        action_row = ctk.CTkFrame(left, fg_color="transparent")
        action_row.pack(fill="x", padx=8, pady=(4, 0))

        self._preview_btn = ctk.CTkButton(
            action_row, text="Preview (dry-run)",
            fg_color="#394b6e", hover_color="#2a3955",
            command=self._preview_selected,
        )
        self._preview_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self._cancel_btn = ctk.CTkButton(
            action_row, text="Cancel",
            fg_color="#8c3030", hover_color="#611f1f",
            command=self._cancel_clean,
            state="disabled",
        )
        self._cancel_btn.pack(side="left", fill="x", expand=True)

        # == Left: RAM section ==
        sep = ctk.CTkFrame(left, height=1, fg_color="#444444")
        sep.pack(fill="x", padx=8, pady=(8, 6))

        ctk.CTkLabel(
            left, text="RAM Optimiser",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12)

        self._ram_label = ctk.CTkLabel(
            left, text="RAM: measuring...",
            font=ctk.CTkFont(size=11), text_color="#aaaaaa",
        )
        self._ram_label.pack(anchor="w", padx=12, pady=(2, 4))

        ram_row = ctk.CTkFrame(left, fg_color="transparent")
        ram_row.pack(fill="x", padx=8, pady=(0, 2))

        self._ram_btn = ctk.CTkButton(
            ram_row, text="Trim Working Sets",
            width=145,
            fg_color="#5c3a9e", hover_color="#3d2670",
            command=self._start_ram_optimize,
        )
        self._ram_btn.pack(side="left", padx=(0, 4))

        self._standby_btn = ctk.CTkButton(
            ram_row, text="Purge Standby RAM",
            width=155,
            fg_color="#7b1fa2", hover_color="#4a148c",
            command=self._start_standby_purge,
        )
        self._standby_btn.pack(side="left")
        if not self._is_admin:
            self._standby_btn.configure(state="disabled")

        self._ram_freed_label = ctk.CTkLabel(
            left, text="",
            font=ctk.CTkFont(size=11), text_color="#4caf50",
        )
        self._ram_freed_label.pack(anchor="w", padx=12, pady=(2, 0))

        # == Left: Explorer restart ==
        sep2 = ctk.CTkFrame(left, height=1, fg_color="#444444")
        sep2.pack(fill="x", padx=8, pady=(6, 6))

        explorer_row = ctk.CTkFrame(left, fg_color="transparent")
        explorer_row.pack(fill="x", padx=8, pady=(0, 8))

        self._explorer_btn = ctk.CTkButton(
            explorer_row,
            text="Restart Explorer",
            width=145,
            fg_color="#bf360c", hover_color="#8c2700",
            command=self._restart_explorer,
        )
        self._explorer_btn.pack(side="left", padx=(0, 8))

        ctk.CTkLabel(
            explorer_row,
            text="Frees leaked RAM + unlocks caches",
            font=ctk.CTkFont(size=10),
            text_color="#888888",
        ).pack(side="left")

        # == Right: live log ==
        ctk.CTkLabel(
            right, text="Clean Log",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 2))

        self._log_box = ctk.CTkTextbox(
            right,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word",
            state="disabled",
        )
        self._log_box.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        # Status bar
        status_bar = ctk.CTkFrame(right, height=30, fg_color="#111111", corner_radius=6)
        status_bar.pack(fill="x", padx=8, pady=(0, 8))
        status_bar.pack_propagate(False)

        ctk.CTkLabel(
            status_bar, text="Session total freed:",
            font=ctk.CTkFont(size=11), text_color="#888888",
        ).pack(side="left", padx=10)

        self._total_label = ctk.CTkLabel(
            status_bar, text="0 B",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="#4fc3f7",
        )
        self._total_label.pack(side="left")

    # ──────────────────────────────────────────
    # Uptime display
    # ──────────────────────────────────────────
    def _update_uptime(self):
        try:
            td = _get_system_uptime()
            text = f"Uptime: {_format_uptime(td)}"
            days = td.total_seconds() / 86400

            if days >= 14:
                color = "#f44336"
                text += "  !!  RESTART RECOMMENDED"
            elif days >= 7:
                color = "#ff9800"
                text += "  !  Consider restarting"
            elif days >= 3:
                color = "#ffeb3b"
            else:
                color = "#4caf50"

            self._uptime_label.configure(text=text, text_color=color)
        except (tk.TclError, AttributeError):
            # Widget destroyed during shutdown or not yet attached.
            pass
        try:
            self.after(30000, self._update_uptime)
        except tk.TclError:
            # Tk root gone — stop rescheduling.
            pass

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────
    def _select_all(self, value: bool):
        for key, bvar in self._check_vars.items():
            cat = next(c for c in CATEGORIES if c["key"] == key)
            if cat["admin"] and not self._is_admin:
                continue
            bvar.set(value)

    def _log(self, msg: str):
        self.after(0, lambda m=msg: self._log_ui(m))

    def _log_ui(self, msg: str):
        self._log_box.configure(state="normal")
        self._log_box.insert("end", msg + "\n")
        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    # ──────────────────────────────────────────
    # Size scanning
    # ──────────────────────────────────────────
    def _start_size_scan(self):
        if self._is_scanning:
            return
        self._is_scanning = True
        self._clean_btn.configure(state="disabled")
        for key, lbl in self._size_labels.items():
            cat = next(c for c in CATEGORIES if c["key"] == key)
            if cat["type"] in _NO_SIZE_TYPES:
                lbl.configure(text="N/A", text_color="#555555")
            else:
                lbl.configure(text="...", text_color="#888888")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        for cat in CATEGORIES:
            key   = cat["key"]
            ctype = cat["type"]
            size  = None

            if ctype in _NO_SIZE_TYPES:
                self.after(0, lambda k=key: self._update_size_label(k, None))
                continue

            if ctype == "recycle_bin":
                size = _query_recycle_bin_size()
            elif ctype == "firefox_cache":
                paths = _resolve_firefox_cache_paths()
                size = sum(_dir_size(p) for p in paths)
            elif ctype == "gpu_shader":
                paths = _resolve_gpu_shader_paths()
                size = sum(_dir_size(p) for p in paths)
            elif ctype == "thumbcache":
                pattern = os.path.join(
                    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
                    "thumbcache_*.db"
                )
                size = sum(
                    os.path.getsize(f) for f in glob.glob(pattern)
                    if os.path.isfile(f)
                )
            elif ctype == "dir_contents":
                path = cat["path"]
                size = _dir_size(path) if os.path.isdir(path) else 0
            else:
                size = 0

            self.after(0, lambda k=key, s=size: self._update_size_label(k, s))

        self.after(0, self._scan_done)

    def _update_size_label(self, key: str, size):
        lbl = self._size_labels[key]
        if size is None:
            lbl.configure(text="N/A", text_color="#555555")
            return
        self._size_cache[key] = size
        text = format_size(size)
        if size == 0:
            color = "#555555"
        elif size >= 50 * 1024 * 1024:
            color = "#ff9800"
        elif size >= 10 * 1024 * 1024:
            color = "#ffeb3b"
        else:
            color = "#aaaaaa"
        lbl.configure(text=text, text_color=color)

    def _scan_done(self):
        self._is_scanning = False
        self._clean_btn.configure(state="normal")

    # ──────────────────────────────────────────
    # Cleaning
    # ──────────────────────────────────────────
    def _describe_target(self, cat: dict) -> str:
        """Return a human-readable target path for the confirmation dialog."""
        ctype = cat["type"]
        if ctype == "dir_contents":
            return cat.get("path") or "(none)"
        if ctype == "recycle_bin":
            return "Recycle Bin (all drives)"
        if ctype == "firefox_cache":
            paths = _resolve_firefox_cache_paths()
            return ", ".join(paths) if paths else "(no Firefox profiles found)"
        if ctype == "gpu_shader":
            paths = _resolve_gpu_shader_paths()
            return ", ".join(paths) if paths else "(none)"
        if ctype == "thumbcache":
            return os.path.join(
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
                "thumbcache_*.db",
            )
        if ctype == "delivery_opt":
            return os.path.expandvars(
                r"%SYSTEMROOT%\ServiceProfiles\NetworkService"
                r"\AppData\Local\Microsoft\Windows\DeliveryOptimization"
            )
        if ctype == "event_logs":
            return "wevtutil cl (Application, System, Security, Setup)"
        if ctype == "clipboard":
            return "Windows clipboard"
        if ctype == "dns_flush":
            return "ipconfig /flushdns"
        return "(n/a)"

    def _build_confirmation_body(self, selected: list, mode: DeleteMode) -> str:
        """Compose the confirmation-dialog body with per-category size + path + badge."""
        lines = [f"Clean {len(selected)} selected item(s)?", ""]
        trash_badge = "[Recycle Bin]" if mode is DeleteMode.TRASH else "[PERMANENT]"
        for cat in selected:
            key = cat["key"]
            size = self._size_cache.get(key)
            if cat["type"] in _NO_SIZE_TYPES or size is None:
                size_txt = "n/a"
            else:
                size_txt = format_size(size)
            target = self._describe_target(cat)
            lines.append(f"- {cat['label']}  {trash_badge}")
            lines.append(f"    size: {size_txt}")
            lines.append(f"    path: {target}")
        lines.append("")
        if mode is DeleteMode.TRASH:
            lines.append("Files go to the Recycle Bin and can be restored.")
        else:
            lines.append("PERMANENT delete -- this cannot be undone.")
        return "\n".join(lines)

    def _clean_selected(self):
        if self._is_cleaning or self._is_scanning:
            return
        selected = [c for c in CATEGORIES if self._check_vars[c["key"]].get()]
        if not selected:
            messagebox.showinfo("Nothing selected", "Please select at least one item to clean.")
            return

        mode = DEFAULT_DELETE_MODE
        if mode is DeleteMode.TRASH and not _HAS_SEND2TRASH:
            messagebox.showwarning(
                "send2trash missing",
                "send2trash is not installed. Install with:\n\n"
                "    pip install send2trash\n\n"
                "Falling back to Preview (dry-run) instead.",
                parent=self.parent,
            )
            self._preview_selected()
            return

        body = self._build_confirmation_body(selected, mode)
        if not messagebox.askyesno("Confirm Clean", body, parent=self.parent):
            return

        self._start_worker(selected, mode)

    def _preview_selected(self):
        if self._is_cleaning or self._is_scanning:
            return
        selected = [c for c in CATEGORIES if self._check_vars[c["key"]].get()]
        if not selected:
            messagebox.showinfo("Nothing selected", "Please select at least one item to preview.")
            return
        self._start_worker(selected, DeleteMode.DRY_RUN)

    def _cancel_clean(self):
        """Signal the worker thread to stop between categories."""
        if not self._is_cleaning:
            return
        self._cancel_flag.set()
        self._log("  [Cancel requested -- will stop after current category]")

    def _start_worker(self, selected: list, mode: DeleteMode) -> None:
        self._cancel_flag.clear()
        self._is_cleaning = True
        self._clean_btn.configure(state="disabled", text="Cleaning...")
        self._preview_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        header = "Preview (dry-run)" if mode is DeleteMode.DRY_RUN else f"Clean ({mode.value})"
        self._log("=" * 45)
        self._log(f"Starting {header} -- {len(selected)} item(s) selected")
        self._log("=" * 45)
        threading.Thread(
            target=self._clean_worker, args=(selected, mode), daemon=True
        ).start()

    def _clean_worker(self, selected: list, mode: DeleteMode):
        session_freed = 0
        cleaned_count = 0
        remaining: list = []
        for cat in selected:
            if self._cancel_flag.is_set():
                remaining.append(cat["label"])
                continue
            self._log(f"\n-- {cat['label']} --")
            freed = self._run_category_clean(cat, mode)
            session_freed += freed
            cleaned_count += 1
            if cat["type"] not in _NO_SIZE_TYPES:
                label = "Would free" if mode is DeleteMode.DRY_RUN else "Freed"
                self._log(f"  {label}: {format_size(freed)}")

        if mode is not DeleteMode.DRY_RUN:
            self._total_freed += session_freed

        self._log(f"\n{'=' * 45}")
        if remaining:
            self._log(f"Cancelled. Cleaned {cleaned_count}, remaining: {', '.join(remaining)}")
        else:
            verb = "Would free" if mode is DeleteMode.DRY_RUN else "Freed"
            self._log(f"Done! {verb} {format_size(session_freed)} this run")
        if mode is not DeleteMode.DRY_RUN:
            self._log(f"   Session total: {format_size(self._total_freed)}")
        self._log(f"{'=' * 45}\n")
        self.after(0, lambda: self._clean_done(mode))

    def _clean_done(self, mode: DeleteMode):
        self._is_cleaning = False
        self._cancel_flag.clear()
        self._clean_btn.configure(state="normal", text="Clean Selected")
        self._preview_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._total_label.configure(text=format_size(self._total_freed))
        if mode is not DeleteMode.DRY_RUN:
            self.after(300, self._start_size_scan)

    def _run_category_clean(self, cat: dict, mode: DeleteMode = DEFAULT_DELETE_MODE) -> int:
        ctype = cat["type"]
        log   = self._log
        dry   = mode is DeleteMode.DRY_RUN

        if ctype == "dir_contents":
            if cat["admin"] and not self._is_admin:
                log("  Skipped -- requires Administrator")
                return 0
            return _delete_dir_contents(cat["path"], log, mode)

        if ctype == "recycle_bin":
            size = _query_recycle_bin_size()
            if dry:
                log(f"  [dry-run] Would empty Recycle Bin ({format_size(size)})")
                return size
            try:
                ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x00000007)
                log("  Recycle Bin emptied")
            except (AttributeError, OSError) as e:
                # AttributeError on non-Windows; OSError on shell32 call failure.
                log(f"  Error: {e}")
                return 0
            return size

        if ctype == "firefox_cache":
            paths = _resolve_firefox_cache_paths()
            if not paths:
                log("  Firefox not found or no cache")
                return 0
            total = 0
            for p in paths:
                total += _delete_dir_contents(p, log, mode)
            return total

        if ctype == "gpu_shader":
            paths = _resolve_gpu_shader_paths()
            if not paths:
                log("  No GPU shader cache found")
                return 0
            total = 0
            for p in paths:
                vendor = "NVIDIA" if "NVIDIA" in p.upper() else \
                         "AMD" if "AMD" in p.upper() else \
                         "Intel" if "INTEL" in p.upper() else "D3D"
                log(f"  Cleaning {vendor}: {os.path.basename(p)}")
                total += _delete_dir_contents(p, log, mode)
            return total

        if ctype == "thumbcache":
            pattern = os.path.join(
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
                "thumbcache_*.db"
            )
            freed = _delete_glob_files(pattern, log, mode)
            if freed == 0 and not dry:
                log("  Thumbcache files are locked while Explorer runs")
                log("  Use 'Restart Explorer' button to unlock them")
            return freed

        if ctype == "delivery_opt":
            if not self._is_admin:
                log("  Skipped -- requires Administrator")
                return 0
            if dry:
                do_path = os.path.expandvars(
                    r"%SYSTEMROOT%\ServiceProfiles\NetworkService"
                    r"\AppData\Local\Microsoft\Windows\DeliveryOptimization"
                )
                log(f"  [dry-run] Would clear Delivery Optimisation cache ({do_path})")
                return _delete_dir_contents(do_path, log, mode) if os.path.isdir(do_path) else 0
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Delete-DeliveryOptimizationCache -Force"],
                    capture_output=True, text=True,
                    creationflags=_CREATE_NO_WINDOW,
                    timeout=30,
                )
                if result.returncode == 0:
                    log("  Delivery Optimisation cache cleared")
                else:
                    # Fallback: direct folder delete
                    do_path = os.path.expandvars(
                        r"%SYSTEMROOT%\ServiceProfiles\NetworkService"
                        r"\AppData\Local\Microsoft\Windows\DeliveryOptimization"
                    )
                    if os.path.isdir(do_path):
                        return _delete_dir_contents(do_path, log, mode)
                    log("  No Delivery Optimisation cache found")
            except (OSError, subprocess.SubprocessError) as e:
                # OSError: spawn failure. SubprocessError: TimeoutExpired etc.
                log(f"  Error: {e}")
            return 0

        if ctype == "event_logs":
            if not self._is_admin:
                log("  Skipped -- requires Administrator")
                return 0
            if dry:
                log("  [dry-run] Would clear: Application, System, Security, Setup")
                return 0
            cleared = 0
            for logname in ("Application", "System", "Security", "Setup"):
                try:
                    result = subprocess.run(
                        ["wevtutil", "cl", logname],
                        capture_output=True, text=True,
                        creationflags=_CREATE_NO_WINDOW,
                        timeout=15,
                    )
                    if result.returncode == 0:
                        log(f"  Cleared: {logname}")
                        cleared += 1
                    else:
                        log(f"  Could not clear {logname}: {result.stderr.strip()}")
                except (OSError, subprocess.SubprocessError) as e:
                    # wevtutil spawn failure or timeout per-log.
                    log(f"  Error clearing {logname}: {e}")
            log(f"  {cleared} event log(s) cleared")
            return 0

        if ctype == "clipboard":
            if dry:
                log("  [dry-run] Would clear clipboard")
                return 0
            try:
                ctypes.windll.user32.OpenClipboard(0)
                ctypes.windll.user32.EmptyClipboard()
                ctypes.windll.user32.CloseClipboard()
                log("  Clipboard cleared")
            except (AttributeError, OSError) as e:
                # AttributeError on non-Windows; OSError on user32 call failure.
                log(f"  {e}")
            return 0

        if ctype == "dns_flush":
            if dry:
                log("  [dry-run] Would run ipconfig /flushdns")
                return 0
            try:
                result = subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True, text=True,
                    creationflags=_CREATE_NO_WINDOW,
                    timeout=10,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line:
                        log(f"  {line}")
            except (OSError, subprocess.SubprocessError) as e:
                # ipconfig spawn failure or timeout.
                log(f"  {e}")
            return 0

        return 0

    # ──────────────────────────────────────────
    # RAM monitor & working-set trim
    # ──────────────────────────────────────────
    def _start_ram_update_loop(self):
        try:
            vm   = psutil.virtual_memory()
            used = vm.used / (1024 ** 3)
            tot  = vm.total / (1024 ** 3)
            pct  = vm.percent
            color = "#4caf50" if pct < 60 else "#ff9800" if pct < 85 else "#f44336"
            self._ram_label.configure(
                text=f"RAM: {used:.1f} GB / {tot:.1f} GB  ({pct:.0f}% used)",
                text_color=color,
            )
        except (OSError, AttributeError, tk.TclError):
            # OSError: psutil read failure. AttributeError: label not attached.
            # TclError: widget destroyed during shutdown.
            pass
        try:
            self.after(2000, self._start_ram_update_loop)
        except tk.TclError:
            # Tk root gone — stop rescheduling.
            pass

    def _start_ram_optimize(self):
        if self._is_ram_opt:
            return
        self._is_ram_opt = True
        self._ram_btn.configure(state="disabled", text="Trimming...")
        self._ram_freed_label.configure(text="")
        threading.Thread(target=self._ram_optimize_worker, daemon=True).start()

    def _ram_optimize_worker(self):
        before = psutil.virtual_memory().used
        self._log("\n-- RAM: Trim Working Sets --")
        trimmed = 0
        failed  = 0

        PROCESS_SET_QUOTA = 0x0100
        kernel32 = ctypes.windll.kernel32

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid    = proc.info["pid"]
                handle = kernel32.OpenProcess(PROCESS_SET_QUOTA, False, pid)
                if handle:
                    kernel32.SetProcessWorkingSetSize(
                        handle,
                        ctypes.c_size_t(-1),
                        ctypes.c_size_t(-1),
                    )
                    kernel32.CloseHandle(handle)
                    trimmed += 1
            except (psutil.Error, OSError, AttributeError):
                # psutil.Error: process vanished. OSError: kernel32 call rejected.
                # AttributeError: windll missing on non-Windows.
                failed += 1

        time.sleep(0.8)
        after  = psutil.virtual_memory().used
        freed  = max(0, before - after)

        self._log(f"  Trimmed {trimmed} processes")
        if failed:
            self._log(f"  {failed} processes denied access (normal)")
        self._log(f"  RAM freed: {format_size(freed)}")

        self.after(0, lambda: self._ram_optimize_done(freed))

    def _ram_optimize_done(self, freed: int):
        self._is_ram_opt = False
        self._ram_btn.configure(state="normal", text="Trim Working Sets")
        if freed > 0:
            self._ram_freed_label.configure(text=f"Freed {format_size(freed)}")
        else:
            self._ram_freed_label.configure(text="RAM already optimal")

    # ──────────────────────────────────────────
    # Standby memory purge (admin only)
    # ──────────────────────────────────────────
    def _start_standby_purge(self):
        if self._is_ram_opt:
            return
        if not self._is_admin:
            messagebox.showwarning(
                "Admin Required",
                "Standby memory purge requires running as Administrator.",
                parent=self.parent,
            )
            return
        self._is_ram_opt = True
        self._standby_btn.configure(state="disabled", text="Purging...")
        self._ram_freed_label.configure(text="")
        threading.Thread(target=self._standby_purge_worker, daemon=True).start()

    def _standby_purge_worker(self):
        before = psutil.virtual_memory().available
        self._log("\n-- RAM: Purge Standby List --")

        success = False
        try:
            # Enable SeProfileSingleProcessPrivilege (required)
            _enable_privilege("SeProfileSingleProcessPrivilege")

            # NtSetSystemInformation(SystemMemoryListInformation=80, MemoryPurgeStandbyList=4)
            ntdll = ctypes.windll.ntdll
            purge_cmd = ctypes.c_ulong(4)  # MemoryPurgeStandbyList
            status = ntdll.NtSetSystemInformation(
                80,  # SystemMemoryListInformation
                ctypes.byref(purge_cmd),
                ctypes.sizeof(purge_cmd),
            )
            if status == 0:
                success = True
                self._log("  Standby memory purged via NtSetSystemInformation")
            else:
                self._log(f"  NtSetSystemInformation returned status: 0x{status & 0xFFFFFFFF:08X}")
        except (AttributeError, OSError) as e:
            # AttributeError on non-Windows; OSError on ntdll syscall failure.
            self._log(f"  Error: {e}")

        time.sleep(0.5)
        after = psutil.virtual_memory().available
        freed = max(0, after - before)

        if success:
            self._log(f"  Available RAM increased by: {format_size(freed)}")
        else:
            self._log("  Could not purge standby memory")

        self.after(0, lambda: self._standby_purge_done(freed, success))

    def _standby_purge_done(self, freed: int, success: bool):
        self._is_ram_opt = False
        self._standby_btn.configure(state="normal", text="Purge Standby RAM")
        if success and freed > 0:
            self._ram_freed_label.configure(text=f"Standby freed: {format_size(freed)}")
        elif success:
            self._ram_freed_label.configure(text="Standby list was already small")
        else:
            self._ram_freed_label.configure(text="Purge failed (see log)", text_color="#f44336")

    # ──────────────────────────────────────────
    # Explorer restart
    # ──────────────────────────────────────────
    def _restart_explorer(self):
        if not messagebox.askyesno(
            "Restart Explorer",
            "This will briefly close your taskbar and desktop.\n"
            "All Explorer/File Manager windows will close.\n\n"
            "Continue?",
            parent=self.parent,
        ):
            return
        self._explorer_btn.configure(state="disabled", text="Restarting...")
        threading.Thread(target=self._restart_explorer_worker, daemon=True).start()

    def _restart_explorer_worker(self):
        self._log("\n-- Restart Explorer --")
        try:
            # Get memory usage before
            explorer_mem = 0
            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                if proc.info["name"] and proc.info["name"].lower() == "explorer.exe":
                    try:
                        explorer_mem += proc.info["memory_info"].rss
                    except (psutil.Error, AttributeError):
                        # Process vanished mid-iter, or memory_info unavailable.
                        pass

            if explorer_mem:
                self._log(f"  Explorer using: {format_size(explorer_mem)}")

            # Kill explorer
            subprocess.run(
                ["taskkill", "/F", "/IM", "explorer.exe"],
                capture_output=True, text=True,
                creationflags=_CREATE_NO_WINDOW,
                timeout=10,
            )
            self._log("  Explorer stopped")
            time.sleep(1.5)

            # Restart explorer
            subprocess.Popen(
                ["explorer.exe"],
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW,
            )
            time.sleep(2)

            # Verify explorer.exe is actually running
            explorer_running = any(
                p.info["name"] and p.info["name"].lower() == "explorer.exe"
                for p in psutil.process_iter(["name"])
            )
            if not explorer_running:
                time.sleep(3)
                explorer_running = any(
                    p.info["name"] and p.info["name"].lower() == "explorer.exe"
                    for p in psutil.process_iter(["name"])
                )

            if explorer_running:
                self._log("  Explorer restarted successfully")
            else:
                self._log("  WARNING: Explorer may not have restarted -- check your taskbar")

            # Check new memory
            new_mem = 0
            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                if proc.info["name"] and proc.info["name"].lower() == "explorer.exe":
                    try:
                        new_mem += proc.info["memory_info"].rss
                    except (psutil.Error, AttributeError):
                        # Process vanished mid-iter, or memory_info unavailable.
                        pass

            if explorer_mem and new_mem:
                saved = max(0, explorer_mem - new_mem)
                self._log(f"  New Explorer using: {format_size(new_mem)}")
                if saved > 0:
                    self._log(f"  RAM recovered: {format_size(saved)}")
            self._log("  Thumbnail and icon caches are now unlocked")

        except Exception as e:  # noqa: BLE001
            # Thread-worker boundary: taskkill/explorer.exe spawn + psutil iter
            # raise a wide surface (OSError, subprocess.SubprocessError,
            # psutil.Error, AttributeError). Catch-all keeps the restart UX
            # coherent and logs a full traceback for diagnosis.
            log.exception("restart_explorer_worker failed")
            self._log(f"  Error: {e}")

        self.after(0, lambda: self._explorer_btn.configure(
            state="normal", text="Restart Explorer"))

    # ──────────────────────────────────────────
    def force_stop(self):
        self._is_cleaning = False
        self._is_scanning = False
        self._is_ram_opt  = False
        try:
            self.parent.destroy()
        except tk.TclError:
            # Already destroyed.
            pass


# ======================================================
# Entry point
# ======================================================
def run_tool():
    try:
        root = tk._default_root
    except AttributeError:
        root = None

    win = ctk.CTkToplevel(root)
    win.title("System Cleaner Pro")
    win.geometry("960x750")
    win.attributes("-topmost", True)
    win.after(200, lambda: win.attributes("-topmost", False))

    app = App(win)
    win.protocol("WM_DELETE_WINDOW", app.force_stop)

    # Centre on screen
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x  = (sw - 960) // 2
    y  = (sh - 750) // 2
    win.geometry(f"960x750+{x}+{y}")


# ======================================================
# Headless scan / clean helpers (CLI)
# ======================================================
def _category_size(cat: dict) -> Optional[int]:
    """Return current on-disk size for a category, or None if not applicable."""
    ctype = cat["type"]
    if ctype in _NO_SIZE_TYPES:
        return None
    if ctype == "recycle_bin":
        return _query_recycle_bin_size()
    if ctype == "firefox_cache":
        return sum(_dir_size(p) for p in _resolve_firefox_cache_paths())
    if ctype == "gpu_shader":
        return sum(_dir_size(p) for p in _resolve_gpu_shader_paths())
    if ctype == "thumbcache":
        pattern = os.path.join(
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
            "thumbcache_*.db",
        )
        return sum(os.path.getsize(f) for f in glob.glob(pattern) if os.path.isfile(f))
    if ctype == "dir_contents":
        path = cat.get("path")
        return _dir_size(path) if path and os.path.isdir(path) else 0
    return 0


def _select_categories(keys_or_labels: Optional[str]) -> List[dict]:
    """Resolve a comma-separated list of category keys or labels. None -> all."""
    if not keys_or_labels:
        return list(CATEGORIES)
    wanted = {s.strip().lower() for s in keys_or_labels.split(",") if s.strip()}
    out: List[dict] = []
    for cat in CATEGORIES:
        if cat["key"].lower() in wanted or cat["label"].lower() in wanted:
            out.append(cat)
    return out


def _cli_log(line: str) -> None:
    """Print a cleaning log line to stdout for CLI consumers."""
    print(line)


def _run_headless(mode: DeleteMode, selection: List[dict]) -> int:
    """Execute category cleaning in headless mode and return total bytes freed."""
    total = 0
    for cat in selection:
        _cli_log(f"\n-- {cat['label']} --")
        ctype = cat["type"]
        if ctype == "dir_contents":
            if cat["admin"] and not is_admin():
                _cli_log("  Skipped -- requires Administrator")
                continue
            freed = _delete_dir_contents(cat["path"], _cli_log, mode)
        elif ctype == "firefox_cache":
            freed = 0
            for p in _resolve_firefox_cache_paths():
                freed += _delete_dir_contents(p, _cli_log, mode)
        elif ctype == "gpu_shader":
            freed = 0
            for p in _resolve_gpu_shader_paths():
                freed += _delete_dir_contents(p, _cli_log, mode)
        elif ctype == "thumbcache":
            pattern = os.path.join(
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
                "thumbcache_*.db",
            )
            freed = _delete_glob_files(pattern, _cli_log, mode)
        else:
            # Non-delete operations (recycle_bin, event_logs, clipboard, etc.)
            # are intentionally *not* fired from CLI — too many side effects
            # for a batch path. Scan shows sizes; use the GUI for those.
            _cli_log(f"  Skipped in CLI (use GUI): type={ctype}")
            freed = 0
        verb = "Would free" if mode is DeleteMode.DRY_RUN else "Freed"
        if ctype not in _NO_SIZE_TYPES:
            _cli_log(f"  {verb}: {format_size(freed)}")
        total += freed
    return total


def _run_scan(selection: List[dict]) -> int:
    """Print per-category size report to stdout; returns total."""
    total = 0
    for cat in selection:
        size = _category_size(cat)
        size_txt = "n/a" if size is None else format_size(size)
        _cli_log(f"{cat['label']:<32} {size_txt}")
        if size:
            total += size
    _cli_log(f"\nTOTAL: {format_size(total)}")
    return total


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. With no args, launches the GUI."""
    parser = argparse.ArgumentParser(
        prog="system_cleaner",
        description="System Cleaner Pro -- scan or clean system junk.",
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Report category sizes and exit (no disk changes).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run the clean path without touching disk.",
    )
    parser.add_argument(
        "--permanent", action="store_true",
        help="Permanently delete (bypass Recycle Bin). Requires explicit opt-in.",
    )
    parser.add_argument(
        "--categories", type=str, default=None,
        help='Comma-separated list of category keys or labels (e.g. "user_temp,chrome_cache").',
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Confirm that you understand --permanent is irreversible (required with --permanent).",
    )
    args = parser.parse_args(argv)

    # No flags -> GUI (preserves Launch.pyw flow).
    if not (args.scan or args.dry_run or args.permanent):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        root = ctk.CTk()
        root.withdraw()
        run_tool()
        root.mainloop()
        return 0

    # Validate --permanent safeguards
    if args.permanent:
        if not args.yes:
            print(
                "--permanent requires --yes to confirm you understand this is irreversible.",
                file=sys.stderr,
            )
            return 2
        if not args.categories:
            print(
                "--permanent requires --categories to be explicitly specified (refusing to delete ALL categories by default).",
                file=sys.stderr,
            )
            return 2

    selection = _select_categories(args.categories)
    if not selection:
        print("No matching categories.", file=sys.stderr)
        return 2

    if args.scan:
        _run_scan(selection)
        return 0

    if args.dry_run and args.permanent:
        print("--dry-run and --permanent are mutually exclusive.", file=sys.stderr)
        return 2

    mode = DeleteMode.PERMANENT if args.permanent else DeleteMode.DRY_RUN if args.dry_run else DEFAULT_DELETE_MODE
    freed = _run_headless(mode, selection)
    verb = "Would free" if mode is DeleteMode.DRY_RUN else "Freed"
    print(f"\n{verb} total: {format_size(freed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
