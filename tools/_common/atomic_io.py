"""Crash-safe file writes and corruption-tolerant JSON reads.

Every JSON save in the toolbox used to truncate the live file *before*
writing the new contents (``open(path, "w")`` then ``json.dump``). A crash or
power loss mid-write left a half-written or zero-length file, and the next
load silently reset it to empty. For the Network Intrusion Detector's
trust / known-devices state that silent reset is security-relevant: it
re-alarms every known device and can re-trust a now-compromised gateway
(see ``plans/2026-07-10-network-tools-audit.md`` §4).

This module provides:
    * :func:`atomic_write` — write bytes/text to a uniquely-named temp file in
      the *same directory*, ``fsync`` it, then ``os.replace`` over the target.
      Readers ever see either the old file or the complete new one.
    * :func:`atomic_write_json` — ``json.dumps`` + :func:`atomic_write`.
    * :func:`read_json` — read + parse JSON; on a decode error, quarantine the
      corrupt file to ``<name>.corrupt`` and log, instead of silently
      discarding it.
    * :func:`sweep_stale_tmp` — remove leftover temp files from a prior crashed
      write (call once on startup).

``fsync`` before the replace is deliberate: without it a power loss can still
leave a zero-length file after the metadata-only rename lands first.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Optional, Union

from tools._common.logging import get_logger

_log = get_logger(__name__)

# Temp files written by :func:`atomic_write` are dot-prefixed and end in this
# suffix so :func:`sweep_stale_tmp` can find leftovers without touching temp
# files created by unrelated code.
_TMP_SUFFIX = ".tmp"


def atomic_write(
    path: Union[str, os.PathLike],
    data: Union[str, bytes],
    *,
    encoding: str = "utf-8",
) -> None:
    """Atomically write *data* to *path* (temp file + fsync + ``os.replace``).

    Writes to a uniquely-named temp file in the *same directory* as *path*
    (``os.replace`` is only atomic within one filesystem), flushes and
    ``fsync``\\ s it so the bytes reach disk, then renames it over *path*. A
    crash at any point leaves either the previous file or the complete new
    one — never a truncated file. The temp file is removed if the write fails.

    Args:
        path: Destination path. Parent directories are created if missing.
        data: ``str`` or ``bytes`` to write. ``str`` is encoded with *encoding*.
        encoding: Text encoding used when *data* is a ``str``.

    Raises:
        OSError: If the temp file cannot be written or the replace fails.
        TypeError: If *data* is neither ``str`` nor ``bytes``.
    """
    path = Path(path)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode(encoding)

    fd, tmp = tempfile.mkstemp(
        dir=str(directory), prefix=f".{path.name}.", suffix=_TMP_SUFFIX
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        # Never leave the half-written temp file behind on any failure.
        with suppress(OSError):
            os.unlink(tmp)
        raise


def atomic_write_json(
    path: Union[str, os.PathLike],
    obj: Any,
    *,
    indent: Optional[int] = 2,
    ensure_ascii: bool = False,
    encoding: str = "utf-8",
) -> None:
    """Serialize *obj* to JSON and write it atomically.

    Thin wrapper over :func:`atomic_write` — see it for the durability
    guarantee. The full JSON string is built in memory first, so a
    serialization error (``TypeError``) never touches the target file.

    Args:
        path: Destination path.
        obj: JSON-serializable object.
        indent: ``json.dumps`` indent (pretty-print by default).
        ensure_ascii: ``json.dumps`` ensure_ascii flag.
        encoding: Text encoding for the file.

    Raises:
        OSError: On write failure (see :func:`atomic_write`).
        TypeError: If *obj* is not JSON-serializable.
    """
    text = json.dumps(obj, indent=indent, ensure_ascii=ensure_ascii)
    atomic_write(path, text, encoding=encoding)


def read_json(
    path: Union[str, os.PathLike],
    *,
    default: Any = None,
    encoding: str = "utf-8",
) -> Any:
    """Read and parse JSON from *path*, quarantining corrupt files.

    On a JSON decode error the bad file is renamed to ``<name>.corrupt``
    (overwriting any previous quarantine) and a warning is logged, instead of
    being silently discarded — the operator keeps a recoverable copy and sees
    the event. A missing file, or an OS error opening it, returns *default*
    without quarantine.

    Args:
        path: Path to the JSON file.
        default: Value returned when the file is missing, unreadable, or
            corrupt. Defaults to ``None``.
        encoding: Text encoding used to read the file.

    Returns:
        The parsed object, or *default*.
    """
    path = Path(path)
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding=encoding) as f:
            return json.load(f)
    except json.JSONDecodeError as err:
        _quarantine(path, err)
        return default
    except OSError:
        return default


def _quarantine(path: Path, error: Exception) -> None:
    """Move a corrupt JSON file aside to ``<name>.corrupt`` and log; never raise."""
    corrupt = path.with_name(path.name + ".corrupt")
    try:
        os.replace(str(path), str(corrupt))
        _log.warning("Corrupt JSON %s quarantined to %s (%s)", path, corrupt.name, error)
    except OSError as move_err:
        _log.warning(
            "Corrupt JSON %s could not be quarantined: %s (decode error: %s)",
            path, move_err, error,
        )


def sweep_stale_tmp(directory: Union[str, os.PathLike]) -> int:
    """Remove leftover ``.<name>.*.tmp`` files from a prior crashed write.

    :func:`atomic_write` names its temp files ``.<target>.<random>.tmp`` in the
    target's directory. A crash between ``mkstemp`` and ``os.replace`` leaves
    one behind. Call this once on startup for each directory that holds
    atomically-written state. Only dot-prefixed ``.tmp`` files are removed, so
    unrelated temp files are left untouched.

    Args:
        directory: Directory to sweep.

    Returns:
        The number of stale temp files removed.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return 0
    removed = 0
    for entry in directory.glob(f".*{_TMP_SUFFIX}"):
        if entry.is_file():
            with suppress(OSError):
                entry.unlink()
                removed += 1
    return removed


__all__ = [
    "atomic_write",
    "atomic_write_json",
    "read_json",
    "sweep_stale_tmp",
]
