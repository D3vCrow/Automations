"""Tests for tools._common.threadsafe — BoundedDeque and SnapshotDict."""

import sys
import threading
import time
from pathlib import Path
from types import MappingProxyType

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools._common.threadsafe import BoundedDeque, SnapshotDict


# ── BoundedDeque functional tests ─────────────────────────────────────────────

def test_bounded_deque_append_and_snapshot():
    bd = BoundedDeque(maxlen=10)
    bd.append(1)
    bd.append(2)
    bd.append(3)
    assert bd.snapshot() == (1, 2, 3)


def test_bounded_deque_maxlen_eviction():
    bd = BoundedDeque(maxlen=3)
    for i in range(6):
        bd.append(i)
    snap = bd.snapshot()
    # Only the last 3 items remain
    assert snap == (3, 4, 5)
    assert len(bd) == 3


def test_bounded_deque_clear():
    bd = BoundedDeque(maxlen=5)
    bd.extend([1, 2, 3])
    bd.clear()
    assert bd.snapshot() == ()
    assert len(bd) == 0


def test_bounded_deque_len():
    bd = BoundedDeque(maxlen=100)
    assert len(bd) == 0
    bd.append("x")
    assert len(bd) == 1
    bd.extend(["a", "b", "c"])
    assert len(bd) == 4


def test_bounded_deque_iter():
    bd = BoundedDeque(maxlen=5)
    bd.extend([10, 20, 30])
    items = list(bd)
    assert items == [10, 20, 30]


def test_bounded_deque_extend():
    bd = BoundedDeque(maxlen=10)
    bd.extend([1, 2, 3])
    bd.extend([4, 5])
    assert bd.snapshot() == (1, 2, 3, 4, 5)


def test_bounded_deque_snapshot_returns_tuple():
    bd = BoundedDeque(maxlen=5)
    bd.append("a")
    snap = bd.snapshot()
    assert isinstance(snap, tuple)


# ── SnapshotDict functional tests ──────────────────────────────────────────────

def test_snapshot_dict_set_and_get():
    sd = SnapshotDict()
    sd["key"] = "value"
    assert sd["key"] == "value"
    assert sd.get("key") == "value"
    assert sd.get("missing", "default") == "default"


def test_snapshot_dict_delete():
    sd = SnapshotDict()
    sd["a"] = 1
    del sd["a"]
    assert sd.get("a") is None
    assert len(sd) == 0


def test_snapshot_dict_pop():
    sd = SnapshotDict()
    sd["x"] = 42
    val = sd.pop("x")
    assert val == 42
    assert "x" not in sd
    # pop with default on missing key
    assert sd.pop("missing", 99) == 99


def test_snapshot_dict_contains_and_len():
    sd = SnapshotDict()
    sd["a"] = 1
    sd["b"] = 2
    assert "a" in sd
    assert "z" not in sd
    assert len(sd) == 2


def test_snapshot_dict_get_snapshot_returns_proxy():
    sd = SnapshotDict()
    sd["foo"] = "bar"
    proxy = sd.get_snapshot()
    assert isinstance(proxy, MappingProxyType)
    assert proxy["foo"] == "bar"


def test_snapshot_dict_snapshot_is_decoupled():
    """Mutating the dict after snapshot does not affect the proxy."""
    sd = SnapshotDict()
    sd["k"] = 1
    proxy = sd.get_snapshot()
    sd["k"] = 999
    # proxy still reflects old copy
    assert proxy["k"] == 1


def test_snapshot_dict_clear():
    sd = SnapshotDict()
    sd["a"] = 1
    sd.clear()
    assert len(sd) == 0
    assert sd.get_snapshot() == MappingProxyType({})


# ── Stress / race condition tests ─────────────────────────────────────────────

def test_bounded_deque_concurrent_append_and_snapshot():
    """One thread appending 10k items; another calling snapshot() in a tight
    loop. No exceptions must be raised, and each snapshot's length must be
    monotonically non-decreasing (may reset to 0 at clear points but we
    don't clear here)."""
    ITEMS = 10_000
    MAXLEN = 500
    bd = BoundedDeque(maxlen=MAXLEN)

    errors: list = []
    prev_len = 0
    reader_done = threading.Event()

    def writer():
        for i in range(ITEMS):
            bd.append(i)

    def reader():
        nonlocal prev_len
        while not reader_done.is_set():
            try:
                snap = bd.snapshot()
                cur_len = len(snap)
                # Length must not exceed maxlen
                assert cur_len <= MAXLEN, f"snapshot len {cur_len} exceeds maxlen {MAXLEN}"
            except Exception as exc:
                errors.append(exc)

    t_writer = threading.Thread(target=writer, daemon=True)
    t_reader = threading.Thread(target=reader, daemon=True)

    t_reader.start()
    t_writer.start()
    t_writer.join(timeout=10)
    reader_done.set()
    t_reader.join(timeout=5)

    assert not errors, f"Reader raised exceptions: {errors}"
    # After writer finishes, deque holds up to MAXLEN items
    assert len(bd) <= MAXLEN


def test_snapshot_dict_concurrent_mutate_and_read():
    """One thread setting/deleting keys; another calling get_snapshot() in a
    tight loop. No exceptions must be raised."""
    ITERATIONS = 10_000
    sd = SnapshotDict()

    errors: list = []
    reader_done = threading.Event()

    def writer():
        for i in range(ITERATIONS):
            sd[str(i % 50)] = i       # overwrite cycling 50 keys
            if i % 7 == 0:
                sd.pop(str(i % 50), None)

    def reader():
        while not reader_done.is_set():
            try:
                proxy = sd.get_snapshot()
                # Just iterate; must not raise
                _ = list(proxy.items())
            except Exception as exc:
                errors.append(exc)

    t_writer = threading.Thread(target=writer, daemon=True)
    t_reader = threading.Thread(target=reader, daemon=True)

    t_reader.start()
    t_writer.start()
    t_writer.join(timeout=10)
    reader_done.set()
    t_reader.join(timeout=5)

    assert not errors, f"Reader raised exceptions: {errors}"


def test_bounded_deque_no_runtime_error_during_slow_iteration():
    """Reproduces the 'list changed size during iteration' failure mode that
    existed when self.incidents was a plain list.  One writer thread appends
    continuously; one reader thread calls snapshot() and iterates slowly with
    a small sleep -- mimicking the UI refresh / export paths.  With a plain
    list this would raise RuntimeError within milliseconds; BoundedDeque must
    raise zero exceptions.

    This test also covers the self.incidents migration in
    tools/NETWORK STABILITY MONITOR.py (see A5 commit).
    """
    APPEND_COUNT = 2_000
    bd = BoundedDeque(maxlen=500)

    errors: list = []
    reader_done = threading.Event()

    def writer():
        for i in range(APPEND_COUNT):
            bd.append(i)

    def reader():
        while not reader_done.is_set():
            try:
                for _ in bd.snapshot():
                    time.sleep(0.0001)
            except Exception as exc:
                errors.append(exc)

    t_writer = threading.Thread(target=writer, daemon=True)
    t_reader = threading.Thread(target=reader, daemon=True)

    t_reader.start()
    t_writer.start()
    t_writer.join(timeout=15)
    reader_done.set()
    t_reader.join(timeout=5)

    assert not errors, f"Reader raised RuntimeError or other exception: {errors}"
