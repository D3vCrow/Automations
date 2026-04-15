"""Thread-safe collection wrappers for shared mutable state.

These wrappers are used by any tool that shares mutable lists or dicts
between a worker thread and the Tkinter main loop.
"""

import collections
import threading
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Optional, Tuple


class BoundedDeque:
    """Thread-safe bounded deque backed by ``collections.deque(maxlen=maxlen)``.

    All mutating methods acquire the internal lock before touching the
    underlying deque. ``snapshot()`` copies under the lock and releases it
    immediately so callers can iterate without holding the lock.

    Args:
        maxlen: Maximum number of items retained. Oldest items are dropped
            automatically when the deque is full (same as ``collections.deque``).
    """

    def __init__(self, maxlen: int) -> None:
        self._dq: collections.deque = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    # ── Write operations ──────────────────────────────────────────────────────

    def append(self, item: Any) -> None:
        """Append *item* to the right end (thread-safe).

        Args:
            item: Any object to store.
        """
        with self._lock:
            self._dq.append(item)

    def extend(self, items: Iterable[Any]) -> None:
        """Extend the deque with *items* (thread-safe).

        Args:
            items: Iterable of objects to append in order.
        """
        with self._lock:
            self._dq.extend(items)

    def clear(self) -> None:
        """Remove all items (thread-safe)."""
        with self._lock:
            self._dq.clear()

    # ── Read operations ───────────────────────────────────────────────────────

    def snapshot(self) -> Tuple[Any, ...]:
        """Return an immutable snapshot of current contents (thread-safe).

        Copies under the lock, then releases it, so callers can iterate
        as long as they like without blocking writers.

        Returns:
            A ``tuple`` containing all current items in insertion order.
        """
        with self._lock:
            return tuple(self._dq)

    def __len__(self) -> int:
        with self._lock:
            return len(self._dq)

    def __iter__(self) -> Iterator[Any]:
        """Iterate a point-in-time snapshot. Callers see a consistent view."""
        return iter(self.snapshot())


class SnapshotDict:
    """Thread-safe dict wrapper with a snapshot read for UI refresh paths.

    All operations that mutate or read internal state acquire the internal
    lock. ``get_snapshot()`` returns a ``MappingProxyType`` wrapping a copy
    so callers hold no reference to the live dict.

    Behaves like a regular ``dict`` for most operations, but never exposes
    the internal dict directly.
    """

    def __init__(self) -> None:
        self._d: dict = {}
        self._lock = threading.Lock()

    # ── Write operations ──────────────────────────────────────────────────────

    def __setitem__(self, key: Any, value: Any) -> None:
        with self._lock:
            self._d[key] = value

    def __delitem__(self, key: Any) -> None:
        with self._lock:
            del self._d[key]

    def pop(self, key: Any, *args: Any) -> Any:
        """Remove and return value for *key*.

        Args:
            key: Dict key to remove.
            *args: Optional default value (same as ``dict.pop``).

        Returns:
            The removed value, or default if key absent and default given.

        Raises:
            KeyError: If key absent and no default provided.
        """
        with self._lock:
            return self._d.pop(key, *args)

    def clear(self) -> None:
        """Remove all items (thread-safe)."""
        with self._lock:
            self._d.clear()

    # ── Read operations ───────────────────────────────────────────────────────

    def __getitem__(self, key: Any) -> Any:
        with self._lock:
            return self._d[key]

    def get(self, key: Any, default: Any = None) -> Any:
        """Return value for *key* or *default* if absent (thread-safe).

        Args:
            key: Dict key to look up.
            default: Value returned when key is absent. Defaults to ``None``.

        Returns:
            Stored value or *default*.
        """
        with self._lock:
            return self._d.get(key, default)

    def __contains__(self, key: Any) -> bool:
        with self._lock:
            return key in self._d

    def __len__(self) -> int:
        with self._lock:
            return len(self._d)

    def get_snapshot(self) -> MappingProxyType:
        """Return a read-only proxy of a dict copy (thread-safe).

        Copies under the lock, then releases it. The returned
        ``MappingProxyType`` wraps a plain dict copy so callers iterate
        without holding the lock.

        Returns:
            ``MappingProxyType`` of a shallow dict copy.
        """
        with self._lock:
            return MappingProxyType(dict(self._d))
