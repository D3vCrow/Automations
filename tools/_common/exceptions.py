"""Narrow-except helpers used by the Tier B broad-except sweep.

The toolbox has ~300 ``except Exception:`` sites that the audit wants
replaced with an explicit allow-list. Each site has its own local
behaviour (return ``None``, log, retry, etc.), so a one-size decorator
cannot replace them all. This module provides two thin primitives that
cover the common cases cleanly:

* :func:`narrow_excepts` — decorator: wrap a callable so only listed
  exception types are caught (optionally logged) and a default value
  returned. Non-listed exceptions propagate unchanged.
* :func:`suppress_and_log` — context manager: suppress listed exceptions
  inside a ``with`` block and emit a WARNING with the exception repr.

Use the decorator when a whole helper function should degrade gracefully
on specific errors; use the context manager for a few lines inside a
larger function.
"""

from __future__ import annotations

import functools
import logging
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, Type, TypeVar

_F = TypeVar("_F", bound=Callable[..., Any])


def narrow_excepts(
    *types: Type[BaseException],
    default: Any = None,
    logger: Optional[logging.Logger] = None,
) -> Callable[[_F], _F]:
    """Decorator: catch only the listed exception types.

    A surgical replacement for a top-level ``except Exception`` inside a
    function. Exceptions NOT in ``types`` propagate unchanged.

    Args:
        *types: Exception classes to catch. At least one required.
        default: Value returned when a listed exception is caught.
        logger: Optional logger used to emit a WARNING with the exception
            class and message. ``None`` means silent suppression — prefer
            passing a logger in production code.

    Returns:
        A decorator that wraps a callable with the narrow try/except.

    Raises:
        ValueError: If no exception types are passed.
    """
    if not types:
        raise ValueError("narrow_excepts requires at least one exception type")

    def decorator(fn: _F) -> _F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except types as exc:
                if logger is not None:
                    logger.warning(
                        "%s swallowed %s: %s",
                        fn.__qualname__,
                        type(exc).__name__,
                        exc,
                    )
                return default

        return wrapper  # type: ignore[return-value]

    return decorator


@contextmanager
def suppress_and_log(
    logger: logging.Logger,
    *types: Type[BaseException],
    message: str = "suppressed",
) -> Iterator[None]:
    """Context manager: suppress listed exceptions and log a WARNING.

    Example::

        with suppress_and_log(log, FileNotFoundError, PermissionError,
                              message="failed to unlink temp"):
            path.unlink()

    Args:
        logger: Destination logger for the WARNING.
        *types: Exception classes to suppress. At least one required.
        message: Prefix for the log line so callers can identify the site.

    Raises:
        ValueError: If no exception types are passed.
    """
    if not types:
        raise ValueError("suppress_and_log requires at least one exception type")
    try:
        yield
    except types as exc:
        logger.warning("%s: %s: %s", message, type(exc).__name__, exc)


__all__ = ["narrow_excepts", "suppress_and_log"]
