"""Reactive retry policy: which failures to retry and how long to wait.

Pure helpers shared by the sync and async request loops (no I/O, no async), so
they are hand-written once rather than generated. Backoff is exponential
(0.5s -> 8s) with jitter and honours a server ``Retry-After`` (numeric seconds
**or** an HTTP-date).
"""

from __future__ import annotations

import random
from typing import Any

from ._exceptions import APIConnectionError, ErrorInfo, _parse_retry_after

# Statuses that are retryable regardless of method (plus any 5xx).
_RETRY_STATUSES = frozenset({408, 409, 429})

# Vulners errorCodes returned inside an HTTP 200 that are safe to retry. Curated
# and empty until the taxonomy is confirmed; extend as retryable codes appear.
RETRYABLE_ERROR_CODES: frozenset[int] = frozenset()

_INITIAL_BACKOFF = 0.5
_MAX_BACKOFF = 8.0
# Cap on how long a server Retry-After hint is honoured before falling back to
# our own backoff — a hostile/broken upstream cannot pin us for minutes.
_MAX_RETRY_AFTER = 60.0


def _header_override(headers: Any) -> bool | None:
    """Explicit ``x-should-retry`` signal from the server, if present."""
    if headers is None:
        return None
    signal = headers.get("x-should-retry")
    if signal is None:
        return None
    signal = signal.strip().lower()
    if signal == "true":
        return True
    if signal == "false":
        return False
    return None


def _should_retry(err: ErrorInfo | Exception, headers: Any = None) -> bool:
    """Whether *err* is retryable in principle (ignores attempt count/idempotency).

    The caller is responsible for gating read-timeouts to idempotent methods and
    for never retrying mid-stream.
    """
    override = _header_override(headers)
    if override is not None:
        return override
    if isinstance(err, ErrorInfo):
        status = err.status_code
        if status is not None and (status in _RETRY_STATUSES or status >= 500):
            return True
        return isinstance(err.error_code, int) and err.error_code in RETRYABLE_ERROR_CODES
    # A raw exception: connection failures (incl. timeouts) are retryable.
    return isinstance(err, APIConnectionError)


def _retry_after_seconds(headers: Any) -> float | None:
    """Honoured Retry-After hint (numeric or HTTP-date), clamped to a sane range."""
    if headers is None:
        return None
    seconds = _parse_retry_after(headers.get("Retry-After"))
    if seconds is None:
        raw_ms = headers.get("retry-after-ms")
        if raw_ms:
            try:
                seconds = float(raw_ms) / 1000.0
            except (TypeError, ValueError):
                seconds = None
    if seconds is not None and 0 <= seconds <= _MAX_RETRY_AFTER:
        return seconds
    return None


def _retry_timeout(attempt: int, headers: Any = None) -> float:
    """Seconds to wait before retry *attempt* (1-based).

    A valid server Retry-After wins; otherwise exponential backoff with 75-100%
    jitter, starting at 0.5s and capped at 8s.
    """
    hinted = _retry_after_seconds(headers)
    if hinted is not None:
        return hinted
    base = min(_INITIAL_BACKOFF * (2 ** max(attempt - 1, 0)), _MAX_BACKOFF)
    # Jitter in [0.75, 1.0) so concurrent clients de-synchronise their retries.
    return base * (1.0 - random.random() * 0.25)


__all__ = [
    "RETRYABLE_ERROR_CODES",
    "_retry_timeout",
    "_should_retry",
]
