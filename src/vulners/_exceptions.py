"""Exception hierarchy and server-error normalization for the v4 core.

A two-axis model: the class is chosen first by the Vulners ``errorCode`` carried
in the body (:data:`ERROR_CODE_MAP`), then by HTTP status as a fallback. The
error surface is normalized into an :class:`ErrorInfo` by :func:`_extract_error`,
which understands every observed response shape:

* v3 envelope ``{"result": "error", "data": {"error", "errorCode"}}`` — which
  can arrive with **HTTP 200** (a malformed v3 parameter, or a v4 business error
  returned in the v3 envelope);
* v4 validation ``{"errors": [{type, loc, msg, input}]}`` — HTTP 400, the server
  echoes the whole request in ``input`` (so bodies are redacted before logging);
* FastAPI validation ``{"detail": [...]}`` — HTTP 422;
* 404 ``{"data": {"error": ...}}`` — no ``errorCode``;
* no key — HTTP 403 ``text/html`` (Cloudflare) — a non-JSON body.

The hierarchy is new, but it stays catchable by legacy handlers: server-reported
failures (:class:`APIError` and below) also inherit the v3
:class:`~vulners.base.VulnersApiError`, so a ``try/except VulnersApiError`` written
for the legacy client keeps working against the v4 client. Transport-side failures
(:class:`APIConnectionError`/:class:`APITimeoutError`) and response-shape failures
(:class:`APIResponseValidationError`) are deliberate siblings of ``APIError`` —
the legacy client surfaced those as raw ``httpx`` exceptions, never as
``VulnersApiError``, and the v4 tree preserves that meaning: ``APIError`` ==
"the server told us something went wrong".
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from .base import VulnersApiError as _LegacyVulnersApiError

# ---------------------------------------------------------------------------
# Secret redaction (ported from vulners.base)
# ---------------------------------------------------------------------------

# Field names (compared case-insensitively) whose value in an error payload is
# API-key material and must never reach a log/APM through str()/repr().
_SECRET_FIELD_NAMES = frozenset({"apikey", "x-api-key"})


def _redact_secret(obj: Any, secret: str | None = None) -> Any:
    """Return *obj* with API-key material masked, for safe error stringification.

    A dict entry whose key names the credential (``apiKey`` / ``X-Api-Key``) has
    its value replaced with ``"[REDACTED]"``; when the real key value is known,
    any string that contains it is masked too. A payload that carries no key is
    returned with equal contents, so an ordinary error message stays
    byte-identical.
    """
    if isinstance(obj, dict):
        return {
            k: (
                "[REDACTED]"
                if isinstance(k, str) and k.lower() in _SECRET_FIELD_NAMES
                else _redact_secret(v, secret)
            )
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_secret(v, secret) for v in obj]
    if isinstance(obj, str) and secret and secret in obj:
        return obj.replace(secret, "[REDACTED]")
    return obj


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header value into seconds, or None.

    Accepts either a delta-seconds number or an HTTP-date (RFC 9110). Only a
    finite, non-negative value is returned; a past date collapses to 0.0 and
    anything unparseable to None.
    """
    if not value:
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        pass
    else:
        if math.isfinite(seconds) and seconds >= 0:
            return seconds
        return None
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if (
        when is None
    ):  # pragma: no cover - parsedate_to_datetime raises (never returns None) on py>=3.10
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)


def _extract_message(data: Any) -> tuple[Any, str | None]:
    """Best-effort ``(error_code, message)`` from a Vulners error payload.

    Reads the human-readable problem description from the several error shapes
    (v3 envelope, v4 ``errors``/``detail`` lists, a plain string) without echoing
    the request ``input`` a validation item carries (it can repeat sensitive
    request data).
    """
    if isinstance(data, str):
        return None, (data or None)
    if not isinstance(data, dict):
        return None, None
    # Unwrap a full v3 envelope {"result": ..., "data": {"error": ...}}.
    inner = data.get("data")
    if isinstance(inner, dict) and ("error" in inner or "errorCode" in inner):
        data = inner
    if "error" in data:
        err = data["error"]
        code = data.get("errorCode")
        message = err if isinstance(err, str) else str(err)
        if code is not None:
            message = f"{message} (errorCode {code})"
        return code, message
    items = data.get("errors") or data.get("detail")
    if isinstance(items, list) and items:
        parts = []
        for item in items:
            if not isinstance(item, dict):
                continue
            loc = ".".join(str(x) for x in item.get("loc", ()))
            msg = str(item.get("msg", "")).strip()
            parts.append(f"{msg} at {loc}" if loc else msg)
        parts = [p for p in parts if p]
        if parts:
            return None, "; ".join(parts)
    return None, None


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class VulnersError(Exception):
    """Root of every error the SDK raises."""


class APIError(VulnersError, _LegacyVulnersApiError):
    """The server reported a failure.

    Carries what the pipeline could recover about the failure. ``status_code`` is
    the HTTP status (``None`` only in synthetic cases); ``error_code`` is the
    Vulners ``errorCode`` when the body carried one; ``data`` is the full,
    secret-redacted error payload; ``retry_after`` is the parsed Retry-After
    hint; ``request_id`` is the server request correlation id when a response
    header carried one; ``validation_errors`` holds the structured items of a v4
    validation failure (each without the ``input`` echo).

    Also inherits the legacy :class:`~vulners.base.VulnersApiError`, so v3-era
    ``except VulnersApiError`` handlers catch v4 server errors during migration
    (the legacy class itself is untouched). ``http_status`` and ``body`` are the
    v3-compatible spellings of ``status_code`` and ``data``.
    """

    status_code: int | None
    error_code: int | str | None
    message: str | None
    data: Any
    retry_after: float | None
    request_id: str | None
    validation_errors: list[dict[str, Any]]

    def __init__(
        self,
        message: str | None = None,
        *,
        status_code: int | None = None,
        error_code: int | str | None = None,
        data: Any = None,
        retry_after: float | None = None,
        request_id: str | None = None,
        validation_errors: list[dict[str, Any]] | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.data = data
        self.retry_after = retry_after
        self.request_id = request_id
        self.validation_errors = validation_errors or []
        # Direct Exception.__init__: the legacy VulnersApiError.__init__ in the
        # MRO has an incompatible (http_status, data) signature and must not run.
        Exception.__init__(self, message if message is not None else data)

    # The legacy base declares http_status as a writeable attribute; here it is an
    # intentional read-only v3-compat alias of status_code (never assigned), which
    # is safe but narrower than the base attr, so the override check is suppressed.
    @property
    def http_status(self) -> int | None:  # type: ignore[override]
        """v3-compatible alias of :attr:`status_code`."""
        return self.status_code

    @property
    def body(self) -> Any:
        """Alias of :attr:`data` (the redacted error payload)."""
        return self.data


class APIConnectionError(VulnersError):
    """The request never got a response (DNS/connect/read failure).

    A sibling of :class:`APIError`, not a subclass: no server was heard from, so
    there is no status/errorCode surface — and legacy ``except VulnersApiError``
    deliberately does not match (v3 surfaced these as raw httpx errors too).
    """

    message: str
    data: Any

    def __init__(self, message: str = "Connection error.", *, data: Any = None) -> None:
        self.message = message
        self.data = data
        super().__init__(message)


class APITimeoutError(APIConnectionError):
    """The request timed out before a response was received."""

    def __init__(self, message: str = "Request timed out.") -> None:
        super().__init__(message)


class APIResponseValidationError(VulnersError):
    """A 2xx response body did not match what the endpoint promised.

    A sibling of :class:`APIError`: the server did not report an error — the
    response shape itself is what failed. ``status_code`` is informational (the
    2xx status the malformed body arrived with).
    """

    message: str
    data: Any
    status_code: int | None

    def __init__(self, message: str, *, status_code: int | None = None, data: Any = None) -> None:
        self.message = message
        self.status_code = status_code
        self.data = data
        super().__init__(message)


class APIStatusError(APIError):
    """A non-success HTTP status (or a 200 carrying an error envelope).

    ``status_code`` is always populated for this branch (never ``None``).
    """


class BadRequestError(APIStatusError):
    """400 (or a v3 bad-parameter error)."""


class AuthenticationError(APIStatusError):
    """401 — the API key is missing or invalid."""


class PermissionDeniedError(APIStatusError):
    """403 — the key is valid but not permitted (or blocked upstream)."""


class NotFoundError(APIStatusError):
    """404 — the resource does not exist."""


class ConflictError(APIStatusError):
    """409 — the request conflicts with the current server state."""


class UnprocessableEntityError(APIStatusError):
    """422 — request validation failed."""


class RateLimitError(APIStatusError):
    """429 — too many requests; inspect ``retry_after``."""


class InternalServerError(APIStatusError):
    """5xx — the server failed to handle the request."""


# Plan-vocabulary aliases: the architecture names these ValidationError and
# ServerError; the primary names follow the wider SDK convention. Both spellings
# are importable and identical classes.
ValidationError = UnprocessableEntityError
ServerError = InternalServerError


class SearchWindowExceeded(VulnersError, ValueError):
    """The search page window (offset + limit > 10000) was exceeded.

    Derives from :class:`ValueError` too, so existing ``except ValueError``
    handlers around pagination keep matching.
    """


# Curated map of Vulners ``errorCode`` -> exception class. The server does not
# yet publish a machine-readable taxonomy, so this is a small hand-verified set;
# unknown codes fall back to the HTTP-status mapping in _make_error.
ERROR_CODE_MAP: dict[int, type[APIStatusError]] = {
    # "Missing parameters" — the request lacked a required field.
    103: BadRequestError,
    # "Wrong/invalid parameter value".
    104: BadRequestError,
}


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ErrorInfo:
    """Normalized description of a failed response, before it becomes an error."""

    status_code: int | None
    error_code: int | str | None = None
    message: str | None = None
    data: Any = field(default=None)
    retry_after: float | None = None
    request_id: str | None = None
    validation_errors: tuple[dict[str, Any], ...] = ()

    def __repr__(self) -> str:
        # Explicit repr (not dataclass-generated) so this frozen record is not
        # picked up as a codegen endpoint by the test suite's scanner.
        return (
            f"ErrorInfo(status_code={self.status_code}, error_code={self.error_code!r}, "
            f"message={self.message!r})"
        )


def _has_error_markers(body: Any) -> bool:
    """True when a parsed body carries an error shape regardless of HTTP status."""
    if isinstance(body, str):
        return False
    if not isinstance(body, dict):
        return False
    if body.get("result") == "error":
        return True
    inner = body.get("data")
    if isinstance(inner, dict) and "error" in inner:
        return True
    if "error" in body:
        return True
    items = body.get("errors") or body.get("detail")
    return isinstance(items, list) and bool(items)


def _extract_error(
    status: int,
    headers: Any,
    parsed_body: Any,
    *,
    secret: str | None = None,
) -> ErrorInfo | None:
    """Return an :class:`ErrorInfo` if the response is an error, else ``None``.

    Called **before** the status check so an error carried in an HTTP 200 body
    (a known Vulners quirk) is not mistaken for success. ``headers`` is anything
    with a case-insensitive ``.get`` (an ``httpx.Headers``); ``parsed_body`` is
    the decoded JSON (dict/list) or the decoded text of a non-JSON body.
    """
    is_http_error = status >= 400
    if not is_http_error and not _has_error_markers(parsed_body):
        return None
    error_code, message = _extract_message(parsed_body)
    # Mask the key through the same primitive as ``data`` so a server that echoes
    # it into the error text can never leak it via str(exc) while data is redacted.
    message = _redact_secret(message, secret)
    retry_after = None
    request_id = None
    if headers is not None:
        retry_after = _parse_retry_after(headers.get("Retry-After"))
        request_id = headers.get("X-Request-Id") or headers.get("X-Vulners-Request-Id")
    return ErrorInfo(
        status_code=status,
        error_code=error_code,
        message=message,
        data=_redact_secret(parsed_body, secret),
        retry_after=retry_after,
        request_id=request_id,
        validation_errors=_validation_items(parsed_body, secret),
    )


def _validation_items(body: Any, secret: str | None) -> tuple[dict[str, Any], ...]:
    """Structured v4 validation items (``errors``/``detail``), without the
    ``input`` echo — the server repeats the whole request there, which can carry
    sensitive data and belongs in neither logs nor exception payloads."""
    if not isinstance(body, dict):
        return ()
    items = body.get("errors") or body.get("detail")
    if not isinstance(items, list):
        return ()
    return tuple(
        {k: _redact_secret(v, secret) for k, v in item.items() if k != "input"}
        for item in items
        if isinstance(item, dict)
    )


def _status_class(status: int | None) -> type[APIStatusError]:
    if status is None:
        return APIStatusError
    if status == 400:
        return BadRequestError
    if status == 401:
        return AuthenticationError
    if status == 403:
        return PermissionDeniedError
    if status == 404:
        return NotFoundError
    if status == 409:
        return ConflictError
    if status == 422:
        return UnprocessableEntityError
    if status == 429:
        return RateLimitError
    if status >= 500:
        return InternalServerError
    return APIStatusError


def _make_error(info: ErrorInfo) -> APIStatusError:
    """Build the most specific exception for *info* (errorCode first, then status)."""
    cls: type[APIStatusError] | None = None
    if isinstance(info.error_code, int):
        cls = ERROR_CODE_MAP.get(info.error_code)
    if cls is None:
        cls = _status_class(info.status_code)
    return cls(
        info.message,
        status_code=info.status_code,
        error_code=info.error_code,
        data=info.data,
        retry_after=info.retry_after,
        request_id=info.request_id,
        validation_errors=list(info.validation_errors),
    )


__all__ = [
    "ERROR_CODE_MAP",
    "APIConnectionError",
    "APIError",
    "APIResponseValidationError",
    "APIStatusError",
    "APITimeoutError",
    "AuthenticationError",
    "BadRequestError",
    "ConflictError",
    "ErrorInfo",
    "InternalServerError",
    "NotFoundError",
    "PermissionDeniedError",
    "RateLimitError",
    "SearchWindowExceeded",
    "ServerError",
    "UnprocessableEntityError",
    "ValidationError",
    "VulnersError",
]
