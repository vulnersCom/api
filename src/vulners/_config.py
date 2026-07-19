"""Client configuration, auth resolution and the network-policy defaults.

The API key is held as a :class:`pydantic.SecretStr` so it never leaks through a
``repr`` of the config or the client. Configuration precedence for the key and
base URL is: explicit argument, then environment (``VULNERS_API_KEY`` /
``VULNERS_BASE_URL``), then the built-in default.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Literal

import httpx
from pydantic import SecretStr

from ._exceptions import VulnersError

DEFAULT_BASE_URL = "https://vulners.com"

# Timeout profiles (R#12): a generous read budget by default and a much larger
# one for archive/bulk downloads that stream for a long time.
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=30.0, pool=10.0)
ARCHIVE_TIMEOUT = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=10.0)

DEFAULT_LIMITS = httpx.Limits(max_connections=1000, max_keepalive_connections=100)

DEFAULT_MAX_RETRIES = 2
# Connection-phase retries handed to the httpx transport (as v3's retry_count).
DEFAULT_CONNECT_RETRIES = 3
DEFAULT_MAX_RATE_LIMIT_WAIT = 60.0

TimeoutProfile = Literal["default", "archive"]


@dataclasses.dataclass(frozen=True)
class ClientConfig:
    """Immutable resolved configuration for a client instance.

    Copy-with-overrides via :meth:`replace` backs ``client.with_options(...)``.
    """

    api_key: SecretStr
    base_url: httpx.URL
    user_agent: str
    # httpx.Timeout / httpx.Limits are unhashable, so use default_factory.
    timeout: httpx.Timeout = dataclasses.field(default_factory=lambda: DEFAULT_TIMEOUT)
    archive_timeout: httpx.Timeout = dataclasses.field(default_factory=lambda: ARCHIVE_TIMEOUT)
    max_retries: int = DEFAULT_MAX_RETRIES
    connect_retries: int = DEFAULT_CONNECT_RETRIES
    limits: httpx.Limits = dataclasses.field(default_factory=lambda: DEFAULT_LIMITS)
    max_rate_limit_wait: float = DEFAULT_MAX_RATE_LIMIT_WAIT
    max_response_bytes: int | None = None
    follow_redirects: bool = True

    def timeout_for(self, profile: TimeoutProfile) -> httpx.Timeout:
        return self.archive_timeout if profile == "archive" else self.timeout

    def replace(self, **changes: object) -> ClientConfig:
        return dataclasses.replace(self, **changes)  # type: ignore[arg-type]

    def __repr__(self) -> str:
        # Explicit (not the dataclass-generated one) so the SecretStr key is the
        # only key material shown and it is masked by SecretStr's own repr.
        return (
            f"ClientConfig(api_key={self.api_key!r}, base_url={self.base_url!r}, "
            f"max_retries={self.max_retries}, max_response_bytes={self.max_response_bytes})"
        )


def _coerce_key(api_key: str | SecretStr | None) -> SecretStr | None:
    if api_key is None:
        return None
    if isinstance(api_key, SecretStr):
        return api_key if api_key.get_secret_value() else None
    return SecretStr(api_key) if api_key else None


def resolve_config(
    *,
    api_key: str | SecretStr | None = None,
    base_url: str | httpx.URL | None = None,
    version: str = "unknown",
    timeout: float | httpx.Timeout | None = None,
    max_retries: int | None = None,
    max_response_bytes: int | None = None,
) -> ClientConfig:
    """Resolve constructor arguments and environment into a :class:`ClientConfig`."""
    key = _coerce_key(api_key)
    if key is None:
        env_key = os.environ.get("VULNERS_API_KEY", "").strip()
        key = SecretStr(env_key) if env_key else None
    if key is None:
        raise VulnersError(
            "No API key provided. Pass api_key= or set the VULNERS_API_KEY "
            "environment variable. Get a free key at https://vulners.com"
        )

    resolved_base = base_url or os.environ.get("VULNERS_BASE_URL") or DEFAULT_BASE_URL

    config = ClientConfig(
        api_key=key,
        base_url=httpx.URL(str(resolved_base)),
        user_agent=f"Vulners Python API {version}",
        max_response_bytes=max_response_bytes,
    )
    changes: dict[str, object] = {}
    if timeout is not None:
        changes["timeout"] = (
            timeout if isinstance(timeout, httpx.Timeout) else httpx.Timeout(timeout)
        )
    if max_retries is not None:
        changes["max_retries"] = max_retries
    return config.replace(**changes) if changes else config


__all__ = [
    "ARCHIVE_TIMEOUT",
    "DEFAULT_BASE_URL",
    "DEFAULT_LIMITS",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_TIMEOUT",
    "ClientConfig",
    "TimeoutProfile",
    "resolve_config",
]
