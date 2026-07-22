"""Client configuration, auth resolution and the network-policy defaults.

The API key is held as a :class:`pydantic.SecretStr` so it never leaks through a
``repr`` of the config or the client. Configuration precedence for the key and
base URL is: explicit argument, then environment (``VULNERS_API_KEY`` /
``VULNERS_BASE_URL``), then the built-in default.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import ssl
import urllib.request
from collections.abc import Callable
from typing import Any, Literal

import httpx
from pydantic import SecretStr

from ._exceptions import VulnersError

DEFAULT_BASE_URL = "https://vulners.com"

# Timeout profiles: a generous read budget by default and a much larger one for
# archive/bulk downloads that stream for a long time.
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=30.0, pool=10.0)
ARCHIVE_TIMEOUT = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=10.0)

DEFAULT_LIMITS = httpx.Limits(max_connections=1000, max_keepalive_connections=100)

DEFAULT_MAX_RETRIES = 2
# Connection-phase retries handed to the httpx transport (as v3's retry_count).
DEFAULT_CONNECT_RETRIES = 3
DEFAULT_MAX_RATE_LIMIT_WAIT = 60.0

TimeoutProfile = Literal["default", "archive"]


def _is_local_host(url: httpx.URL) -> bool:
    """True for a loopback/private/link-local host (safe to reach over plain HTTP)."""
    host = url.host
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def resolve_proxy(config: ClientConfig) -> str | httpx.Proxy | None:
    """The proxy for the SDK-owned transport.

    An explicit ``proxy=`` wins. Otherwise, when ``trust_env`` is set, honour the
    environment proxy for ``base_url`` (``HTTPS_PROXY`` / ``HTTP_PROXY`` /
    ``ALL_PROXY``, respecting ``NO_PROXY``). httpx would build these as *client*
    mounts, but the SDK passes an explicit transport — which bypasses that mount
    building — so the env proxy is resolved here or it would be silently ignored.
    """
    if config.proxy is not None:
        return config.proxy
    if not config.trust_env:
        return None
    # base_url always has a host (validated in __post_init__). proxy_bypass_environment
    # is a real, long-standing stdlib function that typeshed happens not to stub.
    if urllib.request.proxy_bypass_environment(config.base_url.host):  # type: ignore[attr-defined]
        return None
    proxies = urllib.request.getproxies_environment()
    return proxies.get(config.base_url.scheme) or proxies.get("all")


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
    # HTTP/2 for the SDK-owned transport. On by default (h2 is a core dependency):
    # request multiplexing over one connection speeds up concurrent API calls.
    # Pass http2=False for huge single-stream archive downloads, where HTTP/1.1
    # avoids h2's fixed flow-control window overhead on one long body.
    http2: bool = True
    # Convenience transport settings for the SDK-owned client. They cannot be
    # combined with a bring-your-own http_client (the client constructor rejects
    # that mix), because httpx ignores client-level verify/proxy once an explicit
    # transport is passed — so these ride on the SDK's inner transport instead.
    proxy: str | httpx.Proxy | None = None
    verify: bool | str | ssl.SSLContext = True
    trust_env: bool = True
    # Observation hooks. before_request/after_response are wired as httpx
    # event_hooks on the SDK-owned client; on_error fires in the request loop
    # when a request finally fails (after retries are exhausted). The client
    # constructors normalize user input into these tuples (the async client
    # adapts sync callables to async ones).
    before_request: tuple[Callable[..., Any], ...] = ()
    after_response: tuple[Callable[..., Any], ...] = ()
    on_error: tuple[Callable[..., Any], ...] = ()

    def __post_init__(self) -> None:
        # Validate on construction *and* on every ``replace()`` (with_options),
        # so a bad override fails fast here instead of deep inside httpx or as
        # silently wrong behaviour later.
        if self.max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {self.max_retries}")
        if self.connect_retries < 0:
            raise ValueError(f"connect_retries must be >= 0, got {self.connect_retries}")
        if self.max_response_bytes is not None and self.max_response_bytes < 1:
            raise ValueError(
                f"max_response_bytes must be >= 1 or None, got {self.max_response_bytes}"
            )
        if self.max_rate_limit_wait < 0:
            raise ValueError(f"max_rate_limit_wait must be >= 0, got {self.max_rate_limit_wait}")
        if self.base_url.scheme not in ("http", "https"):
            raise ValueError(
                f"base_url scheme must be http or https, got {self.base_url.scheme!r}"
            )
        if not self.base_url.host:
            raise ValueError(f"base_url must include a host, got {str(self.base_url)!r}")
        if self.base_url.path not in ("", "/"):
            raise ValueError(
                f"base_url must not carry a path prefix ({self.base_url.path!r}); "
                "reverse-proxy path prefixes are not supported — point base_url at the "
                "host root (e.g. https://host, not https://host/prefix/)"
            )
        # The API key rides in the X-Api-Key header on every request; over plain
        # HTTP to a public host it would cross the network in cleartext. Allow http
        # only for loopback/private hosts (local dev, on-prem); require https otherwise.
        if self.base_url.scheme != "https" and not _is_local_host(self.base_url):
            raise ValueError(
                f"refusing to send the API key over plain HTTP to a public host "
                f"({self.base_url.host!r}); use https, or point base_url at a "
                "loopback/private host for local development"
            )

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


def _coerce_timeout(value: float | httpx.Timeout | None) -> httpx.Timeout:
    """Normalize a scalar / ``None`` / ``httpx.Timeout`` into an ``httpx.Timeout``.

    Single source of truth for timeout coercion, shared by construction, the
    per-request override and ``with_options`` (``None`` means "no timeout").
    """
    if value is None:
        return httpx.Timeout(None)
    return value if isinstance(value, httpx.Timeout) else httpx.Timeout(value)


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
    http2: bool = True,
    proxy: str | httpx.Proxy | None = None,
    verify: bool | str | ssl.SSLContext = True,
    trust_env: bool = True,
    before_request: tuple[Callable[..., Any], ...] = (),
    after_response: tuple[Callable[..., Any], ...] = (),
    on_error: tuple[Callable[..., Any], ...] = (),
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
        http2=http2,
        proxy=proxy,
        verify=verify,
        trust_env=trust_env,
        before_request=before_request,
        after_response=after_response,
        on_error=on_error,
    )
    changes: dict[str, object] = {}
    if timeout is not None:
        changes["timeout"] = _coerce_timeout(timeout)
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
    "_coerce_timeout",
    "resolve_config",
]
