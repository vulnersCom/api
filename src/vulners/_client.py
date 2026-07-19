"""The ``Vulners`` and ``AsyncVulners`` clients.

Two mirror clients: a synchronous one owning an ``httpx.Client`` and an async one
owning an ``httpx.AsyncClient``. Resources hang off each as ``cached_property``.
Both are re-exported from the package root — prefer ``from vulners import
Vulners, AsyncVulners`` in downstream code.
"""

from __future__ import annotations

import contextlib
from functools import cached_property
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from ._config import ClientConfig, resolve_config
from ._logging import install_key_redaction
from ._resources._async.archive import AsyncArchive
from ._resources._async.audit import AsyncAudit
from ._resources._async.misc import AsyncMisc
from ._resources._async.report import AsyncReport
from ._resources._async.search import AsyncSearch
from ._resources._async.stix import AsyncStix
from ._resources._async.subscriptions import AsyncSubscriptions
from ._resources._async.subscriptions_v4 import AsyncSubscriptionsV4
from ._resources._async.vscanner import AsyncVscanner
from ._resources._async.webhooks import AsyncWebhooks
from ._resources._sync.archive import Archive
from ._resources._sync.audit import Audit
from ._resources._sync.misc import Misc
from ._resources._sync.report import Report
from ._resources._sync.search import Search
from ._resources._sync.stix import Stix
from ._resources._sync.subscriptions import Subscriptions
from ._resources._sync.subscriptions_v4 import SubscriptionsV4
from ._resources._sync.vscanner import Vscanner
from ._resources._sync.webhooks import Webhooks
from ._transport_client_async import AsyncAPIClient
from ._transport_client_sync import SyncAPIClient
from ._types import NotGiven, not_given
from ._version import __version__

if TYPE_CHECKING:
    import httpx
    from pydantic import SecretStr


def _timeout_change(timeout: float | httpx.Timeout | None | NotGiven) -> dict[str, Any]:
    import httpx as _httpx

    if isinstance(timeout, NotGiven):
        return {}
    if timeout is None:
        return {"timeout": _httpx.Timeout(None)}
    resolved = timeout if isinstance(timeout, _httpx.Timeout) else _httpx.Timeout(timeout)
    return {"timeout": resolved}


class Vulners:
    """Synchronous Vulners API client."""

    def __init__(
        self,
        api_key: str | SecretStr | None = None,
        *,
        base_url: str | httpx.URL | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int | None = None,
        max_response_bytes: int | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Create a synchronous Vulners API client.

        Args:
            api_key: Your Vulners API key, as a ``str`` or ``pydantic.SecretStr``.
                If omitted or empty, falls back to the ``VULNERS_API_KEY``
                environment variable; when neither is set, ``VulnersError`` is
                raised. Get a free key at https://vulners.com.
            base_url: Override the API base URL. If omitted, falls back to the
                ``VULNERS_BASE_URL`` environment variable, then to
                ``https://vulners.com``.
            timeout: Per-request timeout, in seconds or as an ``httpx.Timeout``.
                ``None`` (the default) uses the built-in timeout profiles (a 60s
                read budget for normal calls, 300s for archive/bulk streams).
            max_retries: How many times to retry a failed request (connection
                errors and retryable status codes, honouring ``Retry-After``).
                ``None`` uses the built-in default (2).
            max_response_bytes: Optional cap on the decoded/decompressed response
                size, in bytes. ``None`` (the default) leaves decompression
                unbounded so legitimate multi-gigabyte archive downloads succeed;
                set it to guard against decompression-bomb amplification when
                pointing ``base_url`` at an untrusted host.
            http_client: Bring your own ``httpx.Client`` (e.g. for custom proxies,
                transport or connection limits). Its transport is wrapped with the
                SDK's credential-safety guard so the ``X-Api-Key`` is still
                stripped on cross-origin redirects. A client you pass is not
                closed by this client's ``close()``.
        """
        config = resolve_config(
            api_key=api_key,
            base_url=base_url,
            version=__version__,
            timeout=timeout,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
        )
        install_key_redaction(config.api_key.get_secret_value())
        self._api = SyncAPIClient(config, http_client=http_client)

    @property
    def config(self) -> ClientConfig:
        return self._api.config

    @property
    def base_url(self) -> httpx.URL:
        return self._api.config.base_url

    @cached_property
    def search(self) -> Search:
        return Search(self._api)

    @cached_property
    def audit(self) -> Audit:
        return Audit(self._api)

    @cached_property
    def archive(self) -> Archive:
        return Archive(self._api)

    @cached_property
    def misc(self) -> Misc:
        return Misc(self._api)

    @cached_property
    def report(self) -> Report:
        return Report(self._api)

    @cached_property
    def stix(self) -> Stix:
        return Stix(self._api)

    @cached_property
    def subscriptions(self) -> Subscriptions:
        return Subscriptions(self._api)

    @cached_property
    def subscriptions_v4(self) -> SubscriptionsV4:
        return SubscriptionsV4(self._api)

    @cached_property
    def webhooks(self) -> Webhooks:
        return Webhooks(self._api)

    @cached_property
    def vscanner(self) -> Vscanner:
        return Vscanner(self._api)

    def with_options(
        self,
        *,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | NotGiven = not_given,
        max_response_bytes: int | None | NotGiven = not_given,
    ) -> Vulners:
        """A copy of this client sharing the same connection pool, with overrides."""
        changes: dict[str, Any] = _timeout_change(timeout)
        if not isinstance(max_retries, NotGiven):
            changes["max_retries"] = max_retries
        if not isinstance(max_response_bytes, NotGiven):
            changes["max_response_bytes"] = max_response_bytes
        clone = object.__new__(type(self))
        # The shared httpx client is injected, so the clone never closes it; the
        # parent's pacing buckets are shared so rate-limit pacing is not reset.
        clone._api = SyncAPIClient(
            self._api.config.replace(**changes),
            http_client=self._api._client,
            buckets=self._api._buckets,
        )
        return clone

    @property
    def is_closed(self) -> bool:
        return self._api.is_closed

    def close(self) -> None:
        self._api.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort finalizer; interpreter shutdown can already have torn down
        # the httpx client, so swallow anything it raises.
        with contextlib.suppress(Exception):  # pragma: no cover
            self.close()


class AsyncVulners:
    """Asynchronous Vulners API client."""

    def __init__(
        self,
        api_key: str | SecretStr | None = None,
        *,
        base_url: str | httpx.URL | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int | None = None,
        max_response_bytes: int | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create an asynchronous Vulners API client.

        Args:
            api_key: Your Vulners API key, as a ``str`` or ``pydantic.SecretStr``.
                If omitted or empty, falls back to the ``VULNERS_API_KEY``
                environment variable; when neither is set, ``VulnersError`` is
                raised. Get a free key at https://vulners.com.
            base_url: Override the API base URL. If omitted, falls back to the
                ``VULNERS_BASE_URL`` environment variable, then to
                ``https://vulners.com``.
            timeout: Per-request timeout, in seconds or as an ``httpx.Timeout``.
                ``None`` (the default) uses the built-in timeout profiles (a 60s
                read budget for normal calls, 300s for archive/bulk streams).
            max_retries: How many times to retry a failed request (connection
                errors and retryable status codes, honouring ``Retry-After``).
                ``None`` uses the built-in default (2).
            max_response_bytes: Optional cap on the decoded/decompressed response
                size, in bytes. ``None`` (the default) leaves decompression
                unbounded so legitimate multi-gigabyte archive downloads succeed;
                set it to guard against decompression-bomb amplification when
                pointing ``base_url`` at an untrusted host.
            http_client: Bring your own ``httpx.AsyncClient`` (e.g. for custom
                proxies, transport or connection limits). Its transport is wrapped
                with the SDK's credential-safety guard so the ``X-Api-Key`` is
                still stripped on cross-origin redirects. A client you pass is not
                closed by this client's ``aclose()``.
        """
        config = resolve_config(
            api_key=api_key,
            base_url=base_url,
            version=__version__,
            timeout=timeout,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
        )
        install_key_redaction(config.api_key.get_secret_value())
        self._api = AsyncAPIClient(config, http_client=http_client)

    @property
    def config(self) -> ClientConfig:
        return self._api.config

    @property
    def base_url(self) -> httpx.URL:
        return self._api.config.base_url

    @cached_property
    def search(self) -> AsyncSearch:
        return AsyncSearch(self._api)

    @cached_property
    def audit(self) -> AsyncAudit:
        return AsyncAudit(self._api)

    @cached_property
    def archive(self) -> AsyncArchive:
        return AsyncArchive(self._api)

    @cached_property
    def misc(self) -> AsyncMisc:
        return AsyncMisc(self._api)

    @cached_property
    def report(self) -> AsyncReport:
        return AsyncReport(self._api)

    @cached_property
    def stix(self) -> AsyncStix:
        return AsyncStix(self._api)

    @cached_property
    def subscriptions(self) -> AsyncSubscriptions:
        return AsyncSubscriptions(self._api)

    @cached_property
    def subscriptions_v4(self) -> AsyncSubscriptionsV4:
        return AsyncSubscriptionsV4(self._api)

    @cached_property
    def webhooks(self) -> AsyncWebhooks:
        return AsyncWebhooks(self._api)

    @cached_property
    def vscanner(self) -> AsyncVscanner:
        return AsyncVscanner(self._api)

    def with_options(
        self,
        *,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | NotGiven = not_given,
        max_response_bytes: int | None | NotGiven = not_given,
    ) -> AsyncVulners:
        """A copy of this client sharing the same connection pool, with overrides."""
        changes: dict[str, Any] = _timeout_change(timeout)
        if not isinstance(max_retries, NotGiven):
            changes["max_retries"] = max_retries
        if not isinstance(max_response_bytes, NotGiven):
            changes["max_response_bytes"] = max_response_bytes
        clone = object.__new__(type(self))
        # The shared httpx client is injected, so the clone never closes it; the
        # parent's pacing buckets are shared so rate-limit pacing is not reset.
        clone._api = AsyncAPIClient(
            self._api.config.replace(**changes),
            http_client=self._api._client,
            buckets=self._api._buckets,
        )
        return clone

    @property
    def is_closed(self) -> bool:
        return self._api.is_closed

    async def aclose(self) -> None:
        await self._api.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


__all__ = ["AsyncVulners", "Vulners"]
