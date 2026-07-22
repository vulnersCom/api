"""The ``Vulners`` and ``AsyncVulners`` clients.

Two mirror clients: a synchronous one owning an ``httpx.Client`` and an async one
owning an ``httpx.AsyncClient``. Resources hang off each as ``cached_property``.
Both are re-exported from the package root — prefer ``from vulners import
Vulners, AsyncVulners`` in downstream code.
"""

from __future__ import annotations

import contextlib
import inspect
from collections.abc import Callable, Mapping, Sequence
from functools import cached_property
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from ._config import ClientConfig, _coerce_timeout, resolve_config
from ._logging import install_key_redaction
from ._resources._async.archive import AsyncArchive
from ._resources._async.audit import AsyncAudit
from ._resources._async.documents import Documents as AsyncDocuments
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
from ._resources._sync.documents import Documents
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
    import ssl

    import httpx
    from pydantic import SecretStr

# A hook is any callable taking the request / response / error as its single
# argument; each may be passed alone or as a sequence. The async client also
# accepts async callables (sync ones are adapted).
Hook = Callable[..., Any]


def _hook_tuple(value: Hook | Sequence[Hook] | None) -> tuple[Hook, ...]:
    """Normalize a single callable / sequence / ``None`` into a tuple of hooks."""
    if value is None:
        return ()
    if callable(value):
        return (value,)
    return tuple(value)


def _sync_hooks(value: Hook | Sequence[Hook] | None, name: str) -> tuple[Hook, ...]:
    """Hooks for the sync client: plain callables only (async ones cannot run)."""
    hooks = _hook_tuple(value)
    for hook in hooks:
        if inspect.iscoroutinefunction(hook):
            raise TypeError(
                f"{name} hook {hook!r} is async; the synchronous Vulners client only "
                "accepts plain callables — use AsyncVulners for async hooks."
            )
    return hooks


def _async_hooks(value: Hook | Sequence[Hook] | None) -> tuple[Hook, ...]:
    """Hooks for the async client: every hook is adapted to an async callable.

    httpx event hooks on an ``AsyncClient`` (and the async request loop) await
    their hooks, while callers may hand us plain sync callables; the adapter
    awaits an awaitable result, so both flavours work.
    """

    def _adapt(hook: Hook) -> Hook:
        async def _call(arg: Any) -> None:
            result = hook(arg)
            if inspect.isawaitable(result):
                await result

        return _call

    return tuple(_adapt(hook) for hook in _hook_tuple(value))


def _check_byo_conflicts(
    http_client: object,
    proxy: object,
    verify: object,
    trust_env: bool,
    before_request: object,
    after_response: object,
) -> None:
    """Reject SDK-owned-transport settings when the caller brings their own client.

    ``proxy=``/``verify=``/``trust_env=`` configure the transport the SDK builds,
    and ``before_request=``/``after_response=`` are wired as httpx event hooks on
    the SDK-owned client; silently ignoring them next to ``http_client=`` would
    hide misconfiguration, so the mix raises. (``on_error=`` runs in the SDK's
    request loop and works with any client, so it is allowed.)
    """
    if http_client is None:
        return
    if (
        proxy is not None
        or verify is not True
        or trust_env is not True
        or before_request is not None
        or after_response is not None
    ):
        raise ValueError(
            "proxy=, verify=, trust_env=, before_request= and after_response= "
            "configure the HTTP client the SDK builds and cannot be combined with "
            "http_client=; configure your own httpx client instead."
        )


def _timeout_change(timeout: float | httpx.Timeout | None | NotGiven) -> dict[str, Any]:
    if isinstance(timeout, NotGiven):
        return {}
    return {"timeout": _coerce_timeout(timeout)}


def _option_changes(
    timeout: float | httpx.Timeout | None | NotGiven,
    max_retries: int | NotGiven,
    max_response_bytes: int | None | NotGiven,
) -> dict[str, Any]:
    """Assemble the config-override dict for ``with_options`` (shared sync/async)."""
    changes: dict[str, Any] = _timeout_change(timeout)
    if not isinstance(max_retries, NotGiven):
        changes["max_retries"] = max_retries
    if not isinstance(max_response_bytes, NotGiven):
        changes["max_response_bytes"] = max_response_bytes
    return changes


class Vulners:
    """Synchronous Vulners API client."""

    # Set on a with_options() clone to keep its pool's owner alive (the clone shares
    # but does not own the pool). Deliberately no class-level default: it must be
    # *absent* on a top-level client so with_options's getattr(self, "_owner", self)
    # captures the parent, not None.
    _owner: Vulners | None

    def __init__(
        self,
        api_key: str | SecretStr | None = None,
        *,
        base_url: str | httpx.URL | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int | None = None,
        max_response_bytes: int | None = None,
        http2: bool = True,
        proxy: str | httpx.Proxy | None = None,
        verify: bool | str | ssl.SSLContext = True,
        trust_env: bool = True,
        before_request: Hook | Sequence[Hook] | None = None,
        after_response: Hook | Sequence[Hook] | None = None,
        on_error: Hook | Sequence[Hook] | None = None,
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
            http2: Negotiate HTTP/2 on the SDK-owned transport (default ``True``;
                ``h2`` is a core dependency, so no extra is needed). HTTP/2
                multiplexes many concurrent API calls over one connection. Pass
                ``http2=False`` to force HTTP/1.1 — preferable for a huge
                single-stream archive download, where HTTP/1.1 avoids h2's
                flow-control window overhead on one long body. Ignored when you
                pass your own ``http_client`` (set it on that client instead).
            proxy: Route all SDK traffic through this proxy (URL string or
                ``httpx.Proxy``). Applies to the SDK-owned transport; cannot be
                combined with ``http_client=``.
            verify: TLS verification for the SDK-owned transport: ``True``
                (default), ``False``, a CA-bundle path, or an
                ``ssl.SSLContext``. Cannot be combined with ``http_client=``.
            trust_env: Whether the SDK-owned client trusts environment settings —
                TLS (``SSL_CERT_FILE``/``SSL_CERT_DIR``) and proxies
                (``HTTPS_PROXY``/``HTTP_PROXY``/``ALL_PROXY``, honouring
                ``NO_PROXY``) when ``proxy=`` is not given. Cannot be combined
                with ``http_client=``.
            before_request: Callable (or sequence of callables) invoked with the
                ``httpx.Request`` before it is sent (an httpx request event
                hook on the SDK-owned client).
            after_response: Callable (or sequence of callables) invoked with the
                ``httpx.Response`` when it arrives (an httpx response event
                hook on the SDK-owned client).
            on_error: Callable (or sequence of callables) invoked with the final
                error when a request fails for good (after retries). Exceptions
                raised by a hook propagate to the caller.
            http_client: Bring your own ``httpx.Client`` (e.g. for custom proxies,
                transport or connection limits). Its transport is wrapped with the
                SDK's credential-safety guard — scoped to the SDK's own requests —
                so the ``X-Api-Key`` is still stripped on cross-origin redirects
                while your application's own traffic through the shared client is
                left untouched. A client you pass is not closed by this client's
                ``close()``.
        """
        _check_byo_conflicts(
            http_client, proxy, verify, trust_env, before_request, after_response
        )
        config = resolve_config(
            api_key=api_key,
            base_url=base_url,
            version=__version__,
            timeout=timeout,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
            http2=http2,
            proxy=proxy,
            verify=verify,
            trust_env=trust_env,
            before_request=_sync_hooks(before_request, "before_request"),
            after_response=_sync_hooks(after_response, "after_response"),
            on_error=_sync_hooks(on_error, "on_error"),
        )
        install_key_redaction(config.api_key.get_secret_value())
        self._api = SyncAPIClient(config, http_client=http_client)

    @property
    def config(self) -> ClientConfig:
        """The resolved, immutable client configuration."""
        return self._api.config

    @property
    def base_url(self) -> httpx.URL:
        """The API base URL requests are sent to."""
        return self._api.config.base_url

    @cached_property
    def search(self) -> Search:
        return Search(self._api)

    @cached_property
    def documents(self) -> Documents:
        return Documents(self._api)

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

    @property
    def reports(self) -> Report:
        """Alias of :attr:`report` (the primary plural name)."""
        return self.report

    @cached_property
    def stix(self) -> Stix:
        return Stix(self._api)

    @cached_property
    def subscriptions(self) -> SubscriptionsV4:
        """The v4 subscriptions CRUD (``list``/``get``/``create``/``update``/``delete``)."""
        return SubscriptionsV4(self._api)

    @property
    def subscriptions_v4(self) -> SubscriptionsV4:
        # Deprecated alias of `subscriptions`, kept for the pre-release window.
        return self.subscriptions

    @cached_property
    def subscriptions_email(self) -> Subscriptions:
        """The legacy v3 email subscriptions (moved here from ``subscriptions``)."""
        return Subscriptions(self._api)

    @cached_property
    def webhooks(self) -> Webhooks:
        return Webhooks(self._api)

    @cached_property
    def vscanner(self) -> Vscanner:
        return Vscanner(self._api)

    # -- escape hatches ----------------------------------------------------
    # Thin, untyped access to any API path (e.g. a legacy v3 endpoint without a
    # dedicated method). These route through the same core pipeline as the typed
    # resources — credential-safety transport, retries and rate-limit pacing —
    # and return the parsed response body.

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """GET an arbitrary API ``path``; ``params`` become the query string."""
        return self._api.get(path, params=params, timeout=timeout)

    def post(
        self,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """POST ``json`` to an arbitrary API ``path``; ``params`` add query args."""
        return self._api.post(path, body=json, params=params, timeout=timeout)

    def put(
        self,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """PUT ``json`` to an arbitrary API ``path``; ``params`` add query args."""
        return self._api.put(path, body=json, params=params, timeout=timeout)

    def delete(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """DELETE an arbitrary API ``path``; ``params`` become the query string."""
        return self._api.delete(path, params=params, timeout=timeout)

    def with_options(
        self,
        *,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | NotGiven = not_given,
        max_response_bytes: int | None | NotGiven = not_given,
    ) -> Vulners:
        """A copy of this client sharing the same connection pool, with overrides."""
        changes = _option_changes(timeout, max_retries, max_response_bytes)
        clone = object.__new__(type(self))
        # The shared httpx client is injected, so the clone's own api treats the
        # pool as externally-supplied and never closes it; the parent's pacing
        # buckets are shared so rate-limit pacing is not reset.
        clone._api = SyncAPIClient(
            self._api.config.replace(**changes),
            http_client=self._api._client,
            buckets=self._api._buckets,
        )
        # Keep the pool's real owner alive for the clone's whole lifetime, and
        # route close through it. Without this, `Vulners(key).with_options(...)`
        # would drop the temporary owner immediately — its finalizer closing the
        # shared pool out from under the clone (RuntimeError on the next request).
        clone._owner = getattr(self, "_owner", self)
        return clone

    @property
    def is_closed(self) -> bool:
        """Whether the underlying connection pool has been closed."""
        return self._api.is_closed

    def close(self) -> None:
        """Close the underlying connection pool.

        A no-op for an ``http_client`` you passed in; prefer the ``with`` context
        manager. A ``with_options()`` clone shares one httpx client with its owner
        (and any sibling clones), so closing any of them closes that shared pool for
        all — use separate clients if you need independent lifetimes.
        """
        owner = getattr(self, "_owner", None)
        if owner is not None:
            # Clone: close the shared pool through its owner (the clone's own _api
            # treats the pool as borrowed and would no-op). Drop the ref so a second
            # close is a safe no-op and the owner can be collected.
            owner.close()
            self._owner = None
        else:
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

    # See Vulners._owner: kept only on a with_options() clone, no class default.
    _owner: AsyncVulners | None

    def __init__(
        self,
        api_key: str | SecretStr | None = None,
        *,
        base_url: str | httpx.URL | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int | None = None,
        max_response_bytes: int | None = None,
        http2: bool = True,
        proxy: str | httpx.Proxy | None = None,
        verify: bool | str | ssl.SSLContext = True,
        trust_env: bool = True,
        before_request: Hook | Sequence[Hook] | None = None,
        after_response: Hook | Sequence[Hook] | None = None,
        on_error: Hook | Sequence[Hook] | None = None,
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
            http2: Negotiate HTTP/2 on the SDK-owned transport (default ``True``;
                ``h2`` is a core dependency, so no extra is needed). HTTP/2
                multiplexes many concurrent API calls over one connection. Pass
                ``http2=False`` to force HTTP/1.1 — preferable for a huge
                single-stream archive download, where HTTP/1.1 avoids h2's
                flow-control window overhead on one long body. Ignored when you
                pass your own ``http_client`` (set it on that client instead).
            proxy: Route all SDK traffic through this proxy (URL string or
                ``httpx.Proxy``). Applies to the SDK-owned transport; cannot be
                combined with ``http_client=``.
            verify: TLS verification for the SDK-owned transport: ``True``
                (default), ``False``, a CA-bundle path, or an
                ``ssl.SSLContext``. Cannot be combined with ``http_client=``.
            trust_env: Whether the SDK-owned client trusts environment settings —
                TLS (``SSL_CERT_FILE``/``SSL_CERT_DIR``) and proxies
                (``HTTPS_PROXY``/``HTTP_PROXY``/``ALL_PROXY``, honouring
                ``NO_PROXY``) when ``proxy=`` is not given. Cannot be combined
                with ``http_client=``.
            before_request: Callable (or sequence of callables) invoked with the
                ``httpx.Request`` before it is sent (an httpx request event
                hook on the SDK-owned client). Sync or async callables.
            after_response: Callable (or sequence of callables) invoked with the
                ``httpx.Response`` when it arrives (an httpx response event
                hook on the SDK-owned client). Sync or async callables.
            on_error: Callable (or sequence of callables) invoked with the final
                error when a request fails for good (after retries). Sync or
                async callables; exceptions raised by a hook propagate.
            http_client: Bring your own ``httpx.AsyncClient`` (e.g. for custom
                proxies, transport or connection limits). Its transport is wrapped
                with the SDK's credential-safety guard — scoped to the SDK's own
                requests — so the ``X-Api-Key`` is still stripped on cross-origin
                redirects while your application's own traffic through the shared
                client is left untouched. A client you pass is not closed by this
                client's ``aclose()``.
        """
        _check_byo_conflicts(
            http_client, proxy, verify, trust_env, before_request, after_response
        )
        config = resolve_config(
            api_key=api_key,
            base_url=base_url,
            version=__version__,
            timeout=timeout,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
            http2=http2,
            proxy=proxy,
            verify=verify,
            trust_env=trust_env,
            before_request=_async_hooks(before_request),
            after_response=_async_hooks(after_response),
            on_error=_async_hooks(on_error),
        )
        install_key_redaction(config.api_key.get_secret_value())
        self._api = AsyncAPIClient(config, http_client=http_client)

    @property
    def config(self) -> ClientConfig:
        """The resolved, immutable client configuration."""
        return self._api.config

    @property
    def base_url(self) -> httpx.URL:
        """The API base URL requests are sent to."""
        return self._api.config.base_url

    @cached_property
    def search(self) -> AsyncSearch:
        return AsyncSearch(self._api)

    @cached_property
    def documents(self) -> AsyncDocuments:
        return AsyncDocuments(self._api)

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

    @property
    def reports(self) -> AsyncReport:
        """Alias of :attr:`report` (the primary plural name)."""
        return self.report

    @cached_property
    def stix(self) -> AsyncStix:
        return AsyncStix(self._api)

    @cached_property
    def subscriptions(self) -> AsyncSubscriptionsV4:
        """The v4 subscriptions CRUD (``list``/``get``/``create``/``update``/``delete``)."""
        return AsyncSubscriptionsV4(self._api)

    @property
    def subscriptions_v4(self) -> AsyncSubscriptionsV4:
        # Deprecated alias of `subscriptions`, kept for the pre-release window.
        return self.subscriptions

    @cached_property
    def subscriptions_email(self) -> AsyncSubscriptions:
        """The legacy v3 email subscriptions (moved here from ``subscriptions``)."""
        return AsyncSubscriptions(self._api)

    @cached_property
    def webhooks(self) -> AsyncWebhooks:
        return AsyncWebhooks(self._api)

    @cached_property
    def vscanner(self) -> AsyncVscanner:
        return AsyncVscanner(self._api)

    # -- escape hatches ----------------------------------------------------
    # Thin, untyped access to any API path (e.g. a legacy v3 endpoint without a
    # dedicated method). These route through the same core pipeline as the typed
    # resources — credential-safety transport, retries and rate-limit pacing —
    # and return the parsed response body.

    async def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """GET an arbitrary API ``path``; ``params`` become the query string."""
        return await self._api.get(path, params=params, timeout=timeout)

    async def post(
        self,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """POST ``json`` to an arbitrary API ``path``; ``params`` add query args."""
        return await self._api.post(path, body=json, params=params, timeout=timeout)

    async def put(
        self,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """PUT ``json`` to an arbitrary API ``path``; ``params`` add query args."""
        return await self._api.put(path, body=json, params=params, timeout=timeout)

    async def delete(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        """DELETE an arbitrary API ``path``; ``params`` become the query string."""
        return await self._api.delete(path, params=params, timeout=timeout)

    def with_options(
        self,
        *,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | NotGiven = not_given,
        max_response_bytes: int | None | NotGiven = not_given,
    ) -> AsyncVulners:
        """A copy of this client sharing the same connection pool, with overrides."""
        changes = _option_changes(timeout, max_retries, max_response_bytes)
        clone = object.__new__(type(self))
        # The shared httpx client is injected, so the clone's own api treats the
        # pool as externally-supplied and never closes it; the parent's pacing
        # buckets are shared so rate-limit pacing is not reset.
        clone._api = AsyncAPIClient(
            self._api.config.replace(**changes),
            http_client=self._api._client,
            buckets=self._api._buckets,
        )
        # Keep the pool's real owner alive for the clone's lifetime and route
        # aclose through it. Without this the temporary owner of
        # `AsyncVulners(key).with_options(...)` would be dropped with no async
        # finalizer, leaking the pool (nothing ever closes it).
        clone._owner = getattr(self, "_owner", self)
        return clone

    @property
    def is_closed(self) -> bool:
        """Whether the underlying connection pool has been closed."""
        return self._api.is_closed

    async def aclose(self) -> None:
        """Close the underlying connection pool.

        A no-op for an ``http_client`` you passed in; prefer the ``async with``
        context manager. A ``with_options()`` clone shares one httpx client with its
        owner (and any sibling clones), so closing any of them closes that shared
        pool for all — use separate clients if you need independent lifetimes.
        """
        owner = getattr(self, "_owner", None)
        if owner is not None:
            await owner.aclose()
            self._owner = None
        else:
            await self._api.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


__all__ = ["AsyncVulners", "Vulners"]
