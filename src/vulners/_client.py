"""The ``Vulners`` and ``AsyncVulners`` clients.

Two mirror clients: a synchronous one owning an ``httpx.Client`` and an async one
owning an ``httpx.AsyncClient``. Resources hang off each as ``cached_property``.
These are not yet re-exported from the package root — import them from
``vulners._client`` for now; public wiring lands with a later work package.
"""

from __future__ import annotations

import contextlib
from functools import cached_property
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from ._base_client import AsyncAPIClient, SyncAPIClient
from ._config import ClientConfig, resolve_config
from ._logging import install_key_redaction
from ._resources._async.search import AsyncSearch
from ._resources._sync.search import Search
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
        # The shared httpx client is injected, so the clone never closes it.
        clone._api = SyncAPIClient(
            self._api.config.replace(**changes), http_client=self._api._client
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
        clone._api = AsyncAPIClient(
            self._api.config.replace(**changes), http_client=self._api._client
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
