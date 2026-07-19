"""Base class for async resources (unasyncd source for the sync resources).

Resources are stateless thin wrappers over the client's request loop. A resource
obtained via :attr:`with_raw_response` / :attr:`with_streaming_response` is a
sibling instance flagged so its methods return an :class:`APIResponse` instead of
the parsed model.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given

if TYPE_CHECKING:
    import httpx

    from ... import _base_client


class AsyncBaseResource:
    """Common wiring shared by every async resource."""

    def __init__(self, client: _base_client.AsyncAPIClient, _wrap: str | None = None) -> None:
        self._client = client
        self._wrap = _wrap

    @property
    def _api_key(self) -> str:
        """The configured API key value, for endpoints that echo it in query/body."""
        return self._client.config.api_key.get_secret_value()

    @property
    def with_raw_response(self) -> Self:
        """A view whose methods return an :class:`APIResponse` (status/headers + parse)."""
        return type(self)(self._client, _wrap="raw")

    @property
    def with_streaming_response(self) -> Self:
        """A view whose methods return an :class:`APIResponse` for iterative reads."""
        return type(self)(self._client, _wrap="stream")

    async def _request(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> Any:
        if self._wrap is not None:
            return await self._client.request_with_response(
                spec, cast=cast, params=params, body=body, files=files, timeout=timeout
            )
        return await self._client.request(
            spec, cast=cast, params=params, body=body, files=files, timeout=timeout
        )
