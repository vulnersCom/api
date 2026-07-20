"""Async I/O client (unasyncd source for the sync :class:`SyncAPIClient`).

The sans-IO :class:`~vulners._base_client.BaseClient` holds every pure helper;
this module adds the small amount of real I/O — rate-limit pacing, the send,
capped reads, the retry loop and streaming — as :class:`AsyncAPIClient`. The sync
mirror ``_transport_client_sync.py`` (:class:`SyncAPIClient`) is generated from
this file by ``unasyncd``, so the security-relevant retry/backoff/pacing logic
stays identical across the two transports by construction. Edit this file only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any

import httpx
from typing_extensions import Self

from ._base_client import BaseClient, RequestSpec, _mount_guard
from ._config import ClientConfig
from ._exceptions import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    ErrorInfo,
)
from ._logging import logger
from ._ratelimit_async import AsyncRateLimitBucket
from ._response import APIResponse, AsyncStreamedAPIResponse
from ._retry import _retry_timeout, _should_retry
from ._streaming import is_zip_media, iter_zip_ndjson, make_ndjson_decoder
from ._transport import AsyncVulnersTransport
from ._types import NotGiven, Omit, not_given


class AsyncAPIClient(BaseClient):
    """Asynchronous request loop over an ``httpx.AsyncClient``."""

    def __init__(
        self,
        config: ClientConfig,
        http_client: httpx.AsyncClient | None = None,
        buckets: dict[str, AsyncRateLimitBucket] | None = None,
    ) -> None:
        super().__init__(config)
        # Account-scoped pacing buckets. A clone (with_options) passes the parent's
        # dict so client-side rate-limit pacing is shared, not reset per variant.
        self._buckets: dict[str, AsyncRateLimitBucket] = {} if buckets is None else buckets
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
            # Wrap the caller's transport(s) so the cross-origin X-Api-Key strip,
            # set-cookie drop and SSRF redirect guard run on a BYO client too.
            _mount_guard(http_client, AsyncVulnersTransport, config.base_url)
        else:
            # h2 is a core dependency, so http2=True always works; no guard needed.
            transport = AsyncVulnersTransport(
                httpx.AsyncHTTPTransport(retries=config.connect_retries, http2=config.http2),
                origin=config.base_url,
            )
            self._client = httpx.AsyncClient(
                base_url=config.base_url,
                transport=transport,
                timeout=config.timeout,
                limits=config.limits,
                follow_redirects=config.follow_redirects,
            )
            self._owns_client = True

    def _bucket_for(self, key: str) -> AsyncRateLimitBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets.setdefault(key, AsyncRateLimitBucket())
        return bucket

    async def _send(
        self, spec: RequestSpec, request: httpx.Request
    ) -> tuple[httpx.Response, bytes]:
        if self._config.max_response_bytes is None:
            response = await self._client.send(request)
            return response, response.content
        response = await self._client.send(request, stream=True)
        try:
            self._reject_declared_length(
                response.headers.get("content-length"), response.status_code
            )
            buf = bytearray()
            async for chunk in response.aiter_bytes():
                buf += chunk
                self._guard_cap(len(buf), response.status_code)
        finally:
            await response.aclose()
        return response, bytes(buf)

    async def _send_with_retries(
        self, spec: RequestSpec, request: httpx.Request, retries: int
    ) -> tuple[httpx.Response, bytes, Any]:
        bucket = self._bucket_for(self._ratelimit_key(spec))
        attempt = 0
        while True:
            await bucket.consume(self._config.max_rate_limit_wait)
            try:
                response, content = await self._send(spec, request)
            except httpx.TimeoutException as exc:
                error: APIConnectionError = APITimeoutError(f"Request timed out: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    await self._sleep(_retry_timeout(attempt))
                    continue
                raise error from exc
            except httpx.TransportError as exc:
                error = APIConnectionError(f"Connection error: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    await self._sleep(_retry_timeout(attempt))
                    continue
                raise error from exc
            self._update_bucket_from_headers(bucket, response)
            try:
                parsed = self._process_response(spec, response, content)
            except APIStatusError as err:
                info = ErrorInfo(status_code=err.status_code, error_code=err.error_code)
                if attempt < retries and _should_retry(
                    info, response.headers, idempotent=self._idempotent(spec)
                ):
                    attempt += 1
                    logger.debug(
                        "retrying %s %s after status %s", spec.method, spec.path, err.status_code
                    )
                    await self._sleep(_retry_timeout(attempt, response.headers))
                    continue
                raise
            return response, content, parsed

    async def request(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        headers: Mapping[str, str | Omit] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | None = None,
    ) -> Any:
        retries = self._config.max_retries if max_retries is None else max_retries
        request = self._build_request(
            spec, params=params, body=body, files=files, headers=headers, timeout=timeout
        )
        _, _, parsed = await self._send_with_retries(spec, request, retries)
        return cast(parsed) if cast is not None else parsed

    async def request_with_response(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        headers: Mapping[str, str | Omit] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | None = None,
    ) -> APIResponse[Any]:
        retries = self._config.max_retries if max_retries is None else max_retries
        request = self._build_request(
            spec, params=params, body=body, files=files, headers=headers, timeout=timeout
        )
        response, content, parsed = await self._send_with_retries(spec, request, retries)
        return APIResponse(response, content, parsed, cast)

    async def stream_records(
        self,
        spec: RequestSpec,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> AsyncIterator[Any]:
        """Lazily yield NDJSON records from a streamed (bulk archive) response."""
        request = self._build_request(spec, params=params, body=body, timeout=timeout)
        bucket = self._bucket_for(self._ratelimit_key(spec))
        await bucket.consume(self._config.max_rate_limit_wait)
        response = await self._client.send(request, stream=True)
        try:
            self._update_bucket_from_headers(bucket, response)
            if response.status_code >= 400:
                self._raise_stream_error(response, await response.aread())
            media = self._media_type(response)
            cap = self._config.max_response_bytes
            if is_zip_media(media):
                buf = bytearray()
                async for chunk in response.aiter_bytes():
                    buf += chunk
                    if cap is not None:
                        self._guard_cap(len(buf), response.status_code)
                for record in iter_zip_ndjson(bytes(buf), cap):
                    yield record
            else:
                decoder = make_ndjson_decoder(media, cap)
                raw = 0
                async for chunk in response.aiter_bytes():
                    if cap is not None:
                        raw += len(chunk)
                        self._guard_cap(raw, response.status_code)
                    for record in decoder.feed(chunk):
                        yield record
                for record in decoder.flush():
                    yield record
        finally:
            await response.aclose()

    def stream_response(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> AsyncStreamContext:
        """A context manager yielding a live :class:`AsyncStreamedAPIResponse`."""
        request = self._build_request(
            spec, params=params, body=body, files=files, timeout=timeout
        )
        return AsyncStreamContext(self, spec, request, cast)

    @staticmethod
    async def _sleep(seconds: float) -> None:
        import asyncio

        await asyncio.sleep(seconds)

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None, **kw: Any) -> Any:
        return await self.request(
            RequestSpec("GET", path, body_mode="query"), params=params, **kw
        )

    async def post(self, path: str, *, body: Any = None, **kw: Any) -> Any:
        return await self.request(RequestSpec("POST", path, body_mode="json"), body=body, **kw)

    async def put(self, path: str, *, body: Any = None, **kw: Any) -> Any:
        return await self.request(RequestSpec("PUT", path, body_mode="json"), body=body, **kw)

    async def delete(
        self, path: str, *, params: Mapping[str, Any] | None = None, **kw: Any
    ) -> Any:
        return await self.request(
            RequestSpec("DELETE", path, body_mode="query"), params=params, **kw
        )

    # -- lifecycle ---------------------------------------------------------

    @property
    def is_closed(self) -> bool:
        return self._client.is_closed

    async def aclose(self) -> None:
        if self._owns_client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class AsyncStreamContext:
    """Async context manager that opens a stream and yields a live response."""

    def __init__(
        self,
        client: AsyncAPIClient,
        spec: RequestSpec,
        request: httpx.Request,
        cast: Callable[[Any], Any] | None,
    ) -> None:
        self._client = client
        self._spec = spec
        self._request = request
        self._cast = cast
        self._response: httpx.Response | None = None

    async def __aenter__(self) -> AsyncStreamedAPIResponse[Any]:
        client = self._client
        bucket = client._bucket_for(client._ratelimit_key(self._spec))
        await bucket.consume(client._config.max_rate_limit_wait)
        response = await client._client.send(self._request, stream=True)
        self._response = response
        client._update_bucket_from_headers(bucket, response)
        if response.status_code >= 400:
            content = await response.aread()
            try:
                client._raise_stream_error(response, content)
            finally:
                await response.aclose()
        return AsyncStreamedAPIResponse(response, client._stream_parser(self._spec, self._cast))

    async def __aexit__(self, *exc: object) -> None:
        if self._response is not None:
            await self._response.aclose()


__all__ = ["AsyncAPIClient", "AsyncStreamContext"]
