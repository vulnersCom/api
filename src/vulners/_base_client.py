"""Sans-IO request/response core plus the thin sync and async request loops.

:class:`BaseClient` holds only pure helpers — build a request, decode/validate a
response, decide retryability — with no I/O. :class:`SyncAPIClient` and
:class:`AsyncAPIClient` add the small amount of real I/O: rate-limit pacing, the
send, capped reads and the retry loop. The response pipeline mirrors
``vulners.base._invoke`` (media dispatch, gzip/zip, v3/v4 envelope unwrap, the
opt-in ``max_response_bytes`` capped read).
"""

from __future__ import annotations

import dataclasses
import io
import math
import zipfile
import zlib
from collections.abc import Callable, Mapping
from typing import Any, Literal

import httpx
import orjson
from typing_extensions import Self

from ._config import ClientConfig
from ._exceptions import (
    APIConnectionError,
    APIResponseValidationError,
    APIStatusError,
    APITimeoutError,
    ErrorInfo,
    _extract_error,
    _make_error,
)
from ._logging import logger
from ._ratelimit import RateLimitBucket
from ._ratelimit_async import AsyncRateLimitBucket
from ._response import APIResponse
from ._retry import _retry_timeout, _should_retry
from ._transport import AsyncVulnersTransport, VulnersTransport
from ._types import NotGiven, Omit, not_given

BodyMode = Literal["json", "multipart", "text", "query", "none"]
ResponseMode = Literal["json", "bytes", "stream", "ndjson"]

# Chunk size for the opt-in capped read/decompress loops.
_CAP_CHUNK = 1 << 18

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})


@dataclasses.dataclass(frozen=True)
class RequestSpec:
    """All per-endpoint request knowledge, as a frozen declaration."""

    method: str
    path: str
    body_mode: BodyMode = "none"
    unwrap: tuple[str, ...] = ()
    response_mode: ResponseMode = "json"
    timeout_profile: Literal["default", "archive"] = "default"
    ratelimit_group: str | None = None
    idempotent: bool | None = None

    def __repr__(self) -> str:
        # Explicit repr (not dataclass-generated, which reprlib wraps) so this
        # frozen spec is never mistaken for a codegen endpoint by the test suite.
        return f"RequestSpec({self.method} {self.path})"


def _clean_params(params: Mapping[str, Any]) -> dict[str, Any]:
    """Drop not-given / omit / None query params before they hit the wire."""
    out: dict[str, Any] = {}
    for key, value in params.items():
        if value is None or isinstance(value, (NotGiven, Omit)):
            continue
        out[key] = value
    return out


class BaseClient:
    """Sans-IO helpers shared by the sync and async clients."""

    def __init__(self, config: ClientConfig) -> None:
        self._config = config

    @property
    def config(self) -> ClientConfig:
        return self._config

    # -- request building --------------------------------------------------

    def _default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "X-Api-Key": self._config.api_key.get_secret_value(),
        }

    def _resolve_timeout(
        self, spec: RequestSpec, timeout: float | httpx.Timeout | None | NotGiven
    ) -> httpx.Timeout:
        if isinstance(timeout, NotGiven):
            return self._config.timeout_for(spec.timeout_profile)
        if timeout is None:
            return httpx.Timeout(None)
        return timeout if isinstance(timeout, httpx.Timeout) else httpx.Timeout(timeout)

    def _build_request(
        self,
        spec: RequestSpec,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        headers: Mapping[str, str | Omit] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> httpx.Request:
        url = self._config.base_url.join(spec.path)

        query: dict[str, Any] = {}
        if spec.body_mode == "query" and isinstance(body, Mapping):
            query.update(body)
        if params:
            query.update(params)
        if query:
            url = url.copy_merge_params(_clean_params(query))

        req_headers = self._default_headers()
        if headers:
            for key, value in headers.items():
                if isinstance(value, Omit):
                    req_headers.pop(key, None)
                else:
                    req_headers[key] = value

        content: bytes | None = None
        request_files = files
        if spec.body_mode == "json" and body is not None:
            content = self._encode_json(body)
            req_headers["Content-Type"] = "application/json"
        elif spec.body_mode == "text" and body is not None:
            content = body.encode("utf-8") if isinstance(body, str) else bytes(body)
            req_headers["Content-Type"] = "text/plain; charset=utf-8"

        extensions = {"timeout": self._resolve_timeout(spec, timeout).as_dict()}
        return httpx.Request(
            spec.method,
            url,
            headers=req_headers,
            content=content,
            files=request_files,
            extensions=extensions,
        )

    @staticmethod
    def _encode_json(body: Any) -> bytes:
        # orjson only encodes 64-bit-range ints; fall back to httpx's stdlib json
        # encoder for anything it cannot handle, matching v3 behaviour.
        try:
            return orjson.dumps(body)
        except TypeError:
            import json

            return json.dumps(body).encode("utf-8")

    # -- request policy ----------------------------------------------------

    def _idempotent(self, spec: RequestSpec) -> bool:
        if spec.idempotent is not None:
            return spec.idempotent
        return spec.method.upper() in _IDEMPOTENT_METHODS

    def _ratelimit_key(self, spec: RequestSpec) -> str:
        return spec.ratelimit_group or spec.path

    def _retryable_exc(self, exc: Exception, spec: RequestSpec) -> bool:
        # Connection-establishment failures never delivered the request, so they
        # are always safe to retry; read/write failures only on idempotent verbs.
        if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
            return True
        return self._idempotent(spec)

    # -- response processing ----------------------------------------------

    @staticmethod
    def _media_type(response: httpx.Response) -> str:
        return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    def _unwrap(self, spec: RequestSpec, parsed: Any) -> Any:
        current = parsed
        for key in spec.unwrap:
            if isinstance(current, Mapping) and key in current:
                current = current[key]
            else:
                break
        return current

    def _process_response(
        self, spec: RequestSpec, response: httpx.Response, content: bytes
    ) -> Any:
        media = self._media_type(response)
        status = response.status_code
        secret = self._config.api_key.get_secret_value()

        if media == "application/json":
            parsed: Any = None
            if content:
                try:
                    parsed = orjson.loads(content)
                except orjson.JSONDecodeError as exc:
                    snippet = content[:1024].decode(errors="replace")
                    if status >= 400:
                        info = _extract_error(status, response.headers, snippet, secret=secret)
                        assert info is not None
                        raise _make_error(info) from exc
                    raise APIResponseValidationError(
                        f"expected a JSON response body but could not parse it: {snippet}",
                        status_code=status,
                        data=snippet,
                    ) from exc
            info = _extract_error(status, response.headers, parsed, secret=secret)
            if info is not None:
                raise _make_error(info)
            return self._unwrap(spec, parsed)

        # Non-JSON content type. Check the status for every mode first, so an
        # HTML/plain gateway error surfaces as a typed error, not silent bytes.
        if status >= 400:
            snippet = content[:1024].decode(errors="replace")
            info = _extract_error(status, response.headers, snippet, secret=secret)
            assert info is not None
            raise _make_error(info)

        if spec.response_mode == "bytes":
            return self._decode_binary(media, content, status)
        if spec.response_mode == "ndjson":
            return self._decode_ndjson(content)

        # response_mode == "json" but a non-JSON 2xx body: parse leniently.
        if not content:
            return None
        try:
            return self._unwrap(spec, orjson.loads(content))
        except orjson.JSONDecodeError as exc:
            raise APIResponseValidationError(
                "expected a JSON response body but got a non-JSON payload",
                status_code=status,
                data=content[:1024].decode(errors="replace"),
            ) from exc

    def _decode_binary(self, media: str, content: bytes, status: int) -> bytes:
        cap = self._config.max_response_bytes
        if media in ("application/x-gzip-compressed", "application/gzip", "application/x-gzip"):
            if cap is None:
                return zlib.decompress(content, wbits=31)
            return self._inflate_capped(content, status)
        if media in ("application/x-zip-compressed", "application/zip"):
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = archive.namelist()
                if len(names) != 1:
                    raise APIResponseValidationError(
                        "unexpected file count in Vulners ZIP archive", status_code=status
                    )
                with archive.open(names[0]) as member:
                    if cap is None:
                        return member.read()
                    return self._read_member_capped(member, status)
        return content

    @staticmethod
    def _decode_ndjson(content: bytes) -> list[Any]:
        out: list[Any] = []
        for line in content.split(b"\n"):
            line = line.strip()
            if line:
                out.append(orjson.loads(line))
        return out

    def _inflate_capped(self, data: bytes, status: int) -> bytes:
        cap = self._config.max_response_bytes
        assert cap is not None
        decompressor = zlib.decompressobj(wbits=31)
        out = bytearray()
        for i in range(0, len(data), _CAP_CHUNK):
            out += decompressor.decompress(data[i : i + _CAP_CHUNK], _CAP_CHUNK)
            while decompressor.unconsumed_tail:
                out += decompressor.decompress(decompressor.unconsumed_tail, _CAP_CHUNK)
            if len(out) > cap:
                raise APIResponseValidationError(
                    "decompressed response exceeds max_response_bytes", status_code=status
                )
        out += decompressor.flush()
        if len(out) > cap:
            raise APIResponseValidationError(
                "decompressed response exceeds max_response_bytes", status_code=status
            )
        return bytes(out)

    def _read_member_capped(self, member: Any, status: int) -> bytes:
        cap = self._config.max_response_bytes
        assert cap is not None
        out = bytearray()
        while True:
            chunk = member.read(_CAP_CHUNK)
            if not chunk:
                break
            out += chunk
            if len(out) > cap:
                raise APIResponseValidationError(
                    "decompressed response exceeds max_response_bytes", status_code=status
                )
        return bytes(out)

    def _reject_declared_length(self, declared: str | None, status: int) -> None:
        """Fail fast when a declared Content-Length already exceeds the cap."""
        cap = self._config.max_response_bytes
        assert cap is not None
        if declared is None:
            return
        try:
            over = int(declared) > cap
        except ValueError:
            return
        if over:
            raise APIResponseValidationError(
                "response exceeds max_response_bytes", status_code=status
            )

    def _guard_cap(self, length: int, status: int) -> None:
        """Abort as soon as a running byte total exceeds the cap."""
        cap = self._config.max_response_bytes
        assert cap is not None
        if length > cap:
            raise APIResponseValidationError(
                "response exceeds max_response_bytes", status_code=status
            )

    def _update_bucket_from_headers(
        self, bucket: RateLimitBucket | AsyncRateLimitBucket, response: httpx.Response
    ) -> None:
        limit = response.headers.get("X-Vulners-Ratelimit-Reqlimit")
        if not limit:
            return
        try:
            rate = float(limit) / 60.0
        except (TypeError, ValueError):
            return
        # Only trust a finite server limit of at least 1 req/min.
        if math.isfinite(rate) and rate >= 1.0 / 60.0:
            bucket.update(rate=rate)


class SyncAPIClient(BaseClient):
    """Synchronous request loop over an ``httpx.Client``."""

    def __init__(self, config: ClientConfig, http_client: httpx.Client | None = None) -> None:
        super().__init__(config)
        self._buckets: dict[str, RateLimitBucket] = {}
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            transport = VulnersTransport(
                httpx.HTTPTransport(retries=config.connect_retries),
                origin=config.base_url,
            )
            self._client = httpx.Client(
                base_url=config.base_url,
                transport=transport,
                timeout=config.timeout,
                limits=config.limits,
                follow_redirects=config.follow_redirects,
            )
            self._owns_client = True

    def _bucket_for(self, key: str) -> RateLimitBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets.setdefault(key, RateLimitBucket())
        return bucket

    def _send(self, spec: RequestSpec, request: httpx.Request) -> tuple[httpx.Response, bytes]:
        if self._config.max_response_bytes is None:
            response = self._client.send(request)
            return response, response.content
        response = self._client.send(request, stream=True)
        try:
            self._reject_declared_length(
                response.headers.get("content-length"), response.status_code
            )
            buf = bytearray()
            for chunk in response.iter_bytes():
                buf += chunk
                self._guard_cap(len(buf), response.status_code)
        finally:
            response.close()
        return response, bytes(buf)

    def _send_with_retries(
        self, spec: RequestSpec, request: httpx.Request, retries: int
    ) -> tuple[httpx.Response, bytes, Any]:
        bucket = self._bucket_for(self._ratelimit_key(spec))
        attempt = 0
        while True:
            bucket.consume(self._config.max_rate_limit_wait)
            try:
                response, content = self._send(spec, request)
            except httpx.TimeoutException as exc:
                error: APIConnectionError = APITimeoutError(f"Request timed out: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    self._sleep(_retry_timeout(attempt))
                    continue
                raise error from exc
            except httpx.TransportError as exc:
                error = APIConnectionError(f"Connection error: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    self._sleep(_retry_timeout(attempt))
                    continue
                raise error from exc
            self._update_bucket_from_headers(bucket, response)
            try:
                parsed = self._process_response(spec, response, content)
            except APIStatusError as err:
                info = ErrorInfo(status_code=err.status_code, error_code=err.error_code)
                if attempt < retries and _should_retry(info, response.headers):
                    attempt += 1
                    logger.debug(
                        "retrying %s %s after status %s", spec.method, spec.path, err.status_code
                    )
                    self._sleep(_retry_timeout(attempt, response.headers))
                    continue
                raise
            return response, content, parsed

    def request(
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
        _, _, parsed = self._send_with_retries(spec, request, retries)
        return cast(parsed) if cast is not None else parsed

    def request_with_response(
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
        response, content, parsed = self._send_with_retries(spec, request, retries)
        return APIResponse(response, content, parsed, cast)

    @staticmethod
    def _sleep(seconds: float) -> None:
        import time

        time.sleep(seconds)

    def get(self, path: str, *, params: Mapping[str, Any] | None = None, **kw: Any) -> Any:
        return self.request(RequestSpec("GET", path, body_mode="query"), params=params, **kw)

    def post(self, path: str, *, body: Any = None, **kw: Any) -> Any:
        return self.request(RequestSpec("POST", path, body_mode="json"), body=body, **kw)

    def put(self, path: str, *, body: Any = None, **kw: Any) -> Any:
        return self.request(RequestSpec("PUT", path, body_mode="json"), body=body, **kw)

    def delete(self, path: str, *, params: Mapping[str, Any] | None = None, **kw: Any) -> Any:
        return self.request(RequestSpec("DELETE", path, body_mode="query"), params=params, **kw)

    # -- lifecycle ---------------------------------------------------------

    @property
    def is_closed(self) -> bool:
        return self._client.is_closed

    def close(self) -> None:
        if self._owns_client and not self._client.is_closed:
            self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncAPIClient(BaseClient):
    """Asynchronous request loop over an ``httpx.AsyncClient``."""

    def __init__(
        self, config: ClientConfig, http_client: httpx.AsyncClient | None = None
    ) -> None:
        super().__init__(config)
        self._buckets: dict[str, AsyncRateLimitBucket] = {}
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            transport = AsyncVulnersTransport(
                httpx.AsyncHTTPTransport(retries=config.connect_retries),
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
                if attempt < retries and _should_retry(info, response.headers):
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


__all__ = ["AsyncAPIClient", "BaseClient", "RequestSpec", "SyncAPIClient"]
