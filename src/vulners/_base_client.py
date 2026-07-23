"""Sans-IO request/response core shared by the sync and async request loops.

:class:`BaseClient` holds only pure helpers — build a request, decode/validate a
response, decide retryability — with no I/O. The two I/O clients that add real
network work (rate-limit pacing, the send, capped reads, the retry loop and
streaming) live in the async source ``_transport_client_async.py``
(:class:`AsyncAPIClient`) and its ``unasyncd``-generated sync mirror
``_transport_client_sync.py`` (:class:`SyncAPIClient`); both import ``BaseClient``
from here (imports flow one way to keep this module cycle-free). The response
pipeline mirrors ``vulners.base._invoke`` (media dispatch, gzip/zip, v3/v4
envelope unwrap, the opt-in ``max_response_bytes`` capped read).
"""

from __future__ import annotations

import dataclasses
import io
import json
import math
import zipfile
from collections.abc import Callable, Mapping
from typing import Any, Literal

import httpx
import orjson

from ._config import ClientConfig, _coerce_timeout
from ._exceptions import (
    APIResponseValidationError,
    _extract_error,
    _make_error,
)
from ._ratelimit import RateLimitBucket
from ._ratelimit_async import AsyncRateLimitBucket
from ._streaming import _GZIP_MAGIC, _GZIP_MEDIA, _ZIP_MEDIA, _igzip, _new_gzip_decompressor
from ._types import NotGiven, Omit, not_given

BodyMode = Literal["json", "multipart", "text", "query", "none"]
ResponseMode = Literal["json", "bytes", "stream"]

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
    # When False (the default), a missing unwrap key is a contract violation and
    # raises APIResponseValidationError instead of silently returning the whole
    # envelope. Set True for endpoints whose envelope key is genuinely optional.
    unwrap_optional: bool = False
    response_mode: ResponseMode = "json"
    timeout_profile: Literal["default", "archive"] = "default"
    ratelimit_group: str | None = None
    idempotent: bool | None = None

    def __repr__(self) -> str:
        # Explicit repr (not dataclass-generated, which reprlib wraps) so this
        # frozen spec is never mistaken for a codegen endpoint by the test suite.
        return f"RequestSpec({self.method} {self.path})"


def _mount_guard(client: Any, transport_cls: Any, origin: httpx.URL) -> None:
    """Wrap a bring-your-own client's transport(s) with the credential guard.

    Mounts ``transport_cls`` (``VulnersTransport`` / ``AsyncVulnersTransport``)
    over the client's base transport and any per-pattern mounts, keyed to the SDK
    origin, so the cross-origin ``X-Api-Key`` strip, ``Set-Cookie`` drop and SSRF
    redirect guard run even when the caller supplies their own client.

    The guard is scoped to SDK-originated requests only (``sdk_only=True``): the
    SDK tags its requests via the ``vulners_sdk`` request extension (set in
    ``_build_request`` and preserved by httpx across redirect hops), so the
    application's own traffic through a shared client passes through untouched.

    Idempotent: a client already guarded (e.g. reused by ``with_options`` or
    shared across clients) is left as-is rather than double-wrapped.
    """
    if isinstance(client._transport, transport_cls):
        return
    client._transport = transport_cls(client._transport, origin=origin, sdk_only=True)
    client._mounts = {
        pattern: (
            transport_cls(mount, origin=origin, sdk_only=True) if mount is not None else mount
        )
        for pattern, mount in client._mounts.items()
    }


def _redact_proxy(proxy: str | httpx.Proxy) -> str:
    """A credential-free ``scheme://host[:port]`` rendering of a proxy.

    Safe to put in an error message or log: any userinfo (a proxy password) is
    dropped, so naming the proxy that failed can never leak its credentials.
    """
    url = proxy.url if isinstance(proxy, httpx.Proxy) else httpx.URL(proxy)
    netloc = url.host if url.port is None else f"{url.host}:{url.port}"
    return f"{url.scheme}://{netloc}"


def _is_proxy_auth_error(exc: BaseException) -> bool:
    """True for a ``407 Proxy Authentication Required`` from the configured proxy.

    httpx surfaces the proxy's CONNECT status only in the ``ProxyError`` message
    (there is no numeric status attribute), so the 407 is matched on that text.
    The failure is terminal — the same credentials are rejected on every attempt
    — so the retry loop must treat it as non-retryable rather than repeating it.
    """
    return isinstance(exc, httpx.ProxyError) and str(exc).lstrip().startswith("407")


def _json_loads_lenient(data: bytes | bytearray | str) -> Any:
    """Decode JSON with orjson, falling back to the stdlib decoder on its edges.

    orjson rejects ``NaN``/``Infinity`` literals and integers outside the 64-bit
    range, all of which occur in real-world CVE data; the stdlib decoder accepts
    them, so it backstops the fast path. Genuinely invalid JSON raises the
    stdlib error — a ``ValueError``, like ``orjson.JSONDecodeError``.
    """
    try:
        return orjson.loads(data)
    except orjson.JSONDecodeError:
        return json.loads(data)


def _call_blocking(func: Callable[..., Any], *args: Any) -> Any:
    # Sync-mirror shim: unasyncd rewrites ``await asyncio.to_thread(fn, *args)``
    # in the async resources to ``_call_blocking(fn, *args)``, so the generated
    # sync code runs the blocking call inline (no thread hop) while the async
    # source offloads it off the event loop.
    return func(*args)


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
        # The proxy the SDK-owned transport actually uses (explicit ``proxy=`` or
        # the one resolved from the environment); ``None`` for a bring-your-own
        # client. Set by the I/O subclasses and used only to name the proxy in a
        # connection-error message.
        self._proxy: str | httpx.Proxy | None = None

    @property
    def config(self) -> ClientConfig:
        return self._config

    def _connection_error_message(self, exc: Exception) -> str:
        """``Connection error: ...``, naming the proxy when one is configured.

        A failure to reach the API *through a proxy* otherwise surfaces as a bare
        ``Connection refused`` / ``407 ...`` that gives no hint the proxy — not
        the API host — is the unreachable/rejecting hop.
        """
        message = f"Connection error: {exc}"
        if self._proxy is not None:
            message = f"{message} (proxy {_redact_proxy(self._proxy)})"
        return message

    # -- request building --------------------------------------------------

    def _default_headers(self) -> dict[str, str]:
        # Advertise modern response compression (httpx auto-decompresses br/zstd
        # because brotli/zstandard are core deps). In capped (untrusted-host) mode
        # advertise identity instead: with no Content-Encoding there is no
        # transport-level decompression-bomb vector, so the byte cap applies to
        # raw wire bytes exactly rather than to httpx's unbounded per-chunk inflate.
        accept_encoding = (
            "identity"
            if self._config.max_response_bytes is not None
            else "gzip, deflate, br, zstd"
        )
        return {
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": accept_encoding,
            "X-Api-Key": self._config.api_key.get_secret_value(),
        }

    def _resolve_timeout(
        self, spec: RequestSpec, timeout: float | httpx.Timeout | None | NotGiven
    ) -> httpx.Timeout:
        if isinstance(timeout, NotGiven):
            return self._config.timeout_for(spec.timeout_profile)
        return _coerce_timeout(timeout)

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

        extensions: dict[str, Any] = {
            "timeout": self._resolve_timeout(spec, timeout).as_dict(),
            # Tag the request as SDK-originated so a guard transport mounted on
            # a shared (bring-your-own) client applies the credential/SSRF
            # policy only to the SDK's own traffic. httpx carries extensions
            # across redirect hops, so the tag survives redirects.
            "vulners_sdk": True,
            # The SDK origin this request is scoped to, so one guarded transport
            # shared across clients with different base_urls compares each request
            # against its own origin (not whichever client wrapped the transport
            # first). httpx preserves extensions across redirect hops.
            "vulners_origin": str(self._config.base_url),
        }
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
        # orjson only encodes 64-bit-range ints; fall back to the stdlib json
        # encoder for anything it cannot handle, matching v3 behaviour.
        try:
            return orjson.dumps(body)
        except TypeError:
            return json.dumps(body).encode("utf-8")

    # -- request policy ----------------------------------------------------

    def _idempotent(self, spec: RequestSpec) -> bool:
        if spec.idempotent is not None:
            return spec.idempotent
        return spec.method.upper() in _IDEMPOTENT_METHODS

    def _ratelimit_key(self, spec: RequestSpec) -> str:
        return spec.ratelimit_group or spec.path

    def _retryable_exc(self, exc: Exception, spec: RequestSpec) -> bool:
        # A 407 from the proxy is terminal (the credentials will not change
        # between attempts), so it is never retried — even on an idempotent verb.
        if _is_proxy_auth_error(exc):
            return False
        # Connection-establishment failures never delivered the request, so they
        # are always safe to retry; read/write failures only on idempotent verbs.
        if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
            return True
        return self._idempotent(spec)

    # -- response processing ----------------------------------------------

    @staticmethod
    def _media_type(response: httpx.Response) -> str:
        return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    @staticmethod
    def _is_json_media(media: str) -> bool:
        # Accept application/json and any vendor/problem "+json" structured suffix
        # (RFC 6839): application/problem+json, application/vnd.api+json, etc. carry
        # a JSON error/body that must be parsed, not handed back as opaque bytes.
        return media == "application/json" or media.endswith("+json")

    def _unwrap(self, spec: RequestSpec, parsed: Any, status: int) -> Any:
        current = parsed
        for key in spec.unwrap:
            if isinstance(current, Mapping) and key in current:
                current = current[key]
            elif spec.unwrap_optional:
                break
            else:
                # A required envelope key is absent: surface the contract drift
                # instead of silently returning a differently-shaped object that
                # only fails later, deep in caller code.
                available = (
                    sorted(current) if isinstance(current, Mapping) else type(current).__name__
                )
                raise APIResponseValidationError(
                    f"response is missing the expected envelope key {key!r} (got {available!r})",
                    status_code=status,
                )
        return current

    def _process_response(
        self, spec: RequestSpec, response: httpx.Response, content: bytes
    ) -> Any:
        media = self._media_type(response)
        status = response.status_code
        secret = self._config.api_key.get_secret_value()

        if self._is_json_media(media):
            parsed: Any = None
            if content:
                try:
                    parsed = _json_loads_lenient(content)
                except ValueError as exc:  # both decoders rejected the body
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
            return self._unwrap(spec, parsed, status)

        # Non-JSON content type. Check the status for every mode first, so an
        # HTML/plain gateway error surfaces as a typed error, not silent bytes.
        if status >= 400:
            snippet = content[:1024].decode(errors="replace")
            info = _extract_error(status, response.headers, snippet, secret=secret)
            assert info is not None
            raise _make_error(info)

        if spec.response_mode == "bytes":
            return self._decode_binary(media, content, status)

        # response_mode == "json" but a non-JSON 2xx body: parse leniently.
        if not content:
            return None
        try:
            return self._unwrap(spec, _json_loads_lenient(content), status)
        except ValueError as exc:  # both decoders rejected the body
            raise APIResponseValidationError(
                "expected a JSON response body but got a non-JSON payload",
                status_code=status,
                data=content[:1024].decode(errors="replace"),
            ) from exc

    def _decode_binary(self, media: str, content: bytes, status: int) -> bytes:
        # Decompression cap: with the default max_response_bytes=None the gzip/zip
        # body inflates fully into memory with no bound. This is deliberate —
        # Vulners archives are legitimately multi-gigabyte and a default cap would
        # break normal downloads. A caller pointing base_url at an untrusted host
        # opts into the bound by passing max_response_bytes= (upgrade path), which
        # switches to the streamed, per-chunk-capped inflate/read below.
        cap = self._config.max_response_bytes
        if media in _GZIP_MEDIA:
            if cap is None:
                # igzip.decompress handles multi-member gzip natively (no first-member
                # truncation) and is ISA-L accelerated.
                return _igzip.decompress(content)
            return self._inflate_capped(content, status)
        if media in _ZIP_MEDIA:
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

    def _inflate_capped(self, data: bytes, status: int) -> bytes:
        cap = self._config.max_response_bytes
        assert cap is not None
        out = bytearray()

        def _extend(piece: bytes) -> None:
            # Guard after every decompress step so a single slice cannot inflate to
            # hundreds of MB before the cap fires (bomb overshoot bounded to _CAP_CHUNK).
            out.extend(piece)
            if len(out) > cap:
                raise APIResponseValidationError(
                    "decompressed response exceeds max_response_bytes", status_code=status
                )

        decompressor = _new_gzip_decompressor()
        remaining = data
        while remaining:
            _extend(decompressor.decompress(remaining, _CAP_CHUNK))
            if decompressor.eof:
                # Multi-member gzip: carry trailing bytes into a fresh member; stop
                # at trailing padding (not a real member) after the last one.
                rest = decompressor.unused_data
                if rest[:2] != _GZIP_MAGIC:
                    break
                decompressor = _new_gzip_decompressor()
                remaining = rest
            else:
                # Either more output is pending for this member (unconsumed_tail) or
                # the input ran out mid-member (truncated) -> the while exits.
                remaining = decompressor.unconsumed_tail
        _extend(decompressor.flush())
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

    def _raise_stream_error(self, response: httpx.Response, content: bytes) -> None:
        """Turn an error status on a streaming response into a typed error."""
        secret = self._config.api_key.get_secret_value()
        media = self._media_type(response)
        parsed: Any
        if self._is_json_media(media) and content:
            try:
                parsed = _json_loads_lenient(content)
            except ValueError:
                parsed = content[:1024].decode(errors="replace")
        else:
            parsed = content[:1024].decode(errors="replace")
        info = _extract_error(response.status_code, response.headers, parsed, secret=secret)
        assert info is not None
        raise _make_error(info)

    def _stream_parser(
        self, spec: RequestSpec, cast: Callable[[Any], Any] | None
    ) -> Callable[[httpx.Response, bytes], Any]:
        def _parse(response: httpx.Response, content: bytes) -> Any:
            parsed = self._process_response(spec, response, content)
            return cast(parsed) if cast is not None else parsed

        return _parse


__all__ = ["BaseClient", "RequestSpec"]
