from __future__ import annotations

import __future__
import inspect
import ipaddress
import math
import os
import pathlib
import re
import stat
import sys
import textwrap
import threading
import warnings
import zlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import wraps
from importlib.metadata import PackageNotFoundError, version
from time import monotonic, sleep
from typing import Any, Callable, ClassVar, Literal, Mapping
from urllib.parse import parse_qsl, quote, urlencode

import httpx
import orjson

# Rebuild a request body stream after scrubbing the credential out of it (see
# VulnersApiTransport._scrub_credential). Guarded: if this httpx internal moves,
# the credential is still removed from the header and the query, and the body
# scrub simply becomes a no-op rather than breaking import.
try:
    from httpx._content import ByteStream as _HttpxByteStream
except Exception:  # pragma: no cover - defensive against httpx internals moving
    _HttpxByteStream = None  # type: ignore[assignment, misc]
from pydantic import ConfigDict, create_model

# httpx masks only Authorization / Proxy-Authorization when it renders a Headers
# object (repr(request.headers), an event-hook/DEBUG log, an error's request
# context). The API key rides in a custom X-Api-Key header, so register that name
# in the same obfuscation set to keep it out of logs. Display only: the on-wire
# header name and value, and every value accessor (.get / [] / .raw), are
# unchanged. Guarded so an httpx internal rename cannot break import.
try:
    from httpx._models import SENSITIVE_HEADERS as _HTTPX_SENSITIVE_HEADERS

    _HTTPX_SENSITIVE_HEADERS.add("x-api-key")
except Exception:  # pragma: no cover - defensive against httpx internals moving
    pass
from pydantic.fields import FieldInfo
from typing_extensions import Self
from typing_inspection import introspection

try:
    __version__ = version("vulners")
except PackageNotFoundError:
    # No installed distribution metadata (checkout / vendored / frozen): fall
    # back to a placeholder instead of failing import.
    __version__ = "unknown"


# Field names (compared case-insensitively) whose value in an error payload is
# API-key material and must never reach a log/APM through str()/repr().
_SECRET_FIELD_NAMES = frozenset({"apikey", "x-api-key"})


def _redact_secret(obj: Any, secret: str | None = None) -> Any:
    """Return *obj* with API-key material masked, for safe error stringification.

    A dict entry whose key names the credential (``apiKey`` / ``X-Api-Key``) has
    its value replaced with ``"[REDACTED]"``; when the real key value is known,
    any string that contains it is masked too. A payload that carries no key is
    returned with equal contents, so an ordinary error message stays
    byte-identical (``str``/``repr`` and ``== `` unchanged).
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


def _extract_api_error(data: Any) -> tuple[Any, str | None]:
    """Best-effort ``(error_code, message)`` from a Vulners error payload.

    Reads the human-readable problem description the server returns in its
    several error shapes — the v3 envelope (``{"error", "errorCode"}``), the v4
    validation lists (``{"errors": [...]}`` / ``{"detail": [...]}``), and a plain
    string body — without echoing the request ``input`` a validation item
    carries (it can repeat sensitive request data).
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


class VulnersApiError(Exception):
    """Raised for a Vulners API error response.

    Attributes:
        http_status: HTTP status code, or None for a client-side error.
        error_code:  the Vulners ``errorCode`` when the payload carries one.
        message:     human-readable problem description parsed from the
                     response, or None when the payload has no recognizable one.
        data:        the full, secret-redacted error payload.
        retry_after: seconds to wait before retrying, from a Retry-After header.
    """

    def __init__(self, http_status, data, retry_after=None):
        # Mask any API-key material (a value under an apiKey/X-Api-Key field, or
        # a server echo of the request that carried the key) before it reaches
        # str()/repr() and from there logs, APM or a crash reporter.
        data = _redact_secret(data)
        self.http_status = http_status
        self.retry_after = retry_after
        self.data = data
        self.error_code, self.message = _extract_api_error(data)
        super().__init__(self.message if self.message is not None else data)


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header value into seconds, or None.

    Accepts either a delta-seconds number or an HTTP-date (RFC 7231). Only a
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
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)


class RateLimitBucket:
    """An implementation of the Token Bucket algorithm."""

    def __init__(self, rate=10.0, burst=1.0):
        # Serializes all access to the mutable accounting fields below; the
        # bucket is shared between threads and instances.
        self._lock = threading.Lock()
        self._rate = float(rate)
        # Never clamp the burst below one whole token: with burst < 1 the
        # allowance can never reach the price of a request and consume() would
        # loop forever for any server limit below 60 req/min.
        self._burst = max(1.0, min(float(burst), self._rate))
        self._allowance = self._burst
        self._last_check = monotonic()

    def update(self, rate, burst=1.0):
        # Ignore non-positive / NaN rates (poisoned server header). Written as
        # "not (rate > 0)" so NaN is rejected too.
        if not (rate > 0):
            return
        with self._lock:
            self._rate = float(rate)
            self._burst = max(1.0, min(float(burst), self._rate))

    def consume(self):
        # A non-positive / NaN rate would divide by zero in the sleep below;
        # skip pacing entirely in that case.
        if not (self._rate > 0):
            return
        while 1:
            with self._lock:
                now = monotonic()
                # number of seconds since the last call
                delta = now - self._last_check
                self._last_check = now
                # increase the number of allowed calls; clamp a negative delta
                # to 0 so a backward clock step (or a racing thread that moved
                # _last_check ahead) can't freeze the bucket
                self._allowance += max(delta, 0.0) * self._rate
                if self._allowance > self._burst:
                    # don't allow more than "burst" calls
                    self._allowance = self._burst
                if self._allowance >= 1:
                    self._allowance -= 1
                    return
                # cold down
                delay = (1 - self._allowance) / self._rate
            # sleep OUTSIDE the lock so other threads/instances aren't blocked,
            # then re-enter and recompute the allowance
            sleep(delay)


def _port_or_default(url: httpx.URL) -> int:
    return url.port if url.port is not None else (443 if url.scheme == "https" else 80)


class VulnersApiTransport(httpx.BaseTransport):
    def __init__(
        self, transport: httpx.BaseTransport, origin: httpx.URL | None = None
    ):
        self.transport = transport
        # Origin (scheme/host/port) of the configured server_url. When set, the
        # X-Api-Key header is stripped from any request that leaves this origin.
        # follow_redirects=True stays on, but httpx only strips Authorization on
        # a cross-origin redirect, so a custom auth header would otherwise be
        # delivered to a third-party host after an open redirect.
        self._origin = origin

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Compared against the fixed origin (not the previous hop): once the key
        # is dropped it stays dropped for every later hop, and a bounce back to
        # the origin does not restore it (mirrors httpx's Authorization policy).
        if self._origin is not None and not self._key_allowed(request.url):
            request.headers.pop("x-api-key", None)
            # The header strip above covers 301/302/303 (which also drop the
            # body), but a 307/308 preserves the method and body: an
            # add_api_key endpoint carries the key in the JSON/form body (or in
            # the query for a GET), so a cross-origin hop would otherwise ship
            # the credential to a third-party host. Scrub it from the outgoing
            # request too. Same-origin requests never reach this branch, so
            # their body/query stay byte-identical.
            self._scrub_credential(request)
            self._guard_redirect_target(request.url)
        response = self.transport.handle_request(request)
        if "set-cookie" in response.headers:
            del response.headers["set-cookie"]
        return response

    def _guard_redirect_target(self, url: httpx.URL) -> None:
        # Reached only for a cross-origin hop (same-origin returns before this),
        # so an on-prem server_url that is itself a private IP still works: its
        # own requests are same-origin and never checked. follow_redirects stays
        # on and any public host (a storage.googleapis.com archive redirect, its
        # public IP, or a non-IP hostname) is delegated unchanged. What is
        # refused is a redirect whose target is an IP literal in a loopback /
        # link-local / private / reserved range (cloud metadata at
        # 169.254.169.254, 127.0.0.0/8, ::1, RFC1918, 0.0.0.0), which would turn
        # the client into an SSRF probe.
        try:
            ip = ipaddress.ip_address(url.host)
        except ValueError:
            return
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise VulnersApiError(
                None,
                "refusing to follow a redirect to a private or internal address: %s"
                % url.host,
            )

    def _scrub_credential(self, request: httpx.Request) -> None:
        # Mirror the header strip for the two other places the key can ride when
        # add_api_key=True: the query string (GET) and the request body (POST).
        if "apiKey" in request.url.params:
            request.url = request.url.copy_remove_param("apiKey")
        media_type = (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        )
        # Only decode/rewrite the two body encodings the SDK produces for an
        # add_api_key call. A multipart/streaming upload is left untouched (its
        # content-type is multipart/form-data), so reading the stream here can
        # never consume an upload body.
        if media_type == "application/json":
            try:
                body = orjson.loads(request.read())
            except orjson.JSONDecodeError:
                return
            if not isinstance(body, dict) or "apiKey" not in body:
                return
            del body["apiKey"]
            new_content = orjson.dumps(body)
        elif media_type == "application/x-www-form-urlencoded":
            pairs = parse_qsl(request.read().decode("utf-8"), keep_blank_values=True)
            if not any(k == "apiKey" for k, _ in pairs):
                return
            new_content = urlencode(
                [(k, v) for k, v in pairs if k != "apiKey"]
            ).encode("utf-8")
        else:
            return
        request._content = new_content
        request.headers["content-length"] = str(len(new_content))
        if _HttpxByteStream is not None:
            request.stream = _HttpxByteStream(new_content)

    def _key_allowed(self, url: httpx.URL) -> bool:
        o = self._origin
        assert o is not None
        if (url.scheme, url.host, _port_or_default(url)) == (
            o.scheme,
            o.host,
            _port_or_default(o),
        ):
            return True
        # http->https upgrade of the same host on default ports: httpx keeps the
        # key here, so mirror that one exception (a https->http downgrade is not
        # covered and the key is stripped).
        return (
            url.host == o.host
            and o.scheme == "http"
            and _port_or_default(o) == 80
            and url.scheme == "https"
            and _port_or_default(url) == 443
        )

    def close(self) -> None:
        # httpx.BaseTransport.close() is a no-op, so without this delegation
        # Client.close() would never reach the wrapped HTTPTransport and its
        # connection pool would stay open.
        self.transport.close()


class VulnersApiProxy:
    def __init__(self, base: VulnersApiBase):
        self._invoke = base._invoke


class VulnersApiBase:
    _ratelimit_key: ClassVar[str] = ""

    def __init__(
        self,
        api_key: str,
        proxy: str | None = None,
        *,
        retry_count: int = 3,
        server_url: str = "https://vulners.com",
        timeout: float = 60.0,
        max_response_bytes: int | None = None,
    ):
        """
        Create API.

        :param api_key:
            Vulners API key. You can get one from https://vulners.com
        :param proxy:
            Proxy url, example: "https://myproxy.com:3128"
        :param retry_count:
            Number of connection retries handed to the httpx transport. Only
            connection failures (ConnectError / ConnectTimeout) are retried;
            HTTP error responses (429, 5xx) and read timeouts are NOT retried.
            When a ``proxy`` is configured, httpx 0.28 does not apply these
            retries at all.
        :param max_response_bytes:
            Optional cap, in bytes, on how much of a response the client keeps in
            memory. ``None`` (the default) means no limit, so behavior is
            unchanged and large archive downloads (which can reach several
            gigabytes) keep working. When set, the raw response body and the
            output of gzip/zip decompression are each bounded by this value and a
            ``VulnersApiError`` is raised if it is exceeded, guarding against a
            decompression bomb or an unbounded response from a compromised
            upstream. Set it only above the largest response you expect.
        """
        if not api_key:
            raise ValueError(
                "API key must be provided. You can obtain one for free at https://vulners.com"
            )

        if not isinstance(api_key, str):
            raise TypeError("api_key parameter must be a string value")

        self._client = httpx.Client(
            follow_redirects=True,
            base_url=server_url,
            transport=VulnersApiTransport(
                httpx.HTTPTransport(proxy=proxy, retries=retry_count),
                origin=httpx.URL(server_url),
            ),
            headers={
                "User-Agent": "Vulners Python API %s" % __version__,
                "X-Api-Key": api_key,
            },
            timeout=httpx.Timeout(timeout),
        )
        self._api_key = api_key
        self._max_response_bytes = max_response_bytes
        # Per-instance buckets so one api-key's (or a poisoned) bucket can't
        # affect other instances.
        self._ratelimits: dict[str, RateLimitBucket] = {}

    def close(self) -> None:
        """Close the underlying httpx client and its connection pool.

        Reusing a single instance is still preferred; this releases the pooled
        sockets when the instance is done.
        """
        self._client.close()

    def __enter__(self) -> Self:
        # Return Self, not the base class, so a typed `with VulnersApi(...) as
        # api:` keeps the concrete subclass and its sub-API attributes resolve.
        return self

    def __exit__(self, *exc_info: Any) -> None:
        # Return None so an exception raised inside the `with` block is not
        # suppressed.
        self.close()

    # Chunk size for the opt-in capped read/decompress loops below.
    _CAP_CHUNK: ClassVar[int] = 1 << 18

    def _read_capped(self, response: httpx.Response) -> bytes:
        # Only reached when max_response_bytes is set. Reject early on a declared
        # Content-Length over budget, then accumulate streamed chunks and abort
        # the moment the running total exceeds the cap (covers a chunked / no
        # Content-Length / slow-drip body too).
        cap = self._max_response_bytes
        assert cap is not None
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                over = int(declared) > cap
            except ValueError:
                over = False
            if over:
                raise VulnersApiError(
                    response.status_code, "response exceeds max_response_bytes"
                )
        buf = bytearray()
        for chunk in response.iter_bytes():
            buf += chunk
            if len(buf) > cap:
                raise VulnersApiError(
                    response.status_code, "response exceeds max_response_bytes"
                )
        return bytes(buf)

    def _inflate_capped(self, data: bytes, status: int | None) -> bytes:
        # Incremental gzip inflate that stops as soon as the decompressed output
        # exceeds the cap, so a small archive cannot expand into gigabytes of
        # RAM. Produces the same bytes as zlib.decompress(data, wbits=31) when
        # the output is within budget.
        cap = self._max_response_bytes
        assert cap is not None
        d = zlib.decompressobj(wbits=31)
        out = bytearray()
        for i in range(0, len(data), self._CAP_CHUNK):
            out += d.decompress(data[i : i + self._CAP_CHUNK], self._CAP_CHUNK)
            while d.unconsumed_tail:
                out += d.decompress(d.unconsumed_tail, self._CAP_CHUNK)
            if len(out) > cap:
                raise VulnersApiError(
                    status, "decompressed response exceeds max_response_bytes"
                )
        out += d.flush()
        if len(out) > cap:
            raise VulnersApiError(
                status, "decompressed response exceeds max_response_bytes"
            )
        return bytes(out)

    def _read_member_capped(self, f: Any, status: int | None) -> bytes:
        # Bounded chunked read of a single zip member, counting the bytes
        # actually read (the declared ZipInfo.file_size is attacker-controlled).
        cap = self._max_response_bytes
        assert cap is not None
        out = bytearray()
        while True:
            chunk = f.read(self._CAP_CHUNK)
            if not chunk:
                break
            out += chunk
            if len(out) > cap:
                raise VulnersApiError(
                    status, "decompressed response exceeds max_response_bytes"
                )
        return bytes(out)

    def _api_error(self, response: httpx.Response, payload: Any) -> VulnersApiError:
        return VulnersApiError(
            response.status_code,
            _redact_secret(payload, self._api_key),
            retry_after=_parse_retry_after(response.headers.get("Retry-After")),
        )

    def _invoke(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"],
        url: str,
        params: dict[str, Any],
        path_params: tuple[str, ...],
        file_params: list[str] | None = None,
        add_api_key: bool = False,
        timeout: float | None = None,
        parse_content: bool = True,
    ):
        if path_params:
            # Quote each value so it stays a single path segment: a raw "/" (or
            # "?"/"#") in a str path parameter would otherwise retarget the URL.
            # Placeholders are collected from the URL and popped once each so a
            # repeated placeholder does not KeyError; canonical UUID values are a
            # fixed point of quote(), so the public API wire stays byte-identical
            path_values = {
                name: quote(str(params.pop(name)), safe="")
                for name in dict.fromkeys(re.findall("{([^}]*)}", url))
            }
            url = re.sub("{([^}]*)}", lambda m: path_values[m.group(1)], url)
        if add_api_key:
            # setdefault (not assign) so an endpoint that declares its own
            # optional apiKey param can name a different owner key; endpoints
            # with no such param never populate "apiKey" here, so they still
            # fall through to the client's own key and the wire is unchanged.
            params.setdefault("apiKey", self._api_key)
        file_paths = {}
        if file_params:
            for file_param in file_params:
                file_path = params.pop(file_param, None)
                if file_path:
                    file_paths[file_param] = file_path
        if file_paths:
            kwargs: dict[str, Any] = {"data": params}
        elif method in ("GET", "DELETE"):
            kwargs = {"params": params}
        else:
            # orjson only encodes 64-bit-range ints; fall back to httpx json for
            # anything it can't encode.
            try:
                body = orjson.dumps(params)
            except TypeError:
                kwargs = {"json": params}
            else:
                kwargs = {
                    "content": body,
                    "headers": {"Content-Type": "application/json"},
                }
        if timeout is not None:
            kwargs["timeout"] = timeout
        # setdefault keeps first-touch construction atomic so concurrent callers
        # share one bucket per key.
        key = self._ratelimit_key or url
        bucket = self._ratelimits.get(key)
        if bucket is None:
            bucket = self._ratelimits.setdefault(key, RateLimitBucket())
        bucket.consume()
        # Open the upload files only after pacing, and close them even if a
        # partial open or the request itself raises. Files stay closed by
        # the time any response-parsing error is raised below.
        files = {}
        try:
            for file_param, file_path in file_paths.items():
                fh = open(file_path, "rb")
                # Validate the descriptor we actually opened, not the path that
                # was validated earlier: the pydantic FilePath check runs at call
                # time and only follows the name, so between then and here (after
                # the rate-limit sleep) the path could be swapped for a device,
                # FIFO or directory. Rejecting a non-regular target closes that
                # TOCTOU window. A regular file (including a symlink to one) has
                # S_ISREG set and is uploaded exactly as before.
                if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                    fh.close()
                    raise VulnersApiError(None, "upload path is not a regular file")
                files[file_param] = fh
            if files:
                kwargs["files"] = files
            if self._max_response_bytes is None:
                # Buffer the whole body eagerly so legitimate multi-GB archive
                # downloads keep working.
                response = self._client.request(method, url, **kwargs)
                content = response.content
            else:
                # Opt-in cap: stream the body and abort as soon as the running
                # total exceeds the budget, so an oversized/hostile response is
                # never buffered without bound.
                with self._client.stream(method, url, **kwargs) as response:
                    content = self._read_capped(response)
        finally:
            for file in files.values():
                file.close()
        limit = response.headers.get("X-Vulners-Ratelimit-Reqlimit")
        if limit:
            try:
                rate = float(limit) / 60.0
            except (TypeError, ValueError):
                pass
            else:
                # Only trust a finite server limit of at least 1 req/min. A
                # zero/negative/sub-1-rpm value would freeze the bucket and a
                # non-finite one would poison it.
                if math.isfinite(rate) and rate >= 1.0 / 60.0:
                    bucket.update(rate=rate)
        # Dispatch on the media-type only: tolerate a charset/parameter suffix,
        # a missing header (no KeyError), and case differences.
        media_type = (
            response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        )
        if media_type == "application/json":
            # An empty body (e.g. 204 with a JSON content-type from a proxy)
            # decodes to None instead of raising on orjson.loads. A body
            # mislabelled as JSON (an HTML gateway page carrying an
            # application/json content-type) is wrapped as VulnersApiError
            # rather than leaking a raw JSONDecodeError.
            try:
                result = orjson.loads(content) if content else None
            except orjson.JSONDecodeError as err:
                raise self._api_error(
                    response, content[:1024].decode(errors="replace")
                ) from err
            if isinstance(result, dict) and "data" in result:
                data = result["data"]
                # Presence, not truthiness: a success envelope never carries an
                # "error" key (server fact), so `"error" in data` is enough and
                # a falsy error value (""/0/null) still raises.
                if isinstance(data, dict) and "error" in data:
                    raise self._api_error(response, data)
                # An HTTP >= 400 body that happens to carry "data" must not be
                # returned as success. Checked after the error-key branch so a
                # 4xx+error envelope keeps raising with the unwrapped `data`;
                # here the full envelope is raised so a top-level message
                # survives.
                if response.status_code >= 400:
                    raise self._api_error(response, result)
                return data
            if response.status_code >= 400:
                raise self._api_error(response, result)
            return result

        # Non-JSON branch. Verify the status for every content-type (including
        # the parse_content=False callers) before touching the body, so an
        # HTML/plain gateway error surfaces as VulnersApiError instead of silent
        # bytes or a KeyError from a missing content-type header.
        if response.status_code >= 400:
            raise self._api_error(
                response, content[:1024].decode(errors="replace")
            )

        if media_type == "application/x-gzip-compressed":
            if self._max_response_bytes is None:
                content = zlib.decompress(content, wbits=31)
            else:
                content = self._inflate_capped(content, response.status_code)
        elif media_type == "application/x-zip-compressed":
            import io
            import zipfile

            with zipfile.ZipFile(io.BytesIO(content)) as z:
                names = z.namelist()
                # An empty (EOCD-only) archive must also be rejected, else
                # names[0] raises IndexError.
                if len(names) != 1:
                    raise RuntimeError("Unexpected file count in Vulners ZIP archive")
                with z.open(names[0]) as f:
                    if self._max_response_bytes is None:
                        content = f.read()
                    else:
                        content = self._read_member_capped(f, response.status_code)
        if parse_content:
            # Wrap a malformed body (e.g. an HTML page returned with a 2xx
            # status) so callers get VulnersApiError, not a raw
            # JSONDecodeError that escapes `except VulnersApiError`.
            try:
                return orjson.loads(content) if content else None
            except orjson.JSONDecodeError as err:
                raise self._api_error(
                    response, content[:1024].decode(errors="replace")
                ) from err
        return content


# Leading identifier of a dotted name (a module root such as ``typing`` in
# ``typing.Any``); the lookbehind skips attribute accesses like ``uuid.UUID``.
_ANNOTATION_ROOT_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\.")
# String literals in the generated code (e.g. a default value ``'partial'``) so
# they can be blanked out before scanning for module roots.
_QUOTED_LITERAL_RE = re.compile(r"'[^']*'|\"[^\"]*\"")


def _ann_repr(t: Any) -> str:
    if isinstance(t, type):
        if t.__module__ != "builtins":
            return f"{t.__module__}.{t.__name__}"
        return t.__name__
    return repr(t)


class VulnersDeprecationWarning(DeprecationWarning):
    """Category for the SDK's own deprecation notices.

    A DeprecationWarning subclass, so ``except DeprecationWarning``, ``-W`` rules
    and ``pytest.warns(DeprecationWarning)`` keep matching by issubclass, while
    the package can scope its warning filter to just its own notices instead of
    flipping the process-global DeprecationWarning policy.
    """


# Stable URL of the v3 -> v4 migration guide, appended to every deprecation
# notice so the reader always has one click to the upgrade instructions.
MIGRATION_GUIDE_URL = "https://vulnersCom.github.io/api/explanation/migration/"


def deprecation_warning(text: str) -> None:
    # Intended to be called from the body of a deprecated wrapper (a @deprecated
    # shim or an endpoint(deprecated=...) function). Both call paths are the same
    # depth, so stacklevel=3 attributes the warning to the user's call site
    # instead of this module.
    text = textwrap.indent(text, "[!] ")
    warnings.warn(
        f"\n[!] DEPRECATION WARNING\n{text}\n[!] Migration guide: {MIGRATION_GUIDE_URL}",
        VulnersDeprecationWarning,
        stacklevel=3,
    )


# Set while running inside a @deprecated shim so the inner
# endpoint(deprecated=...) warning is suppressed: a shim delegating to a
# deprecated endpoint should warn exactly once (with its own message), while a
# direct endpoint call still warns. Thread-local so concurrent calls don't
# cross-suppress each other.
_shim_guard = threading.local()


def deprecated(message: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            deprecation_warning(message)
            previous = getattr(_shim_guard, "active", False)
            _shim_guard.active = True
            try:
                return func(*args, **kwargs)
            finally:
                # Restored even if the wrapped call raises.
                _shim_guard.active = previous

        # PEP 702-style runtime marker so tooling/tests can detect the
        # deprecation without parsing the warning text.
        wrapper.__deprecated__ = message  # type: ignore[attr-defined]
        return wrapper

    return decorator


def endpoint(
    name: str,
    /,
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"],
    url: str,
    description: str | None = None,
    params: Mapping[str, Any] | None = None,
    response_handler: Callable[[Any], Any] | None = None,
    parse_response: bool = True,
    wrapper: Any = None,
    add_api_key: bool = False,
    deprecated: str | None = None,
    timeout: float | None = None,
) -> Callable[..., Any]:
    assert method in ("GET", "POST", "PUT", "DELETE", "PATCH")
    assert isinstance(url, str)
    assert description is None or isinstance(description, str)
    assert params is None or isinstance(params, Mapping)

    # Module for the generated function's __module__ = the caller's module.
    # sys._getframe is a CPython detail; keep it inline so the frame depth stays
    # 1. Fall back to this module without it, and to __name__ if the caller's
    # globals carry no __name__ key.
    getframe = getattr(sys, "_getframe", None)
    if getframe is not None:
        module = getframe(1).f_globals.get("__name__", __name__)
    else:
        module = __name__
    params = params or {}

    path_params = tuple(re.findall("{([^}]*)}", url))
    for param in path_params:
        assert param in params

    if wrapper is not None:
        returns = f"{wrapper.__module__}.{wrapper.__name__}"
    else:
        returns = "dict[str, typing.Any]"

    func_args = []
    file_params = []
    for param, param_type in params.items():
        ann = introspection.inspect_annotation(
            param_type, annotation_source=introspection.AnnotationSource.FUNCTION
        )
        # Pick the FieldInfo out of the Annotated metadata explicitly: metadata
        # may contain none, or the FieldInfo may not be first.
        metadata = next((x for x in ann.metadata if isinstance(x, FieldInfo)), None)
        if ann.type is pathlib.Path:
            file_params.append((metadata.alias or param) if metadata else param)
        if metadata and not metadata.is_required():
            func_args.append(f"{param}: {_ann_repr(ann.type)} = {metadata.default!r}")
        else:
            func_args.append(f"{param}: {_ann_repr(ann.type)}")

    call_args = "{" + ", ".join(f"{name!r}: {name}" for name in params) + "}"
    model = create_model(
        name,
        **params,
        __config__=ConfigDict(extra="forbid", validate_by_name=True),
        # Pass __module__ explicitly: with it left to default, pydantic 2.11+
        # unconditionally calls sys._getframe(1) itself, so import would still
        # crash on an implementation without _getframe.
        __module__=__name__,
    )
    code = "\n".join(
        [
            f"def endpoint({', '.join(func_args)}) -> {returns}:",
            f"    _callargs = {{ _k: _v for _k, _v in {call_args}.items() if _v is not Unset }}",
            "    return __model(**_callargs).model_dump(mode='json', exclude_unset=True, by_alias=True)",
        ]
    )
    namespace: dict[str, Any] = {"__model": model, "Unset": Unset}
    # Inject the root modules referenced by the (string) annotations so
    # typing.get_type_hints() / signature(eval_str=True) can resolve them instead
    # of raising NameError on every endpoint. Only modules already imported are
    # added (no fresh imports at endpoint-definition time), and string literals
    # are blanked first so a quoted default can't masquerade as a dotted name;
    # the sys.modules guard makes any stray match harmless.
    for _root in set(_ANNOTATION_ROOT_RE.findall(_QUOTED_LITERAL_RE.sub("", code))):
        if _root in sys.modules:
            namespace[_root] = sys.modules[_root]
    # Compile with the annotations future flag set explicitly (dont_inherit=True)
    # so import no longer silently relies on this module keeping
    # `from __future__ import annotations`; __annotations__ stay strings.
    exec(
        compile(
            code,
            "<vulners.base.endpoint>",
            "exec",
            flags=__future__.annotations.compiler_flag,
            dont_inherit=True,
        ),
        namespace,
    )
    endpoint = namespace["endpoint"]
    endpoint.__name__ = name.rsplit(".", 1)[1] if "." in name else name
    endpoint.__qualname__ = name
    endpoint.__module__ = module

    @wraps(endpoint)
    def func(api: VulnersApiBase, *args: Any, **kwargs: Any) -> Any:
        # Suppress this warning when reached through a @deprecated shim (which
        # already warned) so the call warns exactly once; a direct call still
        # warns.
        if deprecated and not getattr(_shim_guard, "active", False):
            deprecation_warning(deprecated)

        params = endpoint(*args, **kwargs)
        content = api._invoke(
            method, url, params, path_params, file_params, add_api_key, timeout, parse_response
        )
        # An empty/None body (e.g. a proxy 204 carrying a JSON content-type)
        # decodes to None. Endpoints that unwrap it with a response_handler or a
        # wrapper would otherwise raise a bare TypeError ("NoneType is not
        # subscriptable"/"not iterable") that escapes `except VulnersApiError`;
        # surface the malformed response as VulnersApiError to match the rest of
        # the response-parsing contract. Plain endpoints keep returning None.
        if content is None and (response_handler or wrapper is not None):
            raise VulnersApiError(None, "empty response body")
        if response_handler:
            content = response_handler(content)
        if wrapper is not None:
            content = wrapper(api, content)
        return content

    # Give the wrapper a truthful signature. @wraps set func.__wrapped__ to the
    # generated function, which has no leading self/api parameter, so
    # inspect.signature of a *bound* endpoint method would drop its first real
    # wire parameter as if it were self (get_bulletin_history -> (), software ->
    # missing "software"). __signature__ takes priority over __wrapped__; prepend
    # an explicit `self` so the unbound method reads (self, <wire params>) and the
    # bound one reads (<wire params>). `endpoint` here is the shadowed
    # exec-generated function, not this factory.
    _generated_sig = inspect.signature(endpoint)
    func.__signature__ = _generated_sig.replace(  # type: ignore[attr-defined]
        parameters=[
            inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            *_generated_sig.parameters.values(),
        ]
    )
    if deprecated:
        # PEP 702-style runtime marker on the deprecated endpoint too.
        func.__deprecated__ = deprecated  # type: ignore[attr-defined]
    func.__doc__ = description
    return func


class ResultSet(list):
    # Annotate the class attribute so that, once py.typed makes these types
    # visible, the documented `res.total > n` pattern does not raise a new
    # mypy error from `total` being inferred as None.
    total: int | None = None

    @classmethod
    def from_dataset(cls, data, total):
        ret = cls(data)
        ret.total = total
        return ret


class _Unset:
    def __repr__(self) -> str:
        return "Unset"


Unset = _Unset()
