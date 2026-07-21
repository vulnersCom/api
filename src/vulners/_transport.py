"""httpx transport wrappers that enforce the SDK's credential-safety policy.

Ported from ``vulners.base.VulnersApiTransport`` and provided in both a sync
(:class:`VulnersTransport`) and async (:class:`AsyncVulnersTransport`) flavour;
the policy itself is sans-IO module-level helpers shared by both. On any
cross-origin hop the ``X-Api-Key`` header, a body-carried key and a query key are
all stripped, a redirect to a private/internal address is refused (SSRF guard),
and ``Set-Cookie`` is dropped from every response. When mounted over a
caller-supplied client (``sdk_only=True``) the policy applies only to requests
the SDK itself built (tagged via the ``vulners_sdk`` request extension); the
application's own traffic passes through unchanged.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode

import httpx
import orjson

from ._exceptions import APIConnectionError

# Rebuild a request body stream after scrubbing the credential out of it. Guarded:
# if this httpx internal moves, the credential is still removed from the header
# and the query, and the body scrub simply becomes a no-op rather than breaking.
try:
    from httpx._content import ByteStream as _HttpxByteStream
except Exception:  # pragma: no cover - defensive against httpx internals moving
    _HttpxByteStream = None  # type: ignore[assignment, misc]


def _port_or_default(url: httpx.URL) -> int:
    return url.port if url.port is not None else (443 if url.scheme == "https" else 80)


def _key_allowed(url: httpx.URL, origin: httpx.URL) -> bool:
    if (url.scheme, url.host, _port_or_default(url)) == (
        origin.scheme,
        origin.host,
        _port_or_default(origin),
    ):
        return True
    # http->https upgrade of the same host on default ports: httpx keeps the key
    # here, so mirror that one exception (https->http downgrade is not covered).
    return (
        url.host == origin.host
        and origin.scheme == "http"
        and _port_or_default(origin) == 80
        and url.scheme == "https"
        and _port_or_default(url) == 443
    )


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _host_as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a host that is an IP *literal*, matching what the OS resolver accepts.

    Covers dotted-quad and IPv6 literals plus every numeric IPv4 obfuscation the
    resolver honours via ``inet_aton``: single-integer decimal/hex/octal
    (``2130706433``, ``0x7f000001``), dotted short-forms (``127.1``) and per-octet
    hex/octal (``0x7f.0.0.1``, ``169.254.43518`` -> 169.254.169.254). Returns
    ``None`` for a real DNS name, which is delegated to the resolver unchanged.
    """
    try:
        return ipaddress.ip_address(host)  # canonical IPv4 + every IPv6 literal
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(host)  # IPv4 shorthand / mixed-radix, as getaddrinfo
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def _guard_redirect_target(url: httpx.URL) -> None:
    # Reached only for a cross-origin hop, so an on-prem server_url that is itself
    # a private IP still works (its own requests are same-origin). Any public host
    # is delegated unchanged; what is refused is a redirect whose target is an IP
    # literal in a loopback / link-local / private / reserved range (cloud
    # metadata at 169.254.169.254, 127.0.0.0/8, ::1, RFC1918, 0.0.0.0), including
    # the numeric-encoded forms above.
    # simplification: only literal hosts are inspected; a DNS name that *resolves*
    # to an internal address is not caught (no getaddrinfo here — this mirrors
    # httpx/legacy behaviour and avoids blocking I/O plus a rebinding TOCTOU on
    # the redirect path). Upgrade path: resolve and check every A/AAAA record.
    ip = _host_as_ip(url.host)
    if ip is not None and _is_forbidden_ip(ip):
        raise APIConnectionError(
            f"refusing to follow a redirect to a private or internal address: {url.host}"
        )


def _scrub_credential(request: httpx.Request) -> None:
    # Mirror the header strip for the two other places the key can ride: the query
    # string (GET) and the request body (POST). A multipart/streaming upload is
    # left untouched, so reading the stream here can never consume an upload body.
    if "apiKey" in request.url.params:
        request.url = request.url.copy_remove_param("apiKey")
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type == "application/json" or media_type.endswith("+json"):
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
        new_content = urlencode([(k, v) for k, v in pairs if k != "apiKey"]).encode("utf-8")
    else:
        return
    # Fail closed: httpx transmits ``request.stream``, so setting ``_content``
    # alone would leave the credential-bearing stream in place. If we cannot
    # rebuild the stream via httpx's ByteStream, refuse the cross-origin hop
    # rather than risk sending the key onward.
    if _HttpxByteStream is None:
        raise APIConnectionError(
            "cannot strip the API key from the request body for a cross-origin "
            "redirect (httpx internals changed); refusing to follow the redirect"
        )
    request._content = new_content
    request.headers["content-length"] = str(len(new_content))
    request.stream = _HttpxByteStream(new_content)


def _apply_request_guards(request: httpx.Request, origin: httpx.URL | None) -> None:
    # Prefer the per-request origin the SDK stamped in ``_build_request`` so one
    # guarded transport shared across clients with different base_urls compares
    # each request against its own origin — not whichever client wrapped the
    # transport first — falling back to the transport's fixed origin otherwise.
    # Compared against the origin (not the previous hop): once the key is dropped
    # it stays dropped for every later hop, and a bounce back to the origin does
    # not restore it (mirrors httpx's Authorization policy).
    req_origin = request.extensions.get("vulners_origin")
    effective = httpx.URL(req_origin) if req_origin else origin
    if effective is not None and not _key_allowed(request.url, effective):
        request.headers.pop("x-api-key", None)
        _scrub_credential(request)
        _guard_redirect_target(request.url)


def _strip_set_cookie(response: httpx.Response) -> None:
    if "set-cookie" in response.headers:
        del response.headers["set-cookie"]


def _passes_unguarded(request: httpx.Request, sdk_only: bool) -> bool:
    # A guard mounted on a shared (bring-your-own) client is scoped to
    # SDK-originated requests: the SDK tags them via the ``vulners_sdk`` request
    # extension (set in ``_build_request``; httpx preserves extensions across
    # redirect hops). The application's own traffic — including any credentials
    # or cookies it carries — passes through completely untouched.
    return sdk_only and not request.extensions.get("vulners_sdk")


class VulnersTransport(httpx.BaseTransport):
    """Sync transport wrapper enforcing the credential-safety policy."""

    def __init__(
        self,
        transport: httpx.BaseTransport,
        origin: httpx.URL | None = None,
        sdk_only: bool = False,
    ) -> None:
        self._transport = transport
        self._origin = origin
        self._sdk_only = sdk_only

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if _passes_unguarded(request, self._sdk_only):
            return self._transport.handle_request(request)
        _apply_request_guards(request, self._origin)
        response = self._transport.handle_request(request)
        _strip_set_cookie(response)
        return response

    def close(self) -> None:
        # httpx.BaseTransport.close() is a no-op, so delegate to release the pool.
        # The inherited __enter__/__exit__ route through this close().
        self._transport.close()


class AsyncVulnersTransport(httpx.AsyncBaseTransport):
    """Async transport wrapper enforcing the credential-safety policy."""

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport,
        origin: httpx.URL | None = None,
        sdk_only: bool = False,
    ) -> None:
        self._transport = transport
        self._origin = origin
        self._sdk_only = sdk_only

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if _passes_unguarded(request, self._sdk_only):
            return await self._transport.handle_async_request(request)
        _apply_request_guards(request, self._origin)
        response = await self._transport.handle_async_request(request)
        _strip_set_cookie(response)
        return response

    async def aclose(self) -> None:
        # The inherited __aenter__/__aexit__ route through this aclose().
        await self._transport.aclose()


__all__ = ["AsyncVulnersTransport", "VulnersTransport"]
