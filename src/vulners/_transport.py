"""httpx transport wrappers that enforce the SDK's credential-safety policy.

Ported from ``vulners.base.VulnersApiTransport`` and provided in both a sync
(:class:`VulnersTransport`) and async (:class:`AsyncVulnersTransport`) flavour;
the policy itself is sans-IO module-level helpers shared by both. On any
cross-origin hop the ``X-Api-Key`` header, a body-carried key and a query key are
all stripped, a redirect to a private/internal address is refused (SSRF guard),
and ``Set-Cookie`` is dropped from every response.
"""

from __future__ import annotations

import ipaddress
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
    """Parse a host that is an IP *literal*, including bare-integer encodings.

    Covers dotted-quad / IPv6 literals plus the single-integer decimal, hex
    (``0x…``) and octal (``0…``) forms that the OS resolver accepts — classic
    SSRF obfuscations of, e.g., 127.0.0.1 as ``2130706433`` / ``0x7f000001``.
    Returns ``None`` for anything that is not a numeric literal (a real DNS name).
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    base: int | None = None
    if host.isdigit():
        base = 8 if len(host) > 1 and host[0] == "0" else 10
    elif host[:2].lower() == "0x":
        base = 16
    if base is None:
        return None
    try:
        return ipaddress.ip_address(int(host, base))
    except ValueError:
        return None


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
        new_content = urlencode([(k, v) for k, v in pairs if k != "apiKey"]).encode("utf-8")
    else:
        return
    request._content = new_content
    request.headers["content-length"] = str(len(new_content))
    if _HttpxByteStream is not None:
        request.stream = _HttpxByteStream(new_content)


def _apply_request_guards(request: httpx.Request, origin: httpx.URL | None) -> None:
    # Compared against the fixed origin (not the previous hop): once the key is
    # dropped it stays dropped for every later hop, and a bounce back to the
    # origin does not restore it (mirrors httpx's Authorization policy).
    if origin is not None and not _key_allowed(request.url, origin):
        request.headers.pop("x-api-key", None)
        _scrub_credential(request)
        _guard_redirect_target(request.url)


def _strip_set_cookie(response: httpx.Response) -> None:
    if "set-cookie" in response.headers:
        del response.headers["set-cookie"]


class VulnersTransport(httpx.BaseTransport):
    """Sync transport wrapper enforcing the credential-safety policy."""

    def __init__(self, transport: httpx.BaseTransport, origin: httpx.URL | None = None) -> None:
        self._transport = transport
        self._origin = origin

    def handle_request(self, request: httpx.Request) -> httpx.Response:
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
        self, transport: httpx.AsyncBaseTransport, origin: httpx.URL | None = None
    ) -> None:
        self._transport = transport
        self._origin = origin

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _apply_request_guards(request, self._origin)
        response = await self._transport.handle_async_request(request)
        _strip_set_cookie(response)
        return response

    async def aclose(self) -> None:
        # The inherited __aenter__/__aexit__ route through this aclose().
        await self._transport.aclose()


__all__ = ["AsyncVulnersTransport", "VulnersTransport"]
