"""Parallel (multi-connection) file download for large archive endpoints.

The v3 archive endpoints (getsploit, distributive) 302-redirect to a pre-signed
Google Cloud Storage URL that supports HTTP range requests. This module saturates
the link by fetching many byte ranges concurrently and writing each straight to
its offset in a pre-allocated file — the aria2/axel model.

This is NOT part of the unasyncd async->sync mirror: the fan-out is structurally
different in the two worlds (``asyncio.gather`` of coroutines vs a
``ThreadPoolExecutor`` of blocking calls), so both flavours are written by hand.
The archive resource's async method calls :func:`parallel_download_async`; the
generated sync mirror calls :func:`parallel_download_sync` via a unasyncd name map.

Everything that is pure (range math, positional writes, atomic finish) is shared
module-level; only the two orchestrators and their per-range I/O diverge.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import os
import tempfile
import threading
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

import httpx

from ._base_client import RequestSpec
from ._exceptions import (
    APIConnectionError,
    APIResponseValidationError,
    APIStatusError,
    ErrorInfo,
)
from ._retry import _retry_timeout, _should_retry
from ._types import NotGiven

if TYPE_CHECKING:
    from ._transport_client_async import AsyncAPIClient
    from ._transport_client_sync import SyncAPIClient

# simplification: fixed 16 MiB range chunks over a fixed worker pool. Plenty of
# chunks for load-balancing a ~500 MiB archive across 8 workers without a tunable;
# expose a chunk_size arg only if a very different archive size ever needs it.
_CHUNK = 16 * 1024 * 1024
# Streaming read granularity for the positional write: caps per-worker memory, so
# total peak is ~= connections * _READ (not the chunk or the file size).
_READ = 1024 * 1024
_HAS_PWRITE = hasattr(os, "pwrite")  # POSIX: lock-free concurrent positional writes


# -- pure, shared helpers --------------------------------------------------


def _chunk_ranges(total: int, chunk: int) -> list[tuple[int, int]]:
    """Split ``[0, total)`` into inclusive ``(start, end)`` byte ranges."""
    return [(start, min(start + chunk, total) - 1) for start in range(0, total, chunk)]


def _parse_total(content_range: str | None) -> int:
    # "bytes 0-0/512875493" -> 512875493; return 0 when absent/unparseable so the
    # caller falls back to a single-stream download rather than guessing a size.
    if not content_range or "/" not in content_range:
        return 0
    tail = content_range.rsplit("/", 1)[1].strip()
    return int(tail) if tail.isdigit() else 0


def _open_prealloc(dest: str, total: int) -> tuple[int, str]:
    """Open a temp file beside ``dest`` sized to ``total``; return ``(fd, tmp_path)``."""
    directory = os.path.dirname(os.path.abspath(dest)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".vulners-dl-", dir=directory)
    if total:
        os.ftruncate(fd, total)
    return fd, tmp_path


def _write_at(fd: int, data: bytes, offset: int, lock: threading.Lock | None) -> None:
    """Write all of ``data`` at ``offset`` (thread-safe for distinct offsets)."""
    mv = memoryview(data)
    if lock is None:  # os.pwrite: atomic per call, no shared file position
        while mv:
            written = os.pwrite(fd, mv, offset)
            mv = mv[written:]
            offset += written
        return
    with lock:  # Windows fallback: serialize the (fast) seek+write; net stays parallel
        while mv:
            os.lseek(fd, offset, os.SEEK_SET)
            written = os.write(fd, mv)
            mv = mv[written:]
            offset += written


def _make_lock() -> threading.Lock | None:
    """A write lock where os.pwrite is unavailable (Windows); None (lock-free) on POSIX."""
    return None if _HAS_PWRITE else threading.Lock()


def _finish_atomic(fd: int, tmp_path: str, dest: str) -> None:
    """Flush, close (exactly once), and atomically move the temp file onto ``dest``.

    Owns the fd's final close and its own post-close failure cleanup, so the caller
    must run this only on the success path — outside the block whose ``except`` calls
    :func:`_cleanup`. A second ``os.close`` of an fd whose number may already have
    been reused by another thread would close an unrelated descriptor, and
    ``suppress(OSError)`` cannot catch that (closing a live reused fd raises nothing).
    """
    closed = False
    try:
        os.fsync(fd)
        os.close(fd)
        closed = True
        os.replace(tmp_path, dest)
    except BaseException:
        if not closed:  # fsync failed before the close; close once, still guarded
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _cleanup(fd: int, tmp_path: str) -> None:
    with contextlib.suppress(OSError):
        os.close(fd)
    with contextlib.suppress(OSError):
        os.unlink(tmp_path)


def _cap(client: AsyncAPIClient | SyncAPIClient) -> int | None:
    return client._config.max_response_bytes


def _check_total_cap(total: int, cap: int | None) -> None:
    if cap is not None and total > cap:
        raise APIResponseValidationError(
            f"archive is {total} bytes, over the max_response_bytes limit of {cap}"
        )


def _range_headers(start: int, end: int) -> dict[str, str]:
    return {"Range": f"bytes={start}-{end}"}


def _storage_request(
    client: AsyncAPIClient | SyncAPIClient,
    url: str,
    headers: dict[str, str] | None,
    timeout: httpx.Timeout,
) -> httpx.Request:
    # Keyless request to the pre-signed storage URL, tagged so the guarded
    # transport still applies its SSRF/redirect policy (auth rides in the URL
    # signature, so no X-Api-Key is sent or needed on the cross-origin hop).
    # ``timeout`` is the caller-resolved download timeout, so an explicit
    # ``timeout=`` bounds every storage leg, not just the initial resolve.
    # Built and sent on the storage client (HTTP/1.1 for an SDK-owned client) so a
    # parallel download opens real per-connection sockets instead of h2-multiplexing.
    return client._storage_client.build_request(
        "GET",
        url,
        headers=headers,
        timeout=timeout,
        extensions={"vulners_sdk": True, "vulners_origin": str(client._config.base_url)},
    )


def _short_range_error(start: int, end: int, remaining: int) -> APIResponseValidationError:
    # A cleanly-framed short 206 (e.g. a chunked body that terminates early, or a
    # Content-Length matching a short body while Content-Range over-claims the total)
    # raises no transport error, so without this the ftruncate zero-fill in the
    # unwritten tail would be published as a "complete" download. Fail loudly instead.
    return APIResponseValidationError(
        f"storage returned only {end - start + 1 - remaining} of "
        f"{end - start + 1} bytes for range {start}-{end}"
    )


# ========================================================================
# Async
# ========================================================================


async def _resilient_send_async(
    client: AsyncAPIClient,
    http: httpx.AsyncClient,
    request: httpx.Request,
    *,
    follow_redirects: bool = True,
    retry_reads: bool = True,
) -> httpx.Response:
    """Open a streaming response on ``http``, retrying transient failures and typing it.

    Gives the raw sends this module issues (resolve on the main client, range probe
    and single-stream fallback on the storage client) the SDK's connect-phase
    resilience, so a transport failure surfaces as ``APIConnectionError`` rather than
    a bare httpx error. With ``retry_reads`` False (the billable resolve), only
    pre-dispatch connect failures are retried — a post-dispatch read/timeout is not
    re-issued, so the archive-open, which the server bills, is never charged twice.
    Storage sends (not billed) retry freely.
    """
    attempt = 0
    retries = client._config.max_retries
    while True:
        try:
            return await http.send(request, stream=True, follow_redirects=follow_redirects)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            retryable = retry_reads or isinstance(exc, httpx.ConnectError)
            if attempt >= retries or not retryable:
                raise APIConnectionError(str(exc)) from exc
            attempt += 1
            await asyncio.sleep(_retry_timeout(attempt))


async def parallel_download_async(
    client: AsyncAPIClient,
    spec: RequestSpec,
    dest: str,
    *,
    params: Mapping[str, Any] | None = None,
    connections: int,
    timeout: float | httpx.Timeout | NotGiven,
) -> int:
    """Resolve the archive redirect and download it to ``dest``; return bytes written.

    Fetches many byte ranges concurrently when the storage supports them, else
    falls back to a single streaming download. Writes atomically (temp file +
    ``os.replace``), so an interrupted download never clobbers an existing file.
    """
    try:
        return await _download_async(
            client, spec, dest, params=params, connections=connections, timeout=timeout
        )
    except (APIConnectionError, APIStatusError) as error:
        # Same contract as the SDK request loop: on_error hooks observe the final
        # network/status failure of a download too (validation/IO errors are not
        # on_error events, matching _send_with_retries / _open_stream).
        await client._emit_error(error)
        raise


async def _download_async(
    client: AsyncAPIClient,
    spec: RequestSpec,
    dest: str,
    *,
    params: Mapping[str, Any] | None,
    connections: int,
    timeout: float | httpx.Timeout | NotGiven,
) -> int:
    dl_timeout = client._resolve_timeout(spec, timeout)
    resp = await _resolve_archive_async(client, spec, params, timeout)
    if not resp.is_redirect:  # 200: endpoint streamed the body directly
        try:
            return await _stream_to_file_async(client, resp, dest)
        finally:
            await resp.aclose()
    location = resp.headers.get("location")
    await resp.aclose()
    if not location:
        raise APIConnectionError("archive redirect carried no Location header")

    total, ranged = await _probe_range_async(client, location, dl_timeout)
    if not ranged or total <= 0:  # storage won't range: one stream, still correct
        return await _stream_url_async(client, location, dest, dl_timeout)
    _check_total_cap(total, _cap(client))
    return await _ranges_async(client, location, dest, total, connections, dl_timeout)


async def _resolve_archive_async(
    client: AsyncAPIClient,
    spec: RequestSpec,
    params: Mapping[str, Any] | None,
    timeout: float | httpx.Timeout | NotGiven,
) -> httpx.Response:
    """Open the archive endpoint through the SDK's pacing + retry policy.

    Paces on the account rate-limit bucket and retries a retryable error *status*
    (408/429 always, idempotent 5xx) with backoff — the same resilience every other
    SDK call gets — while never re-issuing a *successful* open: only a pre-dispatch
    connect failure (``retry_reads=False``) or a server-rejected-before-processing
    status is retried, so the billable archive-open is never charged twice.
    """
    bucket = client._bucket_for(client._ratelimit_key(spec))
    retries = client._config.max_retries
    attempt = 0
    while True:
        await bucket.consume(client._config.max_rate_limit_wait)
        request = client._build_request(spec, params=params, timeout=timeout)
        resp = await _resilient_send_async(
            client, client._client, request, follow_redirects=False, retry_reads=False
        )
        client._update_bucket_from_headers(bucket, resp)
        if resp.status_code < 400:
            return resp
        # Error status on the (billable) archive-open: read a bounded body, then retry
        # only server-rejected-before-processing statuses (408/429) or idempotent 5xx.
        body = await client._read_error_capped(resp)
        info = ErrorInfo(status_code=resp.status_code, error_code=None)
        await resp.aclose()
        if attempt < retries and _should_retry(
            info, resp.headers, idempotent=client._idempotent(spec)
        ):
            attempt += 1
            await asyncio.sleep(_retry_timeout(attempt, resp.headers))
            continue
        client._raise_stream_error(resp, body)  # always raises


async def _probe_range_async(
    client: AsyncAPIClient, url: str, timeout: httpx.Timeout
) -> tuple[int, bool]:
    request = _storage_request(client, url, _range_headers(0, 0), timeout)
    resp = await _resilient_send_async(client, client._storage_client, request)
    try:
        ranged = resp.status_code == httpx.codes.PARTIAL_CONTENT
        total = _parse_total(resp.headers.get("content-range")) if ranged else 0
    finally:
        await resp.aclose()
    return total, ranged


async def _ranges_async(
    client: AsyncAPIClient,
    url: str,
    dest: str,
    total: int,
    connections: int,
    timeout: httpx.Timeout,
) -> int:
    ranges = _chunk_ranges(total, _CHUNK)
    fd, tmp_path = _open_prealloc(dest, total)
    lock = _make_lock()
    sem = asyncio.Semaphore(connections)
    abort = asyncio.Event()

    async def one(start: int, end: int) -> None:
        async with sem:  # bound concurrency to `connections` in-flight ranges
            if abort.is_set():  # a sibling range already failed; skip queued work
                return
            await _fetch_range_async(client, url, start, end, fd, lock, timeout)

    tasks = [asyncio.ensure_future(one(start, end)) for start, end in ranges]
    try:
        for completed in asyncio.as_completed(tasks):
            await completed  # surfaces the first failing range immediately
    except BaseException:
        # Do NOT cancel the tasks: cancelling one parked in `await to_thread(_write_at)`
        # does not stop the OS write thread, which would then race _cleanup closing the
        # fd (and could scribble on a reused fd). Signal abort so queued ranges skip,
        # and await natural completion so no write is in flight when the fd is closed.
        abort.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.to_thread(_cleanup, fd, tmp_path)
        raise
    # All ranges done, no write in flight: _finish_atomic owns the fd's single close,
    # so it runs outside the try above (which would else re-close via _cleanup).
    await asyncio.to_thread(_finish_atomic, fd, tmp_path, dest)
    return total


async def _fetch_range_async(
    client: AsyncAPIClient,
    url: str,
    start: int,
    end: int,
    fd: int,
    lock: threading.Lock | None,
    timeout: httpx.Timeout,
) -> None:
    attempt = 0
    retries = client._config.max_retries
    while True:
        try:
            request = _storage_request(client, url, _range_headers(start, end), timeout)
            resp = await client._storage_client.send(request, stream=True)
            try:
                if resp.status_code != httpx.codes.PARTIAL_CONTENT:
                    raise APIConnectionError(
                        f"range request returned {resp.status_code}, expected 206"
                    )
                offset = start
                remaining = end - start + 1
                async for sub in resp.aiter_bytes(_READ):
                    if len(sub) > remaining:
                        raise APIResponseValidationError(
                            f"storage returned more than the requested range {start}-{end}"
                        )
                    await asyncio.to_thread(_write_at, fd, sub, offset, lock)
                    offset += len(sub)
                    remaining -= len(sub)
                if remaining:  # short 206: would leave a zero-filled hole — fail loudly
                    raise _short_range_error(start, end, remaining)
            finally:
                await resp.aclose()
            return
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            if attempt >= retries:
                raise APIConnectionError(f"range {start}-{end} failed: {exc}") from exc
            attempt += 1
            await asyncio.sleep(_retry_timeout(attempt))


async def _stream_url_async(
    client: AsyncAPIClient, url: str, dest: str, timeout: httpx.Timeout
) -> int:
    request = _storage_request(client, url, None, timeout)
    resp = await _resilient_send_async(client, client._storage_client, request)
    try:
        return await _stream_to_file_async(client, resp, dest)
    finally:
        await resp.aclose()


async def _stream_to_file_async(client: AsyncAPIClient, resp: httpx.Response, dest: str) -> int:
    cap = _cap(client)
    fd, tmp_path = _open_prealloc(dest, 0)
    lock = _make_lock()
    written = 0
    write: asyncio.Future[None] | None = None
    try:
        async for chunk in resp.aiter_bytes(_READ):
            # Keep a handle on the shielded positional write: external cancellation
            # (asyncio.wait_for / task.cancel) raises into this coroutine but cannot
            # stop the OS write thread, so the except path must drain the in-flight
            # write before _cleanup closes the fd — else os.close could race a live
            # write and scribble on a reused fd (the same discipline _ranges_async uses).
            write = asyncio.ensure_future(asyncio.to_thread(_write_at, fd, chunk, written, lock))
            await asyncio.shield(write)
            written += len(chunk)
            if cap is not None and written > cap:
                raise APIResponseValidationError(
                    f"archive exceeded the max_response_bytes limit of {cap}"
                )
    except BaseException:
        if write is not None:
            await asyncio.gather(write, return_exceptions=True)  # drain any in-flight write
        await asyncio.to_thread(_cleanup, fd, tmp_path)
        raise
    await asyncio.to_thread(_finish_atomic, fd, tmp_path, dest)
    return written


# ========================================================================
# Sync
# ========================================================================


def _resilient_send_sync(
    client: SyncAPIClient,
    http: httpx.Client,
    request: httpx.Request,
    *,
    follow_redirects: bool = True,
    retry_reads: bool = True,
) -> httpx.Response:
    """Sync twin of :func:`_resilient_send_async`."""
    attempt = 0
    retries = client._config.max_retries
    while True:
        try:
            return http.send(request, stream=True, follow_redirects=follow_redirects)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            retryable = retry_reads or isinstance(exc, httpx.ConnectError)
            if attempt >= retries or not retryable:
                raise APIConnectionError(str(exc)) from exc
            attempt += 1
            time.sleep(_retry_timeout(attempt))


def parallel_download_sync(
    client: SyncAPIClient,
    spec: RequestSpec,
    dest: str,
    *,
    params: Mapping[str, Any] | None = None,
    connections: int,
    timeout: float | httpx.Timeout | NotGiven,
) -> int:
    """Sync twin of :func:`parallel_download_async` (see it for semantics)."""
    try:
        return _download_sync(
            client, spec, dest, params=params, connections=connections, timeout=timeout
        )
    except (APIConnectionError, APIStatusError) as error:
        client._emit_error(error)
        raise


def _download_sync(
    client: SyncAPIClient,
    spec: RequestSpec,
    dest: str,
    *,
    params: Mapping[str, Any] | None,
    connections: int,
    timeout: float | httpx.Timeout | NotGiven,
) -> int:
    dl_timeout = client._resolve_timeout(spec, timeout)
    resp = _resolve_archive_sync(client, spec, params, timeout)
    if not resp.is_redirect:
        try:
            return _stream_to_file_sync(client, resp, dest)
        finally:
            resp.close()
    location = resp.headers.get("location")
    resp.close()
    if not location:
        raise APIConnectionError("archive redirect carried no Location header")

    total, ranged = _probe_range_sync(client, location, dl_timeout)
    if not ranged or total <= 0:
        return _stream_url_sync(client, location, dest, dl_timeout)
    _check_total_cap(total, _cap(client))
    return _ranges_sync(client, location, dest, total, connections, dl_timeout)


def _resolve_archive_sync(
    client: SyncAPIClient,
    spec: RequestSpec,
    params: Mapping[str, Any] | None,
    timeout: float | httpx.Timeout | NotGiven,
) -> httpx.Response:
    """Sync twin of :func:`_resolve_archive_async`."""
    bucket = client._bucket_for(client._ratelimit_key(spec))
    retries = client._config.max_retries
    attempt = 0
    while True:
        bucket.consume(client._config.max_rate_limit_wait)
        request = client._build_request(spec, params=params, timeout=timeout)
        resp = _resilient_send_sync(
            client, client._client, request, follow_redirects=False, retry_reads=False
        )
        client._update_bucket_from_headers(bucket, resp)
        if resp.status_code < 400:
            return resp
        body = client._read_error_capped(resp)
        info = ErrorInfo(status_code=resp.status_code, error_code=None)
        resp.close()
        if attempt < retries and _should_retry(
            info, resp.headers, idempotent=client._idempotent(spec)
        ):
            attempt += 1
            time.sleep(_retry_timeout(attempt, resp.headers))
            continue
        client._raise_stream_error(resp, body)  # always raises


def _probe_range_sync(
    client: SyncAPIClient, url: str, timeout: httpx.Timeout
) -> tuple[int, bool]:
    request = _storage_request(client, url, _range_headers(0, 0), timeout)
    resp = _resilient_send_sync(client, client._storage_client, request)
    try:
        ranged = resp.status_code == httpx.codes.PARTIAL_CONTENT
        total = _parse_total(resp.headers.get("content-range")) if ranged else 0
    finally:
        resp.close()
    return total, ranged


def _ranges_sync(
    client: SyncAPIClient,
    url: str,
    dest: str,
    total: int,
    connections: int,
    timeout: httpx.Timeout,
) -> int:
    ranges = _chunk_ranges(total, _CHUNK)
    fd, tmp_path = _open_prealloc(dest, total)
    lock = _make_lock()
    workers = min(connections, len(ranges))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [
            pool.submit(_fetch_range_sync, client, url, start, end, fd, lock, timeout)
            for start, end in ranges
        ]
        for future in concurrent.futures.as_completed(futures):
            future.result()  # re-raise the first chunk error
        pool.shutdown(wait=True)  # drain in-flight writes before the fd is closed
    except BaseException:
        # Cancel queued ranges and wait for in-flight ones before closing the fd,
        # so no thread writes to a closed descriptor.
        pool.shutdown(wait=True, cancel_futures=True)
        _cleanup(fd, tmp_path)
        raise
    # Writes drained above: _finish_atomic owns the fd's single close, so it runs
    # outside the try (which would else re-close via _cleanup).
    _finish_atomic(fd, tmp_path, dest)
    return total


def _fetch_range_sync(
    client: SyncAPIClient,
    url: str,
    start: int,
    end: int,
    fd: int,
    lock: threading.Lock | None,
    timeout: httpx.Timeout,
) -> None:
    attempt = 0
    retries = client._config.max_retries
    while True:
        try:
            request = _storage_request(client, url, _range_headers(start, end), timeout)
            resp = client._storage_client.send(request, stream=True)
            try:
                if resp.status_code != httpx.codes.PARTIAL_CONTENT:
                    raise APIConnectionError(
                        f"range request returned {resp.status_code}, expected 206"
                    )
                offset = start
                remaining = end - start + 1
                for sub in resp.iter_bytes(_READ):
                    if len(sub) > remaining:
                        raise APIResponseValidationError(
                            f"storage returned more than the requested range {start}-{end}"
                        )
                    _write_at(fd, sub, offset, lock)
                    offset += len(sub)
                    remaining -= len(sub)
                if remaining:  # short 206: would leave a zero-filled hole — fail loudly
                    raise _short_range_error(start, end, remaining)
            finally:
                resp.close()
            return
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            if attempt >= retries:
                raise APIConnectionError(f"range {start}-{end} failed: {exc}") from exc
            attempt += 1
            time.sleep(_retry_timeout(attempt))


def _stream_url_sync(client: SyncAPIClient, url: str, dest: str, timeout: httpx.Timeout) -> int:
    request = _storage_request(client, url, None, timeout)
    resp = _resilient_send_sync(client, client._storage_client, request)
    try:
        return _stream_to_file_sync(client, resp, dest)
    finally:
        resp.close()


def _stream_to_file_sync(client: SyncAPIClient, resp: httpx.Response, dest: str) -> int:
    cap = _cap(client)
    fd, tmp_path = _open_prealloc(dest, 0)
    lock = _make_lock()
    written = 0
    try:
        for chunk in resp.iter_bytes(_READ):
            _write_at(fd, chunk, written, lock)
            written += len(chunk)
            if cap is not None and written > cap:
                raise APIResponseValidationError(
                    f"archive exceeded the max_response_bytes limit of {cap}"
                )
    except BaseException:
        _cleanup(fd, tmp_path)
        raise
    # Sync writes run inline (no worker thread to drain, unlike the async twin), so
    # _finish_atomic just needs to sit outside the try that _cleanup guards — the fd
    # is still closed exactly once either way.
    _finish_atomic(fd, tmp_path, dest)
    return written


__all__ = ["parallel_download_async", "parallel_download_sync"]
