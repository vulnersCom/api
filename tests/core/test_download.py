"""Parallel getsploit download (``vulners._download`` + ``archive.download_getsploit``).

Covers the wire (resolve 302 -> ranged 206 fan-out), the fallbacks (no-range and
direct 200), the caps, per-range retry, failure cleanup/atomicity, and the pure
helpers — sync and async, against an ``httpx.MockTransport`` so nothing hits the net.
"""

from __future__ import annotations

import os
import threading

import httpx
import pytest

import vulners._download as dl
from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import (
    APIConnectionError,
    APIResponseValidationError,
    APIStatusError,
)

KEY = "SYNTHETIC-TEST-KEY"
GCS = "https://storage.googleapis.com/bucket/getsploit.db.zip?sig=abc"


def _parse_range(value: str) -> tuple[int, int | None]:
    lo, _, hi = value.split("=", 1)[1].partition("-")
    return int(lo), (int(hi) if hi else None)


class Storage:
    """MockTransport handler: vulners.com -> 302; the GCS leg serves ranges/faults."""

    def __init__(
        self,
        data: bytes,
        *,
        ranged: bool = True,
        redirect: bool = True,
        resolve_status: int = 302,
        resolve_statuses: list[int] | None = None,
        location: str | None = GCS,
        chunk_status: int = 206,
        chunk_overflow: bool = False,
        short_range: bool = False,
        faults: dict[str, list[Exception]] | None = None,
        resolve_faults: list[Exception] | None = None,
    ) -> None:
        self.data = data
        self.ranged = ranged
        self.redirect = redirect
        self.resolve_status = resolve_status
        # A queue of statuses returned on successive resolve calls (then the default
        # takes over): lets a test drive a retryable error status -> 302 sequence.
        self.resolve_statuses = resolve_statuses or []
        self.location = location
        self.chunk_status = chunk_status
        self.chunk_overflow = chunk_overflow
        self.short_range = short_range
        self.faults = faults or {}
        self.resolve_faults = resolve_faults or []
        self.gcs_calls = 0
        self.resolve_calls = 0
        self.gcs_timeout: dict[str, float | None] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "vulners.com":
            self.resolve_calls += 1
            if self.resolve_faults:
                raise self.resolve_faults.pop(0)
            status = (
                self.resolve_statuses.pop(0) if self.resolve_statuses else self.resolve_status
            )
            if status >= 400:
                return httpx.Response(status, json={"result": "error", "data": {}})
            if not self.redirect:
                return httpx.Response(200, content=self.data)
            headers = {"location": self.location} if self.location else {}
            return httpx.Response(status, headers=headers)

        # --- GCS storage leg ---
        self.gcs_calls += 1
        self.gcs_timeout = request.extensions.get("timeout")
        rng = request.headers.get("range")
        if self.faults.get(rng):
            raise self.faults[rng].pop(0)
        total = len(self.data)
        if rng is None:  # keyless whole-file GET (stream fallback)
            return httpx.Response(200, content=self.data)
        if rng == "bytes=0-0":  # range probe
            if not self.ranged:
                return httpx.Response(200, content=self.data)
            return httpx.Response(
                206,
                content=self.data[:1],
                headers={"content-range": f"bytes 0-0/{total}", "accept-ranges": "bytes"},
            )
        if self.chunk_status != 206:  # server ignored the range
            return httpx.Response(self.chunk_status, content=b"")
        start, end = _parse_range(rng)
        end = total - 1 if end is None else end
        body = self.data[start : end + 1]
        if self.chunk_overflow:
            body += b"EXTRA"  # more bytes than the client asked for
        if self.short_range:
            body = body[:-1]  # one byte short of the range the content-range still claims
        return httpx.Response(
            206,
            content=body,
            headers={"content-range": f"bytes {start}-{end}/{total}", "accept-ranges": "bytes"},
        )


def _sync(st: Storage, **cfg: object) -> Vulners:
    byo = httpx.Client(transport=httpx.MockTransport(st.handler), follow_redirects=True)
    return Vulners(KEY, http_client=byo, **cfg)  # type: ignore[arg-type]


def _async(st: Storage, **cfg: object) -> AsyncVulners:
    byo = httpx.AsyncClient(transport=httpx.MockTransport(st.handler), follow_redirects=True)
    return AsyncVulners(KEY, http_client=byo, **cfg)  # type: ignore[arg-type]


# ============================ happy path ============================


class TestParallelHappy:
    def test_sync_multi_chunk(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_CHUNK", 8)  # 40 bytes -> 5 chunks over the pool
        data = bytes(range(40))
        st = Storage(data)
        dest = tmp_path / "getsploit.db.zip"
        with _sync(st) as client:
            written = client.archive.download_getsploit(dest, connections=4)
        assert written == 40
        assert dest.read_bytes() == data

    async def test_async_multi_chunk(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_CHUNK", 8)
        data = bytes(range(40))
        st = Storage(data)
        dest = tmp_path / "getsploit.db.zip"
        async with _async(st) as client:
            written = await client.archive.download_getsploit(dest, connections=4)
        assert written == 40
        assert dest.read_bytes() == data


# ============================ fallbacks ============================


class TestFallback:
    def test_sync_no_range_falls_back_to_stream(self, tmp_path):
        data = b"no-range-server-body"
        st = Storage(data, ranged=False)
        dest = tmp_path / "out"
        with _sync(st) as client:
            written = client.archive.download_getsploit(dest)
        assert written == len(data)
        assert dest.read_bytes() == data

    async def test_async_no_range_falls_back_to_stream(self, tmp_path):
        data = b"no-range-server-body"
        st = Storage(data, ranged=False)
        dest = tmp_path / "out"
        async with _async(st) as client:
            assert await client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data

    def test_sync_direct_200_no_redirect(self, tmp_path):
        data = b"served-directly-no-redirect"
        st = Storage(data, redirect=False)
        dest = tmp_path / "out"
        with _sync(st) as client:
            assert client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data

    async def test_async_direct_200_no_redirect(self, tmp_path):
        data = b"served-directly-no-redirect"
        st = Storage(data, redirect=False)
        dest = tmp_path / "out"
        async with _async(st) as client:
            assert await client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data


# ============================ errors ============================


class TestErrors:
    def test_sync_resolve_error_status(self, tmp_path):
        st = Storage(b"x", resolve_status=404)
        with _sync(st) as client, pytest.raises(APIStatusError):
            client.archive.download_getsploit(tmp_path / "out")

    async def test_async_resolve_error_status(self, tmp_path):
        st = Storage(b"x", resolve_status=404)
        async with _async(st) as client:
            with pytest.raises(APIStatusError):
                await client.archive.download_getsploit(tmp_path / "out")

    def test_sync_no_location(self, tmp_path):
        st = Storage(b"x", location=None)
        with _sync(st) as client, pytest.raises(APIConnectionError):
            client.archive.download_getsploit(tmp_path / "out")

    async def test_async_no_location(self, tmp_path):
        st = Storage(b"x", location=None)
        async with _async(st) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.download_getsploit(tmp_path / "out")

    def test_sync_chunk_not_206(self, tmp_path):
        st = Storage(b"payload-bytes", chunk_status=200)
        with _sync(st, max_retries=0) as client, pytest.raises(APIConnectionError):
            client.archive.download_getsploit(tmp_path / "out")

    async def test_async_chunk_not_206(self, tmp_path):
        st = Storage(b"payload-bytes", chunk_status=200)
        async with _async(st, max_retries=0) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.download_getsploit(tmp_path / "out")

    def test_sync_chunk_overflow_rejected(self, tmp_path):
        st = Storage(b"0123456789", chunk_overflow=True)
        with _sync(st, max_retries=0) as client:
            with pytest.raises(APIResponseValidationError):
                client.archive.download_getsploit(tmp_path / "out")

    async def test_async_chunk_overflow_rejected(self, tmp_path):
        st = Storage(b"0123456789", chunk_overflow=True)
        async with _async(st, max_retries=0) as client:
            with pytest.raises(APIResponseValidationError):
                await client.archive.download_getsploit(tmp_path / "out")

    def test_sync_total_over_cap(self, tmp_path):
        st = Storage(b"0123456789")  # 10 bytes, cap 4
        with _sync(st, max_response_bytes=4) as client:
            with pytest.raises(APIResponseValidationError):
                client.archive.download_getsploit(tmp_path / "out")

    async def test_async_total_over_cap(self, tmp_path):
        st = Storage(b"0123456789")
        async with _async(st, max_response_bytes=4) as client:
            with pytest.raises(APIResponseValidationError):
                await client.archive.download_getsploit(tmp_path / "out")

    def test_sync_stream_over_cap(self, tmp_path):
        st = Storage(b"0123456789", redirect=False)  # direct 200 path
        with _sync(st, max_response_bytes=4) as client:
            with pytest.raises(APIResponseValidationError):
                client.archive.download_getsploit(tmp_path / "out")

    async def test_async_stream_over_cap(self, tmp_path):
        st = Storage(b"0123456789", redirect=False)
        async with _async(st, max_response_bytes=4) as client:
            with pytest.raises(APIResponseValidationError):
                await client.archive.download_getsploit(tmp_path / "out")


# ============================ retry ============================


class TestRetry:
    def test_sync_range_retried_then_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"retry-me-please!!"
        st = Storage(data, faults={f"bytes=0-{len(data) - 1}": [httpx.ReadError("transient")]})
        dest = tmp_path / "out"
        with _sync(st, max_retries=2) as client:
            assert client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data

    async def test_async_range_retried_then_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"retry-me-please!!"
        st = Storage(data, faults={f"bytes=0-{len(data) - 1}": [httpx.ReadError("transient")]})
        dest = tmp_path / "out"
        async with _async(st, max_retries=2) as client:
            assert await client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data

    def test_sync_probe_retried_then_succeeds(self, tmp_path, monkeypatch):
        # A transient failure on the range probe is retried + typed by _resilient_send.
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"probe-retry-data"
        st = Storage(data, faults={"bytes=0-0": [httpx.ConnectError("transient")]})
        dest = tmp_path / "out"
        with _sync(st, max_retries=2) as client:
            assert client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data

    async def test_async_probe_retried_then_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"probe-retry-data"
        st = Storage(data, faults={"bytes=0-0": [httpx.ConnectError("transient")]})
        dest = tmp_path / "out"
        async with _async(st, max_retries=2) as client:
            assert await client.archive.download_getsploit(dest) == len(data)
        assert dest.read_bytes() == data


# ============================ failure cleanup / atomicity ============================


class TestAtomicity:
    def _fault_all(self, data: bytes) -> dict[str, list[Exception]]:
        return {f"bytes=0-{len(data) - 1}": [httpx.ConnectError("down")]}

    def test_sync_existing_file_untouched_and_no_temp(self, tmp_path):
        data = b"the-new-archive-bytes"
        dest = tmp_path / "out"
        dest.write_bytes(b"OLD")
        st = Storage(data, faults=self._fault_all(data))
        with _sync(st, max_retries=0) as client:
            with pytest.raises(APIConnectionError):
                client.archive.download_getsploit(dest)
        assert dest.read_bytes() == b"OLD"
        assert not list(tmp_path.glob(".vulners-dl-*"))

    async def test_async_existing_file_untouched_and_no_temp(self, tmp_path):
        data = b"the-new-archive-bytes"
        dest = tmp_path / "out"
        dest.write_bytes(b"OLD")
        st = Storage(data, faults=self._fault_all(data))
        async with _async(st, max_retries=0) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.download_getsploit(dest)
        assert dest.read_bytes() == b"OLD"
        assert not list(tmp_path.glob(".vulners-dl-*"))

    def test_sync_multi_range_failure_drains_and_cleans(self, tmp_path, monkeypatch):
        # One of several ranges fails while others are in flight/queued: the pool
        # must drain, leave the existing file intact, and remove the temp.
        monkeypatch.setattr(dl, "_CHUNK", 8)  # 40 bytes -> 5 ranges
        data = bytes(range(40))
        dest = tmp_path / "out"
        dest.write_bytes(b"OLD")
        st = Storage(data, faults={"bytes=0-7": [httpx.ConnectError("down")]})
        with _sync(st, max_retries=0) as client:
            with pytest.raises(APIConnectionError):
                client.archive.download_getsploit(dest, connections=2)
        assert dest.read_bytes() == b"OLD"
        assert not list(tmp_path.glob(".vulners-dl-*"))

    async def test_async_multi_range_failure_drains_and_cleans(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_CHUNK", 8)
        data = bytes(range(40))
        dest = tmp_path / "out"
        dest.write_bytes(b"OLD")
        st = Storage(data, faults={"bytes=0-7": [httpx.ConnectError("down")]})
        async with _async(st, max_retries=0) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.download_getsploit(dest, connections=2)
        assert dest.read_bytes() == b"OLD"
        assert not list(tmp_path.glob(".vulners-dl-*"))


# ============================ resolve billing safety ============================


class TestResolveBilling:
    def test_sync_resolve_read_error_not_retried(self, tmp_path, monkeypatch):
        # A post-dispatch read error on the billable archive-open must NOT re-issue.
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        st = Storage(b"data", resolve_faults=[httpx.ReadError("post-dispatch")])
        with _sync(st, max_retries=3) as client:
            with pytest.raises(APIConnectionError):
                client.archive.download_getsploit(tmp_path / "out")
        assert st.resolve_calls == 1

    async def test_async_resolve_read_error_not_retried(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        st = Storage(b"data", resolve_faults=[httpx.ReadError("post-dispatch")])
        async with _async(st, max_retries=3) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.download_getsploit(tmp_path / "out")
        assert st.resolve_calls == 1

    def test_sync_resolve_connect_error_retried(self, tmp_path, monkeypatch):
        # A pre-dispatch connect failure (never billed) is safe to retry.
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"data-after-reconnect"
        st = Storage(data, resolve_faults=[httpx.ConnectError("pre-dispatch")])
        with _sync(st, max_retries=3) as client:
            assert client.archive.download_getsploit(tmp_path / "out") == len(data)
        assert st.resolve_calls == 2

    async def test_async_resolve_connect_error_retried(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"data-after-reconnect"
        st = Storage(data, resolve_faults=[httpx.ConnectError("pre-dispatch")])
        async with _async(st, max_retries=3) as client:
            assert await client.archive.download_getsploit(tmp_path / "out") == len(data)
        assert st.resolve_calls == 2


# ============================ method guard + pure helpers ============================


class TestMethodGuardAndHelpers:
    def test_connections_below_one_rejected(self):
        with Vulners(KEY) as client:
            with pytest.raises(ValueError, match="connections"):
                client.archive.download_getsploit("x", connections=0)

    async def test_connections_below_one_rejected_async(self):
        async with AsyncVulners(KEY) as client:
            with pytest.raises(ValueError, match="connections"):
                await client.archive.download_getsploit("x", connections=0)

    def test_collection_connections_below_one_rejected(self):
        with Vulners(KEY) as client:
            with pytest.raises(ValueError, match="connections"):
                client.archive.download_collection("cve", "x", connections=0)

    async def test_collection_connections_below_one_rejected_async(self):
        async with AsyncVulners(KEY) as client:
            with pytest.raises(ValueError, match="connections"):
                await client.archive.download_collection("cve", "x", connections=0)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("bytes 0-0/512", 512),
            ("bytes 0-1023/9999", 9999),
            (None, 0),
            ("garbage", 0),
            ("bytes 0-0/notanumber", 0),
        ],
    )
    def test_parse_total(self, value, expected):
        assert dl._parse_total(value) == expected

    def test_chunk_ranges(self):
        assert dl._chunk_ranges(10, 4) == [(0, 3), (4, 7), (8, 9)]
        assert dl._chunk_ranges(8, 4) == [(0, 3), (4, 7)]

    @pytest.mark.skipif(not dl._HAS_PWRITE, reason="os.pwrite is POSIX-only")
    def test_write_at_pwrite_branch(self, tmp_path):
        p = tmp_path / "f"
        fd = os.open(p, os.O_RDWR | os.O_CREAT)
        try:
            os.ftruncate(fd, 6)
            dl._write_at(fd, b"CD", 2, None)  # lock=None -> pwrite
            dl._write_at(fd, b"AB", 0, None)
        finally:
            os.close(fd)
        assert p.read_bytes() == b"ABCD\x00\x00"

    def test_write_at_lock_branch(self, tmp_path):
        p = tmp_path / "f"
        fd = os.open(p, os.O_RDWR | os.O_CREAT)
        lock = threading.Lock()
        try:
            os.ftruncate(fd, 4)
            dl._write_at(fd, b"ZZ", 2, lock)  # lock set -> lseek+write
            dl._write_at(fd, b"YY", 0, lock)
        finally:
            os.close(fd)
        assert p.read_bytes() == b"YYZZ"

    def test_make_lock_posix(self, monkeypatch):
        monkeypatch.setattr(dl, "_HAS_PWRITE", True)
        assert dl._make_lock() is None

    def test_make_lock_windows(self, monkeypatch):
        monkeypatch.setattr(dl, "_HAS_PWRITE", False)
        assert isinstance(dl._make_lock(), type(threading.Lock()))


# ============================ short (truncated) range ============================


class TestShortRange:
    # A cleanly-framed short 206 (body shorter than the content-range claims, no
    # transport error) must be rejected, not published with a zero-filled hole.
    def test_sync_short_range_rejected(self, tmp_path):
        st = Storage(b"0123456789", short_range=True)
        dest = tmp_path / "out"
        with _sync(st, max_retries=0) as client:
            with pytest.raises(APIResponseValidationError, match="of 10 bytes for range 0-9"):
                client.archive.download_getsploit(dest)
        assert not dest.exists()
        assert not list(tmp_path.glob(".vulners-dl-*"))

    async def test_async_short_range_rejected(self, tmp_path):
        st = Storage(b"0123456789", short_range=True)
        dest = tmp_path / "out"
        async with _async(st, max_retries=0) as client:
            with pytest.raises(APIResponseValidationError, match="of 10 bytes for range 0-9"):
                await client.archive.download_getsploit(dest)
        assert not dest.exists()
        assert not list(tmp_path.glob(".vulners-dl-*"))


# ============================ resolve retry on retryable status ============================


class TestResolveRetry:
    def test_sync_retryable_status_retried_then_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"after-429-retry-body"
        st = Storage(data, resolve_statuses=[429])  # 429 (retried) -> 302
        with _sync(st, max_retries=3) as client:
            assert client.archive.download_getsploit(tmp_path / "out") == len(data)
        assert st.resolve_calls == 2

    async def test_async_retryable_status_retried_then_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        data = b"after-429-retry-body"
        st = Storage(data, resolve_statuses=[429])
        async with _async(st, max_retries=3) as client:
            assert await client.archive.download_getsploit(tmp_path / "out") == len(data)
        assert st.resolve_calls == 2

    def test_sync_retryable_status_exhausted_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        st = Storage(b"x", resolve_statuses=[429, 429, 429, 429])
        with _sync(st, max_retries=2) as client:
            with pytest.raises(APIStatusError):
                client.archive.download_getsploit(tmp_path / "out")
        assert st.resolve_calls == 3  # initial + 2 retries

    async def test_async_retryable_status_exhausted_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dl, "_retry_timeout", lambda *a, **k: 0.0)
        st = Storage(b"x", resolve_statuses=[429, 429, 429, 429])
        async with _async(st, max_retries=2) as client:
            with pytest.raises(APIStatusError):
                await client.archive.download_getsploit(tmp_path / "out")
        assert st.resolve_calls == 3


# ============================ caller timeout reaches storage legs ============================


class TestTimeout:
    def test_sync_timeout_applied_to_storage_leg(self, tmp_path):
        st = Storage(b"payload-bytes")
        with _sync(st) as client:
            client.archive.download_getsploit(tmp_path / "out", timeout=5.0)
        assert st.gcs_timeout is not None
        assert st.gcs_timeout["read"] == 5.0  # not the 300s archive default

    async def test_async_timeout_applied_to_storage_leg(self, tmp_path):
        st = Storage(b"payload-bytes")
        async with _async(st) as client:
            await client.archive.download_getsploit(tmp_path / "out", timeout=5.0)
        assert st.gcs_timeout is not None
        assert st.gcs_timeout["read"] == 5.0


# ============================ atomic-finish failure ============================


class TestFinishFailure:
    # os.replace fails after a complete download: _finish_atomic owns the fd's single
    # close and unlinks its own temp, and _cleanup (which would re-close the fd) must
    # NOT run — the download error surfaces, the destination is untouched.
    def test_sync_replace_failure_cleans_up_without_recleanup(self, tmp_path, monkeypatch):
        st = Storage(b"0123456789")
        cleanup_fds: list[int] = []
        orig = dl._cleanup

        def spy(fd: int, tmp: str) -> None:
            cleanup_fds.append(fd)
            orig(fd, tmp)

        monkeypatch.setattr(dl, "_cleanup", spy)
        monkeypatch.setattr(
            os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError("boom"))
        )
        dest = tmp_path / "out"
        with _sync(st) as client:
            with pytest.raises(OSError, match="boom"):
                client.archive.download_getsploit(dest)
        assert cleanup_fds == []
        assert not dest.exists()
        assert not list(tmp_path.glob(".vulners-dl-*"))

    async def test_async_replace_failure_cleans_up_without_recleanup(self, tmp_path, monkeypatch):
        st = Storage(b"0123456789")
        cleanup_fds: list[int] = []
        orig = dl._cleanup

        def spy(fd: int, tmp: str) -> None:
            cleanup_fds.append(fd)
            orig(fd, tmp)

        monkeypatch.setattr(dl, "_cleanup", spy)
        monkeypatch.setattr(
            os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError("boom"))
        )
        dest = tmp_path / "out"
        async with _async(st) as client:
            with pytest.raises(OSError, match="boom"):
                await client.archive.download_getsploit(dest)
        assert cleanup_fds == []
        assert not dest.exists()
        assert not list(tmp_path.glob(".vulners-dl-*"))

    def test_finish_atomic_fsync_failure_closes_once_and_unlinks(self, tmp_path, monkeypatch):
        # fsync raises before the close: the fd is still closed exactly once and the
        # temp removed (the pre-close failure branch).
        dest = str(tmp_path / "out")
        fd, tmp = dl._open_prealloc(dest, 4)
        monkeypatch.setattr(os, "fsync", lambda f: (_ for _ in ()).throw(OSError("fsync boom")))
        with pytest.raises(OSError, match="fsync boom"):
            dl._finish_atomic(fd, tmp, dest)
        assert not os.path.exists(tmp)
        assert not os.path.exists(dest)

    async def test_async_stream_read_error_before_first_write_cleans_up(self, tmp_path):
        # A read error before any write leaves `write` None: the drain must be skipped
        # and the temp still cleaned (covers the single-stream cancel/error path).
        class _BoomStream:
            async def aiter_bytes(self, size: int):
                raise httpx.ReadError("boom")
                yield b""  # pragma: no cover — marks this an async generator

        dest = str(tmp_path / "out")
        async with AsyncVulners(KEY) as client:
            with pytest.raises(httpx.ReadError):
                await dl._stream_to_file_async(client.archive._client, _BoomStream(), dest)
        assert not list(tmp_path.glob(".vulners-dl-*"))


# ============================ on_error hooks ============================


class TestOnErrorHook:
    # A download's final network/status failure must reach the caller's on_error
    # hooks, like every other SDK call; a successful download must not.
    def test_sync_fires_on_connection_failure(self, tmp_path):
        errors: list[Exception] = []
        st = Storage(b"payload", faults={"bytes=0-6": [httpx.ConnectError("down")]})
        with _sync(st, max_retries=0, on_error=[errors.append]) as client:
            with pytest.raises(APIConnectionError):
                client.archive.download_getsploit(tmp_path / "out")
        assert len(errors) == 1
        assert isinstance(errors[0], APIConnectionError)

    async def test_async_fires_on_connection_failure(self, tmp_path):
        errors: list[Exception] = []
        st = Storage(b"payload", faults={"bytes=0-6": [httpx.ConnectError("down")]})
        async with _async(st, max_retries=0, on_error=[errors.append]) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.download_getsploit(tmp_path / "out")
        assert len(errors) == 1
        assert isinstance(errors[0], APIConnectionError)

    def test_sync_fires_on_status_error(self, tmp_path):
        errors: list[Exception] = []
        st = Storage(b"x", resolve_status=404)
        with _sync(st, on_error=[errors.append]) as client:
            with pytest.raises(APIStatusError):
                client.archive.download_getsploit(tmp_path / "out")
        assert len(errors) == 1
        assert isinstance(errors[0], APIStatusError)

    async def test_async_fires_on_status_error(self, tmp_path):
        errors: list[Exception] = []
        st = Storage(b"x", resolve_status=404)
        async with _async(st, on_error=[errors.append]) as client:
            with pytest.raises(APIStatusError):
                await client.archive.download_getsploit(tmp_path / "out")
        assert len(errors) == 1
        assert isinstance(errors[0], APIStatusError)

    def test_sync_not_fired_on_success(self, tmp_path):
        errors: list[Exception] = []
        st = Storage(b"payload-bytes")
        with _sync(st, on_error=[errors.append]) as client:
            client.archive.download_getsploit(tmp_path / "out")
        assert errors == []

    async def test_async_not_fired_on_success(self, tmp_path):
        errors: list[Exception] = []
        st = Storage(b"payload-bytes")
        async with _async(st, on_error=[errors.append]) as client:
            await client.archive.download_getsploit(tmp_path / "out")
        assert errors == []


# ============================ storage client (HTTP/1.1 legs) ============================


class TestStorageClient:
    # An SDK-owned client gets a dedicated HTTP/1.1 client for the parallel storage
    # legs; a bring-your-own client is reused as-is.
    def test_owned_is_dedicated_and_cached(self):
        with Vulners(KEY) as client:
            api = client.archive._client
            sc = api._storage_client
            assert sc is not api._client  # dedicated, not the main (h2) client
            assert sc is api._storage_client  # cached on repeat access

    async def test_owned_is_dedicated_and_cached_async(self):
        async with AsyncVulners(KEY) as client:
            api = client.archive._client
            sc = api._storage_client
            assert sc is not api._client
            assert sc is api._storage_client

    def test_byo_reuses_caller_client(self):
        st = Storage(b"x")
        with _sync(st) as client:
            api = client.archive._client
            assert api._storage_client is api._client

    async def test_byo_reuses_caller_client_async(self):
        st = Storage(b"x")
        async with _async(st) as client:
            api = client.archive._client
            assert api._storage_client is api._client

    def test_owned_storage_client_closed_on_exit(self):
        with Vulners(KEY) as client:
            sc = client.archive._client._storage_client
        assert sc.is_closed

    async def test_owned_storage_client_closed_on_exit_async(self):
        async with AsyncVulners(KEY) as client:
            sc = client.archive._client._storage_client
        assert sc.is_closed
