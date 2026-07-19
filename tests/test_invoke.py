"""Pins for VulnersApiBase._invoke: HTTP method mapping, path/file/api-key
params, headers, envelope unwrapping, gzip/zip handling, set-cookie stripping.

Mock responses use the exact content-type "application/json" (no charset) —
strict equality is current behavior (pinned).
"""

from __future__ import annotations

import gzip
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import orjson
import pytest

import vulners
import vulners.base
from vulners.base import VulnersApiError, _parse_retry_after
from vulners.vscanner import TaskList
from vulners.vulners.search import DEFAULT_FIELDS


class TestMethodParamMapping:
    def test_get_sends_params_in_query(self, api, server):
        server.enqueue_envelope({"result": [{"synthetic": True}]})
        api.search.get_bulletin_history(id="CVE-2099-99999")
        req = server.last
        assert req.method == "GET"
        assert req.url.path == "/api/v3/search/history/"
        assert dict(req.url.params) == {"id": "CVE-2099-99999"}
        assert req.content == b""

    def test_post_sends_params_as_json_body(self, api, server):
        server.enqueue_envelope(
            {"search": [{"_source": {"id": "CVE-2099-0001"}}], "total": 1}
        )
        result = api.search.search_bulletins("type:synthetic", limit=5)
        req = server.last
        assert req.method == "POST"
        assert req.url.path == "/api/v3/search/lucene/"
        assert req.headers["content-type"] == "application/json"
        assert not dict(req.url.params)
        assert orjson.loads(req.content) == {
            "query": "type:synthetic",
            "size": 5,
            "skip": 0,
            "fields": list(DEFAULT_FIELDS),
        }
        # ResultSet round-trip: documents unwrapped, .total preserved
        assert list(result) == [{"id": "CVE-2099-0001"}]
        assert result.total == 1

    def test_delete_sends_params_in_query(self, api, server):
        server.enqueue_json({"result": "OK"})
        ret = api.subscription_v4.delete(id="SYNTHETIC00-SUB-0001")
        req = server.last
        assert req.method == "DELETE"
        assert req.url.path == "/api/v4/subscriptions/delete/"
        assert dict(req.url.params) == {"id": "SYNTHETIC00-SUB-0001"}
        assert req.content == b""
        # v4-style body without "data" is returned whole
        assert ret == {"result": "OK"}


class TestPostBodySerialization:
    """POST/PUT/PATCH bodies are serialized with orjson."""

    def test_post_body_is_orjson_with_json_content_type(self, api, server):
        payload = {"query": "type:synthetic", "unicode": "é☃", "size": 5, "skip": 0}
        api._invoke("POST", "/synthetic/post", dict(payload), ())
        req = server.last
        assert req.method == "POST"
        assert req.headers["content-type"] == "application/json"
        # byte-identical to orjson and semantically equal to the payload
        assert req.content == orjson.dumps(payload)
        assert orjson.loads(req.content) == payload
        assert req.headers["content-length"] == str(len(req.content))

    def test_get_body_unaffected(self, api, server):
        api._invoke("GET", "/synthetic/get", {"q": "x"}, ())
        req = server.last
        assert req.content == b""
        assert dict(req.url.params) == {"q": "x"}

    def test_oversize_int_body_falls_back_to_stdlib_json(self, api, server):
        # orjson only encodes 64-bit integers; a body carrying a larger int must
        # still be sent (as it was before the orjson fast path) rather than
        # crashing with an uncaught TypeError.
        payload = {"threshold": 2 ** 70}
        api._invoke("POST", "/synthetic/bigint", dict(payload), ())
        req = server.last
        assert req.method == "POST"
        assert req.headers["content-type"] == "application/json"
        # the oversize int survives the round-trip on the wire
        assert json.loads(req.content) == payload
        # byte-identical to the pre-orjson (httpx stdlib json) encoder
        assert req.content == httpx.Request("POST", req.url, json=payload).content


class TestPathParams:
    """URL path-placeholder substitution: values quoted to a single segment,
    the path key popped so it never leaks into the body/query."""

    def test_path_params_substituted_and_popped(self, api, server):
        api._invoke("GET", "/synthetic/{item_id}/detail", {"item_id": "SYNTH-0001", "q": "x"}, ("item_id",))
        req = server.last
        assert req.url.path == "/synthetic/SYNTH-0001/detail"
        # pop semantics: the path key must not leak into the query
        assert dict(req.url.params) == {"q": "x"}

    def test_uuid_path_value_is_byte_identical(self, api, server):
        uid = "00000000-0000-4000-8000-000000000001"
        api._invoke(
            "GET",
            "/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks",
            {"project_id": uid},
            ("project_id",),
        )
        req = server.last
        expected = f"/api/v3/proxy/vscanner/v2/projects/{uid}/tasks"
        assert req.url.path == expected
        assert req.url.raw_path == expected.encode()

    def test_slash_in_path_value_stays_one_segment(self, api, server):
        api._invoke(
            "GET",
            "/api/v3/vscanner/{pid}/tasks",
            {"pid": "../../api/v3/apiKey/info"},
            ("pid",),
        )
        raw = server.last.url.raw_path
        # slashes percent-encoded -> value cannot traverse to another endpoint
        assert b"%2F" in raw
        assert b"/api/v3/apiKey/info" not in raw

    def test_repeated_placeholder_no_keyerror(self, api, server):
        api._invoke("GET", "/a/{id}/b/{id}", {"id": "X1"}, ("id",))
        assert server.last.url.path == "/a/X1/b/X1"

    def test_placeholder_without_matching_param_raises_keyerror(self, api, server):
        # mismatch misuse of the private _invoke still raises KeyError (pinned)
        with pytest.raises(KeyError):
            api._invoke("GET", "/a/{missing}", {"other": "x"}, ("missing",))
        assert len(server.requests) == 0

    def test_path_key_popped_and_query_not_double_encoded(self, api, server):
        api._invoke("GET", "/x/{id}", {"id": "A B", "q": "a b"}, ("id",))
        req = server.last
        assert req.url.raw_path.startswith(b"/x/A%20B")
        # path key does not leak into the query; query decodes back correctly
        assert dict(req.url.params) == {"q": "a b"}
        assert b"%2520" not in req.url.raw_path

    def test_vscanner_path_param_end_to_end(self, make_api, server):
        vapi = make_api(vulners.VScannerApi)
        project_id = "00000000-0000-4000-8000-000000000001"
        server.enqueue_envelope([{"_id": "00000000-0000-4000-8000-0000000000aa", "name": "synthetic-task"}])
        tasks = vapi.get_tasks(project_id)
        req = server.last
        assert req.method == "GET"
        assert req.url.path == f"/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks"
        # declared defaults go on the wire; project_id does not leak into query
        assert dict(req.url.params) == {"offset": "0", "limit": "50"}
        assert isinstance(tasks, TaskList)
        assert tasks[0]["name"] == "synthetic-task"


class TestFileParams:
    def test_file_sent_as_multipart_and_closed_on_success(self, api, server, tmp_path, monkeypatch):
        sbom = tmp_path / "synthetic-sbom.json"
        payload = b'{"bomFormat": "SYNTHETIC", "components": []}'
        sbom.write_bytes(payload)

        opened = []
        real_open = open

        def spy_open(*args, **kwargs):
            fh = real_open(*args, **kwargs)
            opened.append(fh)
            return fh

        # base.py calls the open() builtin; shadow it via a module attribute
        monkeypatch.setattr(vulners.base, "open", spy_open, raising=False)

        server.enqueue_json({"result": {"vulnerabilities": []}})
        ret = api.audit.sbom_audit(file=sbom)

        req = server.last
        assert req.method == "POST"
        assert req.headers["content-type"].startswith("multipart/form-data; boundary=")
        assert b'name="file"' in req.content
        assert payload in req.content
        assert ret == {"result": {"vulnerabilities": []}}
        # success path closes the file
        assert len(opened) == 1
        assert opened[0].name == str(sbom)
        assert opened[0].closed

    def test_non_regular_upload_path_rejected(self, api, server):
        # A non-regular upload target (here a character device; in the attack, a
        # device/FIFO/dir swapped in after the FilePath validation) is rejected
        # before any request, closing the TOCTOU window. Regular files are
        # unaffected (see the success test above).
        with pytest.raises(VulnersApiError):
            api._invoke("POST", "/synthetic/upload", {"file": "/dev/null"}, (), ["file"])
        assert server.requests == []


class TestFileHandleLeak:
    """Upload files are opened after pacing and always closed."""

    @staticmethod
    def _spy_open(monkeypatch):
        opened: list = []
        real_open = open

        def spy(*args, **kwargs):
            fh = real_open(*args, **kwargs)
            opened.append(fh)
            return fh

        monkeypatch.setattr(vulners.base, "open", spy, raising=False)
        return opened

    def test_file_closed_on_request_exception(self, api, server, tmp_path, monkeypatch):
        f = tmp_path / "sbom.json"
        f.write_bytes(b"{}")
        opened = self._spy_open(monkeypatch)

        def boom(request):
            raise httpx.ConnectError("network down")

        api._client._transport = vulners.base.VulnersApiTransport(httpx.MockTransport(boom))
        with pytest.raises(httpx.ConnectError):
            api._invoke("POST", "/synthetic/upload", {"file": str(f)}, (), ["file"])
        assert len(opened) == 1
        assert opened[0].closed

    def test_files_opened_after_consume(self, api, server, tmp_path, monkeypatch):
        f = tmp_path / "sbom.json"
        f.write_bytes(b"{}")
        events: list = []
        real_open = open

        def spy_open(*args, **kwargs):
            events.append("open")
            return real_open(*args, **kwargs)

        monkeypatch.setattr(vulners.base, "open", spy_open, raising=False)
        bucket_cls = vulners.base.RateLimitBucket
        real_consume = bucket_cls.consume

        def spy_consume(self):
            events.append("consume")
            return real_consume(self)

        monkeypatch.setattr(bucket_cls, "consume", spy_consume)
        server.enqueue_json({"result": {"ok": True}})
        api._invoke("POST", "/synthetic/upload", {"file": str(f)}, (), ["file"])
        assert events == ["consume", "open"]

    def test_partial_open_closes_opened_file_and_skips_request(
        self, api, server, tmp_path, monkeypatch
    ):
        a = tmp_path / "a.json"
        a.write_bytes(b"{}")
        missing = tmp_path / "missing.json"  # never created
        opened = self._spy_open(monkeypatch)
        with pytest.raises(OSError):
            api._invoke(
                "POST",
                "/synthetic/upload",
                {"a": str(a), "b": str(missing)},
                (),
                ["a", "b"],
            )
        # the first file was opened then closed; the request never fired
        assert len(opened) == 1
        assert opened[0].closed
        assert len(server.requests) == 0

    def test_file_closed_on_error_envelope(self, api, server, tmp_path, monkeypatch):
        f = tmp_path / "sbom.json"
        f.write_bytes(b"{}")
        opened = self._spy_open(monkeypatch)
        server.enqueue_envelope({"error": "bad", "errorCode": 104}, result="error")
        with pytest.raises(VulnersApiError):
            api._invoke("POST", "/synthetic/upload", {"file": str(f)}, (), ["file"])
        assert len(opened) == 1
        assert opened[0].closed


class TestApiKeyHandling:
    def test_add_api_key_post_puts_key_in_body(self, api, server):
        server.enqueue_envelope({})
        api.audit.win_audit(
            os="Windows Server 2099",
            os_version="99.0.1",
            kb_list=["KB0000001"],
            software=[{"software": "SyntheticSoft", "version": "1.0"}],
        )
        body = orjson.loads(server.last.content)
        assert body == {
            "os": "Windows Server 2099",
            "os_version": "99.0.1",
            "kb_list": ["KB0000001"],
            "software": [{"software": "SyntheticSoft", "version": "1.0"}],
            "apiKey": api._api_key,
        }

    def test_x_api_key_and_user_agent_headers(self, api, server):
        api._invoke("GET", "/synthetic/headers", {}, ())
        req = server.last
        assert req.headers["x-api-key"] == api._api_key
        # compare against the runtime version, not a pyproject literal
        assert req.headers["user-agent"] == "Vulners Python API %s" % vulners.base.__version__


class TestEnvelopeHandling:
    def test_success_envelope_data_unwrapped(self, api, server):
        server.enqueue_envelope({"value": 1})
        assert api._invoke("GET", "/synthetic/env", {}, ()) == {"value": 1}

    def test_error_envelope_in_http_200_raises(self, api, server):
        error_data = {"error": "Synthetic error message", "errorCode": 104}
        server.enqueue_envelope(error_data, result="error")
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/env-error", {}, ())
        assert excinfo.value.http_status == 200
        assert excinfo.value.data == error_data
        assert excinfo.value.error_code == 104
        assert excinfo.value.message == "Synthetic error message (errorCode 104)"

    def test_body_without_data_key_returned_whole(self, api, server):
        # v4-style envelope: no "data" key -> the whole body is returned
        # (endpoint declarations unwrap via response_handler)
        server.enqueue_json({"result": {"synthetic": 1}})
        assert api._invoke("GET", "/synthetic/v4", {}, ()) == {"result": {"synthetic": 1}}

    def test_json_parsed_even_with_parse_content_false(self, api, server):
        # pin: parse_content only affects non-JSON branches; the JSON branch
        # always parses and unwraps
        server.enqueue_envelope({"value": 2})
        assert api._invoke("GET", "/synthetic/pc", {}, (), parse_content=False) == {"value": 2}


class TestStatusHandling:
    """HTTP >= 400 must not be swallowed as success when the JSON body
    carries a "data" key, and the error key is checked by presence."""

    def test_http_500_with_data_body_raises(self, api, server):
        # HTTP 500 with a success-shaped envelope must still raise
        server.enqueue_envelope({}, status_code=500)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/500-data", {}, ())
        assert excinfo.value.http_status == 500
        # full envelope is the exception payload
        assert excinfo.value.args[0] == {"result": "OK", "data": {}}

    def test_http_403_with_error_data_raises_with_data_payload(self, api, server):
        error_data = {"error": "Wrong API key", "errorCode": 157}
        server.enqueue_envelope(error_data, result="error", status_code=403)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/403", {}, ())
        assert excinfo.value.http_status == 403
        # error-key branch wins: payload is the unwrapped data, not the envelope
        assert excinfo.value.data == error_data
        assert excinfo.value.error_code == 157
        assert excinfo.value.message == "Wrong API key (errorCode 157)"

    def test_http_429_with_data_null_raises(self, api, server):
        server.enqueue_envelope(None, status_code=429)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/429-null", {}, ())
        assert excinfo.value.http_status == 429

    def test_http_500_with_data_list_raises(self, api, server):
        server.enqueue_envelope([{"id": "CVE-2099-0003"}], status_code=500)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/500-list", {}, ())
        assert excinfo.value.http_status == 500

    def test_error_key_checked_by_presence_not_truthiness(self, api, server):
        # a falsy but present "error" value still raises (presence semantics)
        server.enqueue_envelope({"error": "", "errorCode": 0}, result="error")
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/falsy-error", {}, ())
        assert excinfo.value.http_status == 200

    def test_success_200_still_unwraps_data(self, api, server):
        # happy path unchanged
        server.enqueue_envelope({"value": 7})
        assert api._invoke("GET", "/synthetic/ok", {}, ()) == {"value": 7}


class TestContentTypeDispatch:
    """Dispatch by media-type (charset/case tolerant), no KeyError on a
    missing header, status is checked for every content-type."""

    def test_json_with_charset_success_unwrapped(self, api, server):
        server.enqueue_raw(
            orjson.dumps({"result": "OK", "data": {"value": 3}}),
            "application/json; charset=utf-8",
        )
        assert api._invoke("GET", "/synthetic/charset", {}, ()) == {"value": 3}

    def test_json_with_charset_error_raises(self, api, server):
        server.enqueue_raw(
            orjson.dumps({"result": "error", "data": {"error": "boom"}}),
            "application/json; charset=utf-8",
            status_code=400,
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/charset-err", {}, ())
        assert excinfo.value.http_status == 400
        assert excinfo.value.data == {"error": "boom"}
        assert excinfo.value.message == "boom"

    def test_json_content_type_case_insensitive(self, api, server):
        server.enqueue_raw(
            orjson.dumps({"result": "OK", "data": {"ok": True}}), "Application/JSON"
        )
        assert api._invoke("GET", "/synthetic/case", {}, ()) == {"ok": True}

    def test_delete_204_without_content_type_returns_none(self, api, server):
        server.enqueue(httpx.Response(204, content=b"", headers={}))
        assert api._invoke("DELETE", "/synthetic/204", {}, ()) is None

    def test_html_gateway_error_parse_content_true_raises(self, api, server):
        server.enqueue_raw(b"<html>502 Bad Gateway</html>", "text/html", status_code=502)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/html", {}, ())
        assert excinfo.value.http_status == 502
        assert "502 Bad Gateway" in excinfo.value.args[0]

    def test_html_gateway_error_parse_content_false_raises(self, api, server):
        server.enqueue_raw(b"<html>503</html>", "text/html", status_code=503)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/html-raw", {}, (), parse_content=False)
        assert excinfo.value.http_status == 503

    def test_5xx_without_content_type_raises_not_keyerror(self, api, server):
        server.enqueue(httpx.Response(500, content=b"boom", headers={}))
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/no-ct", {}, ())
        assert excinfo.value.http_status == 500

    def test_empty_body_parse_content_false_returns_bytes(self, api, server):
        server.enqueue(httpx.Response(200, content=b"", headers={}))
        assert api._invoke("GET", "/synthetic/empty", {}, (), parse_content=False) == b""


class TestNonJsonErrorWrapping:
    """A non-JSON error body (or a body mislabelled as JSON) is wrapped in
    VulnersApiError instead of leaking orjson.JSONDecodeError."""

    def test_html_body_with_json_content_type_wrapped(self, api, server):
        server.enqueue_raw(
            b"<html>502 Bad Gateway</html>", "application/json", status_code=502
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/mislabelled", {}, ())
        assert excinfo.value.http_status == 502
        assert isinstance(excinfo.value.__cause__, orjson.JSONDecodeError)

    def test_garbage_json_body_at_200_wrapped(self, api, server):
        server.enqueue_raw(b"not json at all", "application/json")
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/garbage", {}, ())
        assert excinfo.value.http_status == 200
        assert isinstance(excinfo.value.__cause__, orjson.JSONDecodeError)

    def test_garbage_body_at_200_non_json_fallback_wrapped(self, api, server):
        # non-JSON content-type, status 200, unparseable body -> fallback wrap
        server.enqueue_raw(b"\xff\xfe not json", "application/octet-stream")
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/fallback-garbage", {}, ())
        assert excinfo.value.http_status == 200
        assert isinstance(excinfo.value.__cause__, orjson.JSONDecodeError)

    def test_binary_error_body_no_unicode_error(self, api, server):
        server.enqueue_raw(b"\xff\xfe\x00\x80", "text/plain", status_code=500)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/binary", {}, ())
        assert excinfo.value.http_status == 500
        assert isinstance(excinfo.value.args[0], str)

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    @pytest.mark.parametrize("ct", ["text/html", "text/plain"])
    def test_gateway_errors_raise(self, api, server, status, ct):
        server.enqueue_raw(b"<html>gateway error</html>", ct, status_code=status)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/gw", {}, ())
        assert excinfo.value.http_status == status

    def test_503_with_gzip_content_type_raises_not_zlib_error(self, api, server):
        server.enqueue_raw(
            b"<html>maintenance</html>", "application/x-gzip-compressed", status_code=503
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/gz-error", {}, ())
        assert excinfo.value.http_status == 503


class TestCompressedContent:
    def test_gzip_content_type_decompressed_and_parsed(self, api, server):
        server.enqueue_raw(
            gzip.compress(orjson.dumps({"synthetic": True})),
            "application/x-gzip-compressed",
        )
        assert api._invoke("GET", "/synthetic/gz", {}, ()) == {"synthetic": True}

    @staticmethod
    def _zip_bytes(entries: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, content in entries.items():
                z.writestr(name, content)
        return buf.getvalue()

    def test_zip_single_file_extracted_and_parsed(self, api, server):
        payload = [{"id": "CVE-2099-0002"}]
        server.enqueue_raw(
            self._zip_bytes({"synthetic.json": orjson.dumps(payload)}),
            "application/x-zip-compressed",
        )
        assert api._invoke("GET", "/synthetic/zip", {}, ()) == payload

    def test_zip_single_file_raw_when_parse_content_false(self, api, server):
        raw = b'{"synthetic": "raw-bytes"}'
        server.enqueue_raw(
            self._zip_bytes({"synthetic.json": raw}), "application/x-zip-compressed"
        )
        assert api._invoke("GET", "/synthetic/zip-raw", {}, (), parse_content=False) == raw

    def test_zip_multiple_files_raises_runtime_error(self, api, server):
        server.enqueue_raw(
            self._zip_bytes({"a.json": b"{}", "b.json": b"{}"}),
            "application/x-zip-compressed",
        )
        with pytest.raises(RuntimeError, match="^Unexpected file count in Vulners ZIP archive$"):
            api._invoke("GET", "/synthetic/zip-multi", {}, ())

    def test_empty_zip_raises_runtime_error_not_indexerror(self, api, server):
        # EOCD-only archive (b"PK\x05\x06" + 18 zero bytes): valid but empty
        empty_zip = b"PK\x05\x06" + b"\x00" * 18
        server.enqueue_raw(empty_zip, "application/x-zip-compressed")
        with pytest.raises(RuntimeError, match="^Unexpected file count in Vulners ZIP archive$"):
            api._invoke("GET", "/synthetic/zip-empty", {}, ())

    def test_zipextfile_is_closed(self, api, server, monkeypatch):
        payload = orjson.dumps({"closed": True})
        # enqueue (which builds the zip) BEFORE installing the spy, so only the
        # read-side open() inside _invoke is captured
        server.enqueue_raw(
            self._zip_bytes({"synthetic.json": payload}), "application/x-zip-compressed"
        )
        captured = []
        real_open = zipfile.ZipFile.open

        def spy_open(self, name, *args, **kwargs):
            fh = real_open(self, name, *args, **kwargs)
            captured.append(fh)
            return fh

        monkeypatch.setattr(zipfile.ZipFile, "open", spy_open)
        assert api._invoke("GET", "/synthetic/zip-close", {}, ()) == {"closed": True}
        assert len(captured) == 1
        assert captured[0].closed


class TestEmptyBodyHandlerGuard:
    """An empty JSON body decodes to None; endpoints that unwrap it via a
    response_handler or wrapper must raise VulnersApiError, not a bare TypeError.
    """

    def test_response_handler_endpoint_empty_body_raises_api_error(self, api, server):
        # get_bulletin_history unwraps via response_handler=lambda c: c["result"]
        server.enqueue(
            httpx.Response(200, content=b"", headers={"content-type": "application/json"})
        )
        with pytest.raises(VulnersApiError):
            api.search.get_bulletin_history(id="CVE-2099-0001")

    def test_wrapper_endpoint_empty_body_raises_api_error(self, make_api, server):
        # get_projects wraps the body in ProjectList (iterates it)
        vapi = make_api(vulners.VScannerApi)
        server.enqueue(
            httpx.Response(200, content=b"", headers={"content-type": "application/json"})
        )
        with pytest.raises(VulnersApiError):
            vapi.get_projects()

    def test_plain_endpoint_empty_body_still_returns_none(self, api, server):
        # no handler/wrapper -> the empty-body None passes through unchanged
        server.enqueue(
            httpx.Response(200, content=b"", headers={"content-type": "application/json"})
        )
        assert api._invoke("GET", "/synthetic/empty-json", {}, ()) is None


class TestSetCookieStripping:
    def test_set_cookie_header_is_stripped(self, api, server):
        server.enqueue_envelope(
            {}, headers={"set-cookie": "session=SYNTHETICCOOKIE; Path=/"}
        )
        api._invoke("GET", "/synthetic/cookie", {}, ())
        assert len(api._client.cookies) == 0


class TestRetryAfter:
    """VulnersApiError carries a retry_after parsed from the
    Retry-After response header at every raise-site."""

    def test_constructor_back_compat_two_positional(self):
        # additive kwarg: the historical two-positional constructor still works
        err = VulnersApiError(500, {"synthetic": 1})
        assert err.http_status == 500
        assert err.args[0] == {"synthetic": 1}
        assert err.retry_after is None

    @pytest.mark.parametrize(
        "header,expected",
        [
            ("30", 30.0),
            ("0", 0.0),
            ("  45  ", 45.0),
            ("abc", None),
            ("soon", None),
            ("-5", None),
            ("inf", None),
            ("nan", None),
            ("", None),
            (None, None),
        ],
    )
    def test_parse_retry_after_values(self, header, expected):
        assert _parse_retry_after(header) == expected

    def test_parse_retry_after_http_date_future(self):
        future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30))
        parsed = _parse_retry_after(future)
        assert parsed is not None
        assert 25 <= parsed <= 35

    def test_parse_retry_after_http_date_past(self):
        past = format_datetime(datetime.now(timezone.utc) - timedelta(days=1))
        assert _parse_retry_after(past) == 0.0

    def test_error_status_raise_populates_retry_after(self, api, server):
        # non-"data" body + status >= 400 -> the status raise-site fills retry_after
        server.enqueue_json(
            {"message": "slow down"}, status_code=429, headers={"Retry-After": "30"}
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/429", {}, ())
        assert excinfo.value.http_status == 429
        assert excinfo.value.retry_after == 30.0
        assert len(server.requests) == 1

    def test_error_envelope_raise_populates_retry_after(self, api, server):
        # 200 result:error path fills retry_after too when the header is present
        server.enqueue_envelope(
            {"error": "throttled", "errorCode": 104},
            result="error",
            headers={"Retry-After": "12"},
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/env-throttle", {}, ())
        assert excinfo.value.http_status == 200
        assert excinfo.value.retry_after == 12.0

    def test_error_without_retry_after_header_is_none(self, api, server):
        server.enqueue_envelope(
            {"error": "boom", "errorCode": 104}, result="error"
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/no-retry", {}, ())
        assert excinfo.value.retry_after is None


class TestRetryCount:
    """retry_count only covers connection retries.

    HTTP error responses must not be retried, and the value must be wired
    straight into the httpx transport.
    """

    def test_http_error_is_not_retried(self, api, server):
        # A 502 is an HTTP error, not a connection failure: exactly one request
        # is made and it raises instead of looping through a retry layer.
        server.enqueue_raw(b"<html>bad gateway</html>", "text/html", status_code=502)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/gateway", {}, ())
        assert excinfo.value.http_status == 502
        assert len(server.requests) == 1

    def test_retry_count_is_wired_into_transport(self, monkeypatch):
        captured: dict = {}
        real_transport = httpx.HTTPTransport

        def spy(*args, **kwargs):
            captured.update(kwargs)
            return real_transport(*args, **kwargs)

        monkeypatch.setattr(httpx, "HTTPTransport", spy)
        vulners.VulnersApi("SYNTHETIC-KEY", retry_count=7)
        assert captured["retries"] == 7

    def test_retry_count_documented(self):
        assert "retry_count" in (vulners.VulnersApi.__init__.__doc__ or "")


class TestErrorMessageParsing:
    """VulnersApiError exposes the server's problem description via .message /
    .error_code across the several error shapes, without echoing the request
    input a validation item carries."""

    def test_v3_error_with_code(self):
        exc = VulnersApiError(200, {"error": "Wrong value type", "errorCode": 104})
        assert exc.error_code == 104
        assert exc.message == "Wrong value type (errorCode 104)"

    def test_v3_error_without_code(self):
        exc = VulnersApiError(404, {"error": "invalid endpoint"})
        assert exc.error_code is None
        assert exc.message == "invalid endpoint"

    def test_v3_full_envelope_is_unwrapped(self):
        exc = VulnersApiError(400, {"result": "error", "data": {"error": "boom", "errorCode": 1}})
        assert exc.message == "boom (errorCode 1)"

    def test_v4_errors_list_uses_msg_and_loc_not_input(self):
        exc = VulnersApiError(
            400,
            {"errors": [{"type": "missing", "loc": ["body", "id"], "msg": "Field required", "input": {"secret": "x"}}]},
        )
        assert exc.error_code is None
        assert exc.message == "Field required at body.id"
        assert "secret" not in str(exc)  # request input is not echoed into the message

    def test_v4_detail_list_is_joined(self):
        exc = VulnersApiError(
            422,
            {"detail": [
                {"loc": ["body", "osVersion"], "msg": "Field required"},
                {"loc": ["body", "packages"], "msg": "Field required"},
            ]},
        )
        assert exc.message == "Field required at body.osVersion; Field required at body.packages"

    def test_string_body_is_the_message(self):
        exc = VulnersApiError(502, "502 Bad Gateway")
        assert exc.message == "502 Bad Gateway"
