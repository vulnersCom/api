"""Async mirrors of the sync resource tests, driving every async resource method.

The async resource modules are the unasyncd *source of truth*; the sync mirror is
generated from them and is already exercised by ``tests/core/test_<resource>.py``.
These tests drive the async side directly so both halves reach full coverage. All
data is synthetic (fake keys/ids); only response shapes mirror the real envelopes.
"""

from __future__ import annotations

import gzip
from datetime import datetime, timezone

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


def _v4(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": payload}))


def _gzip_json(payload: object) -> httpx.Response:
    return httpx.Response(
        200,
        content=gzip.compress(orjson.dumps(payload)),
        headers={"content-type": "application/x-gzip-compressed"},
    )


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


class TestAuditAsyncFull:
    @respx.mock
    async def test_software_with_config(self):
        route = respx.post(f"{BASE}/api/v4/audit/software/").mock(return_value=_v4([]))
        async with AsyncVulners(KEY) as client:
            await client.audit.software(
                ["curl 8.11.1"], fields=["cvss"], config=["c1"], catalog="extended"
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body == {
            "software": ["curl 8.11.1"],
            "match": "partial",
            "catalog": "extended",
            "fields": ["cvss"],
            "config": ["c1"],
        }

    @respx.mock
    async def test_host_all_optionals(self):
        route = respx.post(f"{BASE}/api/v4/audit/host/").mock(return_value=_v4([]))
        async with AsyncVulners(KEY) as client:
            await client.audit.host(
                ["curl 8.11.1"],
                application="app",
                operating_system="ubuntu",
                hardware="hw",
                match="full",
                fields=["cvss"],
                config=["c1"],
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["application"] == "app"
        assert body["operating_system"] == "ubuntu"
        assert body["hardware"] == "hw"
        assert body["fields"] == ["cvss"]
        assert body["config"] == ["c1"]

    @respx.mock
    async def test_os_audit(self):
        route = respx.post(f"{BASE}/api/v3/audit/audit/").mock(return_value=_v3({"ok": 1}))
        async with AsyncVulners(KEY) as client:
            out = await client.audit.os_audit(os="ubuntu", version="22.04", packages=["bash 5.1"])
        assert out == {"ok": 1}
        assert orjson.loads(route.calls.last.request.content) == {
            "os": "ubuntu",
            "version": "22.04",
            "package": ["bash 5.1"],
        }

    @respx.mock
    async def test_linux_audit(self):
        route = respx.post(f"{BASE}/api/v4/audit/linux").mock(return_value=_v4({}))
        async with AsyncVulners(KEY) as client:
            await client.audit.linux_audit(
                os_name="ubuntu",
                os_version="22.04",
                packages=["bash-5.1-1.amd64"],
                os_arch="amd64",
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["osName"] == "ubuntu"
        assert body["osArch"] == "amd64"

    @respx.mock
    async def test_library_audit(self):
        route = respx.post(f"{BASE}/api/v4/audit/library").mock(return_value=_v4({}))
        async with AsyncVulners(KEY) as client:
            await client.audit.library_audit(
                packages=["pkg:pypi/requests@2.0"], cvelist_metrics=True
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["packages"] == ["pkg:pypi/requests@2.0"]
        assert body["cvelistMetrics"] is True

    @respx.mock
    async def test_sbom_audit(self, tmp_path):
        route = respx.post(f"{BASE}/api/v4/audit/sbom").mock(return_value=_v4({"data": []}))
        sbom = tmp_path / "sbom.json"
        sbom.write_bytes(b'{"bomFormat":"CycloneDX"}')
        async with AsyncVulners(KEY) as client:
            out = await client.audit.sbom_audit(sbom)
        assert out == {"data": []}
        assert b'name="file"' in route.calls.last.request.content

    @respx.mock
    async def test_cve_and_batch(self):
        r1 = respx.post(f"{BASE}/api/v4/audit/cve").mock(return_value=_v4({"cve": "x"}))
        r2 = respx.post(f"{BASE}/api/v4/audit/cves").mock(return_value=_v4([{"cve": "x"}]))
        async with AsyncVulners(KEY) as client:
            await client.audit.cve_audit("CVE-2099-1")
            await client.audit.cve_batch_audit(["CVE-2099-1", "CVE-2099-2"])
        assert orjson.loads(r1.calls.last.request.content) == {"cve": "CVE-2099-1"}
        assert orjson.loads(r2.calls.last.request.content) == {
            "cve": ["CVE-2099-1", "CVE-2099-2"]
        }

    @respx.mock
    async def test_kb_audit(self):
        route = respx.post(f"{BASE}/api/v3/audit/kb/").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            await client.audit.kb_audit(os="Windows Server 2012 R2", kb_list=["KB1"])
        assert orjson.loads(route.calls.last.request.content) == {
            "os": "Windows Server 2012 R2",
            "kbList": ["KB1"],
        }

    @respx.mock
    async def test_win_audit_echoes_key(self):
        route = respx.post(f"{BASE}/api/v3/audit/winaudit/").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            await client.audit.win_audit(
                os="Windows 10",
                os_version="10.0.19045",
                kb_list=["KB1"],
                software=[{"software": "Edge", "version": "1.0"}],
                platform="x86",
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["apiKey"] == KEY
        assert body["platform"] == "x86"

    @respx.mock
    async def test_smart_validation(self):
        respx.post(f"{BASE}/api/v4/audit/smart").mock(return_value=_v4([{"input": "nginx"}]))
        async with AsyncVulners(KEY) as client:
            out = await client.audit.smart(["nginx 1.25"], catalog="extended")
            assert out[0]["input"] == "nginx"
            with pytest.raises(ValueError):
                await client.audit.smart([])
            with pytest.raises(ValueError):
                await client.audit.smart(["x"] * 501)
            with pytest.raises(ValueError):
                await client.audit.smart(["a" * 513])

    @respx.mock
    async def test_with_raw_response(self):
        respx.post(f"{BASE}/api/v4/audit/software/").mock(
            return_value=_v4([{"id": "CVE-2099-7"}])
        )
        async with AsyncVulners(KEY) as client:
            raw = await client.audit.with_raw_response.software(["curl 8.11.1"])
        assert raw.status_code == 200
        assert raw.parse() == [{"id": "CVE-2099-7"}]


# ---------------------------------------------------------------------------
# archive
# ---------------------------------------------------------------------------


class TestArchiveAsyncFull:
    @respx.mock
    async def test_fetch_collection_non_json_bytes(self):
        # gzip body that is not JSON -> _decode_archive returns raw bytes.
        respx.get(f"{BASE}/api/v4/archive/collection").mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(b"not-json-bytes"),
                headers={"content-type": "application/x-gzip-compressed"},
            )
        )
        async with AsyncVulners(KEY) as client:
            out = await client.archive.fetch_collection("cve")
        assert out == b"not-json-bytes"

    @respx.mock
    async def test_fetch_collection_update(self):
        route = respx.get(f"{BASE}/api/v4/archive/collection-update").mock(
            return_value=_gzip_json([])
        )
        after = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        async with AsyncVulners(KEY) as client:
            await client.archive.fetch_collection_update("cve", after)
        params = route.calls.last.request.url.params
        assert params["type"] == "cve"
        assert params["after"] == after.isoformat()

    @respx.mock
    async def test_get_collection(self):
        route = respx.get(f"{BASE}/api/v3/archive/collection/").mock(return_value=_gzip_json({}))
        async with AsyncVulners(KEY) as client:
            await client.archive.get_collection("cve", datefrom="2020-01-01")
        assert route.calls.last.request.url.params["datefrom"] == "2020-01-01"

    @respx.mock
    async def test_get_distributive_extracts_source(self):
        respx.get(f"{BASE}/api/v3/archive/distributive/").mock(
            return_value=_v3([{"_source": {"id": "A"}}, {"no_source": 1}])
        )
        async with AsyncVulners(KEY) as client:
            out = await client.archive.get_distributive("ubuntu", "22.04")
        assert out == [{"id": "A"}]

    @respx.mock
    async def test_get_distributive_non_list_is_empty(self):
        respx.get(f"{BASE}/api/v3/archive/distributive/").mock(
            return_value=_v3({"not": "a list"})
        )
        async with AsyncVulners(KEY) as client:
            assert await client.archive.get_distributive("ubuntu", "22.04") == []

    @respx.mock
    async def test_getsploit_bytes(self):
        respx.get(f"{BASE}/api/v3/archive/getsploit/").mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(b"raw-exploit-db"),
                headers={"content-type": "application/x-gzip-compressed"},
            )
        )
        async with AsyncVulners(KEY) as client:
            assert await client.archive.getsploit() == b"raw-exploit-db"


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


class TestMiscAsyncFull:
    @respx.mock
    async def test_search_cpe(self):
        route = respx.get(f"{BASE}/api/v4/search/cpe").mock(return_value=_v4([{"cpe": "x"}]))
        async with AsyncVulners(KEY) as client:
            out = await client.misc.search_cpe("nginx", vendor="f5", size=10)
        assert out == [{"cpe": "x"}]
        params = route.calls.last.request.url.params
        assert params["product"] == "nginx"
        assert params["vendor"] == "f5"
        assert params["size"] == "10"

    @respx.mock
    async def test_get_suggestion(self):
        route = respx.post(f"{BASE}/api/v3/search/suggest/").mock(
            return_value=_v3({"suggest": [{"value": "a"}]})
        )
        async with AsyncVulners(KEY) as client:
            out = await client.misc.get_suggestion("type")
        assert out == [{"value": "a"}]
        assert orjson.loads(route.calls.last.request.content) == {
            "fieldName": "type",
            "type": "distinct",
        }

    @respx.mock
    async def test_web_application_rules(self):
        respx.get(f"{BASE}/api/v3/burp/rules/").mock(return_value=_v3({"rules": []}))
        async with AsyncVulners(KEY) as client:
            assert await client.misc.get_web_application_rules() == {"rules": []}

    @respx.mock
    async def test_autocomplete_scalar_suggestion(self):
        # A suggestion that is not a list still stringifies (the else branch).
        respx.post(f"{BASE}/api/v3/search/autocomplete/").mock(
            return_value=_v3({"suggestions": ["plain", []]})
        )
        async with AsyncVulners(KEY) as client:
            assert await client.misc.query_autocomplete("ss") == ["plain", "[]"]


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


class TestReportAsyncFull:
    @respx.mock
    async def test_all_report_types(self):
        url = f"{BASE}/api/v3/reports/vulnsreport"
        route = respx.post(url).mock(
            return_value=httpx.Response(
                200, content=orjson.dumps({"result": "OK", "data": {"report": [{"id": 1}]}})
            )
        )
        async with AsyncVulners(KEY) as client:
            for method in (
                client.report.vulns_summary,
                client.report.vulns_list,
                client.report.ip_summary,
                client.report.scan_list,
                client.report.host_vulns,
            ):
                assert await method(limit=5, offset=1, filter={"OS": "x"}, sort="-s") == [
                    {"id": 1}
                ]
            # default (filter=None -> {}) exercises the `filter or {}` fallback.
            await client.report.vulns_summary()
        assert route.called


# ---------------------------------------------------------------------------
# stix
# ---------------------------------------------------------------------------


class TestStixAsyncFull:
    @respx.mock
    async def test_bundle_object_and_opencti(self):
        url = f"{BASE}/api/v4/stix/bundle"
        route = respx.get(url).mock(return_value=_v4({"type": "bundle"}))
        async with AsyncVulners(KEY) as client:
            out = await client.stix.make_bundle_by_id("CVE-2099-1", opencti_id="octi-1")
        assert out == {"type": "bundle"}
        assert route.calls.last.request.url.params["opencti_id"] == "octi-1"

    @respx.mock
    async def test_bundle_non_json_string_result(self):
        # A result string that is not valid JSON is returned as-is.
        url = f"{BASE}/api/v4/stix/bundle"
        respx.get(url).mock(return_value=_v4("not-json"))
        async with AsyncVulners(KEY) as client:
            assert await client.stix.make_bundle_by_id("CVE-1") == "not-json"


# ---------------------------------------------------------------------------
# subscriptions (v3 email)
# ---------------------------------------------------------------------------


class TestSubscriptionsAsyncFull:
    BASE = f"{BASE}/api/v3/subscriptions"

    @respx.mock
    async def test_list(self):
        respx.get(f"{self.BASE}/listEmailSubscriptions/").mock(
            return_value=_v3({"subscriptions": [{"id": "s1"}]})
        )
        async with AsyncVulners(KEY) as client:
            assert await client.subscriptions.list() == [{"id": "s1"}]

    @respx.mock
    async def test_add(self):
        route = respx.post(f"{self.BASE}/addEmailSubscription/").mock(
            return_value=_v3({"id": "s1"})
        )
        async with AsyncVulners(KEY) as client:
            await client.subscriptions.add(query="ssh", email="a@b.c", crontab="0 0 * * *")
        assert orjson.loads(route.calls.last.request.content) == {
            "query": "ssh",
            "email": "a@b.c",
            "format": "html",
            "query_type": "lucene",
            "crontab": "0 0 * * *",
            "apiKey": KEY,
        }

    @respx.mock
    async def test_edit_and_delete(self):
        edit = respx.post(f"{self.BASE}/editEmailSubscription/").mock(return_value=_v3({}))
        dele = respx.post(f"{self.BASE}/removeEmailSubscription/").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            await client.subscriptions.edit(
                "s1", format="json", crontab="* * * * *", active="yes"
            )
            await client.subscriptions.delete("s1")
        ebody = orjson.loads(edit.calls.last.request.content)
        assert ebody["format"] == "json"
        assert ebody["active"] == "yes"
        assert orjson.loads(dele.calls.last.request.content) == {
            "subscriptionid": "s1",
            "apiKey": KEY,
        }


# ---------------------------------------------------------------------------
# subscriptions_v4
# ---------------------------------------------------------------------------


class TestSubscriptionsV4AsyncFull:
    BASE = f"{BASE}/api/v4/subscriptions"

    @respx.mock
    async def test_get_list_and_get(self):
        respx.get(f"{self.BASE}/list/").mock(return_value=_v4([{"id": "s1"}]))
        route = respx.get(f"{self.BASE}/get/").mock(return_value=_v4({"id": "s1"}))
        async with AsyncVulners(KEY) as client:
            assert await client.subscriptions_v4.get_list() == [{"id": "s1"}]
            await client.subscriptions_v4.get("s2")
            with pytest.raises(TypeError):
                await client.subscriptions_v4.get()
        assert route.calls.last.request.url.params["subscription_id"] == "s2"

    @respx.mock
    async def test_update_and_delete(self):
        upd = respx.put(f"{self.BASE}/update/").mock(return_value=_v4({"id": "s1"}))
        dele = respx.delete(f"{self.BASE}/delete/").mock(return_value=_v4({"ok": True}))
        async with AsyncVulners(KEY) as client:
            await client.subscriptions_v4.update(
                "s1",
                name="n",
                query={"type": "software"},
                delivery={"type": "webhook"},
                license_id="lic-1",
                bulletin_fields=["title"],
                is_active=False,
            )
            await client.subscriptions_v4.delete("s1")
        body = orjson.loads(upd.calls.last.request.content)
        assert body["id"] == "s1"
        assert body["licenseId"] == "lic-1"
        assert body["bulletin_fields"] == ["title"]
        assert dele.calls.last.request.url.params["id"] == "s1"


# ---------------------------------------------------------------------------
# webhooks
# ---------------------------------------------------------------------------


class TestWebhooksAsyncFull:
    BASE = f"{BASE}/api/v3/subscriptions"

    @respx.mock
    async def test_list_add_enable_delete(self):
        lst = respx.get(f"{self.BASE}/listWebhookSubscriptions/").mock(
            return_value=_v3({"subscriptions": [{"id": "w1"}]})
        )
        add = respx.post(f"{self.BASE}/addWebhookSubscription/").mock(
            return_value=_v3({"id": "w1"})
        )
        edit = respx.post(f"{self.BASE}/editWebhookSubscription/").mock(return_value=_v3({}))
        dele = respx.post(f"{self.BASE}/removeWebhookSubscription/").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            assert await client.webhooks.list() == [{"id": "w1"}]
            await client.webhooks.add("ssh")
            await client.webhooks.enable("w1", False)
            await client.webhooks.delete("w1")
        assert lst.called
        assert orjson.loads(add.calls.last.request.content) == {"query": "ssh", "apiKey": KEY}
        assert orjson.loads(edit.calls.last.request.content)["active"] == "false"
        assert orjson.loads(dele.calls.last.request.content)["subscriptionid"] == "w1"

    @respx.mock
    async def test_read_newest_only_default(self):
        route = respx.get(f"{self.BASE}/webhook").mock(return_value=_v3({"payloads": []}))
        async with AsyncVulners(KEY) as client:
            await client.webhooks.read("w1")
        params = route.calls.last.request.url.params
        assert params["newest_only"] == "true"
        assert params["apiKey"] == KEY


# ---------------------------------------------------------------------------
# vscanner
# ---------------------------------------------------------------------------

ROOT = f"{BASE}/api/v3/proxy/vscanner/v2/projects"
PID = "11111111-1111-1111-1111-111111111111"
TID = "22222222-2222-2222-2222-222222222222"
RID = "33333333-3333-3333-3333-333333333333"


class TestVscannerAsyncFull:
    @respx.mock
    async def test_licenses_list(self):
        respx.get(f"{BASE}/api/v3/useraction/licenseids").mock(
            return_value=_v3({"license_ids": ["lic-1"]})
        )
        async with AsyncVulners(KEY) as client:
            assert await client.vscanner.licenses.list() == {"license_ids": ["lic-1"]}

    @respx.mock
    async def test_projects_crud(self):
        respx.get(f"{ROOT}/").mock(return_value=_v3([{"_id": PID}]))
        create = respx.post(f"{ROOT}/").mock(return_value=_v3({"_id": PID}))
        put = respx.put(f"{ROOT}/{PID}").mock(return_value=_v3({"_id": PID}))
        dele = respx.delete(f"{ROOT}/{PID}").mock(return_value=_v3({}))
        stat = respx.get(f"{ROOT}/{PID}/statistic").mock(return_value=_v3({"total_hosts": 3}))
        async with AsyncVulners(KEY) as client:
            assert await client.vscanner.projects.list(limit=10) == [{"_id": PID}]
            note = client.vscanner.notification("daily", emails=["a@b.c"])
            await client.vscanner.projects.create(
                name="proj", license_id=PID, notification=note, result_expire_in=30
            )
            await client.vscanner.projects.update(
                PID,
                name="p2",
                license_id=PID,
                notification=client.vscanner.disabled_notification(),
                result_expire_in=None,
            )
            await client.vscanner.projects.delete(PID)
            await client.vscanner.projects.statistics(PID, stat=["total_hosts", "unique_cve"])
        assert (
            orjson.loads(create.calls.last.request.content)["notification"]["period"] == "daily"
        )
        assert orjson.loads(put.calls.last.request.content)["result_expire_in"] is None
        assert dele.called
        assert "stat=total_hosts" in str(stat.calls.last.request.url)

    @respx.mock
    async def test_tasks_crud(self):
        lst = respx.get(f"{ROOT}/{PID}/tasks").mock(return_value=_v3([{"_id": TID}]))
        create = respx.post(f"{ROOT}/{PID}/tasks").mock(return_value=_v3({"_id": TID}))
        put = respx.put(f"{ROOT}/{PID}/tasks/{TID}").mock(return_value=_v3({"_id": TID}))
        start = respx.post(f"{ROOT}/{PID}/tasks/{TID}/start").mock(return_value=_v3({"_id": TID}))
        dele = respx.delete(f"{ROOT}/{PID}/tasks/{TID}").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            await client.vscanner.projects.tasks.list(PID, limit=5)
            await client.vscanner.projects.tasks.create(
                PID,
                name="t",
                networks=["10.0.0.0/24"],
                ports=["80"],
                schedule="0 0 * * *",
                timing="T3",
                enabled=True,
            )
            await client.vscanner.projects.tasks.update(
                PID,
                TID,
                name="t2",
                networks=["10.0.0.0/24"],
                ports=["443"],
                schedule="0 0 * * *",
                timing="T4",
                enabled=False,
            )
            await client.vscanner.projects.tasks.start(PID, TID)
            await client.vscanner.projects.tasks.delete(PID, TID)
        assert lst.called
        assert orjson.loads(create.calls.last.request.content)["name"] == "t"
        assert orjson.loads(put.calls.last.request.content)["name"] == "t2"
        assert start.called and dele.called

    @respx.mock
    async def test_results_list_delete_screenshot(self):
        lst = respx.get(f"{ROOT}/{PID}/results").mock(return_value=_v3([{"_id": RID}]))
        dele = respx.delete(f"{ROOT}/{PID}/results/{RID}").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            await client.vscanner.projects.results.list(
                PID,
                search="nginx",
                in_port=["80"],
                ex_port=["22"],
                min_cvss=7.0,
                max_cvss=9.0,
                last_seen=1,
                first_seen=2,
                last_seen_port=3,
                first_seen_port=4,
                sort="max_cvss",
                sort_dir="desc",
            )
            await client.vscanner.projects.results.delete(PID, RID)
        params = lst.calls.last.request.url.params
        assert params["search"] == "nginx"
        assert params["min_cvss"] == "7.0"
        assert params["sort_dir"] == "desc"
        assert dele.called

    @respx.mock
    async def test_screenshot_base64_and_traversal(self):
        respx.get(f"{BASE}/vscanner/screen/x.png").mock(
            return_value=httpx.Response(
                200, content=b"IMG", headers={"content-type": "image/png"}
            )
        )
        async with AsyncVulners(KEY) as client:
            import base64

            enc = await client.vscanner.projects.results.screenshot("x.png", as_base64=True)
            assert enc == base64.b64encode(b"IMG")
            with pytest.raises(ValueError):
                await client.vscanner.projects.results.screenshot("../../etc/passwd")

    def test_notification_bad_period(self):
        from vulners._resources._async.vscanner import AsyncVscanner

        with pytest.raises(ValueError):
            AsyncVscanner.notification("weekly")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# search (async single/multi lookup + fields)
# ---------------------------------------------------------------------------


class TestSearchAsyncFull:
    LUCENE = f"{BASE}/api/v3/search/lucene/"
    LOOKUP = f"{BASE}/api/v3/search/id/"

    @respx.mock
    async def test_query_with_fields(self):
        route = respx.post(self.LUCENE).mock(
            return_value=_v3({"search": [{"_source": {"id": "CVE-1"}}], "total": 1})
        )
        async with AsyncVulners(KEY) as client:
            page = await client.search.query("ssh", fields=["id", "title"])
        assert page.total == 1
        assert orjson.loads(route.calls.last.request.content)["fields"] == ["id", "title"]

    @respx.mock
    async def test_get_bulletin_found_missing_and_multi(self):
        respx.post(self.LOOKUP).mock(
            return_value=_v3({"documents": {"A": {"id": "A"}, "B": {"id": "B"}}})
        )
        async with AsyncVulners(KEY) as client:
            b = await client.search.get_bulletin("A", fields=["id"])
            assert b is not None and b.id == "A"
            docs = await client.search.get_multiple_bulletins(
                ["A", "B"], fields=["id"], references=True
            )
            assert set(docs) == {"A", "B"}

    @respx.mock
    async def test_get_bulletin_missing_is_none(self):
        respx.post(self.LOOKUP).mock(return_value=_v3({"documents": {}}))
        async with AsyncVulners(KEY) as client:
            assert await client.search.get_bulletin("CVE-0000-0") is None

    @respx.mock
    async def test_get_multiple_without_fields(self):
        respx.post(self.LOOKUP).mock(return_value=_v3({"documents": {"A": {"id": "A"}}}))
        async with AsyncVulners(KEY) as client:
            docs = await client.search.get_multiple_bulletins(["A"])
        assert set(docs) == {"A"}


class TestAsyncOmitAndEdgeBranches:
    """Calls that OMIT optional args, to cover the not-given branch sides."""

    @respx.mock
    async def test_audit_host_no_optionals(self):
        respx.post(f"{BASE}/api/v4/audit/host/").mock(return_value=_v4([]))
        async with AsyncVulners(KEY) as client:
            await client.audit.host(["curl 8.11.1"])

    @respx.mock
    async def test_misc_search_cpe_no_optionals(self):
        route = respx.get(f"{BASE}/api/v4/search/cpe").mock(return_value=_v4([]))
        async with AsyncVulners(KEY) as client:
            await client.misc.search_cpe("nginx")
        params = route.calls.last.request.url.params
        assert "vendor" not in params
        assert "size" not in params

    @respx.mock
    async def test_subscriptions_add_no_crontab_and_edit_subset(self):
        add = respx.post(f"{BASE}/api/v3/subscriptions/addEmailSubscription/").mock(
            return_value=_v3({})
        )
        edit = respx.post(f"{BASE}/api/v3/subscriptions/editEmailSubscription/").mock(
            return_value=_v3({})
        )
        async with AsyncVulners(KEY) as client:
            await client.subscriptions.add(query="ssh", email="a@b.c")
            await client.subscriptions.edit("s1", active="yes")
        assert "crontab" not in orjson.loads(add.calls.last.request.content)
        ebody = orjson.loads(edit.calls.last.request.content)
        assert "format" not in ebody and "crontab" not in ebody

    @respx.mock
    async def test_vscanner_results_list_no_optionals_and_create_no_expire(self):
        respx.get(f"{ROOT}/{PID}/results").mock(return_value=_v3([]))
        create = respx.post(f"{ROOT}/").mock(return_value=_v3({"_id": PID}))
        async with AsyncVulners(KEY) as client:
            await client.vscanner.projects.results.list(PID)
            await client.vscanner.projects.create(
                name="p", license_id=PID, notification=client.vscanner.disabled_notification()
            )
        assert "result_expire_in" not in orjson.loads(create.calls.last.request.content)

    async def test_vscanner_screenshot_excessive_encoding_rejected(self):
        # "%" + "25"*45 decodes one "25" per unquote pass (>40), never stabilizing
        # within the decode-pass cap -> the excessive-percent-encoding guard fires.
        deep = "%" + "25" * 45
        async with AsyncVulners(KEY) as client:
            with pytest.raises(ValueError):
                await client.vscanner.projects.results.screenshot(deep)
