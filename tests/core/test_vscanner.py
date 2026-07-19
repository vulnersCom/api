"""VScanner resource request-wire, path templating and screenshots (respx)."""

from __future__ import annotations

import base64

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"
ROOT = f"{BASE}/api/v3/proxy/vscanner/v2/projects"
PID = "11111111-1111-1111-1111-111111111111"
TID = "22222222-2222-2222-2222-222222222222"
RID = "33333333-3333-3333-3333-333333333333"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


class TestVscannerProjects:
    @respx.mock
    def test_licenses_list(self):
        respx.get(f"{BASE}/api/v3/useraction/licenseids").mock(
            return_value=_v3({"license_ids": ["lic-1"]})
        )
        with Vulners(KEY) as client:
            assert client.vscanner.licenses.list() == {"license_ids": ["lic-1"]}

    @respx.mock
    def test_projects_list_query(self):
        route = respx.get(f"{ROOT}/").mock(return_value=_v3([{"_id": PID}]))
        with Vulners(KEY) as client:
            out = client.vscanner.projects.list(limit=10)
        assert out == [{"_id": PID}]
        params = route.calls.last.request.url.params
        assert params["offset"] == "0"
        assert params["limit"] == "10"

    @respx.mock
    def test_projects_create_serializes_uuid_and_notification(self):
        route = respx.post(f"{ROOT}/").mock(return_value=_v3({"_id": PID}))
        with Vulners(KEY) as client:
            note = client.vscanner.notification("daily", emails=["a@b.c"])
            client.vscanner.projects.create(
                name="proj", license_id=PID, notification=note, result_expire_in=30
            )
        assert orjson.loads(route.calls.last.request.content) == {
            "name": "proj",
            "license_id": PID,
            "notification": {"period": "daily", "email": ["a@b.c"], "slack": []},
            "result_expire_in": 30,
        }

    @respx.mock
    def test_projects_update_and_delete_paths(self):
        put = respx.put(f"{ROOT}/{PID}").mock(return_value=_v3({"_id": PID}))
        dele = respx.delete(f"{ROOT}/{PID}").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.vscanner.projects.update(
                PID,
                name="p2",
                license_id=PID,
                notification=client.vscanner.disabled_notification(),
                result_expire_in=None,
            )
            client.vscanner.projects.delete(PID)
        assert put.called and dele.called
        body = orjson.loads(put.calls.last.request.content)
        assert body["result_expire_in"] is None

    @respx.mock
    def test_statistics_repeats_stat_query(self):
        route = respx.get(f"{ROOT}/{PID}/statistic").mock(return_value=_v3({"total_hosts": 3}))
        with Vulners(KEY) as client:
            client.vscanner.projects.statistics(PID, stat=["total_hosts", "unique_cve"])
        raw = str(route.calls.last.request.url)
        assert "stat=total_hosts" in raw
        assert "stat=unique_cve" in raw


class TestVscannerTasksAndResults:
    @respx.mock
    def test_task_create_and_start_paths(self):
        create = respx.post(f"{ROOT}/{PID}/tasks").mock(return_value=_v3({"_id": TID}))
        start = respx.post(f"{ROOT}/{PID}/tasks/{TID}/start").mock(return_value=_v3({"_id": TID}))
        with Vulners(KEY) as client:
            client.vscanner.projects.tasks.create(
                PID,
                name="t",
                networks=["10.0.0.0/24"],
                ports=["80", "443"],
                schedule="0 0 * * *",
                timing="T3",
                enabled=True,
            )
            client.vscanner.projects.tasks.start(PID, TID)
        assert orjson.loads(create.calls.last.request.content) == {
            "name": "t",
            "networks": ["10.0.0.0/24"],
            "ports": ["80", "443"],
            "schedule": "0 0 * * *",
            "timing": "T3",
            "enabled": True,
        }
        assert start.called

    @respx.mock
    def test_results_list_filters(self):
        route = respx.get(f"{ROOT}/{PID}/results").mock(return_value=_v3([{"_id": RID}]))
        with Vulners(KEY) as client:
            client.vscanner.projects.results.list(
                PID, search="nginx", min_cvss=7.0, in_port=["80"], sort="max_cvss"
            )
        params = route.calls.last.request.url.params
        assert params["search"] == "nginx"
        assert params["min_cvss"] == "7.0"
        assert params["sort"] == "max_cvss"
        assert params["sort_dir"] == "asc"
        assert "80" in str(route.calls.last.request.url)

    @respx.mock
    def test_result_delete_path(self):
        route = respx.delete(f"{ROOT}/{PID}/results/{RID}").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.vscanner.projects.results.delete(PID, RID)
        assert route.called

    @respx.mock
    def test_screenshot_bytes_and_base64(self):
        respx.get(f"{BASE}/vscanner/screen/abc.png").mock(
            return_value=httpx.Response(
                200, content=b"PNGDATA", headers={"content-type": "image/png"}
            )
        )
        with Vulners(KEY) as client:
            raw = client.vscanner.projects.results.screenshot("abc.png")
            assert raw == b"PNGDATA"
        respx.get(f"{BASE}/vscanner/screen/abc.png").mock(
            return_value=httpx.Response(
                200, content=b"PNGDATA", headers={"content-type": "image/png"}
            )
        )
        with Vulners(KEY) as client:
            enc = client.vscanner.projects.results.screenshot("abc.png", as_base64=True)
        assert enc == base64.b64encode(b"PNGDATA")

    def test_screenshot_traversal_is_rejected(self):
        with Vulners(KEY) as client:
            with pytest.raises(ValueError):
                client.vscanner.projects.results.screenshot("../../etc/passwd")


class TestVscannerAsync:
    @respx.mock
    async def test_projects_list_async(self):
        respx.get(f"{ROOT}/").mock(return_value=_v3([{"_id": PID}]))
        async with AsyncVulners(KEY) as client:
            assert await client.vscanner.projects.list() == [{"_id": PID}]

    @respx.mock
    async def test_screenshot_async(self):
        respx.get(f"{BASE}/vscanner/screen/x.png").mock(
            return_value=httpx.Response(
                200, content=b"IMG", headers={"content-type": "image/png"}
            )
        )
        async with AsyncVulners(KEY) as client:
            assert await client.vscanner.projects.results.screenshot("x.png") == b"IMG"
