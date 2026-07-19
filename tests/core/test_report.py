"""Report resource request-wire and parsing (respx)."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
URL = "https://vulners.com/api/v3/reports/vulnsreport"


def _report(payload: object) -> httpx.Response:
    return httpx.Response(
        200, content=orjson.dumps({"result": "OK", "data": {"report": payload}})
    )


class TestReportWire:
    @respx.mock
    def test_each_method_sends_its_reporttype(self):
        route = respx.post(URL).mock(return_value=_report([{"id": 1}]))
        with Vulners(KEY) as client:
            cases = {
                "vulnssummary": client.report.vulns_summary,
                "vulnslist": client.report.vulns_list,
                "ipsummary": client.report.ip_summary,
                "scanlist": client.report.scan_list,
                "hostvulns": client.report.host_vulns,
            }
            for reporttype, method in cases.items():
                out = method(limit=5, offset=10, filter={"OS": "Centos"}, sort="-severity")
                assert out == [{"id": 1}]
                assert orjson.loads(route.calls.last.request.content) == {
                    "reporttype": reporttype,
                    "skip": 10,
                    "size": 5,
                    "filter": {"OS": "Centos"},
                    "sort": "-severity",
                }

    @respx.mock
    def test_defaults(self):
        route = respx.post(URL).mock(return_value=_report([]))
        with Vulners(KEY) as client:
            client.report.vulns_summary()
        assert orjson.loads(route.calls.last.request.content) == {
            "reporttype": "vulnssummary",
            "skip": 0,
            "size": 30,
            "filter": {},
            "sort": "",
        }


class TestReportAsync:
    @respx.mock
    async def test_vulns_list_async(self):
        respx.post(URL).mock(return_value=_report([{"id": 2}]))
        async with AsyncVulners(KEY) as client:
            assert await client.report.vulns_list() == [{"id": 2}]
