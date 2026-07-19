"""Audit resource request-wire and parsing for both clients (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"


def _v4(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": payload}))


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


class TestAuditWire:
    @respx.mock
    def test_software_wire_and_parse(self):
        route = respx.post(f"{BASE}/api/v4/audit/software/").mock(
            return_value=_v4([{"id": "CVE-2099-1"}])
        )
        with Vulners(KEY) as client:
            out = client.audit.software(["curl 8.11.1"], fields=["cvss"])
        assert out == [{"id": "CVE-2099-1"}]
        body = orjson.loads(route.calls.last.request.content)
        assert body == {
            "software": ["curl 8.11.1"],
            "match": "partial",
            "catalog": "official",
            "fields": ["cvss"],
        }
        assert route.calls.last.request.headers["x-api-key"] == KEY

    @respx.mock
    def test_host_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/host/").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.audit.host(["curl 8.11.1"], operating_system="ubuntu", match="full")
        body = orjson.loads(route.calls.last.request.content)
        assert body["operating_system"] == "ubuntu"
        assert body["match"] == "full"
        assert "application" not in body

    @respx.mock
    def test_os_audit_wire(self):
        route = respx.post(f"{BASE}/api/v3/audit/audit/").mock(return_value=_v3({"ok": 1}))
        with Vulners(KEY) as client:
            out = client.audit.os_audit(os="ubuntu", version="22.04", packages=["bash 5.1"])
        assert out == {"ok": 1}
        assert orjson.loads(route.calls.last.request.content) == {
            "os": "ubuntu",
            "version": "22.04",
            "package": ["bash 5.1"],
        }

    @respx.mock
    def test_linux_audit_camelcase_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/linux").mock(return_value=_v4({}))
        with Vulners(KEY) as client:
            client.audit.linux_audit(
                os_name="ubuntu", os_version="22.04", packages=["bash-5.1-1.amd64"]
            )
        assert orjson.loads(route.calls.last.request.content) == {
            "osName": "ubuntu",
            "osVersion": "22.04",
            "packages": ["bash-5.1-1.amd64"],
            "osArch": None,
            "includeUnofficial": False,
            "includeCandidates": False,
            "includeAnyVersion": False,
            "cvelistMetrics": False,
        }

    @respx.mock
    def test_library_audit_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/library").mock(return_value=_v4({}))
        with Vulners(KEY) as client:
            client.audit.library_audit(packages=["pkg:pypi/requests@2.0"], cvelist_metrics=True)
        body = orjson.loads(route.calls.last.request.content)
        assert body["packages"] == ["pkg:pypi/requests@2.0"]
        assert body["cvelistMetrics"] is True

    @respx.mock
    def test_cve_and_batch_wire(self):
        r1 = respx.post(f"{BASE}/api/v4/audit/cve").mock(return_value=_v4({"cve": "x"}))
        r2 = respx.post(f"{BASE}/api/v4/audit/cves").mock(return_value=_v4([{"cve": "x"}]))
        with Vulners(KEY) as client:
            client.audit.cve_audit("CVE-2099-1")
            client.audit.cve_batch_audit(["CVE-2099-1", "CVE-2099-2"])
        assert orjson.loads(r1.calls.last.request.content) == {"cve": "CVE-2099-1"}
        assert orjson.loads(r2.calls.last.request.content) == {
            "cve": ["CVE-2099-1", "CVE-2099-2"]
        }

    @respx.mock
    def test_kb_audit_wire(self):
        route = respx.post(f"{BASE}/api/v3/audit/kb/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.audit.kb_audit(os="Windows Server 2012 R2", kb_list=["KB1"])
        assert orjson.loads(route.calls.last.request.content) == {
            "os": "Windows Server 2012 R2",
            "kbList": ["KB1"],
        }

    @respx.mock
    def test_win_audit_echoes_api_key_in_body(self):
        route = respx.post(f"{BASE}/api/v3/audit/winaudit/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.audit.win_audit(
                os="Windows 10",
                os_version="10.0.19045",
                kb_list=["KB1"],
                software=[{"software": "Edge", "version": "1.0"}],
                platform="x86",
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["apiKey"] == KEY
        assert body["os"] == "Windows 10"
        assert body["os_version"] == "10.0.19045"
        assert body["kb_list"] == ["KB1"]
        assert body["platform"] == "x86"

    @respx.mock
    def test_sbom_audit_multipart(self, tmp_path):
        route = respx.post(f"{BASE}/api/v4/audit/sbom").mock(return_value=_v4({"data": []}))
        sbom = tmp_path / "sbom.json"
        sbom.write_bytes(b'{"bomFormat":"CycloneDX"}')
        with Vulners(KEY) as client:
            out = client.audit.sbom_audit(sbom)
        assert out == {"data": []}
        req = route.calls.last.request
        assert req.headers["content-type"].startswith("multipart/form-data")
        assert b'name="file"' in req.content
        assert b'{"bomFormat":"CycloneDX"}' in req.content

    @respx.mock
    def test_smart_wire_and_billing_validation(self):
        route = respx.post(f"{BASE}/api/v4/audit/smart").mock(
            return_value=_v4([{"input": "nginx", "purls": [], "confidence": 0.9}])
        )
        with Vulners(KEY) as client:
            out = client.audit.smart(["nginx 1.25"], catalog="extended")
            assert out[0]["input"] == "nginx"
            assert orjson.loads(route.calls.last.request.content) == {
                "software": ["nginx 1.25"],
                "catalog": "extended",
            }
            with pytest.raises(ValueError):
                client.audit.smart([])
            with pytest.raises(ValueError):
                client.audit.smart(["x"] * 501)
            with pytest.raises(ValueError):
                client.audit.smart(["a" * 513])

    @respx.mock
    def test_with_raw_response_exposes_status_and_parse(self):
        respx.post(f"{BASE}/api/v4/audit/software/").mock(
            return_value=_v4([{"id": "CVE-2099-7"}])
        )
        with Vulners(KEY) as client:
            raw = client.audit.with_raw_response.software(["curl 8.11.1"])
        assert raw.status_code == 200
        assert raw.parse() == [{"id": "CVE-2099-7"}]


class TestAuditAsync:
    @respx.mock
    async def test_software_async(self):
        route = respx.post(f"{BASE}/api/v4/audit/software/").mock(
            return_value=_v4([{"id": "CVE-2099-9"}])
        )
        async with AsyncVulners(KEY) as client:
            out = await client.audit.software(["curl 8.11.1"])
        assert out == [{"id": "CVE-2099-9"}]
        assert orjson.loads(route.calls.last.request.content) == {
            "software": ["curl 8.11.1"],
            "match": "partial",
            "catalog": "official",
        }

    @respx.mock
    async def test_smart_async(self):
        respx.post(f"{BASE}/api/v4/audit/smart").mock(return_value=_v4([]))
        async with AsyncVulners(KEY) as client:
            assert await client.audit.smart(["nginx"]) == []
