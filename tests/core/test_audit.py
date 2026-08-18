"""Audit resource request-wire and parsing for both clients (respx)."""

from __future__ import annotations

import os

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
    def test_kb_audit_v4_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/kb").mock(
            return_value=_v4({"items": [], "totalPackages": 0})
        )
        with Vulners(KEY) as client:
            out = client.audit.kb_audit(
                "Windows 10", ["KB5028166"], os_version="10.0.19045", fields=["metrics"]
            )
        assert out == {"items": [], "totalPackages": 0}
        assert orjson.loads(route.calls.last.request.content) == {
            "osName": "Windows 10",
            "kbList": ["KB5028166"],
            "osVersion": "10.0.19045",
            "fields": ["metrics"],
        }

    @respx.mock
    def test_kb_audit_v4_minimal_omits_optionals(self):
        route = respx.post(f"{BASE}/api/v4/audit/kb").mock(return_value=_v4({"items": []}))
        with Vulners(KEY) as client:
            client.audit.kb_audit("Windows 10", ["KB1"])
        assert orjson.loads(route.calls.last.request.content) == {
            "osName": "Windows 10",
            "kbList": ["KB1"],
        }

    @respx.mock
    def test_kb_audit_v3_deprecated_wire(self):
        route = respx.post(f"{BASE}/api/v3/audit/kb/").mock(return_value=_v3({"kbMissed": []}))
        with Vulners(KEY) as client:
            out = client.audit.kb_audit_v3("Windows Server 2012 R2", ["KB1"])
        assert out == {"kbMissed": []}
        assert orjson.loads(route.calls.last.request.content) == {
            "os": "Windows Server 2012 R2",
            "kbList": ["KB1"],
        }

    @respx.mock
    def test_smart_fields_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/smart").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.audit.smart(["nginx 1.25"], fields=["metrics", "exploitation"])
        assert orjson.loads(route.calls.last.request.content) == {
            "software": ["nginx 1.25"],
            "catalog": "official",
            "fields": ["metrics", "exploitation"],
        }

    @respx.mock
    def test_software_cvelist_metrics_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/software/").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.audit.software(["curl 8.11.1"], cvelist_metrics=True)
        assert orjson.loads(route.calls.last.request.content)["cvelistMetrics"] is True

    @respx.mock
    def test_host_cvelist_metrics_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/host/").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.audit.host(["curl 8.11.1"], operating_system="ubuntu", cvelist_metrics=True)
        assert orjson.loads(route.calls.last.request.content)["cvelistMetrics"] is True

    @respx.mock
    def test_linux_audit_fields_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/linux").mock(return_value=_v4({}))
        with Vulners(KEY) as client:
            client.audit.linux_audit(
                os_name="ubuntu",
                os_version="22.04",
                packages=["bash 5.1"],
                fields=["metrics"],
            )
        assert orjson.loads(route.calls.last.request.content)["fields"] == ["metrics"]

    @respx.mock
    def test_library_audit_fields_wire(self):
        route = respx.post(f"{BASE}/api/v4/audit/library").mock(return_value=_v4({}))
        with Vulners(KEY) as client:
            client.audit.library_audit(["pkg:pypi/django@3.0"], fields=["metrics"])
        assert orjson.loads(route.calls.last.request.content)["fields"] == ["metrics"]

    @respx.mock
    def test_sbom_cvelist_metrics_query(self, tmp_path):
        route = respx.post(f"{BASE}/api/v4/audit/sbom").mock(return_value=_v4({"data": []}))
        sbom = tmp_path / "sbom.json"
        sbom.write_bytes(b'{"bomFormat":"CycloneDX"}')
        with Vulners(KEY) as client:
            client.audit.sbom_audit(sbom, cvelist_metrics=True)
        assert route.calls.last.request.url.params["cvelistMetrics"] == "true"

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

    @pytest.mark.skipif(os.name != "posix", reason="needs a POSIX non-regular file")
    def test_sbom_audit_rejects_non_regular_file(self):
        # A non-regular upload target (here a character device; in the attack, a
        # device/FIFO/dir swapped in after any earlier path check) is rejected on
        # the opened descriptor before any request — the TOCTOU guard.
        with Vulners(KEY) as client:
            with pytest.raises(ValueError, match="not a regular file"):
                client.audit.sbom_audit("/dev/null")

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

    @pytest.mark.skipif(os.name != "posix", reason="needs a POSIX non-regular file")
    async def test_sbom_audit_rejects_non_regular_file(self):
        # Async mirror of the sync TOCTOU guard test: the opened descriptor is
        # validated with fstat and a non-regular target is rejected pre-request.
        async with AsyncVulners(KEY) as client:
            with pytest.raises(ValueError, match="not a regular file"):
                await client.audit.sbom_audit("/dev/null")


class TestSupportedOS:
    @respx.mock
    def test_supported_os_unwraps_map(self):
        respx.get(f"{BASE}/api/v3/audit/getSupportedOS/").mock(
            return_value=_v3({"supportedOS": {"ubuntu": "dpkg-query ..."}})
        )
        with Vulners(KEY) as client:
            assert client.audit.supported_os() == {"ubuntu": "dpkg-query ..."}

    @respx.mock
    async def test_supported_os_async(self):
        respx.get(f"{BASE}/api/v3/audit/getSupportedOS/").mock(
            return_value=_v3({"supportedOS": {"rhel": "rpm -qa ..."}})
        )
        async with AsyncVulners(KEY) as client:
            assert await client.audit.supported_os() == {"rhel": "rpm -qa ..."}


ECOSYSTEMS = ("maven", "pip", "poetry", "uv", "npm", "golang")


class TestAuditPackages:
    @respx.mock
    def test_each_ecosystem_posts_text_plain(self):
        with Vulners(KEY) as client:
            for eco in ECOSYSTEMS:
                route = respx.post(f"{BASE}/api/v4/audit/package/{eco}").mock(
                    return_value=_v4({"issues": []})
                )
                out = getattr(client.audit.packages, eco)(b"pkg==1.0\n")
                assert out == {"issues": []}
                req = route.calls.last.request
                assert req.content == b"pkg==1.0\n"
                assert req.headers["content-type"].startswith("text/plain")
                # No filters passed -> the server defaults apply (no params sent).
                assert "includeAnyVersion" not in req.url.params

    @respx.mock
    def test_include_filters_sent_as_query_params(self):
        route = respx.post(f"{BASE}/api/v4/audit/package/pip").mock(
            return_value=_v4({"issues": []})
        )
        with Vulners(KEY) as client:
            client.audit.packages.pip(
                b"urllib3==1.26.4\n",
                include_any_version=False,
                include_candidates=True,
                include_unofficial=True,
                include_transitives=False,
            )
        params = route.calls.last.request.url.params
        assert params["includeAnyVersion"] == "false"
        assert params["includeCandidates"] == "true"
        assert params["includeUnofficial"] == "true"
        assert params["includeTransitives"] == "false"

    @respx.mock
    def test_file_inputs_path_text_io_and_binary_io(self, tmp_path):
        import io

        route = respx.post(f"{BASE}/api/v4/audit/package/pip").mock(
            return_value=_v4({"issues": []})
        )
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==2.25.1\n")
        with Vulners(KEY) as client:
            client.audit.packages.pip(manifest)
            assert route.calls.last.request.content == b"requests==2.25.1\n"
            client.audit.packages.pip(io.StringIO("django==3.2\n"))
            assert route.calls.last.request.content == b"django==3.2\n"
            client.audit.packages.pip(io.BytesIO(b"flask==1.0\n"))
            assert route.calls.last.request.content == b"flask==1.0\n"

    @respx.mock
    def test_scan_dispatches_and_rejects_unknown(self):
        route = respx.post(f"{BASE}/api/v4/audit/package/npm").mock(
            return_value=_v4({"issues": []})
        )
        with Vulners(KEY) as client:
            client.audit.packages.scan("npm", b"{}")
            assert route.called
            with pytest.raises(ValueError, match="unsupported ecosystem"):
                client.audit.packages.scan("cargo", b"")  # type: ignore[arg-type]

    def test_packages_path_rejects_non_regular_file(self):
        from vulners._resources._sync.audit import _read_package_manifest

        # A character device is not a regular file; the fstat guard rejects it.
        with pytest.raises(ValueError, match="regular file"):
            _read_package_manifest(os.devnull)


class TestAuditPackagesAsync:
    @respx.mock
    async def test_each_ecosystem_posts_text_plain(self):
        async with AsyncVulners(KEY) as client:
            for eco in ECOSYSTEMS:
                route = respx.post(f"{BASE}/api/v4/audit/package/{eco}").mock(
                    return_value=_v4({"issues": []})
                )
                out = await getattr(client.audit.packages, eco)(b"pkg==1.0\n")
                assert out == {"issues": []}
                assert route.calls.last.request.content == b"pkg==1.0\n"

    @respx.mock
    async def test_scan_filters_and_file_inputs(self, tmp_path):
        import io

        route = respx.post(f"{BASE}/api/v4/audit/package/golang").mock(
            return_value=_v4({"issues": []})
        )
        manifest = tmp_path / "modules.txt"
        manifest.write_text("github.com/gorilla/mux v1.7.4\n")
        async with AsyncVulners(KEY) as client:
            await client.audit.packages.scan("golang", manifest, include_transitives=True)
            assert route.calls.last.request.url.params["includeTransitives"] == "true"
            await client.audit.packages.scan("golang", io.StringIO("example.com/app\n"))
            assert route.calls.last.request.content == b"example.com/app\n"
            with pytest.raises(ValueError, match="unsupported ecosystem"):
                await client.audit.packages.scan("cargo", b"")  # type: ignore[arg-type]
