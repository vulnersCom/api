"""Full-branch coverage for the generated *sync* resource mirror.

The per-resource ``tests/core/test_<resource>.py`` files cover the common paths;
this file drives the remaining optional/edge branches on the sync client so the
generated ``_resources/_sync`` modules reach full coverage, symmetric with
``test_resources_async.py`` on the async source. Synthetic data throughout.
"""

from __future__ import annotations

import base64
import gzip

import httpx
import orjson
import pytest
import respx

from vulners._client import Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"
ROOT = f"{BASE}/api/v3/proxy/vscanner/v2/projects"
PID = "11111111-1111-1111-1111-111111111111"
TID = "22222222-2222-2222-2222-222222222222"
RID = "33333333-3333-3333-3333-333333333333"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


def _v4(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": payload}))


class TestAuditSyncBranches:
    @respx.mock
    def test_software_config_and_host_all_optionals(self):
        sw = respx.post(f"{BASE}/api/v4/audit/software/").mock(return_value=_v4([]))
        host = respx.post(f"{BASE}/api/v4/audit/host/").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.audit.software(["curl 8.11.1"], config=["c1"])
            client.audit.host(
                ["curl 8.11.1"],
                application="app",
                operating_system="ubuntu",
                hardware="hw",
                fields=["cvss"],
                config=["c1"],
            )
        assert orjson.loads(sw.calls.last.request.content)["config"] == ["c1"]
        hbody = orjson.loads(host.calls.last.request.content)
        assert hbody["application"] == "app" and hbody["hardware"] == "hw"

    @respx.mock
    def test_host_no_optionals(self):
        respx.post(f"{BASE}/api/v4/audit/host/").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.audit.host(["curl 8.11.1"])

    @respx.mock
    def test_win_audit_without_platform(self):
        route = respx.post(f"{BASE}/api/v3/audit/winaudit/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.audit.win_audit(
                os="Windows 10", os_version="10.0.19045", kb_list=["KB1"], software=[]
            )
        assert "platform" not in orjson.loads(route.calls.last.request.content)

    @respx.mock
    def test_linux_and_library_and_cve_batch(self):
        lin = respx.post(f"{BASE}/api/v4/audit/linux").mock(return_value=_v4({}))
        lib = respx.post(f"{BASE}/api/v4/audit/library").mock(return_value=_v4({}))
        with Vulners(KEY) as client:
            client.audit.linux_audit(
                os_name="ubuntu", os_version="22.04", packages=["p"], os_arch="amd64"
            )
            client.audit.library_audit(packages=["pkg:pypi/x@1"])
        assert orjson.loads(lin.calls.last.request.content)["osArch"] == "amd64"
        assert orjson.loads(lib.calls.last.request.content)["packages"] == ["pkg:pypi/x@1"]


class TestArchiveSyncBranches:
    @respx.mock
    def test_fetch_collection_non_json_bytes(self):
        respx.get(f"{BASE}/api/v4/archive/collection").mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(b"not-json"),
                headers={"content-type": "application/x-gzip-compressed"},
            )
        )
        with Vulners(KEY) as client:
            assert client.archive.fetch_collection("cve") == b"not-json"

    @respx.mock
    def test_collection_update_and_getsploit(self):
        upd = respx.get(f"{BASE}/api/v4/archive/collection-update").mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(orjson.dumps([])),
                headers={"content-type": "application/x-gzip-compressed"},
            )
        )
        respx.get(f"{BASE}/api/v3/archive/getsploit/").mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(b"db"),
                headers={"content-type": "application/x-gzip-compressed"},
            )
        )
        from datetime import datetime, timezone

        with Vulners(KEY) as client:
            client.archive.fetch_collection_update(
                "cve", datetime(2026, 1, 1, tzinfo=timezone.utc)
            )
            assert client.archive.getsploit() == b"db"
        assert upd.called

    @respx.mock
    def test_get_distributive_non_list_is_empty(self):
        respx.get(f"{BASE}/api/v3/archive/distributive/").mock(return_value=_v3({"x": 1}))
        with Vulners(KEY) as client:
            assert client.archive.get_distributive("ubuntu", "22.04") == []


class TestMiscSyncBranches:
    @respx.mock
    def test_search_cpe_no_optionals(self):
        route = respx.get(f"{BASE}/api/v4/search/cpe").mock(return_value=_v4([]))
        with Vulners(KEY) as client:
            client.misc.search_cpe("nginx")
        params = route.calls.last.request.url.params
        assert "vendor" not in params and "size" not in params

    @respx.mock
    def test_autocomplete_scalar_and_empty(self):
        # A bare-string suggestion passes through; an empty-list one carries no
        # completion and is dropped (previously it stringified to a junk "[]").
        respx.post(f"{BASE}/api/v3/search/autocomplete/").mock(
            return_value=_v3({"suggestions": ["plain", []]})
        )
        with Vulners(KEY) as client:
            assert client.misc.query_autocomplete("s") == ["plain"]


class TestStixSyncBranches:
    @respx.mock
    def test_bundle_non_json_string_result(self):
        respx.get(f"{BASE}/api/v4/stix/bundle").mock(return_value=_v4("not-json"))
        with Vulners(KEY) as client:
            assert client.stix.make_bundle_by_id("CVE-1") == "not-json"


class TestSubscriptionsSyncBranches:
    SUBS = f"{BASE}/api/v3/subscriptions"

    @respx.mock
    def test_add_no_crontab_and_edit_optionals(self):
        add = respx.post(f"{self.SUBS}/addEmailSubscription/").mock(return_value=_v3({}))
        edit = respx.post(f"{self.SUBS}/editEmailSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.subscriptions_email.add(query="ssh", email="a@b.c")
            client.subscriptions_email.edit("s1", format="json", crontab="* * * * *", active="no")
        assert "crontab" not in orjson.loads(add.calls.last.request.content)
        ebody = orjson.loads(edit.calls.last.request.content)
        assert ebody["format"] == "json" and ebody["crontab"] == "* * * * *"


class TestSearchSyncBranches:
    LOOKUP = f"{BASE}/api/v3/search/id/"

    @respx.mock
    def test_get_multiple_with_and_without_fields(self):
        respx.post(self.LOOKUP).mock(
            return_value=_v3({"documents": {"A": {"id": "A"}, "bad": 1}})
        )
        with Vulners(KEY) as client:
            with_fields = client.search.get_multiple_bulletins(
                ["A"], fields=["id"], references=True
            )
            without = client.search.get_multiple_bulletins(["A"])
        assert set(with_fields) == {"A"} and set(without) == {"A"}


class TestVscannerSyncBranches:
    @respx.mock
    def test_tasks_list_update_delete(self):
        lst = respx.get(f"{ROOT}/{PID}/tasks").mock(return_value=_v3([{"_id": TID}]))
        put = respx.put(f"{ROOT}/{PID}/tasks/{TID}").mock(return_value=_v3({"_id": TID}))
        dele = respx.delete(f"{ROOT}/{PID}/tasks/{TID}").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.vscanner.projects.tasks.list(PID, offset=1, limit=5)
            client.vscanner.projects.tasks.update(
                PID,
                TID,
                name="t2",
                networks=["10.0.0.0/24"],
                ports=["443"],
                schedule="0 0 * * *",
                timing="T4",
                enabled=False,
            )
            client.vscanner.projects.tasks.delete(PID, TID)
        assert lst.called and dele.called
        assert orjson.loads(put.calls.last.request.content)["name"] == "t2"

    @respx.mock
    def test_results_list_all_optionals(self):
        route = respx.get(f"{ROOT}/{PID}/results").mock(return_value=_v3([]))
        with Vulners(KEY) as client:
            client.vscanner.projects.results.list(
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
        assert route.calls.last.request.url.params["search"] == "nginx"

    @respx.mock
    def test_results_list_no_optionals(self):
        respx.get(f"{ROOT}/{PID}/results").mock(return_value=_v3([]))
        with Vulners(KEY) as client:
            client.vscanner.projects.results.list(PID)

    @respx.mock
    def test_create_without_result_expire(self):
        route = respx.post(f"{ROOT}/").mock(return_value=_v3({"_id": PID}))
        with Vulners(KEY) as client:
            client.vscanner.projects.create(
                name="p", license_id=PID, notification=client.vscanner.disabled_notification()
            )
        assert "result_expire_in" not in orjson.loads(route.calls.last.request.content)

    def test_notification_bad_period_and_screenshot_encoding(self):
        with Vulners(KEY) as client:
            with pytest.raises(ValueError):
                client.vscanner.notification("weekly")  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                client.vscanner.projects.results.screenshot("%" + "25" * 45)

    @respx.mock
    def test_screenshot_base64(self):
        respx.get(f"{BASE}/vscanner/screen/x.png").mock(
            return_value=httpx.Response(
                200, content=b"IMG", headers={"content-type": "image/png"}
            )
        )
        with Vulners(KEY) as client:
            assert client.vscanner.projects.results.screenshot(
                "x.png", as_base64=True
            ) == base64.b64encode(b"IMG")
