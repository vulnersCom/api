"""Full-surface live exercise of the v4 (modern) client against the real API (opt-in).

Covers every public method on the modern ``Vulners`` / ``AsyncVulners`` client
across all resource namespaces (search, audit, archive, misc, report, stix,
documents, v4 subscriptions, email subscriptions, webhooks, vscanner), plus the
escape hatch and the raw-response accessor. Run it with a real key configured
(``VULNERS_API_KEY`` or ``tests/live.local.toml``); without one the whole module
is skipped at collection time (see conftest).

Rules (the live DB is dynamic, so tests pin STRUCTURE, not data):
- assert types / shapes only — never concrete vulnerabilities or counts;
- keep the API key and any echoed request ``input`` out of assertion messages;
- mutations are contained: subscriptions / webhooks / v4-subscriptions are
  created then deleted in a ``finally`` (with a list sweep as a backstop), using
  pull-based delivery so no external callback fires; vscanner is exercised
  read-only because creating a task launches a real network scan and burns a
  license;
- large archive downloads run against a byte-capped client or are bounded to a
  few streamed records / a recent delta, so nothing pulls gigabytes.

Contract for entitlement-gated endpoints (enterprise reporting, vscanner, sbom,
some audit lookups): the SDK must either return a well-shaped response OR raise a
graceful ``VulnersError`` — an unexpected exception is a real failure.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from vulners import AsyncVulners, Bulletin, Vulners, VulnersError
from vulners._pagination import SearchPage

pytestmark = pytest.mark.live

_FALLBACK_CVE = "CVE-2021-44228"
_KB_ID = "KB5028166"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def capped_v4(live_config):
    """Modern client with an 8 MB response cap for the archive download endpoints."""
    key, base_url = live_config
    client = Vulners(api_key=key, base_url=base_url, max_response_bytes=8_000_000)
    yield client
    client.close()


@pytest.fixture(scope="session")
def live_cve(live_config) -> str:
    """A real, recent CVE id from the live DB (falls back to a well-known one)."""
    key, base_url = live_config
    client = Vulners(api_key=key, base_url=base_url)
    try:
        page = client.search.query("type:cve order:published", limit=1, fields=["id"])
        for b in page.data:
            if b.id:
                return b.id
    except VulnersError:
        pass
    finally:
        client.close()
    return _FALLBACK_CVE


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ok_or_graceful(fn: Callable[[], Any], *shape: type) -> Any:
    """Return the result if it is one of *shape*; treat a graceful ``VulnersError``
    as an acceptable outcome (request built + error handled). Any other exception
    propagates as a real SDK failure."""
    try:
        res = fn()
    except VulnersError:
        return None
    assert isinstance(res, shape), f"unexpected shape: {type(res).__name__}"
    return res


def _reachable_or_capped(fn: Callable[[], Any], *shape: type) -> None:
    """Archive downloads: pass on a well-shaped payload OR on a graceful error
    (the byte cap firing / gated), both of which prove reachability."""
    try:
        res = fn()
    except VulnersError:
        return
    assert isinstance(res, shape), f"unexpected shape: {type(res).__name__}"


def _take(iter_factory: Callable[[], Any], n: int = 3) -> list[Any] | None:
    """Take up to *n* items from a streaming iterator, or None on a graceful error."""
    try:
        return list(itertools.islice(iter_factory(), n))
    except VulnersError:
        return None


def _own_key(client: Any) -> str:
    """The client's own API key as a plain string (``config.api_key`` is a
    pydantic ``SecretStr``); used to exercise the owner-key path explicitly."""
    return client.config.api_key.get_secret_value()


_ID_KEYS = ("id", "subscriptionid", "subscriptionId", "subscription_id", "_id")


def _extract_id(payload: Any) -> str | None:
    for src in (payload.get("result") if isinstance(payload, dict) else None, payload):
        if isinstance(src, str) and src:
            return src
        if isinstance(src, dict):
            for k in _ID_KEYS:
                v = src.get(k)
                if isinstance(v, str) and v:
                    return v
    return None


def _sweep_webhooks_by_query(client: Any, query: str) -> None:
    try:
        subs = client.webhooks.list()
        for s in subs if isinstance(subs, list) else []:
            if isinstance(s, dict) and s.get("query") == query:
                sid = _extract_id(s)
                if sid:
                    client.webhooks.delete(sid)
    except VulnersError:
        pass


def _sweep_v4_by_name(client: Any, name: str) -> None:
    try:
        listing = client.subscriptions.get_list()  # returns a list (result unwrapped)
        rows = listing.get("result") if isinstance(listing, dict) else listing
        for s in rows if isinstance(rows, list) else []:
            if isinstance(s, dict) and s.get("name") == name:
                sid = _extract_id(s)
                if sid:
                    client.subscriptions.delete(sid)
    except VulnersError:
        pass


def _sweep_email_by_query(client: Any, query: str) -> None:
    try:
        subs = client.subscriptions_email.list()
        for s in subs if isinstance(subs, list) else []:
            if isinstance(s, dict) and s.get("query") == query:
                sid = _extract_id(s)
                if sid:
                    client.subscriptions_email.delete(sid)
    except VulnersError:
        pass


# --------------------------------------------------------------------------- #
# 1. Search
# --------------------------------------------------------------------------- #


class TestSearch:
    def test_query_typed_page(self, live_v4):
        page = live_v4.search.query("type:cve", limit=3, fields=["id", "bulletinFamily"])
        assert isinstance(page, SearchPage)
        assert isinstance(page.total, int) and page.total >= 0
        assert len(page.data) <= 3

    def test_iter_query_streams_bulletins(self, live_v4):
        rows = list(itertools.islice(live_v4.search.iter_query("type:cve order:published"), 3))
        assert len(rows) <= 3
        assert all(isinstance(b, Bulletin) for b in rows)

    def test_get_bulletin(self, live_v4, live_cve):
        b = live_v4.search.get_bulletin(live_cve)
        assert b is None or (isinstance(b, Bulletin) and b.id)

    def test_get_multiple_bulletins(self, live_v4, live_cve):
        out = live_v4.search.get_multiple_bulletins([live_cve])
        assert isinstance(out, dict)

    def test_exploits(self, live_v4):
        page = live_v4.search.exploits("apache", limit=2)
        assert isinstance(page, SearchPage)

    def test_collections(self, live_v4):
        _ok_or_graceful(lambda: live_v4.search.collections(), dict, list)

    def test_cpe(self, live_v4):
        _ok_or_graceful(lambda: live_v4.search.cpe("nginx"), dict, list)

    def test_autocomplete(self, live_v4):
        res = live_v4.search.autocomplete("type:cv")
        assert isinstance(res, list)

    def test_suggest(self, live_v4):
        _ok_or_graceful(lambda: live_v4.search.suggest("type"), dict, list)

    def test_web_vulns(self, live_v4):
        _ok_or_graceful(lambda: live_v4.search.web_vulns(), dict, list)


# --------------------------------------------------------------------------- #
# 2. Audit
# --------------------------------------------------------------------------- #


class TestAudit:
    def test_software(self, live_v4):
        res = live_v4.audit.software(["cpe:2.3:a:apache:http_server:2.4.49"])
        assert isinstance(res, (list, dict))

    def test_host(self, live_v4):
        res = live_v4.audit.host(
            ["cpe:2.3:a:apache:http_server:2.4.49"],
            operating_system="cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
            cvelist_metrics=True,
        )
        assert isinstance(res, (list, dict))

    def test_linux_audit(self, live_v4):
        res = live_v4.audit.linux_audit(
            os_name="ubuntu",
            os_version="22.04",
            packages=["bash 5.1-6ubuntu1 amd64"],
            fields=["metrics"],
        )
        assert isinstance(res, dict)
        # v4 reports which enrichment options took effect and any warnings.
        assert "appliedOptions" in res and "warnings" in res

    def test_os_audit(self, live_v4):
        res = live_v4.audit.os_audit("ubuntu", "22.04", ["bash 5.1-6ubuntu1 amd64"])
        assert isinstance(res, dict)

    def test_win_audit(self, live_v4):
        res = live_v4.audit.win_audit(
            os="Windows 10", os_version="10.0.19045", kb_list=[_KB_ID], software=[]
        )
        assert isinstance(res, dict)

    def test_kb_audit(self, live_v4):
        # v4: one finding per missing update, with fixedPackage + advisories.
        res = live_v4.audit.kb_audit(
            "Windows 10", [_KB_ID], os_version="10.0.19045", fields=["metrics"]
        )
        assert isinstance(res, dict) and "items" in res

    def test_kb_audit_v3_deprecated(self, live_v4):
        _ok_or_graceful(lambda: live_v4.audit.kb_audit_v3("Windows 10", [_KB_ID]), dict)

    def test_cve_audit(self, live_v4, live_cve):
        _ok_or_graceful(lambda: live_v4.audit.cve_audit(live_cve), dict)

    def test_cve_batch_audit(self, live_v4, live_cve):
        _ok_or_graceful(lambda: live_v4.audit.cve_batch_audit([live_cve]), dict, list)

    def test_library_audit(self, live_v4):
        _ok_or_graceful(
            lambda: live_v4.audit.library_audit(["pkg:pypi/django@3.0"], fields=["metrics"]),
            dict,
            list,
        )

    def test_sbom_audit(self, live_v4, tmp_path):
        import orjson

        sbom = tmp_path / "sbom.json"
        sbom.write_bytes(
            orjson.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": "django",
                            "version": "3.0",
                            "purl": "pkg:pypi/django@3.0",
                        }
                    ],
                }
            )
        )
        _ok_or_graceful(lambda: live_v4.audit.sbom_audit(sbom, cvelist_metrics=True), dict, list)

    def test_smart(self, live_v4):
        # Preview endpoint — billing is per submitted string, so keep it to one.
        _ok_or_graceful(
            lambda: live_v4.audit.smart(["nginx 1.18.0"], fields=["metrics"]), dict, list
        )

    def test_supported_os(self, live_v4):
        _ok_or_graceful(lambda: live_v4.audit.supported_os(), dict)

    def test_packages_pip(self, live_v4):
        # audit.packages.<ecosystem>() posts a manifest; keep it to one package.
        _ok_or_graceful(lambda: live_v4.audit.packages.pip(b"Django==3.0\n"), dict, list)

    def test_packages_scan(self, live_v4):
        # The generic ecosystem-dispatch entry point.
        _ok_or_graceful(lambda: live_v4.audit.packages.scan("pip", b"Django==3.0\n"), dict, list)


# --------------------------------------------------------------------------- #
# 3. Archive (streamed / delta / byte-capped)
# --------------------------------------------------------------------------- #


class TestArchive:
    def test_iter_collection_streams_dicts(self, live_v4):
        rows = list(itertools.islice(live_v4.archive.iter_collection("cve"), 3))
        assert len(rows) == 3
        assert all(isinstance(r, dict) and r.get("id") for r in rows)

    def test_fetch_collection_update_recent_delta(self, capped_v4):
        after = datetime.now(timezone.utc) - timedelta(hours=2)
        _reachable_or_capped(
            lambda: capped_v4.archive.fetch_collection_update("cve", after), dict, list
        )

    def test_collection_state(self, live_v4):
        _ok_or_graceful(lambda: live_v4.archive.collection_state("cve"), dict, list)

    def test_family_and_state(self, live_v4, capped_v4):
        # family() buffers the whole family archive into memory (no delta bound),
        # so run it against the byte-capped client like the other whole fetches.
        _reachable_or_capped(lambda: capped_v4.archive.family("nvd"), dict, list)
        _ok_or_graceful(lambda: live_v4.archive.family_state("nvd"), dict, list)

    def test_family_update_recent(self, capped_v4):
        after = datetime.now(timezone.utc) - timedelta(hours=2)
        _reachable_or_capped(lambda: capped_v4.archive.family_update("nvd", after), dict, list)

    def test_iter_family_streams(self, live_v4):
        after = datetime.now(timezone.utc) - timedelta(days=1)
        rows = _take(lambda: live_v4.archive.iter_family("nvd", update_from=after), 3)
        assert rows is None or all(isinstance(r, dict) for r in rows)

    def test_download_collection_recent_delta(self, live_v4, tmp_path):
        after = datetime.now(timezone.utc) - timedelta(hours=2)
        dest = tmp_path / "cve.jsonl"
        try:
            written = live_v4.archive.download_collection("cve", dest, update_from=after)
        except VulnersError:
            return
        assert isinstance(written, int) and written >= 0

    def test_fetch_collection_capped(self, capped_v4):
        _reachable_or_capped(lambda: capped_v4.archive.fetch_collection("cve"), dict, list)

    def test_get_collection_capped(self, capped_v4):
        _reachable_or_capped(lambda: capped_v4.archive.get_collection("cve"), dict, list)

    def test_get_distributive_capped(self, capped_v4):
        _reachable_or_capped(lambda: capped_v4.archive.get_distributive("debian", "10"), list)

    def test_getsploit_capped(self, capped_v4):
        _reachable_or_capped(lambda: capped_v4.archive.getsploit(), bytes)


# --------------------------------------------------------------------------- #
# 4. Misc
# --------------------------------------------------------------------------- #


class TestMisc:
    def test_query_autocomplete(self, live_v4):
        assert isinstance(live_v4.misc.query_autocomplete("type:cv"), list)

    def test_search_cpe(self, live_v4):
        _ok_or_graceful(lambda: live_v4.misc.search_cpe("nginx"), dict, list)

    def test_get_suggestion(self, live_v4):
        _ok_or_graceful(lambda: live_v4.misc.get_suggestion("type"), dict, list)

    def test_get_web_application_rules(self, live_v4):
        _ok_or_graceful(lambda: live_v4.misc.get_web_application_rules(), dict, list)


# --------------------------------------------------------------------------- #
# 5. Report (enterprise; entitlement-gated)
# --------------------------------------------------------------------------- #


class TestReport:
    def test_host_vulns(self, live_v4):
        _ok_or_graceful(lambda: live_v4.report.host_vulns(limit=1), dict, list)

    def test_ip_summary(self, live_v4):
        _ok_or_graceful(lambda: live_v4.report.ip_summary(limit=1), dict, list)

    def test_scan_list(self, live_v4):
        _ok_or_graceful(lambda: live_v4.report.scan_list(limit=1), dict, list)

    def test_vulns_list(self, live_v4):
        _ok_or_graceful(lambda: live_v4.report.vulns_list(limit=1), dict, list)

    def test_vulns_summary(self, live_v4):
        _ok_or_graceful(lambda: live_v4.report.vulns_summary(limit=1), dict, list)

    def test_vuln_info(self, live_v4, live_cve):
        _ok_or_graceful(
            lambda: live_v4.report.vuln_info("192.0.2.1", live_cve, limit=1), dict, list
        )


# --------------------------------------------------------------------------- #
# 6. STIX
# --------------------------------------------------------------------------- #


class TestStix:
    def test_make_bundle_by_id(self, live_v4, live_cve):
        _ok_or_graceful(lambda: live_v4.stix.make_bundle_by_id(live_cve), dict, str)

    def test_bundle_alias(self, live_v4, live_cve):
        _ok_or_graceful(lambda: live_v4.stix.bundle(live_cve), dict, str)


# --------------------------------------------------------------------------- #
# 7. Documents
# --------------------------------------------------------------------------- #


class TestDocuments:
    def test_get(self, live_v4, live_cve):
        doc = live_v4.documents.get(live_cve)
        assert doc is None or isinstance(doc, Bulletin)

    def test_get_many(self, live_v4, live_cve):
        out = live_v4.documents.get_many([live_cve])
        assert isinstance(out, dict)

    def test_history(self, live_v4, live_cve):
        _ok_or_graceful(lambda: live_v4.documents.history(live_cve), list)

    def test_references(self, live_v4, live_cve):
        out = live_v4.documents.references(live_cve)
        assert isinstance(out, dict)


# --------------------------------------------------------------------------- #
# 8. v4 subscriptions — contained CRUD (pull-based delivery)
# --------------------------------------------------------------------------- #


class TestSubscriptionsV4:
    def test_list_and_get_list(self, live_v4):
        # Both unwrap ('result',) -> a list of subscriptions, not the envelope.
        assert isinstance(live_v4.subscriptions.get_list(), list)
        assert isinstance(live_v4.subscriptions.list(), list)

    def test_crud_roundtrip(self, live_v4):
        name = "live-check-v4-synthetic"
        query = {"type": "query", "query": "type:cve AND order:published"}
        delivery = {"type": "pooling"}
        sub_id = None
        try:
            created = live_v4.subscriptions.create(name=name, query=query, delivery=delivery)
            sub_id = _extract_id(created)
            assert sub_id, "create() returned no subscription id"
            assert live_v4.subscriptions.get(sub_id) is not None
            # The server's update requires the full definition (name/query/delivery/
            # sendEmptyResult), so pass them all even though the client can send a
            # partial body.
            live_v4.subscriptions.update(
                sub_id,
                name=name + "-2",
                query=query,
                delivery=delivery,
                send_empty_result=False,
            )
        finally:
            if sub_id:
                live_v4.subscriptions.delete(sub_id)
            else:
                _sweep_v4_by_name(live_v4, name)


# --------------------------------------------------------------------------- #
# 9. Email subscriptions — contained CRUD + owner-key
# --------------------------------------------------------------------------- #


class TestEmailSubscriptions:
    def test_list(self, live_v4):
        assert live_v4.subscriptions_email.list() is not None

    def test_crud_roundtrip_with_owner_key(self, live_v4):
        own = _own_key(live_v4)
        query = "type:cve AND cvss.score:[9 TO 10]"
        sub_id = None
        try:
            created = live_v4.subscriptions_email.add(
                query=query,
                email="livecheck@example.com",  # RFC 2606 reserved
                api_key=own,
            )
            sub_id = _extract_id(created)
            assert sub_id, "add() returned no subscription id"
            live_v4.subscriptions_email.edit(sub_id, active="no", api_key=own)
        finally:
            if sub_id:
                live_v4.subscriptions_email.delete(sub_id, api_key=own)
            else:
                _sweep_email_by_query(live_v4, query)


# --------------------------------------------------------------------------- #
# 10. Webhooks — contained CRUD + owner-key
# --------------------------------------------------------------------------- #


class TestWebhooks:
    def test_list(self, live_v4):
        assert live_v4.webhooks.list() is not None

    def test_crud_roundtrip_with_owner_key(self, live_v4):
        own = _own_key(live_v4)
        query = "type:cve AND cvss.score:[9 TO 10]"
        sub_id = None
        try:
            created = live_v4.webhooks.add(query, api_key=own)
            sub_id = _extract_id(created)
            assert sub_id, "add() returned no webhook id"
            live_v4.webhooks.enable(sub_id, False, api_key=own)
            # A freshly-created, disabled subscription has no stored payloads, so
            # read may legitimately return None/empty — just assert it doesn't raise.
            read = live_v4.webhooks.read(sub_id, api_key=own)
            assert read is None or isinstance(read, (dict, list))
        finally:
            if sub_id:
                live_v4.webhooks.delete(sub_id, api_key=own)
            else:
                _sweep_webhooks_by_query(live_v4, query)

    def test_create_set_enabled_aliases(self, live_v4):
        # Exercise the alias names (create -> add, set_enabled -> enable) by name.
        own = _own_key(live_v4)
        query = "type:exploit AND cvss.score:[9 TO 10]"
        sub_id = None
        try:
            created = live_v4.webhooks.create(query, api_key=own)
            sub_id = _extract_id(created)
            assert sub_id, "create() returned no webhook id"
            live_v4.webhooks.set_enabled(sub_id, False, api_key=own)
        finally:
            if sub_id:
                live_v4.webhooks.delete(sub_id, api_key=own)
            else:
                _sweep_webhooks_by_query(live_v4, query)


# --------------------------------------------------------------------------- #
# 11. VScanner — read-only + offline helpers
# --------------------------------------------------------------------------- #


class TestVScanner:
    def test_notification_helpers_offline(self, live_v4):
        # Pure client-side constructors; no network.
        assert isinstance(live_v4.vscanner.disabled_notification(), dict)
        assert isinstance(
            live_v4.vscanner.notification("daily", emails=["a@synthetic.test"]), dict
        )

    def test_licenses_list(self, live_v4):
        _ok_or_graceful(lambda: live_v4.vscanner.licenses.list(), list, dict)

    def test_projects_list(self, live_v4):
        _ok_or_graceful(lambda: live_v4.vscanner.projects.list(limit=1), object)

    def test_project_children_if_exists(self, live_v4):
        # Read-only: only if a project already exists. Never creates projects or
        # tasks (a task launches a real scan and burns a license).
        try:
            projects = live_v4.vscanner.projects.list(limit=1)
        except VulnersError:
            return
        rows = projects if isinstance(projects, list) else getattr(projects, "data", None)
        proj_id = None
        for p in rows or []:
            proj_id = p.get("_id") if isinstance(p, dict) else getattr(p, "_id", None)
            break
        if not proj_id:
            return
        _ok_or_graceful(lambda: live_v4.vscanner.projects.tasks.list(proj_id, limit=1), object)
        _ok_or_graceful(lambda: live_v4.vscanner.projects.results.list(proj_id, limit=1), object)
        _ok_or_graceful(
            lambda: live_v4.vscanner.projects.statistics(proj_id, stat=["total_hosts"]), dict
        )


# --------------------------------------------------------------------------- #
# 12. Client escape hatch + raw response
# --------------------------------------------------------------------------- #


class TestClientPlumbing:
    def test_escape_hatch_post_and_get(self, live_v4):
        out = live_v4.post("/api/v3/search/lucene/", json={"query": "type:cve", "size": 1})
        assert isinstance(out, dict) and out.get("result") == "OK"
        # the GET escape hatch reaches a read-only endpoint through the same core
        got = live_v4.get("/api/v4/subscriptions/list/")
        assert isinstance(got, dict) and "result" in got

    def test_with_raw_response(self, live_v4):
        raw = live_v4.search.with_raw_response.query("type:cve", limit=1, fields=["id"])
        assert raw is not None
        # APIResponse exposes status_code directly (not via a http_response attr).
        status = getattr(raw, "status_code", None)
        if status is not None:
            assert status == 200

    def test_with_options_and_props(self, live_v4):
        assert live_v4.is_closed is False
        assert str(live_v4.base_url)
        client2 = live_v4.with_options(timeout=30.0)
        page = client2.search.query("type:cve", limit=1, fields=["id"])
        assert isinstance(page, SearchPage)


# --------------------------------------------------------------------------- #
# 13. Async client
# --------------------------------------------------------------------------- #


class TestAsync:
    async def test_search_get_bulletin_audit_and_stream(self, live_config, live_cve):
        key, base_url = live_config
        async with AsyncVulners(api_key=key, base_url=base_url) as v:
            page = await v.search.query("type:cve", limit=3, fields=["id", "bulletinFamily"])
            # the async client returns an AsyncSearchPage; assert structurally.
            assert isinstance(page.total, int) and page.total >= 0
            assert len(page.data) <= 3
            b = await v.search.get_bulletin(live_cve)
            assert b is None or isinstance(b, Bulletin)
            res = await v.audit.software(["cpe:2.3:a:apache:http_server:2.4.49"])
            assert isinstance(res, (list, dict))
            records = []
            async for rec in v.archive.aiter_collection("cve"):
                records.append(rec)
                if len(records) >= 3:
                    break
            assert len(records) == 3 and all(isinstance(r, dict) for r in records)

    async def test_async_webhook_crud_owner_key(self, live_config):
        key, base_url = live_config
        query = "type:cve AND cvss.score:[9 TO 10]"
        async with AsyncVulners(api_key=key, base_url=base_url) as v:
            own = _own_key(v)
            sub_id = None
            try:
                created = await v.webhooks.add(query, api_key=own)
                sub_id = _extract_id(created)
                assert sub_id, "async add() returned no webhook id"
                await v.webhooks.enable(sub_id, False, api_key=own)
            finally:
                if sub_id:
                    await v.webhooks.delete(sub_id, api_key=own)
                else:
                    # sweep backstop: remove a created-but-unparsed subscription
                    try:
                        subs = await v.webhooks.list()
                        for s in subs if isinstance(subs, list) else []:
                            if isinstance(s, dict) and s.get("query") == query:
                                sid = _extract_id(s)
                                if sid:
                                    await v.webhooks.delete(sid)
                    except VulnersError:
                        pass
