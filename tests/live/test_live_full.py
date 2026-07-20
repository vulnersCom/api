"""Full-surface live exercise of the 3.2.0 SDK against the real Vulners API (opt-in).

Covers every public method across the ten domains (search, audit, archive, misc,
report, stix, email subscriptions, v4 subscriptions, webhooks, vscanner). Run it
with a real key configured (``VULNERS_API_KEY`` or ``tests/live.local.toml``);
without one the whole module is skipped at collection time (see conftest).

Rules (the live database is dynamic, so tests pin STRUCTURE, not data):
- assert envelope shape / types only — never concrete vulnerabilities or counts;
- keep the API key and any echoed request ``input`` out of assertion messages
  (v4 validation errors echo the request input);
- mutations are contained: subscriptions / webhooks / v4-subscriptions are
  created and then deleted in a ``finally``; vscanner is exercised read-only
  because creating a task launches a real network scan and consumes a license;
- large archive downloads run against a byte-capped client so a multi-GB
  collection cannot be pulled in full — reachability is proven either by a small
  payload or by the cap firing.

Contract for entitlement-gated endpoints (enterprise reporting, vscanner, sbom,
some audit lookups): the SDK must either return a well-shaped response OR raise a
graceful ``VulnersApiError`` — an unexpected exception (crash) is a real failure.
``_ok_or_graceful`` encodes exactly that, so these tests verify the SDK's request
construction and error handling even when the account is not entitled to the data.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import orjson
import pytest

import vulners
from vulners.base import ResultSet, VulnersApiError

pytestmark = pytest.mark.live

_FALLBACK_CVE = "CVE-2021-44228"
_KB_ID = "KB5028166"  # a real Windows KB; a wrong-but-plausible id still exercises the path


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def capped_api(live_config):
    """Client with an 8 MB response cap for the archive download endpoints."""
    key, server_url = live_config
    api = vulners.VulnersApi(key, server_url=server_url, max_response_bytes=8_000_000)
    yield api
    api._client.close()


@pytest.fixture
def vscanner(live_config):
    """VScannerApi is a separate top-level class (not a VulnersApi sub-API)."""
    key, server_url = live_config
    vs = vulners.VScannerApi(key, server_url=server_url)
    yield vs
    vs.close()


@pytest.fixture(scope="session")
def live_cve(live_config) -> str:
    """A real, recent CVE id from the live DB (falls back to a well-known one)."""
    key, server_url = live_config
    api = vulners.VulnersApi(key, server_url=server_url)
    try:
        rs = api.search.search_bulletins("type:cve order:published", limit=1)
        for b in rs:
            cid = b.get("id")
            if cid:
                return cid
    except VulnersApiError:
        pass
    finally:
        api._client.close()
    return _FALLBACK_CVE


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ok_or_graceful(fn: Callable[[], Any], *shape: type) -> Any:
    """Return the result if it is one of *shape*; treat a graceful
    ``VulnersApiError`` as an acceptable outcome (request built + error handled).
    Any other exception propagates as a real SDK failure. Never lets the server
    message (which can echo request input) into an assertion message."""
    try:
        res = fn()
    except VulnersApiError:
        return None
    assert isinstance(res, shape), f"unexpected shape: {type(res).__name__}"
    return res


def _reachable_or_capped(fn: Callable[[], Any], *shape: type) -> None:
    """Archive downloads: pass on a well-shaped payload OR on the byte cap firing
    (both prove the endpoint is reachable and the stream decodes)."""
    try:
        res = fn()
    except VulnersApiError as e:
        assert (
            "exceeds max_response_bytes" in str(e) or getattr(e, "error_code", None) is not None
        )
        return
    assert isinstance(res, shape), f"unexpected shape: {type(res).__name__}"


_ID_KEYS = ("id", "subscriptionid", "subscriptionId", "subscription_id", "_id")


def _extract_id(payload: Any) -> str | None:
    """Pull a subscription id out of a create/add response across the key
    spellings the server may use, unwrapping a v4 ``result`` envelope. Used so a
    mutation's cleanup can always find the id it needs to delete."""
    for src in (payload.get("result") if isinstance(payload, dict) else None, payload):
        if isinstance(src, str) and src:
            return src
        if isinstance(src, dict):
            for k in _ID_KEYS:
                v = src.get(k)
                if isinstance(v, str) and v:
                    return v
    return None


def _sweep_webhooks_by_query(api: Any, query: str) -> None:
    """Cleanup safety net: delete any webhook subscription matching the synthetic
    test query, in case a create succeeded but its id could not be parsed."""
    try:
        subs = api.webhook.list()
        for s in subs if isinstance(subs, list) else []:
            if isinstance(s, dict) and s.get("query") == query:
                sid = _extract_id(s)
                if sid:
                    api.webhook.delete(sid, api_key=api._api_key)
    except VulnersApiError:
        pass


def _sweep_v4_by_name(api: Any, name: str) -> None:
    """Cleanup safety net: delete any v4 subscription with the synthetic name."""
    try:
        listing = api.subscription_v4.get_list()
        rows = listing.get("result") if isinstance(listing, dict) else None
        for s in rows if isinstance(rows, list) else []:
            if isinstance(s, dict) and s.get("name") == name:
                sid = _extract_id(s)
                if sid:
                    api.subscription_v4.delete(sid)
    except VulnersApiError:
        pass


# --------------------------------------------------------------------------- #
# 1. Search
# --------------------------------------------------------------------------- #


class TestSearch:
    def test_search_bulletins(self, live_api):
        rs = live_api.search.search_bulletins("type:cve", limit=2)
        assert isinstance(rs, ResultSet)
        assert isinstance(rs.total, int) and rs.total >= 0
        assert len(rs) <= 2

    def test_search_bulletins_all(self, live_api):
        rs = live_api.search.search_bulletins_all("type:cve order:published", limit=3)
        assert isinstance(rs, ResultSet)
        assert len(rs) <= 3

    def test_search_exploits(self, live_api):
        rs = live_api.search.search_exploits("apache", limit=2)
        assert isinstance(rs, ResultSet)
        assert isinstance(rs.total, int) and rs.total >= 0

    def test_search_exploits_all(self, live_api):
        rs = live_api.search.search_exploits_all("apache", limit=3)
        assert isinstance(rs, ResultSet)

    def test_get_bulletin(self, live_api, live_cve):
        doc = live_api.search.get_bulletin(live_cve)
        assert isinstance(doc, dict)

    def test_get_bulletin_with_references(self, live_api, live_cve):
        doc = live_api.search.get_bulletin_with_references(live_cve)
        assert isinstance(doc, dict)

    def test_get_bulletin_history(self, live_api, live_cve):
        _ok_or_graceful(lambda: live_api.search.get_bulletin_history(live_cve), dict, list)

    def test_get_bulletin_references(self, live_api, live_cve):
        refs = live_api.search.get_bulletin_references(live_cve)
        assert isinstance(refs, dict)

    def test_get_multiple_bulletins(self, live_api, live_cve):
        docs = live_api.search.get_multiple_bulletins([live_cve])
        assert isinstance(docs, dict)

    def test_get_multiple_bulletins_with_references(self, live_api, live_cve):
        docs = live_api.search.get_multiple_bulletins_with_references([live_cve])
        assert isinstance(docs, dict)

    def test_get_multiple_bulletin_references(self, live_api, live_cve):
        refs = live_api.search.get_multiple_bulletin_references([live_cve])
        assert isinstance(refs, dict)

    def test_get_kb_seeds(self, live_api):
        _ok_or_graceful(lambda: live_api.search.get_kb_seeds(_KB_ID), dict, list)

    def test_get_kb_updates(self, live_api):
        _ok_or_graceful(lambda: live_api.search.get_kb_updates(_KB_ID), dict, list, ResultSet)

    def test_get_web_vulns(self, live_api):
        _ok_or_graceful(
            lambda: live_api.search.get_web_vulns(
                paths=["/wp-login.php"], application="wordpress"
            ),
            dict,
        )


# --------------------------------------------------------------------------- #
# 2. Audit
# --------------------------------------------------------------------------- #


class TestAudit:
    def test_software(self, live_api):
        # audit/software returns a list of per-input results.
        res = live_api.audit.software(["cpe:2.3:a:apache:http_server:2.4.49"])
        assert isinstance(res, (list, dict))

    def test_host(self, live_api):
        # host audit requires at least one of operating_system / application /
        # hardware in addition to software (server-enforced).
        res = live_api.audit.host(
            software=["cpe:2.3:a:apache:http_server:2.4.49"],
            operating_system="cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
        )
        assert isinstance(res, (list, dict))

    def test_linux_audit(self, live_api):
        res = live_api.audit.linux_audit(
            os_name="ubuntu", os_version="22.04", packages=["bash 5.1-6ubuntu1 amd64"]
        )
        assert isinstance(res, dict)

    def test_os_audit_deprecated(self, live_api):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            res = live_api.audit.os_audit(
                os="ubuntu", version="22.04", packages=["bash 5.1-6ubuntu1 amd64"]
            )
        assert isinstance(res, dict)

    def test_win_audit(self, live_api):
        res = live_api.audit.win_audit(
            os="Windows 10", os_version="10.0.19045", kb_list=[_KB_ID], software=[]
        )
        assert isinstance(res, dict)

    def test_kb_audit(self, live_api):
        _ok_or_graceful(lambda: live_api.audit.kb_audit(os="Windows 10", kb_list=[_KB_ID]), dict)

    def test_cve_audit(self, live_api, live_cve):
        _ok_or_graceful(lambda: live_api.audit.cve_audit(live_cve), dict)

    def test_cve_batch_audit(self, live_api, live_cve):
        _ok_or_graceful(lambda: live_api.audit.cve_batch_audit([live_cve]), dict)

    def test_library_audit(self, live_api):
        _ok_or_graceful(lambda: live_api.audit.library_audit(["pkg:pypi/django@3.0"]), dict)

    def test_sbom_audit(self, live_api, tmp_path):
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
        _ok_or_graceful(lambda: live_api.audit.sbom_audit(file=sbom), dict)


# --------------------------------------------------------------------------- #
# 3. Archive (byte-capped)
# --------------------------------------------------------------------------- #


class TestArchive:
    def test_fetch_collection_update_recent_delta(self, capped_api):
        after = datetime.now(timezone.utc) - timedelta(hours=2)
        _reachable_or_capped(
            lambda: capped_api.archive.fetch_collection_update("cve", after), dict, list
        )

    def test_fetch_collection(self, capped_api):
        _reachable_or_capped(lambda: capped_api.archive.fetch_collection("cve"), dict, list)

    def test_get_collection_deprecated(self, capped_api):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _reachable_or_capped(lambda: capped_api.archive.get_collection("cve"), dict, list)

    def test_get_distributive_deprecated(self, capped_api):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _reachable_or_capped(
                lambda: capped_api.archive.get_distributive("debian", "10"), dict, list
            )

    def test_getsploit_deprecated(self, capped_api):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _reachable_or_capped(lambda: capped_api.archive.getsploit(), dict, list, bytes)


# --------------------------------------------------------------------------- #
# 4. Misc
# --------------------------------------------------------------------------- #


class TestMisc:
    def test_query_autocomplete(self, live_api):
        # query_autocomplete's response_handler returns a list of completions.
        res = live_api.misc.query_autocomplete("type:cv")
        assert isinstance(res, list)

    def test_search_cpe(self, live_api):
        # `vendor` is optional in the SDK but required by the v4 spec; accept a
        # graceful server error so a spec/entitlement gate isn't a hard failure.
        _ok_or_graceful(lambda: live_api.misc.search_cpe(product="nginx"), dict)

    def test_get_suggestion(self, live_api):
        # get_suggestion returns the `suggest` payload, which is a list for a
        # distinct-value suggestion (dict for other shapes) — accept either.
        _ok_or_graceful(lambda: live_api.misc.get_suggestion(field_name="type"), dict, list)

    def test_get_web_application_rules_deprecated(self, live_api):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _ok_or_graceful(lambda: live_api.misc.get_web_application_rules(), dict, list)


# --------------------------------------------------------------------------- #
# 5. Report (enterprise; entitlement-gated)
# --------------------------------------------------------------------------- #


class TestReport:
    def test_host_vulns(self, live_api):
        _ok_or_graceful(lambda: live_api.report.host_vulns(limit=1), dict, list)

    def test_ip_summary(self, live_api):
        _ok_or_graceful(lambda: live_api.report.ip_summary(limit=1), dict, list)

    def test_scan_list(self, live_api):
        _ok_or_graceful(lambda: live_api.report.scan_list(limit=1), dict, list)

    def test_vulns_list(self, live_api):
        _ok_or_graceful(lambda: live_api.report.vulns_list(limit=1), dict, list)

    def test_vulns_summary(self, live_api):
        _ok_or_graceful(lambda: live_api.report.vulns_summary(limit=1), dict, list)


# --------------------------------------------------------------------------- #
# 6. STIX
# --------------------------------------------------------------------------- #


class TestStix:
    def test_make_bundle_by_id(self, live_api, live_cve):
        # The STIX bundle is returned as a serialized JSON string.
        _ok_or_graceful(lambda: live_api.stix.make_bundle_by_id(live_cve), dict, str)


# --------------------------------------------------------------------------- #
# 7. Email subscriptions (deprecated) — contained CRUD + owner-key
# --------------------------------------------------------------------------- #


class TestEmailSubscriptions:
    def test_list(self, live_api):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            res = live_api.subscription.list()
        assert isinstance(res, (list, dict))

    def test_crud_roundtrip_with_owner_key(self, live_api):
        # add -> edit -> delete, cleaning up in finally. api_key defaults to the
        # client's own key; pass it explicitly to exercise the owner-key path.
        own = live_api._api_key
        sub_id = None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                created = live_api.subscription.add(
                    query="type:cve AND cvss.score:[9 TO 10]",
                    email="livecheck@example.com",  # RFC 2606 reserved domain
                    api_key=own,
                )
                assert isinstance(created, dict)
                sub_id = created.get("id") or created.get("subscriptionid")
                assert sub_id, "add() returned no subscription id"
                edited = live_api.subscription.edit(sub_id, active="false", api_key=own)
                assert isinstance(edited, dict)
            finally:
                if sub_id:
                    live_api.subscription.delete(sub_id, api_key=own)


# --------------------------------------------------------------------------- #
# 8. v4 subscriptions — contained CRUD (pull-based delivery, no external callback)
# --------------------------------------------------------------------------- #


class TestSubscriptionsV4:
    def test_get_list(self, live_api):
        res = live_api.subscription_v4.get_list()
        assert isinstance(res, dict)
        assert "result" in res

    def test_crud_roundtrip(self, live_api):
        name = "live-check-synthetic"
        query = {"type": "query", "query": "type:cve AND order:published"}
        delivery = {"type": "pooling"}  # pull-based: server generates a polling URL
        sub_id = None
        try:
            created = live_api.subscription_v4.create(name=name, query=query, delivery=delivery)
            assert isinstance(created, dict)
            sub_id = _extract_id(created)
            assert sub_id, "create() returned no subscription id"
            got = live_api.subscription_v4.get(sub_id)
            assert isinstance(got, dict)
            updated = live_api.subscription_v4.update(
                id=sub_id, name="live-check-synthetic-2", query=query, delivery=delivery
            )
            assert isinstance(updated, dict)
        finally:
            if sub_id:
                live_api.subscription_v4.delete(sub_id)
            else:
                _sweep_v4_by_name(live_api, name)


# --------------------------------------------------------------------------- #
# 9. Webhooks (v3 polling) — contained CRUD + owner-key
# --------------------------------------------------------------------------- #


class TestWebhooks:
    def test_list(self, live_api):
        res = live_api.webhook.list()
        assert isinstance(res, (list, dict))

    def test_crud_roundtrip_with_owner_key(self, live_api):
        # add -> enable -> read -> delete, cleaning up in finally. Pull-based
        # ("polling") webhook: no external callback fires. api_key names the owner
        # and defaults to the client's own key.
        own = live_api._api_key
        query = "type:cve AND cvss.score:[9 TO 10]"
        sub_id = None
        try:
            created = live_api.webhook.add(query, api_key=own)
            assert isinstance(created, dict)
            sub_id = _extract_id(created)
            assert sub_id, "add() returned no webhook id"
            enabled = live_api.webhook.enable(sub_id, False, api_key=own)
            assert isinstance(enabled, dict)
            read = live_api.webhook.read(sub_id, api_key=own)
            assert isinstance(read, dict)
        finally:
            if sub_id:
                live_api.webhook.delete(sub_id, api_key=own)
            else:
                _sweep_webhooks_by_query(live_api, query)


# --------------------------------------------------------------------------- #
# 10. VScanner — read-only (creating a task launches a real network scan)
# --------------------------------------------------------------------------- #


class TestVScannerReadOnly:
    def test_get_licenses(self, vscanner):
        _ok_or_graceful(lambda: vscanner.get_licenses(), object)

    def test_get_projects(self, vscanner):
        _ok_or_graceful(lambda: vscanner.get_projects(limit=1), object)

    def test_get_tasks_results_statistics_if_project_exists(self, vscanner):
        # Read-only: only if a project already exists. Never creates projects or
        # tasks — that would launch real scans and consume a license.
        try:
            projects = vscanner.get_projects(limit=1)
        except VulnersApiError:
            return  # gated: get_projects is validated by test_get_projects
        # A Project is an ApiObject (Mapping, not dict) whose id lives under `_id`
        # (its own update()/delete() read self._id) — set as an attribute in
        # __init__, so getattr(p, "_id") is the reliable accessor.
        proj_id = None
        for p in projects:
            proj_id = getattr(p, "_id", None)
            break
        if not proj_id:
            return  # no existing project to read from — read path covered by get_projects
        _ok_or_graceful(lambda: vscanner.get_tasks(proj_id, limit=1), object)
        _ok_or_graceful(lambda: vscanner.get_results(proj_id, limit=1), object)
        _ok_or_graceful(lambda: vscanner.get_statistics(proj_id, stat=["total_hosts"]), dict)
