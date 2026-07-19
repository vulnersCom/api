"""Golden-wire oracle for the v3 backward-compatibility contract.

For a representative call to every public sub-API method, this records the exact
HTTP request the v3 SDK puts on the wire (method, path, query, headers, body).
The v4 deprecated shims (WP6) must reproduce each request byte-for-byte.

The baseline was recorded against the real ``vulners==3.2.0`` build; regenerate
with::

    python tests/bc/wire_baseline.py --record       # writes golden/wire.json

The volatile ``User-Agent`` version token is normalized to ``{VERSION}`` so the
only expected delta between 3.2.0 and the v4 tree is the version string.

All identifiers are synthetic (CVE-2099-*, SYNTHETIC-*); no real data.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import orjson

import vulners
from vulners.base import VulnersApiTransport

KEY = "SYNTHETIC-TEST-KEY-0000000000"
GOLDEN = Path(__file__).parent / "golden" / "wire.json"

# A synthetic SBOM file for the multipart sbom_audit call (created on demand).
_SBOM_JSON = orjson.dumps({"spdxVersion": "SPDX-2.3", "name": "synthetic", "packages": []})


def _sbom_path() -> Path:
    path = Path(tempfile.gettempdir()) / "vulners_bc_sbom.json"
    path.write_bytes(_SBOM_JSON)
    return path


# Each entry: (name, fn). fn(api) issues one call; only the first request it
# emits is recorded. Calls may raise while parsing the canned response — we
# already captured the request by then, so exceptions are swallowed.
CALLS: list[tuple[str, Callable[[Any], Any]]] = [
    # --- search ---
    ("search.search_bulletins", lambda a: a.search.search_bulletins("ssh", limit=5)),
    ("search.search_bulletins_all", lambda a: a.search.search_bulletins_all("ssh", limit=5)),
    ("search.search_exploits", lambda a: a.search.search_exploits("CVE-2099-0001")),
    ("search.search_exploits_all", lambda a: a.search.search_exploits_all("CVE-2099-0001")),
    ("search.get_bulletin", lambda a: a.search.get_bulletin("CVE-2099-0001")),
    ("search.get_bulletin_history", lambda a: a.search.get_bulletin_history("CVE-2099-0001")),
    (
        "search.get_bulletin_references",
        lambda a: a.search.get_bulletin_references("CVE-2099-0001"),
    ),
    (
        "search.get_bulletin_with_references",
        lambda a: a.search.get_bulletin_with_references("CVE-2099-0001"),
    ),
    ("search.get_kb_seeds", lambda a: a.search.get_kb_seeds("KB5000001")),
    ("search.get_kb_updates", lambda a: a.search.get_kb_updates("KB5000001")),
    (
        "search.get_multiple_bulletins",
        lambda a: a.search.get_multiple_bulletins(["CVE-2099-0001", "CVE-2099-0002"]),
    ),
    (
        "search.get_multiple_bulletin_references",
        lambda a: a.search.get_multiple_bulletin_references(["CVE-2099-0001", "CVE-2099-0002"]),
    ),
    (
        "search.get_multiple_bulletins_with_references",
        lambda a: a.search.get_multiple_bulletins_with_references(["CVE-2099-0001"]),
    ),
    (
        "search.get_web_vulns",
        lambda a: a.search.get_web_vulns(["/wp-login.php"], application="wordpress"),
    ),
    # --- audit ---
    ("audit.software", lambda a: a.audit.software(["nginx 1.20.0"])),
    ("audit.host", lambda a: a.audit.host(["nginx 1.20.0"])),
    ("audit.os_audit", lambda a: a.audit.os_audit("centos", "7", ["glibc-2.17-292.el7"])),
    (
        "audit.linux_audit",
        lambda a: a.audit.linux_audit("centos", "7", ["glibc-2.17-292.el7"], os_arch="x86_64"),
    ),
    ("audit.kb_audit", lambda a: a.audit.kb_audit("windows-server-2019", ["KB5000001"])),
    (
        "audit.win_audit",
        lambda a: a.audit.win_audit("windows-server-2019", "10.0.17763", ["KB5000001"], []),
    ),
    ("audit.cve_audit", lambda a: a.audit.cve_audit("CVE-2099-0001")),
    (
        "audit.cve_batch_audit",
        lambda a: a.audit.cve_batch_audit(["CVE-2099-0001", "CVE-2099-0002"]),
    ),
    ("audit.library_audit", lambda a: a.audit.library_audit(["pkg:pypi/requests@2.0.0"])),
    ("audit.sbom_audit", lambda a: a.audit.sbom_audit(_sbom_path())),
    # --- misc ---
    ("misc.search_cpe", lambda a: a.misc.search_cpe("nginx", vendor="nginx")),
    ("misc.query_autocomplete", lambda a: a.misc.query_autocomplete("type:exp")),
    ("misc.get_suggestion", lambda a: a.misc.get_suggestion("type")),
    ("misc.get_web_application_rules", lambda a: a.misc.get_web_application_rules()),
    # --- archive ---
    ("archive.get_collection", lambda a: a.archive.get_collection("cve")),
    ("archive.fetch_collection", lambda a: a.archive.fetch_collection("cve")),
    (
        "archive.fetch_collection_update",
        lambda a: a.archive.fetch_collection_update("cve", datetime(2099, 1, 1)),
    ),
    ("archive.get_distributive", lambda a: a.archive.get_distributive("centos", "7")),
    ("archive.getsploit", lambda a: a.archive.getsploit()),
    # --- reports ---
    ("report.vulns_summary", lambda a: a.report.vulns_summary()),
    ("report.vulns_list", lambda a: a.report.vulns_list()),
    ("report.ip_summary", lambda a: a.report.ip_summary()),
    ("report.scan_list", lambda a: a.report.scan_list()),
    ("report.host_vulns", lambda a: a.report.host_vulns()),
    # --- subscriptions v3 ---
    ("subscription.list", lambda a: a.subscription.list()),
    ("subscription.add", lambda a: a.subscription.add("type:exploit", "user@example.com")),
    ("subscription.edit", lambda a: a.subscription.edit("SYNTHETIC-SUB-1", active="no")),
    ("subscription.delete", lambda a: a.subscription.delete("SYNTHETIC-SUB-1")),
    # --- subscriptions v4 ---
    ("subscription_v4.get_list", lambda a: a.subscription_v4.get_list()),
    (
        "subscription_v4.create",
        lambda a: a.subscription_v4.create(
            "synthetic", {"query": "type:exploit"}, {"type": "webhook"}
        ),
    ),
    ("subscription_v4.get", lambda a: a.subscription_v4.get("SYNTHETIC-SUB-1")),
    (
        "subscription_v4.update",
        lambda a: a.subscription_v4.update(
            "SYNTHETIC-SUB-1", "synthetic", {"query": "type:exploit"}, {"type": "webhook"}
        ),
    ),
    ("subscription_v4.delete", lambda a: a.subscription_v4.delete("SYNTHETIC-SUB-1")),
    # --- webhooks ---
    ("webhook.list", lambda a: a.webhook.list()),
    ("webhook.add", lambda a: a.webhook.add("type:exploit")),
    ("webhook.enable", lambda a: a.webhook.enable("SYNTHETIC-WH-1", True)),
    ("webhook.read", lambda a: a.webhook.read("SYNTHETIC-WH-1")),
    ("webhook.delete", lambda a: a.webhook.delete("SYNTHETIC-WH-1")),
    # --- stix ---
    ("stix.make_bundle_by_id", lambda a: a.stix.make_bundle_by_id("CVE-2099-0001")),
]


class _Recorder:
    """MockTransport handler: records requests, answers with an empty envelope."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(
            200,
            content=orjson.dumps({"result": "OK", "data": {}}),
            headers={"content-type": "application/json"},
        )


def _make_api() -> tuple[Any, _Recorder]:
    api = vulners.VulnersApi(KEY)
    rec = _Recorder()
    api._client._transport = VulnersApiTransport(httpx.MockTransport(rec))
    return api, rec


def _multipart_boundary(content_type: str) -> str | None:
    marker = "boundary="
    idx = content_type.find(marker)
    if idx == -1:
        return None
    return content_type[idx + len(marker) :].strip().strip('"')


def canonicalize(request: httpx.Request) -> dict[str, Any]:
    """Byte-exact, version- and boundary-normalized view of an outgoing request.

    Two volatile tokens are normalized (A21): the ``User-Agent`` version and the
    random multipart boundary (regenerated per request by httpx for
    ``sbom_audit``). Everything else is compared byte-for-byte.
    """
    version = vulners.__version__
    boundary = _multipart_boundary(request.headers.get("content-type", ""))
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if version and version in value:
            value = value.replace(version, "{VERSION}")
        if boundary and boundary in value:
            value = value.replace(boundary, "{BOUNDARY}")
        headers[name] = value
    body = request.content
    try:
        body_text = body.decode("utf-8")
        if boundary:
            body_text = body_text.replace(boundary, "{BOUNDARY}")
        body_repr: dict[str, str] = {"text": body_text}
    except UnicodeDecodeError:
        body_repr = {"base64": base64.b64encode(body).decode("ascii")}
    return {
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query.decode("ascii"),
        "headers": dict(sorted(headers.items())),
        "body": body_repr,
    }


def record_call(fn: Callable[[Any], Any]) -> dict[str, Any]:
    """Issue one call against a recording transport; return the canonical request."""
    api, rec = _make_api()
    try:
        # The request is captured before the response is parsed, so a parse error
        # on the canned empty envelope is irrelevant here.
        with contextlib.suppress(Exception):
            fn(api)
        return canonicalize(rec.requests[0]) if rec.requests else {"error": "no request"}
    finally:
        api._client.close()


def record_all() -> dict[str, Any]:
    return dict(sorted((name, record_call(fn)) for name, fn in CALLS))


def main() -> None:
    parser = argparse.ArgumentParser(description="Record the v3 golden-wire baseline.")
    parser.add_argument("--record", action="store_true", help="write golden/wire.json")
    args = parser.parse_args()
    data = record_all()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.record:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(text, encoding="utf-8")
        missing = [k for k, v in data.items() if "error" in v]
        print(f"recorded {len(data)} calls to {GOLDEN}")
        if missing:
            print(f"WARNING: {len(missing)} calls emitted no request: {missing}")
    else:
        print(text)


if __name__ == "__main__":
    main()
