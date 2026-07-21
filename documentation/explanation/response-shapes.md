# Response shapes (untyped endpoints)

The v4 typed models cover the **document** layer end to end: `search`/`documents`/`archive`
records come back as [`Bulletin`](../reference/bulletins/index.md) subclasses with typed fields.
The **audit**, **archive-metadata**, **subscription**, **report** and **VScanner** endpoints,
though, return provider-shaped JSON that the SDK hands back as plain `dict`/`list` (annotated
`Any` / `dict[str, Any]`). This page shows the **real** shape of each so you don't have to guess
at keys.

Examples are abbreviated — one element per list, long strings clipped, captured from live calls
(audit/archive/misc) or the API schema (subscriptions/reports). Every field is optional; treat a
missing key as "not present for this row".

## Audit

### `audit.software(...)` · `audit.host(...)`

Both return a **list**, one entry per input item, each with the affecting vulnerabilities:

```json
[
  {
    "input": {"product": "openssl", "version": "1.0.1"},
    "matched_criteria": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
    "vulnerabilities": [
      {
        "id": "VERACODE:3506",
        "type": "veracode",
        "title": "Denial Of Service (DoS) Through Null Pointer Dereference",
        "published": "2017-02-08T05:51:39",
        "modified": "2019-05-15T06:18:01",
        "href": "https://sca.analysiscenter.veracode.com/vulnerability-database/...",
        "short_description": "OpenSSL DoS vulnerability by null pointer dereference",
        "ai_score": {"value": 6.3},
        "reasons": [
          {
            "config": "vulners",
            "criterias": [[{"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                            "vulnerable": true, "versionEndIncluding": "1.0.1"}]]
          }
        ]
      }
    ]
  }
]
```

`host` items use the raw CPE string as `"input"` instead of a `{product, version}` object; the
rest is identical. `sbom_audit` returns the same per-component shape.

### `audit.linux_audit(...)` · `audit.win_audit(...)`

A single object keyed by `issues` (**not** wrapped in `result` — that is the v3 shape):

```json
{
  "issues": [
    {
      "package": "openssl 1.1.1d-0+deb10u3 amd64",
      "version": "1.1.1d-0+deb10u3",
      "fixedVersion": "1.1.1n-0+deb10u6",
      "fixedPackage": "openssl_1.1.1n-0+deb10u6_amd64.deb",
      "applicableAdvisories": [
        {"id": "OSV:DSA-4807-1", "match": ">=1,<1.1.1d-0+deb10u4", "registry": "deb",
         "distro": ["debian"], "operator": "lt", "version": "any"}
      ]
    }
  ],
  "errors": {},
  "totalPackages": 1
}
```

`win_audit` returns the same envelope for Windows KBs/software. `smart` returns a list like
`software`, with each entry adding the resolved CPE/PURLs and a confidence score.

## Archive metadata

### `archive.collection_state(type)` · `archive.family_state(name)`

The sync cursor and counters for a collection/family — feed `cursor` back as `after` to a
`*_update` download:

```json
{
  "cursor": "2026-07-21T12:40:37.108000Z",
  "upload_time": "2026-07-21T16:12:14.170000Z",
  "write_time": "2026-07-21T15:43:39.470000Z",
  "total_docs": 606
}
```

## Lookups (`misc`)

```json
// misc.search_cpe("http_server", vendor="apache")
{"best_match": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
 "cpe": ["cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*"]}

// misc.query_autocomplete("heartbleed")  -> a list of suggestion strings
["id:\"NMAP:SSL-HEARTBLEED.NSE\"", "heartbleed", "Heartbleed"]
```

## Subscriptions

`subscriptions_email.list/add/edit` return a **list** of email-subscription records:

```json
[
  {
    "id": "…", "active": true, "confirmed": true,
    "query": "type:cve AND cvss.score:[9 TO 10]", "query_type": "lucene",
    "link_query": "https://vulners.com/search?query=…",
    "crontab": "0 9 * * 1",
    "deliveryAddress": "you@example.com", "deliveryFormat": "html"
  }
]
```

`webhooks.list` returns a list of polling-webhook records (id, `active`, the `query`, and the
webhook target). `subscriptions` (the current **v4** API) returns a list of v4 subscription
records; see the [resources reference](../reference/resources.md). An empty list means no
subscriptions exist for the key.

## Reports

`report.*` methods return a **list of rows** whose columns depend on the report type. For example
`report.scan_list()`:

```json
[
  {"id": "…", "ipaddress": "203.0.113.7", "fqdn": "host.example.com",
   "OS": "Ubuntu", "OSVersion": "22.04", "modified": "2026-07-01T00:00:00",
   "cvss": {"score": 9.8, "vector": "AV:N/AC:L/…"}}
]
```

Other report types (`vulns_summary`, `vulns_list`, `ip_summary`, `host_vulns`, `vuln_info`) return
their own row columns — see the [resources reference](../reference/resources.md).

## VScanner

`v.vscanner` (the perimeter scanner) is namespaced — `vscanner.licenses`, `vscanner.projects`,
`vscanner.projects.tasks` and `vscanner.projects.results` — and the `list(...)` calls return
provider-shaped JSON: a project record carries its id, name and scan settings; a task its schedule
and status; a result the per-host/port findings and screenshots. See the
[resources reference](../reference/resources.md) for each call's fields.

---

!!! note "Why `Any`?"
    These endpoints are passed through as provider-shaped JSON rather than modelled, so new
    server-side fields reach you immediately (nothing is dropped). Typed models for the audit and
    report shapes are a planned follow-up; until then, this page is the contract.
