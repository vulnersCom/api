# Migrating v3 → v4

**You do not have to migrate.** The v3 API (`VulnersApi`, `VScannerApi`) stays fully
supported and behaves exactly as before — v4 is additive and lives alongside it in the same
package. Migrate when you want typed responses, async, first-class pagination and the modern
error model.

```python
# both import from the same package
from vulners import VulnersApi           # v3, legacy
from vulners import Vulners, AsyncVulners  # v4, recommended
```

## The three big differences

1. **Typed models, not dicts.** v3 returns plain `dict`s (`bulletin["id"]`). v4 returns
   `Bulletin` models (`bulletin.id`). Fields are attributes and all optional.
2. **Real pagination.** v3 `*_all` helpers materialized lists. v4 `search.query` returns a
   `SearchPage` you iterate (auto-paginating to the [10k window](search-window.md)), plus
   `iter_query` for lazy iteration.
3. **A new error hierarchy.** v3 raised `VulnersApiError`. v4 raises `VulnersError` and its
   subclasses (see [Error model](error-model.md)).

## Client

| v3 | v4 |
|---|---|
| `VulnersApi(api_key="…")` | `Vulners(api_key="…")` (or `Vulners()` reading `VULNERS_API_KEY`) |
| — | `AsyncVulners(...)` for `async`/`await` |
| `with VulnersApi(...) as api:` | `with Vulners(...) as v:` |

## Search

| v3 | v4 |
|---|---|
| `api.search.search_bulletins(query, limit=, offset=)` | `v.search.query(query, limit=, offset=)` → `SearchPage[Bulletin]` |
| `api.search.search_bulletins_all(query)` | iterate the page, or `v.search.iter_query(query)` |
| `api.search.search_exploits(query)` | `v.search.exploits(query)` → `SearchPage[Bulletin]` |
| `api.search.get_bulletin(id)` | `v.search.get_bulletin(id)` → `Bulletin \| None` |
| `api.search.get_multiple_bulletins(ids)` | `v.search.get_multiple_bulletins(ids)` → `dict[str, Bulletin]` |

```python
# v3
for doc in api.search.search_bulletins("type:cve", limit=10):
    print(doc["id"], doc["title"])

# v4  (`.data` is the first page; iterating the page itself auto-paginates)
for doc in v.search.query("type:cve", limit=10).data:
    print(doc.id, doc.title)
```

## Audit

| v3 | v4 |
|---|---|
| `api.audit.software(software, ...)` | `v.audit.software(software, ...)` |
| `api.audit.host(...)` | `v.audit.host(...)` |
| `api.audit.os_audit(os=, version=, packages=)` | `v.audit.os_audit(os=, version=, packages=)` |
| `api.audit.linux_audit(os_name=, os_version=, packages=)` | `v.audit.linux_audit(os_name=, os_version=, packages=)` |
| `api.audit.kb_audit(os=, kb_list=)` | `v.audit.kb_audit(os=, kb_list=)` |
| `api.audit.win_audit(...)` | `v.audit.win_audit(...)` |

!!! note "Return shape"
    Some v4 audit endpoints unwrap the response envelope for you, so where v3 returned
    `{"result": {...}}` v4 may return the inner object directly. Print the result once when
    porting a call to confirm the shape you get.

## Misc, archive, reports

| v3 | v4 |
|---|---|
| `api.misc.search_cpe / query_autocomplete / get_suggestion / get_web_application_rules` | same names on `v.misc` |
| `api.archive.get_collection / get_distributive / getsploit` | same names on `v.archive` |
| — (new) | `v.archive.fetch_collection`, `v.archive.aiter_collection` (streaming), `v.archive.fetch_collection_update` |
| `api.report.*` | `v.report.*` (`vulns_summary`, `vulns_list`, `ip_summary`, `scan_list`, `host_vulns`) |

## Error handling

```python
# v3
from vulners import VulnersApiError
try:
    api.search.get_bulletin("CVE-2021-44228")
except VulnersApiError as err:
    print(err.http_status, err.error_code, err.message)

# v4
from vulners import APIStatusError
try:
    v.search.get_bulletin("CVE-2021-44228")
except APIStatusError as err:
    print(err.status_code, err.error_code, err.message)
```

Note the attribute rename: v3 `err.http_status` → v4 `err.status_code`. v4 adds `err.data`
(redacted payload) and `err.retry_after`.

## Deprecated top-level methods

The old flat methods on `VulnersApi` (`find_all`, `get_bulletin`, `audit_software`,
`winaudit`, …) still work but emit a `VulnersDeprecationWarning`. Their replacements are the
sub-API methods above (`api.search.*`, `api.audit.*`). In v4 there are no flat aliases — use
the resource namespaces on `Vulners` directly.
