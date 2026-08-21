# Vulners Python SDK — API index

<!-- Generated file: do not edit by hand.
     Regenerate with `python dev-tools/generate_api_md.py`. -->

Machine-readable index of the public API of the [`Vulners`](src/vulners/_client.py)
client. Every method exists identically on `AsyncVulners` (awaited; lazy iterators
are named `aiter_*` and iterated with `async for`). Rows: method signature,
return annotation, and the HTTP route the method calls (`-` when the route is
resolved at runtime; `{name}` marks a path segment filled from an argument).

The client itself also exposes untyped escape hatches for any API path —
`get`, `post`, `put`, `delete` — plus `with_options(timeout=..., max_retries=...,
max_response_bytes=...)` for per-call-site overrides on a shared connection pool.

## `client.search`

Search the Vulners database.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `query(query: str, *, limit: int = 20, offset: int = 0, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `SearchPage[Bulletin]` | `POST /api/v3/search/lucene/` | Search using Lucene query syntax |
| `iter_query(query: str, *, page_size: int = 100, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Iterator[Bulletin]` | `POST /api/v3/search/lucene/` | Iterate every matching :class:`Bulletin`, auto-paginating |
| `get_multiple_bulletins(ids: Sequence[str], *, fields: Sequence[str] \| NotGiven = NOT_GIVEN, references: bool = False)` | `dict[str, Bulletin]` | `POST /api/v3/search/id/` | Fetch several documents by id, keyed by id |
| `get_bulletin(id: str, *, fields: Sequence[str] \| NotGiven = NOT_GIVEN)` | `Bulletin \| None` | `POST /api/v3/search/id/` | Fetch a single document by id, or ``None`` if it does not exist |
| `exploits(query: str, *, lucene: bool = False, limit: int = 20, offset: int = 0, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `SearchPage[Bulletin]` | `POST /api/v3/search/lucene/` | Search for public exploits matching a query |
| `collections(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/search/collections` | List every collection available in Vulners |
| `autocomplete(query: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[str \| list[str]]` | - | Return possible completions for a partial Lucene query |
| `suggest(field_name: str, *, type: Literal['distinct'] = 'distinct', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | - | Return distinct value suggestions for a document field |
| `cpe(product: str, *, vendor: str \| NotGiven = NOT_GIVEN, size: int \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | - | Search for CPE strings matching a product (and optional vendor) |
| `web_vulns(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | - | Return the Vulners web-application (burp) detection rule set |

## `client.documents`

Fetch Vulners documents (bulletins) by id.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `get(id: str, *, references: bool = False, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Bulletin \| None` | - | Fetch a single document by id, or ``None`` if it does not exist |
| `get_many(ids: Sequence[str], *, references: bool = False, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Bulletin]` | - | Fetch several documents by id, keyed by id |
| `references(id: str, *, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, list[Bulletin]]` | - | Fetch the documents a bulletin references, grouped by source type |
| `history(id: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[dict[str, Any]]` | - | Read the per-field edition history of a bulletin |

## `client.audit`

Audit software inventories and identifiers against Vulners intelligence.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `supported_os(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, str]` | `GET /api/v3/audit/getSupportedOS/` | List the operating systems accepted by the Linux-package audits |
| `software(software: Sequence[AuditItem \| str], *, match: Literal['partial', 'full'] = 'partial', fields: Sequence[str] \| NotGiven = NOT_GIVEN, config: Sequence[str] \| NotGiven = NOT_GIVEN, catalog: Literal['official', 'extended'] = 'official', cvelist_metrics: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[dict[str, Any]]` | `POST /api/v4/audit/software/` | Audit a list of software (CPE dicts or strings) for vulnerabilities |
| `host(software: Sequence[AuditItem \| str], *, application: AuditItem \| str \| NotGiven = NOT_GIVEN, operating_system: AuditItem \| str \| NotGiven = NOT_GIVEN, hardware: AuditItem \| str \| NotGiven = NOT_GIVEN, match: Literal['partial', 'full'] = 'partial', fields: Sequence[str] \| NotGiven = NOT_GIVEN, config: Sequence[str] \| NotGiven = NOT_GIVEN, catalog: Literal['official', 'extended'] = 'official', cvelist_metrics: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[dict[str, Any]]` | `POST /api/v4/audit/host/` | Audit a whole host: its software plus optional application, OS and hardware CPEs |
| `os_audit(os: str, version: str, packages: Sequence[str], *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v3/audit/audit/` | Audit an OS package list (legacy v3 endpoint; prefer :meth:`linux_audit`) |
| `linux_audit(os_name: str, os_version: str, packages: Sequence[str], *, os_arch: str \| None = None, include_unofficial: bool = False, include_candidates: bool = False, include_any_version: bool = False, cvelist_metrics: bool = False, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v4/audit/linux` | Audit RPM/DEB/APK package lists for a Linux host |
| `library_audit(packages: Sequence[str], *, include_unofficial: bool = False, include_candidates: bool = False, include_any_version: bool = False, cvelist_metrics: bool = False, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v4/audit/library` | Audit a list of packages in PURL format |
| `sbom_audit(file: str \| os.PathLike[str], *, cvelist_metrics: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v4/audit/sbom` | Audit an SBOM file (SPDX or CycloneDX) for vulnerabilities |
| `cve_audit(cve: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v4/audit/cve` | Audit a single CVE identifier |
| `cve_batch_audit(cve: Sequence[str], *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[dict[str, Any]]` | `POST /api/v4/audit/cves` | Audit a batch of CVE identifiers |
| `kb_audit(os_name: str, kb_list: Sequence[str], *, os_version: str \| NotGiven = NOT_GIVEN, fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v4/audit/kb` | Audit a Windows host for missing security updates (``/api/v4/audit/kb``) |
| `kb_audit_v3(os: str, kb_list: Sequence[str], *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v3/audit/kb/` | Audit a Windows host by its installed KBs (deprecated v3 endpoint) |
| `win_audit(os: str, os_version: str, kb_list: Sequence[str], software: Sequence[WinAuditItem], *, platform: str \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | `POST /api/v3/audit/winaudit/` | Audit a Windows host by installed KBs and software |
| `smart(software: Sequence[str], *, catalog: Literal['official', 'extended'] = 'official', fields: Sequence[str] \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[dict[str, Any]]` | `POST /api/v4/audit/smart` | Resolve free-form software strings to CPE/PURLs and their vulnerabilities |
| `metadata(registry: str, name: str, version: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `PackageMetadata` | `POST /api/v4/audit/metadata` | Look up a single package's license and version-range metadata |

## `client.audit.packages`

Audit raw package-manager manifests (``client.audit.packages``).

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `maven(file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit ``mvn dependency:list`` output |
| `pip(file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit ``pip freeze`` output; arguments as in :meth:`maven` |
| `poetry(file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit a ``poetry.lock`` file; arguments as in :meth:`maven` |
| `uv(file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit a ``uv.lock`` file; arguments as in :meth:`maven` |
| `npm(file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit a ``package-lock.json`` file; arguments as in :meth:`maven` |
| `golang(file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit ``go list -m all`` output; arguments as in :meth:`maven` |
| `scan(ecosystem: PackageEcosystem, file: str \| os.PathLike[str] \| IO[bytes] \| IO[str] \| bytes, *, include_any_version: bool \| NotGiven = NOT_GIVEN, include_candidates: bool \| NotGiven = NOT_GIVEN, include_unofficial: bool \| NotGiven = NOT_GIVEN, include_transitives: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `dict[str, Any]` | - | Audit a manifest for the given ``ecosystem``; arguments as in :meth:`maven` |

## `client.archive`

Download bulk archives of the Vulners database.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `fetch_collection(type: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/archive/collection` | Download an entire collection archive by ``type`` (e.g. ``"cve"``) |
| `iter_collection(type: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Iterator[dict[str, Any]]` | `GET /api/v4/archive/collection` | Stream a collection archive element by element (a JSON array) |
| `download_collection(collection: str, path: str \| os.PathLike[str], *, update_from: datetime \| None = None, connections: int = 8, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `int` | - | Download a collection archive to ``path``, in parallel; return bytes written |
| `fetch_collection_update(type: str, after: datetime, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/archive/collection-update` | Download only the collection entries changed after ``after`` |
| `collection_state(type: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/archive/collection-state` | Read the sync cursor and counters for a collection |
| `family(name: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/archive/family` | Download an entire collection-family archive by ``name`` |
| `family_update(name: str, after: datetime, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/archive/family-update` | Download only the family entries changed after ``after`` (max 25h ago) |
| `family_state(name: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/archive/family-state` | Read the sync cursor and counters for a collection family |
| `iter_family(name: str, *, update_from: datetime \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Iterator[dict[str, Any]]` | - | Stream a family archive element by element, like :meth:`iter_collection` |
| `get_collection(type: str, *, datefrom: str = '1976-01-01', dateto: str = '2199-01-01', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/archive/collection/` | Download a collection over a date range (legacy v3 endpoint) |
| `get_distributive(os: str, version: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[Any]` | `GET /api/v3/archive/distributive/` | Download the vulnerability distributive for an OS/version (legacy v3) |
| `getsploit(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `bytes` | `GET /api/v3/archive/getsploit/` | Download the raw getsploit exploit database archive (legacy v3) |
| `download_getsploit(path: str \| os.PathLike[str], *, connections: int = 8, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `int` | - | Stream the getsploit database archive to ``path``, in parallel; return bytes written |

## `client.misc`

Miscellaneous search and metadata helpers.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `search_cpe(product: str, *, vendor: str \| NotGiven = NOT_GIVEN, size: int \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/search/cpe` | Search for CPE strings matching a product (and optional vendor) |
| `query_autocomplete(query: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `list[str \| list[str]]` | `POST /api/v3/search/autocomplete/` | Return possible completions for a partial Lucene query |
| `get_suggestion(field_name: str, *, type: Literal['distinct'] = 'distinct', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/search/suggest/` | Return distinct value suggestions for a document field |
| `get_web_application_rules(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/burp/rules/` | Return the Vulners web-application (burp) detection rule set |

## `client.report`

Reports over Linux-audit results.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `vulns_summary(*, limit: int = 30, offset: int = 0, filter: dict[str, Any] \| None = None, sort: str = '', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/reports/vulnsreport` | Summarise every found vulnerability (id, title, score, severity...) |
| `vulns_list(*, limit: int = 30, offset: int = 0, filter: dict[str, Any] \| None = None, sort: str = '', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/reports/vulnsreport` | List vulnerabilities found on hosts, with host information |
| `ip_summary(*, limit: int = 30, offset: int = 0, filter: dict[str, Any] \| None = None, sort: str = '', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/reports/vulnsreport` | Summarise results per host (agent id, ip, fqdn, os, vulnerability counts) |
| `scan_list(*, limit: int = 30, offset: int = 0, filter: dict[str, Any] \| None = None, sort: str = '', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/reports/vulnsreport` | List scans (host ip/fqdn, os, scan date, cvss score) |
| `host_vulns(*, limit: int = 30, offset: int = 0, filter: dict[str, Any] \| None = None, sort: str = '', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/reports/vulnsreport` | List hosts with their cumulative fix and vulnerability ids |
| `vuln_info(ip_address: str, bulletin_id: str, *, limit: int = 30, offset: int = 0, filter: dict[str, Any] \| None = None, sort: str = '', timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/reports/vulnsreport` | Detail of one vulnerability on one host |

## `client.stix`

Build STIX bundles from Vulners bulletins.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `make_bundle_by_id(id: str, *, opencti_id: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/stix/bundle` | Build a STIX bundle of objects for a bulletin id |
| `bundle(id: str, *, opencti_id: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/stix/bundle` | Alias of :meth:`make_bundle_by_id` (the short primary name) |

## `client.subscriptions`

Manage v4 subscriptions.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/subscriptions/list/` | List every subscription on the account |
| `get_list(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/subscriptions/list/` | Alias of :meth:`list`, kept for the pre-release naming window |
| `get(id: str \| None = None, *, subscription_id: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v4/subscriptions/get/` | Fetch a single subscription by id |
| `create(*, name: str, query: SubscriptionQuery \| Mapping[str, Any], delivery: SubscriptionDelivery \| Mapping[str, Any], license_id: str \| None = None, bulletin_fields: Sequence[str] \| None = None, is_active: bool = True, timestamp_source: TimestampSource = 'modified', send_empty_result: bool = False, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v4/subscriptions/create/` | Create a subscription |
| `update(id: str, *, name: str \| NotGiven = NOT_GIVEN, query: SubscriptionQuery \| Mapping[str, Any] \| NotGiven = NOT_GIVEN, delivery: SubscriptionDelivery \| Mapping[str, Any] \| NotGiven = NOT_GIVEN, license_id: str \| NotGiven \| None = NOT_GIVEN, bulletin_fields: Sequence[str] \| NotGiven = NOT_GIVEN, is_active: bool \| NotGiven = NOT_GIVEN, timestamp_source: TimestampSource \| NotGiven = NOT_GIVEN, send_empty_result: bool \| NotGiven = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `PUT /api/v4/subscriptions/update/` | Update a subscription |
| `delete(id: str, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `DELETE /api/v4/subscriptions/delete/` | Delete a subscription by id |

## `client.subscriptions_email`

Manage v3 email subscriptions.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/subscriptions/listEmailSubscriptions/` | List the email subscriptions registered under the client's API key |
| `add(*, query: str, email: str, format: Literal['html', 'json', 'pdf'] = 'html', crontab: str \| NotGiven = NOT_GIVEN, query_type: str = 'lucene', api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/addEmailSubscription/` | Create an email subscription for a query |
| `edit(subscription_id: str, *, format: Literal['html', 'json', 'pdf'] \| NotGiven = NOT_GIVEN, crontab: str \| NotGiven = NOT_GIVEN, active: Literal['yes', 'no', 'true', 'false'] \| NotGiven = NOT_GIVEN, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/editEmailSubscription/` | Edit an existing email subscription |
| `delete(subscription_id: str, *, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/removeEmailSubscription/` | Delete an email subscription |

## `client.webhooks`

Manage webhook subscriptions.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/subscriptions/listWebhookSubscriptions/` | List the account's webhook subscriptions |
| `add(query: str, *, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/addWebhookSubscription/` | Create a webhook subscription for a query |
| `create(query: str, *, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/addWebhookSubscription/` | Alias of :meth:`add` (the primary CRUD-style name) |
| `enable(id: str, active: bool, *, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/editWebhookSubscription/` | Enable or disable a webhook subscription |
| `set_enabled(id: str, active: bool, *, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/editWebhookSubscription/` | Alias of :meth:`enable` (the explicit setter-style name) |
| `read(id: str, *, newest_only: bool = True, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/subscriptions/webhook` | Read pending webhook payloads for a subscription |
| `delete(id: str, *, api_key: str \| None = None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/subscriptions/removeWebhookSubscription/` | Delete a webhook subscription |

## `client.vscanner`

VScanner product namespace on the client.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `notification(period: Literal['disabled', 'asap', 'hourly', 'daily'], emails: Sequence[str] \| None = None, slack_webhooks: Sequence[str] \| None = None)` | `dict[str, Any]` | - | Build a notification object for a project |
| `disabled_notification()` | `dict[str, Any]` | - | Build a notification object with delivery turned off |

## `client.vscanner.licenses`

VScanner license ids.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(*, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/useraction/licenseids` | List the account's VScanner license ids |

## `client.vscanner.projects`

VScanner projects, plus their tasks and results namespaces.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(*, offset: int = 0, limit: int = 50, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/proxy/vscanner/v2/projects/` | List the account's VScanner projects |
| `create(*, name: str, license_id: uuid.UUID, notification: Mapping[str, Any], result_expire_in: int \| NotGiven \| None = NOT_GIVEN, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/proxy/vscanner/v2/projects/` | Create a project |
| `update(project_id: uuid.UUID, *, name: str, license_id: uuid.UUID, notification: Mapping[str, Any], result_expire_in: int \| None, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `PUT /api/v3/proxy/vscanner/v2/projects/{project_id}` | Replace a project's configuration in full |
| `delete(project_id: uuid.UUID, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `DELETE /api/v3/proxy/vscanner/v2/projects/{project_id}` | Delete a project and its scan data |
| `statistics(project_id: uuid.UUID, *, stat: Sequence[Literal['total_hosts', 'vulnerable_hosts', 'unique_cve', 'min_max_cvss', 'vulnerabilities_rank', 'vulnerable_hosts_rank']], timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/proxy/vscanner/v2/projects/{project_id}/statistic` | Return project statistics for the requested aggregations |

## `client.vscanner.projects.tasks`

Scan tasks within a VScanner project.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(project_id: uuid.UUID, *, offset: int = 0, limit: int = 50, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/proxy/vscanner/v2/projects/{project_id}/tasks` | List the scan tasks defined in a project |
| `create(project_id: uuid.UUID, *, name: str, networks: Sequence[str], ports: Sequence[str], schedule: str, timing: str, enabled: bool, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/proxy/vscanner/v2/projects/{project_id}/tasks` | Create a scan task in a project |
| `update(project_id: uuid.UUID, task_id: uuid.UUID, *, name: str, networks: Sequence[str], ports: Sequence[str], schedule: str, timing: str, enabled: bool, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `PUT /api/v3/proxy/vscanner/v2/projects/{project_id}/tasks/{task_id}` | Replace a scan task's configuration in full |
| `start(project_id: uuid.UUID, task_id: uuid.UUID, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `POST /api/v3/proxy/vscanner/v2/projects/{project_id}/tasks/{task_id}/start` | Queue a task to run as soon as possible, ignoring its schedule |
| `delete(project_id: uuid.UUID, task_id: uuid.UUID, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `DELETE /api/v3/proxy/vscanner/v2/projects/{project_id}/tasks/{task_id}` | Delete a scan task from a project |

## `client.vscanner.projects.results`

Scan results and screenshots within a VScanner project.

| Method | Returns | HTTP route | Summary |
|---|---|---|---|
| `list(project_id: uuid.UUID, *, search: str \| NotGiven = NOT_GIVEN, in_port: Sequence[str] \| NotGiven = NOT_GIVEN, ex_port: Sequence[str] \| NotGiven = NOT_GIVEN, min_cvss: float \| NotGiven = NOT_GIVEN, max_cvss: float \| NotGiven = NOT_GIVEN, last_seen: int \| NotGiven = NOT_GIVEN, first_seen: int \| NotGiven = NOT_GIVEN, last_seen_port: int \| NotGiven = NOT_GIVEN, first_seen_port: int \| NotGiven = NOT_GIVEN, sort: Literal['ip', 'name', 'last_seen', 'first_seen', 'resolved', 'min_cvss', 'max_cvss'] = 'last_seen', sort_dir: Literal['asc', 'desc'] = 'asc', offset: int = 0, limit: int = 50, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `GET /api/v3/proxy/vscanner/v2/projects/{project_id}/results` | List a project's scan results, with optional filtering and sorting |
| `delete(project_id: uuid.UUID, result_id: uuid.UUID, *, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `Any` | `DELETE /api/v3/proxy/vscanner/v2/projects/{project_id}/results/{result_id}` | Delete a single scan result from a project |
| `screenshot(image_uri: str, *, as_base64: bool = False, timeout: float \| httpx.Timeout \| NotGiven = NOT_GIVEN)` | `bytes` | `GET /vscanner/screen/{image_uri}` | Download a result screenshot as bytes |
