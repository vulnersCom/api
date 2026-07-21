# `clickhouse`  ·  ~49 documents

ClickHouse vulnerability collection includes advisories and CVEs specific to ClickHouse database software, sourced from various security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CH:368F308CC07ABC00A34508EF33906155"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-12-10T06:40:01"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-01-05T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-01-05T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-21T02:21:32Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Fixed in ClickHouse v25.1.5.5, 2025-01-05\u2…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"clickhouse"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/clickhouse/CH:368F308CC0…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `30` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.9, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ClickHouse"` |

### Collection fields

Specific to the `clickhouse` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "v25.1.5.5", "operator": "lt", "…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-1385"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"When the library bridge feature is enabled, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-1385", "date": "2026-07-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://clickhouse.com/docs/en/whats-new/sec…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "nvd", "version"…` |

