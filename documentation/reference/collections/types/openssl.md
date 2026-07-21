# `openssl`  ·  ~230 documents

OpenSSL collection includes advisories, CVEs, and security updates specifically related to the OpenSSL cryptographic library.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENSSL:CVE-2024-9143"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-12-03T21:52:11"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-10-16T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-10-16T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-10-15T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Vulnerability in OpenSSL - Low-level invalid…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openssl"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/openssl/OPENSSL:CVE-2024…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `94` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.8, "uncertanity": 1.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OpenSSL"` |

### Collection fields

Specific to the `openssl` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "3.3.3", "operator": "lt", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-9143"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"_Issue summary_ : Use of the low-level GF(2^…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-9143", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://openssl-library.org/news/secadv/2024…` |

