# `prion`  ·  ~210k documents

Prion collection includes advisories and CVEs related to vulnerabilities in software products from various vendors, focusing on security issues and exploits.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PRION:CVE-2024-56067"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-01-29T19:14:25"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-12-31T13:15:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-12-31T13:15:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-12-31T10:15:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2024-56067"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"prion"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/prion/PRION:CVE-2024-56067"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `18` |

### Family fields

Present in every sampled `cve`-family document (typed by [`CveBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-56067"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Missing Authorization vulnerability in Azzar…` |
| `enchantments` | `object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Missing Authorization …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"PRIOn knowledge base"` |

### Collection fields

Specific to the `prion` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-862"]` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-56067", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.prio-n.com/kb/vulnerability/CVE-…` |
| `references` | `list[str]` | External reference URLs. | `["https://patchstack.com/database/wordpress/p…` |

