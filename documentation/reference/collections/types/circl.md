# `circl`  ·  ~180k documents

CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CIRCL:CVE-2026-54300"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:54:09"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T04:31:23"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T04:31:23"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:54:09.757000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-54300"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"circl"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/circl/CIRCL:CVE-2026-54300"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `1` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.3, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies,short_description,tags}, object{score,short_description,tags}, object{short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-54300 observe…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Circl"` |

### Collection fields

Specific to the `circl` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-54300"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"creation_timestamp\| type\| source  \n---\|---\|…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://cve.circl.lu/api/sighting"` |
| `items` | `list[object{content,creation_timestamp,source,type,uuid,vulnerability_lookup_origin}]` | Sub-items/entries contained in the document. | `[{"uuid": "feaaf757-a4e7-4184-8ee5-b9fa89c4a8…` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `references` | `list[str]` | External reference URLs. | `["https://gist.github.com/alon710/108624152e6…` |
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `false` |

