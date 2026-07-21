# `nextcloud`  ·  ~380 documents

Nextcloud vulnerability collection includes advisories and CVEs related to Nextcloud software, focusing on security issues for the Nextcloud platform.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GHSA-285V-P9X9-CJHJ"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-02T14:06:05"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-15T09:43:04"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-15T09:43:04"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-15T10:06:09.518000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Propfind requests for file comments allowed …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nextcloud"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nextcloud/GHSA-285V-P9X9…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `16` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.8, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Nextcloud"` |

### Collection fields

Specific to the `nextcloud` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "31.0.0", "operator": "lt", "nam…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-45810"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"None\n"` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-45810", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/nextcloud/security-adviso…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `references` | `list[str]` | External reference URLs. | `["https://hackerone.com/reports/3425534", "ht…` |

