# `taosecurity`  ·  ~110 documents

TaoSecurity provides advisories and CVEs focused on security vulnerabilities in various software products and operating systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TAOSECURITY:F514823959D5726EAA22AC1802A8D33F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T03:36:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T01:47:42"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T01:43:42"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T03:36:50.687000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"FreeBSD Released the Most Security Advisorie…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"taosecurity"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/taosecurity/TAOSECURITY:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://taosecurity.blogspot.com/2026/07/fre…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Richard Bejtlich (noreply@blogger.com)"` |

### Collection fields

Specific to the `taosecurity` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-44228"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"On average, the FreeBSD security team releas…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-44228", "date": "2026-06-1…` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |

