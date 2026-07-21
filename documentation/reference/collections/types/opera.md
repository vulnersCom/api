# `opera`  ·  ~390 documents

Opera collection includes vulnerability advisories and CVEs related to the Opera web browser, focusing on browser security issues and exploits.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPERA-BLOG-2026-07-SECURITY-FIX-GX-MODS-VULN…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-03T17:43:35"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-03T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-03T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T17:43:35.186000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security fix: Addressing a GX mods vulnerabi…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"opera"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/opera/OPERA-BLOG-2026-07…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"https://security.opera.com"` |

### Collection fields

Specific to the `opera` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-11645"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "chrome-cve-admin", "v…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"News, Security\n\n# Security fix: Addressing…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11645", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blogs.opera.com/security/2026/07/sec…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `references` | `list[str]` | External reference URLs. | `["https://blogs.opera.com/security/2026/07/se…` |

