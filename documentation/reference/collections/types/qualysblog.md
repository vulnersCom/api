# `qualysblog`  ·  ~1.1k documents

Qualys Blog provides vendor-specific security advisories and insights, focusing on vulnerabilities, CVEs, and best practices for various products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"QUALYSBLOG:A80D96DEF684AE444DF70EA31401E15B"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T17:36:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T16:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T17:36:51.763000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Top Five Compliance Audit Software and Tools…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"qualysblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/qualysblog/QUALYSBLOG:A8…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 0.8, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blog.qualys.com/category/product-tech"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Farah Syed"` |

### Collection fields

Specific to the `qualysblog` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42982", "CVE-2026-48561", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"* * *\n\n#### Executive Summary\n\n  * Manua…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42982", "date": "2026-07-1…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |

