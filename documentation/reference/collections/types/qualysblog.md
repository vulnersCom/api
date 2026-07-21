# `qualysblog`  ·  ~1.1k documents

Qualys Blog provides vendor-specific security advisories and insights, focusing on vulnerabilities, CVEs, and best practices for various products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42982", "CVE-2026-48561", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Microsoft's July 2026 Patch Tuesday delivers…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.5, "uncertanity": 2.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42982", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blog.qualys.com/category/vulnerabili…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"QUALYSBLOG:0DF34A114C8559DDD2ED23540B410CA0"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T21:36:51"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T21:23:09"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T21:23:09"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Diksha Ojha"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:36:51.845000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Microsoft and Adobe Patch Tuesday,\u00a0July…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"qualysblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/qualysblog/QUALYSBLOG:0D…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `16` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `qualysblog` collection.

_None in the sample._

