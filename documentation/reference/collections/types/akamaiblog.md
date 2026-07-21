# `akamaiblog`  ·  ~2.4k documents

Akamai Blog provides security advisories and insights related to Akamai's products and services, focusing on web security and performance.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-48282"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@adobe.com", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Discover why traditional security fails agai…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48282", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.akamai.com/blog/security/2026/ju…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKAMAIBLOG:7103E27A864DCBEAFE161C3413006BC9"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:36:50"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@adobe.co…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T06:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T06:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Guy Amit"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:36:50.421000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"From Recon to Free Flights: Precision Prompt…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"akamaiblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/akamaiblog/AKAMAIBLOG:71…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `akamaiblog` collection.

_None in the sample._

