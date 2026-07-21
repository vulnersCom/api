# `talosblog`  ·  ~2k documents

Talos Blog provides security advisories and insights from Cisco Talos, focusing on vulnerabilities across various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42982", "CVE-2026-48561", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![Begun, the Patch Wars have](https://storag…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42982", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blog.talosintelligence.com/begun-the…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TALOSBLOG:44007DB019F02AD1D5DB6CF9A85D8C92"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:00:50"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T18:00:50"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Joe Marshall"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:36:50.995000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Begun, the Patch Wars have"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"talosblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/talosblog/TALOSBLOG:4400…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `talosblog` collection.

_None in the sample._

