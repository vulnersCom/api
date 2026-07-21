# `ripstech`  ·  ~100 documents

Ripstech provides vulnerability data focused on web application security, including advisories and CVEs related to various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2019-12598", "CVE-2019-12601"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"You can read the official announcement here.…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-12598", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blog.ripstech.com/2020/rips-acquired…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RIPSTECH:AB5B8CF1930B43298FDB86523D84A28C"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-05-13T14:04:55"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-05-13T07:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-05-13T07:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"RIPS Technologies Blog"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-05-13T04:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"RIPS and SonarSource are Joining Forces"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ripstech"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ripstech/RIPSTECH:AB5B8C…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `33` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `ripstech` collection.

_None in the sample._

