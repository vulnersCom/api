# `ripstech`  ·  ~100 documents

Ripstech provides vulnerability data focused on web application security, including advisories and CVEs related to various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 10% | Related CVE identifiers referenced by this document. | `["CVE-2019-12598", "CVE-2019-12601"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"You can read the official announcement here.…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-12598", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.ripstech.com/2020/rips-acquired…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RIPSTECH:AB5B8CF1930B43298FDB86523D84A28C"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-05-13T14:04:55"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-05-13T07:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-05-13T07:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"RIPS Technologies Blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-05-13T04:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"RIPS and SonarSource are Joining Forces"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ripstech"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ripstech/RIPSTECH:AB5B8C…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `33` |

