# `rapid7community`  ·  ~140 documents

Rapid7 Community provides vulnerability advisories and CVEs focused on various software products and platforms, sourced from community contributions.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 30% | Related CVE identifiers referenced by this document. | `["CVE-2017-7442", "CVE-2017-8464"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"To many, emails are boring. It&#x27;s been a…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 30% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2017-7442", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://community.rapid7.com/community/rapid…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RAPID7COMMUNITY:2B17DEA73DC543DE4E26A8BC5E2B…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-08-25T16:08:08"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-08-25T16:02:15"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-08-25T16:02:15"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Naveen Bibinagar"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-08-25T13:02:15Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Gone Phishing: A Case Study on Conducting In…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rapid7community"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rapid7community/RAPID7CO…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `173` |

