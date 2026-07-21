# `rapid7community`  ·  ~140 documents

Rapid7 Community provides vulnerability advisories and CVEs focused on various software products and platforms, sourced from community contributions.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RAPID7COMMUNITY:2B17DEA73DC543DE4E26A8BC5E2B…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-08-25T16:08:08"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2017-08-25T16:02:15"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2017-08-25T16:02:15"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-08-25T13:02:15Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Gone Phishing: A Case Study on Conducting In…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rapid7community"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rapid7community/RAPID7CO…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `173` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://community.rapid7.com/community/rapid…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Naveen Bibinagar"` |

### Collection fields

Specific to the `rapid7community` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2017-7442", "CVE-2017-8464"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"To many, emails are boring. It&#x27;s been a…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2017-7442", "date": "2026-06-16…` |

