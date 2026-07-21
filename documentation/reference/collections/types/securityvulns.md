# `securityvulns`  ·  ~47k documents

A collection of security vulnerabilities sourced from various vendors, covering advisories and CVEs across multiple products and operating systems.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITYVULNS:VULN:14754"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-31T11:10:03"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2015-11-02T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2015-11-02T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-11-01T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"audiofile memory corruption"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"securityvulns"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/securityvulns/SECURITYVU…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `173` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 3.1, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"BUGTRAQ"` |

### Collection fields

Specific to the `securityvulns` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "eq", "version": "0.3", "name":…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2015-7747"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Crash on audiofiles processing."` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2015-7747", "date": "2026-06-21…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://vulners.com/securityvulns/SECURITYVU…` |
| `references` | `list[str]` | External reference URLs. | `["https://vulners.com/securityvulns/securityv…` |

