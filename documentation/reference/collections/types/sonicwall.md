# `sonicwall`  ·  ~200 documents

SonicWall collection includes advisories and CVEs related to SonicWall products and services, sourced from their security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SONICWALL:SNWLID-2026-0008"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:48:32"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T14:43:22"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T14:43:22"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:48:32.327000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"SonicWall SMA1000 Series Appliances Affected…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sonicwall"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/sonicwall/SONICWALL:SNWL…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 10.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"SonicWall"` |

### Collection fields

Specific to the `sonicwall` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15409", "CVE-2026-15410"]` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "NONE", "version": "3.0…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-918", "CWE-94"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"<p> </p><p><span style=\"font-size: 11pt; co…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15409", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://psirt.global.sonicwall.com/vuln-deta…` |
| `metrics` | `object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |

