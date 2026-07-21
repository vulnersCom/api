# `opensuse`  ·  ~8k documents

OpenSUSE vulnerability collection includes advisories and CVEs related to OpenSUSE OS and its packages, sourced from the OpenSUSE security team.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENSUSE-SU-2026:11309-1"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T15:38:01"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T15:38:01.847000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"chromedriver-150.0.7871.128-1.1 on GA media …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"opensuse"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/opensuse/OPENSUSE-SU-202…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# chromedriver-150.0.7871.128-1.1 on GA medi…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 2.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OpenSuse"` |

### Collection fields

Specific to the `opensuse` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "opensuse backports", "OSVersion": "1…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15899", "CVE-2026-15900", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "opensuse", "version":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "opensuse", "version": …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50163", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://lists.opensuse.org/archives/list/sec…` |
| `metrics` | `object{adp,cna}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "opensuse", …` |
| `references` | `list[str]` | External reference URLs. | `["#1271656"]` |

