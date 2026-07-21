# `curl`  ·  ~210 documents

This collection from the curl project includes advisories and CVEs related to vulnerabilities in the curl command-line tool and library across various platforms.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-11856"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Successfully using libcurl to do a transfer …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11856", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://curl.se/docs/CVE-2026-11856.html"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CURL:CVE-2026-11856"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T23:39:19"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T07:56:56"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-24T08:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://hackerone.com/reports/3793260"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"curl"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T11:47:29.481000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"cross-origin Digest auth state leak"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"curl"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/curl/CURL:CVE-2026-11856"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "8.21.0", "operator": "lt", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-294"]` |

### Collection fields

Specific to the `curl` collection.

| field | type | description | example |
|---|---|---|---|
| `curlAffects` | `str` | Affected curl versions (curl advisories). | `"lib"` |
| `curlSeverity` | `str` | curl project's severity rating. | `"Medium"` |

