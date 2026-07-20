# `curl`  ·  ~210 documents

This collection from the curl project includes advisories and CVEs related to vulnerabilities in the curl command-line tool and library across various platforms.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "8.21.0", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `curlAffects` | `str` | 100% | Affected curl versions (curl advisories). | `"lib"` |
| `curlSeverity` | `str` | 100% | curl project's severity rating. | `"Medium"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11856"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cwe` | `list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-294"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Successfully using libcurl to do a transfer …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11856", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://curl.se/docs/CVE-2026-11856.html"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CURL:CVE-2026-11856"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T23:39:19"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T07:56:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-24T08:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://hackerone.com/reports/3793260"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"curl"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T11:47:29.481000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"cross-origin Digest auth state leak"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"curl"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/curl/CURL:CVE-2026-11856"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

