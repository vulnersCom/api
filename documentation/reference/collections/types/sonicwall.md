# `sonicwall`  ·  ~200 documents

SonicWall collection includes advisories and CVEs related to SonicWall products and services, sourced from their security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2026-15409", "CVE-2026-15410"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 10.0, "vector": "…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 95% | CVSS v3.x score block. | `{"cvssV3": {"source": "NONE", "version": "3.0…` |
| `cwe` | `list[str]` | 95% | Associated CWE weakness identifiers. | `["CWE-918", "CWE-94"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"<p> </p><p><span style=\"font-size: 11pt; co…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15409", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://psirt.global.sonicwall.com/vuln-deta…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SONICWALL:SNWLID-2026-0008"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:48:32"` |
| `metrics` | `object{vendor}` | 95% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T14:43:22"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T14:43:22"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SonicWall"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:48:32.327000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SonicWall SMA1000 Series Appliances Affected…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sonicwall"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sonicwall/SONICWALL:SNWL…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

