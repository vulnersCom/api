# `opera`  ·  ~390 documents

Opera collection includes vulnerability advisories and CVEs related to the Opera web browser, focusing on browser security issues and exploits.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 25% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11645"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "chrome-cve-admin", "v…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"News, Security\n\n# Security fix: Addressing…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11645", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blogs.opera.com/security/2026/07/sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPERA-BLOG-2026-07-SECURITY-FIX-GX-MODS-VULN…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-03T17:43:35"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-03T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-03T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://blogs.opera.com/security/2026/07/se…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://security.opera.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T17:43:35.186000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security fix: Addressing a GX mods vulnerabi…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"opera"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/opera/OPERA-BLOG-2026-07…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

