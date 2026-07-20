# `kaspersky`  ·  ~4k documents

Kaspersky's collection includes security advisories and CVEs related to their antivirus products and software vulnerabilities.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2026-15899", "CVE-2026-15900", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 85% | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Multiple vulnerabilities were found in Googl…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 40% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47295", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://threats.kaspersky.com/en/vulnerabili…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KLA91155"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:02"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 85% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://chromereleases.googleblog.com/2026/…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Kaspersky Lab"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:37:02.711000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"KLA91155 Multiple vulnerabilities in Google …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kaspersky"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/kaspersky/KLA91155"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `19` |

