# `kaspersky`  ·  ~4k documents

Kaspersky's collection includes security advisories and CVEs related to their antivirus products and software vulnerabilities.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15899", "CVE-2026-15900", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Multiple vulnerabilities were found in Googl…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47295", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://threats.kaspersky.com/en/vulnerabili…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KLA91155"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:02"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://chromereleases.googleblog.com/2026/…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Kaspersky Lab"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:37:02.711000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"KLA91155 Multiple vulnerabilities in Google …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kaspersky"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/kaspersky/KLA91155"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `19` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `kaspersky` collection.

_None in the sample._

