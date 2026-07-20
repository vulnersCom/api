# `cgr`  ·  ~17k documents

CGR (Common Vulnerability Reporting) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 30% | Related CVE identifiers referenced by this document. | `["CVE-2026-56742"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.9, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 30% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Vulnerabilities for packages: kubescape, kub…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.1, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56742", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packages.cgr.dev/chainguard/security…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CHAINGUARD:CVE-2026-56742"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:25:08"` |
| `metrics` | `object{adp,cna,nvd}` | 30% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:25:08"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T20:25:13"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Chainguard"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T20:25:13.349000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-56742 vulnerabilities"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cgr"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cgr/CHAINGUARD:CVE-2026-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

