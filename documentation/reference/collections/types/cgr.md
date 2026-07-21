# `cgr`  ·  ~17k documents

CGR (Common Vulnerability Reporting) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-56742"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.9, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Vulnerabilities for packages: kubescape, kub…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.1, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56742", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packages.cgr.dev/chainguard/security…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CHAINGUARD:CVE-2026-56742"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:25:08"` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:25:08"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T20:25:13"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Chainguard"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T20:25:13.349000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-56742 vulnerabilities"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cgr"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cgr/CHAINGUARD:CVE-2026-…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |

### Collection fields

Specific to the `cgr` collection.

_None in the sample._

