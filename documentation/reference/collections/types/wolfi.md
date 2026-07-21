# `wolfi`  ·  ~12k documents

Wolfi is a vulnerability collection from the Wolfi project, focusing on Linux OS packages, typically containing advisories and CVEs.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WOLFI:CVE-2026-56742"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T02:16:26"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T02:16:26"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T20:24:31"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T20:24:31.654000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-56742 vulnerabilities"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wolfi"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wolfi/WOLFI:CVE-2026-56742"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.9, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Vulnerabilities for packages: hubble-ui, kub…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.1, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Wolfi"` |

### Collection fields

Specific to the `wolfi` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-56742"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56742", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packages.wolfi.dev/os/security.json"` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

