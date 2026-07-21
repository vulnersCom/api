# `almalinux`  ·  ~5.4k documents

AlmaLinux vulnerability collection includes advisories and CVEs specific to AlmaLinux OS, sourced from official security bulletins.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALSA-2026:40895"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T17:40:20"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T08:24:14"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T17:40:20.909000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Important: jackson-annotations, jackson-core…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"almalinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/almalinux/ALSA-2026:40895"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The general-purpose data-binding functionali…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"AlmaLinux"` |

### Collection fields

Specific to the `almalinux` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "almalinux", "OSVersion": "9", "arch"…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-54512", "CVE-2026-54513"]` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "hp-security-alert@hp.c…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-8177", "date": "2026-07-17…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://errata.almalinux.org/9/ALSA-2026-408…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `references` | `list[str]` | External reference URLs. | `["https://access.redhat.com/errata/RHSA-2026:…` |

