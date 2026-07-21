# `cloudlinux`  ·  ~530 documents

CloudLinux provides security advisories and CVEs specific to CloudLinux OS, focusing on vulnerabilities affecting Linux-based web hosting environments.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CLSA-2026:1783793047"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T19:36:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-12T19:19:05"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-12T19:19:05"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T19:36:53.399000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"glib2: Fix of 2 CVEs"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cloudlinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cloudlinux/CLSA-2026:178…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.2, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"- CVE-2026-58011: out-of-bounds read from an…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 2.0, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CloudLinux"` |

### Collection fields

Specific to the `cloudlinux` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Centos", "OSVersion": "6", "arch": "…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-58011", "CVE-2026-58013"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-10879", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://repo.cloudlinux.com/centos6-els/upda…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-5…` |

