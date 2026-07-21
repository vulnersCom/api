# `fedora`  ·  ~34k documents

Fedora collection includes security advisories, CVEs, and patches for vulnerabilities affecting Fedora OS and its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FEDORA:0D89A7F645"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T07:39:30"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T05:48:22"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-19T05:48:22"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T07:39:30.881000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"[SECURITY] Fedora 44 Update: openssh-10.2p1-…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fedora"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/fedora/FEDORA:0D89A7F645"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.4, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"SSH (Secure SHell) is a program for logging …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Fedora"` |

### Collection fields

Specific to the `fedora` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "openssh", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Fedora Linux", "OSVersion": "44", "a…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-59996", "CVE-2026-60002"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@vuldb.com", "versi…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://lists.fedoraproject.org/archives/lis…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

