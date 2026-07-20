# `alpinelinux`  ·  ~13k documents

Alpine Linux vulnerability collection includes advisories and CVEs specific to Alpine Linux OS and its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndIncluding,versionStartIncluding}]` | 85% | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "libgit2", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 85% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Alpine Linux", "OSVersion": "any", "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53583"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 70% | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This candidate has been reserved by an organ…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"dependencies": {"references": [{"type": "cv…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 45% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14741", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.alpinelinux.org/vuln/CVE-20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALPINE:CVE-2026-53583"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:40:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp}` | 75% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"adp": {"ssvc": {"id": "CVE-2026-14741", "ro…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T17:35:53"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T17:35:53"` |
| `references` | `list[str]` | 50% | External reference URLs. | `["https://github.com/squid-cache/squid/commit…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Alpine Linux Development Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:40:00.517000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-53583"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"alpinelinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/alpinelinux/ALPINE:CVE-2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

