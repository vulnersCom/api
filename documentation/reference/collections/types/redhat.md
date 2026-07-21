# `redhat`  ·  ~120k documents

Red Hat's vulnerability database provides advisories and CVEs related to Red Hat products and Linux distributions, focusing on security updates and patches.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42006"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An update for dovecot is now available for R…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://access.redhat.com/errata/RHSA-2026:4…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHSA-2026:41905"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T06:25:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:34:24"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T05:33:50"` |
| `references` | `list[str]` | External reference URLs. | `["https://access.redhat.com/security/updates/…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"RedHat"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T06:25:50.259000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Important: Red Hat Security Advisory: doveco…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhat"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/redhat/RHSA-2026:41905"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "dovecot", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Red Hat Enterprise Linux", "OSVersio…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-770"]` |

### Collection fields

Specific to the `redhat` collection.

| field | type | description | example |
|---|---|---|---|
| `relatesTo` | `str` | Identifier this document relates to. | `"RHSA-2026:41905"` |

