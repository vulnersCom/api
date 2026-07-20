# `redhat`  ·  ~120k documents

Red Hat's vulnerability database provides advisories and CVEs related to Red Hat products and Linux distributions, focusing on security updates and patches.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 80% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "dovecot", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 80% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Red Hat Enterprise Linux", "OSVersio…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42006"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 95% | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `cwe` | `list[str]` | 75% | Associated CWE weakness identifiers. | `["CWE-770"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An update for dovecot is now available for R…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://access.redhat.com/errata/RHSA-2026:4…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHSA-2026:41905"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T06:25:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}, object{nvd}` | 95% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:34:24"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:33:50"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://access.redhat.com/security/updates/…` |
| `relatesTo` | `str` | 80% | Identifier this document relates to. | `"RHSA-2026:41905"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"RedHat"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T06:25:50.259000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important: Red Hat Security Advisory: doveco…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhat"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/redhat/RHSA-2026:41905"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

