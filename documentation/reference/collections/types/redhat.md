# `redhat`  ·  ~120k documents

Red Hat's vulnerability database provides advisories and CVEs related to Red Hat products and Linux distributions, focusing on security updates and patches.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHSA-2026:42122-CVE-2026-14474"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T03:25:45"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T02:34:41"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T22:55:43"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T01:26:15.340000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"sssd: sssd: sudo LDAP provider searches enti…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhat"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/redhat/RHSA-2026:42122-C…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A flaw was found in SSSD's LDAP sudo provide…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 2.5, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"RedHat"` |

### Collection fields

Specific to the `redhat` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "libipa_hbac", "…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Red Hat Enterprise Linux", "OSVersio…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-14474"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert@redhat.com",…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-1188"]` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://access.redhat.com/errata/RHSA-2026:4…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `references` | `list[str]` | External reference URLs. | `["https://access.redhat.com/security/cve/CVE-…` |
| `relatesTo` | `str` | Identifier this document relates to. | `"RHSA-2026:42122"` |

