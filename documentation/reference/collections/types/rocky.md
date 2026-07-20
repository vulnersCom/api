# `rocky`  ·  ~9.4k documents

Rocky Linux vulnerability collection from the Rocky Linux project includes advisories and CVEs related to Rocky Linux OS security.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "hplip", "versio…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Rocky Linux", "OSVersion": "9", "arc…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-14544"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert@redhat.com",…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@python.org", "vers…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An update is available for hplip.\nThis upda…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 40% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14544", "date": "2026-07-1…` |
| `fixes` | `list[str]` | 100% | Fix references (fixed versions / patches). | `["https://bugzilla.redhat.com/show_bug.cgi?id…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://errata.rockylinux.org/RLSA-2026:40831"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RLSA-2026:40831"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T14:37:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T12:03:25"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T12:03:25"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Rockylinux Product Errata"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T14:37:04.872000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"hplip security update"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rocky"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rocky/RLSA-2026:40831"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

