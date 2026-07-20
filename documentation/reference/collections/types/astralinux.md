# `astralinux`  ·  ~18k documents

Astral Linux collection includes security advisories and CVEs specific to the Astral Linux operating system.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"name": "linux-headers-6.1.166-1", "version…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Astra Linux", "OSVersion": "1.8", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-31419"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"In the Linux kernel, the following vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53362", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://wiki.astralinux.ru/astra-linux-se18-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASTRA:1159995680070894737113968011466307"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T04:48:36"` |
| `metrics` | `object{adp,cna,vendor}, object{adp,nvd,vendor}, object{adp}, object{cna,vendor}, object{nvd,vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-09T08:12:13"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-09T08:12:13"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://wiki.astralinux.ru/astra-linux-se18…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AstraLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T18:51:17.671000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Astra Linux \u2013 Vulnerability found in Li…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"astralinux"` |
| `vendorId` | `str` | 100% | Vendor's own identifier for the advisory, when provided. | `"OVAL:ASTRA:DEF:11599956800708947371139680114…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/astralinux/ASTRA:1159995…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

