# `mageia`  ·  ~6k documents

Mageia security advisories provide information on vulnerabilities affecting Mageia Linux, including CVEs and patches for various software packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,version}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "erlang", "versi…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Mageia", "OSVersion": "10", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2026-48855"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 90% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The updated packages fix a security vulnerab…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://advisories.mageia.org/MGASA-2026-027…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MGASA-2026-0270"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T07:40:10"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 90% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T06:29:09"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T06:29:10"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bugs.mageia.org/show_bug.cgi?id=358…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gentoo Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T07:40:10.516000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Updated erlang packages fix a security vulne…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mageia"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mageia/MGASA-2026-0270"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

