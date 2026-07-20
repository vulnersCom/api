# `gentoo`  ·  ~3.8k documents

Gentoo collection includes vulnerability advisories and CVEs specific to Gentoo Linux packages and systems.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Gentoo", "OSVersion": "any", "arch":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2026-33150", "CVE-2026-33179"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 15% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 90% | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories",…` |
| `cvss4` | `object{cvssV4}` | 20% | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Background\n\nFUSE (Filesystem in Usersp…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33150", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.gentoo.org/glsa/202604-03"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GLSA-202604-03"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T05:36:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 90% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gentoo Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-17T20:05:58.799000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"FUSE: Multiple Vulnerabilities"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gentoo"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gentoo/GLSA-202604-03"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

