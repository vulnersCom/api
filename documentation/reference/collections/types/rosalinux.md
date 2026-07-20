# `rosalinux`  ·  ~1.4k documents

Rosalinux collection includes security advisories and CVEs specific to the Rosalyn Linux OS, sourced from the official Rosalyn security team.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 90% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ROSA", "OSVersion": "any", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-34743"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 35% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Component: xz 5.2.9  \nOS: ROSA-CHROME  \nUn…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-34743", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://abf.rosa.ru/advisories/ROSA-SA-2026-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ROSA-SA-2026-3313"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-01T19:20:42"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-01T12:39:24"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-01T12:39:24"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ROSA LAB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-01T19:20:44.006000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Advisory ROSA-SA-2026-3313"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rosalinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rosalinux/ROSA-SA-2026-3…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

