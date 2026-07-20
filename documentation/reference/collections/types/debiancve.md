# `debiancve`  ·  ~60k documents

Debian Vulnerability Database (Debian VDE) provides security advisories and CVEs for Debian OS packages and related software vulnerabilities.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding}], list[object{distro,name,purl,registry,versionEndIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"name": "imagemagick", "versionEndExcluding…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Debian", "OSVersion": "14", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-61870"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 2.9, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 85% | CVSS v3.x score block. | `{"cvssV31": {"source": "disclosure@vulncheck.…` |
| `cvss4` | `object{cvssV4}` | 50% | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"ImageMagick before 7.1.2-26 contains a memor…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-61870", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security-tracker.debian.org/tracker/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DEBIANCVE:CVE-2026-61870"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-12T07:37:40"` |
| `metrics` | `object{adp,cna}, object{cna,nvd}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "disclosure@vuln…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-11T13:01:09"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-11T13:01:09"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Debian Security Bug Tracker"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-11T23:37:52.353000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-61870"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"debiancve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/debiancve/DEBIANCVE:CVE-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

