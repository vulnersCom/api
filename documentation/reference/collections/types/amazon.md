# `amazon`  ·  ~8.9k documents

Amazon's vulnerability collection includes security advisories and CVEs related to AWS services and products, focusing on cloud security issues.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "bpftool", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Amazon Linux", "OSVersion": "2", "ar…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-43499"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 15% | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Issue Overview:**  \n\n\nIn the Linux kern…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 65% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-57635", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://alas.aws.amazon.com/AL2/ALAS2KERNEL-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALAS2KERNEL-5.15-2026-109"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T16:24:45"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-10T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Amazon"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-11T03:16:22.382000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important: kernel"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"amazon"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/amazon/ALAS2KERNEL-5.15-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

