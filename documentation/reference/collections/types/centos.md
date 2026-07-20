# `centos`  ·  ~3.7k documents

CentOS vulnerability collection includes advisories and CVEs specific to CentOS OS, sourced from official vendor bulletins.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "CentOS", "OSVersion": "7", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-5388", "CVE-2024-0743", "CVE-2024-…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**CentOS Errata and Security Advisory** CESA…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-5388", "date": "2026-06-19…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lists.centos.org/pipermail/centos-an…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CESA-2024:1498"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-16T14:22:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-04-03T14:01:39"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-04-03T14:01:39"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://twitter.com/centos", "http://steadf…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CentOS Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-04-03T11:01:39Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"thunderbird security update"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"centos"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/centos/CESA-2024:1498"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `167` |

