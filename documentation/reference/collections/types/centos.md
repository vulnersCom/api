# `centos`  ·  ~3.7k documents

CentOS vulnerability collection includes advisories and CVEs specific to CentOS OS, sourced from official vendor bulletins.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CESA-2024:1498"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-16T14:22:27"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-04-03T14:01:39"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-04-03T14:01:39"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-04-03T11:01:39Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"thunderbird security update"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"centos"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/centos/CESA-2024:1498"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `168` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**CentOS Errata and Security Advisory** CESA…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CentOS Project"` |

### Collection fields

Specific to the `centos` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "CentOS", "OSVersion": "7", "arch": "…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-5388", "CVE-2024-0743", "CVE-2024-…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-5388", "date": "2026-06-19…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://lists.centos.org/pipermail/centos-an…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `references` | `list[str]` | External reference URLs. | `["https://twitter.com/centos", "http://steadf…` |

