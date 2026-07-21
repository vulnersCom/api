# `tomcat`  ·  ~350 documents

This collection includes advisories and CVEs related to Apache Tomcat vulnerabilities, sourced from official Apache security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-59083", "CVE-2026-59084"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Low: EncryptInterceptor requirements not c…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-59083", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://tomcat.apache.org/security-11.html#F…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TOMCAT:39AFF92DA5E3C3CEA2CBAF71C8495582"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T15:11:38"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Apache Tomcat"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T15:11:39.213000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Fixed in Apache Tomcat 11.0.24"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tomcat"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/tomcat/TOMCAT:39AFF92DA5…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "ge", "version": "11.0.0-M1", "…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `tomcat` collection.

_None in the sample._

