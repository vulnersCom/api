# `redos`  ·  ~8.7k documents

Redos collection from various security databases focuses on vulnerabilities related to Regular Expression Denial of Service (ReDoS) across multiple vendors and products, typically including advisories and CVEs.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-1233"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The vulnerability of the Resource Timing app…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.2, "uncertanity": 1.3, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://redos.red-soft.ru/support/secure/uya…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ROS-20260717-73-0038"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:50:18"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Redos"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T11:50:18.849000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"ROS-20260717-73-0038"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redos"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/redos/ROS-20260717-73-0038"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "redos", "operator": "lt", "packageFi…` |

### Collection fields

Specific to the `redos` collection.

_None in the sample._

