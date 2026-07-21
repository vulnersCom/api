# `jetbrains`  ·  ~12 documents

JetBrains collection includes security advisories and CVEs related to JetBrains products, focusing on vulnerabilities in their development tools and IDEs.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-45977", "CVE-2022-24327", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"JetBrains Security\n\n# JetBrains Security B…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-45977", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://blog.jetbrains.com/blog/2022/02/08/j…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JETBRAINS:JETBRAINS-SECURITY-BULLETIN-Q4-2021"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-25T15:06:52"` |
| `metrics` | `object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-02-08T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-02-08T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Jebrains"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-07T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"JetBrains Security Bulletin Q4 2021"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jetbrains"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/jetbrains/JETBRAINS:JETB…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `163` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "2021.1.13890", "operator": "lt"…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `jetbrains` collection.

_None in the sample._

