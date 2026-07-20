# `jetbrains`  ·  ~12 documents

JetBrains collection includes security advisories and CVEs related to JetBrains products, focusing on vulnerabilities in their development tools and IDEs.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2021.1.13890", "operator": "lt"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 92% | Related CVE identifiers referenced by this document. | `["CVE-2021-45977", "CVE-2022-24327", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 92% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 92% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"JetBrains Security\n\n# JetBrains Security B…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 92% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-45977", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.jetbrains.com/blog/2022/02/08/j…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JETBRAINS:JETBRAINS-SECURITY-BULLETIN-Q4-2021"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-25T15:06:52"` |
| `metrics` | `object{cna,nvd}, object{nvd}` | 92% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jebrains"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-07T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"JetBrains Security Bulletin Q4 2021"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jetbrains"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jetbrains/JETBRAINS:JETB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `163` |

