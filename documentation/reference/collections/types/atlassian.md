# `atlassian`  ·  ~4.3k documents

Atlassian's vulnerability collection includes security advisories and CVEs for its software products, focusing on vendor-specific vulnerabilities.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2026-41293"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 95% | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"*This is a vulnerability in a non-Atlassian …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 85% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41293", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://jira.atlassian.com/browse/JSWSERVER-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JSWSERVER-26841"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-16T19:41:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | 95% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-16T17:04:08"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-15T22:22:17"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"security-metrics-bot"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-16T19:41:04.180000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Injection org.apache.tomcat:tomcat-catalina …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"atlassian"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/atlassian/JSWSERVER-26841"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

