# `atlassian`  ·  ~4.3k documents

Atlassian's vulnerability collection includes security advisories and CVEs for its software products, focusing on vendor-specific vulnerabilities.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JSWSERVER-26841"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-16T19:41:04"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-16T17:04:08"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-15T22:22:17"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-16T19:41:04.180000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Injection org.apache.tomcat:tomcat-catalina …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"atlassian"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/atlassian/JSWSERVER-26841"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"security-metrics-bot"` |

### Collection fields

Specific to the `atlassian` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-41293"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"*This is a vulnerability in a non-Atlassian …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41293", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://jira.atlassian.com/browse/JSWSERVER-…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |

