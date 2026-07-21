# `jenkins`  ·  ~1.5k documents

Jenkins vulnerability collection includes advisories and CVEs related to Jenkins software, focusing on security issues affecting the Jenkins automation server.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY-3723"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T19:55:10"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-24T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T19:55:10.254000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"OS command injection vulnerability on agents…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jenkins"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/jenkins/SECURITY-3723"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.0, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Jenkins Security Team"` |

### Collection fields

Specific to the `jenkins` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "6.6.1", "operator": "lt", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-57282"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "jenkinsci-cert", "ver…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"git-client 6.6.0 and earlier does not correc…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-57282", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.jenkins.io/security/advisory/202…` |
| `jenkinsAdvisoryId` | `str` | Jenkins advisory identifier. | `"2026-06-24"` |
| `jenkinsKind` | `str` | Jenkins advisory kind (core/plugin). | `"plugins"` |
| `jenkinsPlugins` | `list[object{fixed,name,previous}], list[object{name,previous}]` | Affected Jenkins plugins (name, fixed/previous versions). | `[{"name": "git-client", "previous": "6.6.0", …` |
| `jenkinsReporter` | `str` | Reporter credited by the Jenkins advisory. | `"Ravindu Wickramasinghe"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "jenkinsci-cert…` |
| `vendorCvss` | `object{severity,vector}` | Vendor-assigned CVSS score block. | `{"severity": "Medium", "vector": "CVSS:3.1/AV…` |

