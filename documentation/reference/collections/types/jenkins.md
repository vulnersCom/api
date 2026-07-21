# `jenkins`  ·  ~1.5k documents

Jenkins vulnerability collection includes advisories and CVEs related to Jenkins software, focusing on security issues affecting the Jenkins automation server.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-57285"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "jenkinsci-cert", "ver…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"github-branch-source 1967.1969.v205fd594c821…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-57285", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.jenkins.io/security/advisory/202…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY-3808"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T19:55:10"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "jenkinsci-cert…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-24T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Jenkins Security Team"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T19:55:10.257000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Missing permission check allows enumerating …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jenkins"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/jenkins/SECURITY-3808"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1967.1970.vd86979736546", "oper…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `jenkins` collection.

| field | type | description | example |
|---|---|---|---|
| `jenkinsAdvisoryId` | `str` | Jenkins advisory identifier. | `"2026-06-24"` |
| `jenkinsKind` | `str` | Jenkins advisory kind (core/plugin). | `"plugins"` |
| `jenkinsPlugins` | `list[object{fixed,name,previous}], list[object{name,previous}]` | Affected Jenkins plugins (name, fixed/previous versions). | `[{"name": "github-branch-source", "previous":…` |
| `jenkinsReporter` | `str` | Reporter credited by the Jenkins advisory. | `"Suman Roy (https://linkedin.com/in/sumanrox)"` |
| `vendorCvss` | `object{severity,vector}` | Vendor-assigned CVSS score block. | `{"severity": "Medium", "vector": "CVSS:3.1/AV…` |

