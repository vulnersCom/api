# `jenkins`  ·  ~1.5k documents

Jenkins vulnerability collection includes advisories and CVEs related to Jenkins software, focusing on security issues affecting the Jenkins automation server.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1967.1970.vd86979736546", "oper…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-57285"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"github-branch-source 1967.1969.v205fd594c821…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-57285", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.jenkins.io/security/advisory/202…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY-3808"` |
| `jenkinsAdvisoryId` | `str` | 100% | Jenkins advisory identifier. | `"2026-06-24"` |
| `jenkinsKind` | `str` | 100% | Jenkins advisory kind (core/plugin). | `"plugins"` |
| `jenkinsPlugins` | `list[object{fixed,name,previous}], list[object{name,previous}]` | 100% | Affected Jenkins plugins (name, fixed/previous versions). | `[{"name": "github-branch-source", "previous":…` |
| `jenkinsReporter` | `null, str` | 100% | Reporter credited by the Jenkins advisory. | `"Suman Roy (https://linkedin.com/in/sumanrox)"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T19:55:10"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "jenkinsci-cert…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-24T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jenkins Security Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T19:55:10.257000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Missing permission check allows enumerating …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jenkins"` |
| `vendorCvss` | `object{severity,vector}` | 100% | Vendor-assigned CVSS score block. | `{"severity": "Medium", "vector": "CVSS:3.1/AV…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jenkins/SECURITY-3808"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

