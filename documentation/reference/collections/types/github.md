# `github`  ·  ~33k documents

GitHub collection includes vulnerability advisories and CVEs related to open-source projects hosted on GitHub, focusing on various software products and libraries.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-50197"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Summary\n\nA wrong policy can be an open…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50197", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/advisories/GHSA-8qqm-fp2q…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GHSA-8QQM-FP2Q-V734"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:44:30"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security-adviso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T21:49:49"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T21:49:48"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/zalando/skipper/security…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"GitHub Advisory Database"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:44:30.931000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Skipper: Incomplete fix for CVE-2026-50197: …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"github"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/github/GHSA-8QQM-FP2Q-V734"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `19` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{ecosystem,name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "0.27.26", "operator": "lt", "ec…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-306"]` |

### Collection fields

Specific to the `github` collection.

_None in the sample._

