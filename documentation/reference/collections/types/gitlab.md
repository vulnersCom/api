# `gitlab`  ·  ~1.5k documents

GitLab's vulnerability database provides advisories and CVEs related to security issues in GitLab products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-50274"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Datadog tracing libraries that implement W3C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50274", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://gitlab.com/api/v4/projects/12006272/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GITLAB-7963EA083ED00561569BCDFDDA908781"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T22:18:46"` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-5…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"https://gitlab.com/gitlab-org/security-produ…` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T06:18:13.758000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"dd-trace-go: Improper parsing of W3C baggage…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitlab"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/gitlab/GITLAB-7963EA083E…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `8` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.24.1", "operator": "le", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `solution` | `str` | Recommended remediation/fix, as text. | `"Unfortunately, there is no solution availabl…` |

### Collection fields

Specific to the `gitlab` collection.

| field | type | description | example |
|---|---|---|---|
| `cweIds` | `list[str]` | Associated CWE weakness identifiers (alternate key). | `["CWE-400", "CWE-770", "CWE-937", "CWE-1035"]` |
| `vendorCvss3` | `str` | Vendor-assigned CVSS v3. | `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"` |

