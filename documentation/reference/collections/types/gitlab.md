# `gitlab`  ·  ~1.5k documents

GitLab's vulnerability database provides advisories and CVEs related to security issues in GitLab products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GITLAB-77FB716CA363680E68C02AF75D6F4E59"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T14:16:39"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T14:16:39.937000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"AngleSharp HTML5 Spec Compliance: mXSS via a…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitlab"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/gitlab/GITLAB-77FB716CA3…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"https://gitlab.com/gitlab-org/security-produ…` |

### Collection fields

Specific to the `gitlab` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.4.3", "operator": "lt", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-54570"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cweIds` | `list[str]` | Associated CWE weakness identifiers (alternate key). | `["CWE-80", "CWE-937", "CWE-1035"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The HTML specification requires that a MathM…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50274", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://gitlab.com/api/v4/projects/12006272/…` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `references` | `list[str]` | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-5…` |
| `solution` | `str` | Recommended remediation/fix, as text. | `"Upgrade to version 1.5.0 or above."` |
| `vendorCvss3` | `str` | Vendor-assigned CVSS v3. | `"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N"` |

