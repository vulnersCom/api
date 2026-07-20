# `gitlab`  ·  ~1.5k documents

GitLab's vulnerability database provides advisories and CVEs related to security issues in GitLab products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.24.1", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-50274"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cweIds` | `list[str]` | 100% | Associated CWE weakness identifiers (alternate key). | `["CWE-400", "CWE-770", "CWE-937", "CWE-1035"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Datadog tracing libraries that implement W3C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50274", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://gitlab.com/api/v4/projects/12006272/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GITLAB-7963EA083ED00561569BCDFDDA908781"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T22:18:46"` |
| `metrics` | `object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-5…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://gitlab.com/gitlab-org/security-produ…` |
| `solution` | `str` | 100% | Recommended remediation/fix, as text. | `"Unfortunately, there is no solution availabl…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T06:18:13.758000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"dd-trace-go: Improper parsing of W3C baggage…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitlab"` |
| `vendorCvss3` | `str` | 100% | Vendor-assigned CVSS v3. | `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gitlab/GITLAB-7963EA083E…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

