# `kubernetes`  ·  ~91 documents

Kubernetes collection includes security advisories, CVEs, and patches specific to Kubernetes and its components from various vendors.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.20.1", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-3865"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**CVSS Rating:**  \n[CVSS:3.1/AV:N/AC:L/PR:H…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-13281", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/kubernetes/kubernetes/iss…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KUBERNETES:CVE-2026-3865"` |
| `kubernetesIssueNumber` | `int` | 100% | Kubernetes issue number for the advisory. | `138319` |
| `kubernetesStatus` | `str` | 100% | Status of the Kubernetes advisory. | `"fixed"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T12:21:15"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-10T17:54:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-10T17:54:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Kubernetes Security Response Committee"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-25T18:16:21.126000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CSI Driver for SMB path traversal via subDir…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kubernetes"` |
| `vendorCvss` | `object{vector}` | 100% | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/kubernetes/KUBERNETES:CV…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `35` |

