# `kubernetes`  ·  ~91 documents

Kubernetes collection includes security advisories, CVEs, and patches specific to Kubernetes and its components from various vendors.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KUBERNETES:CVE-2026-3865"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T12:21:15"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-04-10T17:54:42"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-04-10T17:54:42"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-25T18:16:21.126000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CSI Driver for SMB path traversal via subDir…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kubernetes"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/kubernetes/KUBERNETES:CV…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `35` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Kubernetes Security Response Committee"` |

### Collection fields

Specific to the `kubernetes` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.20.1", "operator": "lt", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-3865"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "NONE", "version": "3.…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**CVSS Rating:**  \n[CVSS:3.1/AV:N/AC:L/PR:H…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-13281", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/kubernetes/kubernetes/iss…` |
| `kubernetesIssueNumber` | `int` | Kubernetes issue number for the advisory. | `138319` |
| `kubernetesStatus` | `str` | Status of the Kubernetes advisory. | `"fixed"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `vendorCvss` | `object{vector}` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/…` |

