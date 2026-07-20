# `redhatcve`  ·  ~210k documents

Red Hat CVE collection provides advisories and CVE entries specifically for Red Hat products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-64077"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-131"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A flaw was found in the Linux kernel's netfi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16118", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://access.redhat.com/security/cve/cve-2…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RH:CVE-2026-64077"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:39:20"` |
| `metrics` | `object{adp,cna,vendor}, object{adp,cna}, object{cna,vendor}, object{vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:25:57"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:25:57"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.cve.org/CVERecord?id=CVE-2026-6…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"redhat.com"` |
| `sourceAffectedData` | `list[?], list[object{OS,OSVersion,packageName,packageVersion,status}]` | 100% | Affected-product data in the source's own shape. | `[{"OS": "redhat", "OSVersion": "10", "package…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:39:20.861000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-64077"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhatcve"` |
| `vendorCvss` | `object{score,vector}, object{}` | 100% | Vendor-assigned CVSS score block. | `{"score": "5.5", "vector": "CVSS:3.1/AV:L/AC:…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/redhatcve/RH:CVE-2026-64…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

