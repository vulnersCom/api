# `gitee`  ·  ~1.9k documents

Gitee provides vulnerability advisories and CVEs related to open-source projects hosted on its platform, primarily focusing on software security.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"849844A4-A8B9-5AEA-912F-9BFC88DFD636"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T21:14:19"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T19:27:22"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T19:27:22"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T21:14:19.402000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"WEB\u811a\u672c\u6f0f\u6d1e\u6316\u6398\u673a"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitee"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/gitee/849844A4-A8B9-5AEA…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Present in every sampled `exploit`-family document (typed by [`ExploitBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |

### Collection fields

Specific to the `gitee` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `list[object{content_type,created,description,extension,file_path,filename,id,last_modified,sha256,size,type}]` | Binary/media attachments associated with the document. | `[{"id": "a44c9336-9f5b-3ae9-beef-be217cbaf847…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-47291", "CVE-2026-49160"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"WEB\u811a\u672c\u6f0f\u6d1e\u6316\u6398\u673…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `exploitProbabilityScoring` | `object{error,files_scanned,group_scores,probability,scan_at,total_score,url,version}` | Model-based exploit-probability scoring. | `{"url": "https://gitee.com/hackingboos/webdig…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://gitee.com/hackingboos/webdig"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"HackBoos"` |

