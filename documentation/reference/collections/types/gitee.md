# `gitee`  ·  ~1.9k documents

Gitee provides vulnerability advisories and CVEs related to open-source projects hosted on its platform, primarily focusing on software security.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `list[object{content_type,created,description,extension,file_path,filename,id,last_modified,sha256,size,type}]` | Binary/media attachments associated with the document. | `[{"id": "7287ccfd-61bd-3850-84d9-40c9b8d19442…` |
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-47291", "CVE-2026-49160"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\u5b8c\u6574\u7684 Claude Code \u914d\u7f6e\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}, object{short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "\u5b8c\u6574\u7684 Cla…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://gitee.com/chaihongjun/everything-cla…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"893FDFE5-9A23-5881-A827-FAC92123448D"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:40:48"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:31:11"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:31:11"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"chaihongjun"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:40:48.961000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"everything-claude-code"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitee"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/gitee/893FDFE5-9A23-5881…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`ExploitBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `gitee` collection.

| field | type | description | example |
|---|---|---|---|
| `exploitProbabilityScoring` | `object{error,files_scanned,group_scores,probability,scan_at,total_score,url,version}` | Model-based exploit-probability scoring. | `{"url": "https://gitee.com/chaihongjun/everyt…` |

