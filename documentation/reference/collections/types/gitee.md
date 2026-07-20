# `gitee`  ·  ~1.9k documents

Gitee provides vulnerability advisories and CVEs related to open-source projects hosted on its platform, primarily focusing on software security.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `attachments` | `list[object{content_type,created,description,extension,file_path,filename,id,last_modified,sha256,size,type}]` | 95% | Binary/media attachments associated with the document. | `[{"id": "7287ccfd-61bd-3850-84d9-40c9b8d19442…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 15% | Related CVE identifiers referenced by this document. | `["CVE-2026-47291", "CVE-2026-49160"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 15% | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\u5b8c\u6574\u7684 Claude Code \u914d\u7f6e\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}, object{short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "\u5b8c\u6574\u7684 Cla…` |
| `exploitProbabilityScoring` | `object{error,files_scanned,group_scores,probability,scan_at,total_score,url,version}` | 100% | Model-based exploit-probability scoring. | `{"url": "https://gitee.com/chaihongjun/everyt…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://gitee.com/chaihongjun/everything-cla…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"893FDFE5-9A23-5881-A827-FAC92123448D"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:40:48"` |
| `metrics` | `object{adp,cna}` | 15% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:31:11"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T08:31:11"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"chaihongjun"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:40:48.961000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"everything-claude-code"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitee"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gitee/893FDFE5-9A23-5881…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

