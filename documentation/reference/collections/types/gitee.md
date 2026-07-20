# `gitee`  ·  ~1.9k documents

Gitee provides vulnerability advisories and CVEs related to open-source projects hosted on its platform, primarily focusing on software security.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `attachments` | `list[?], list[object{content_type,created,description,extension,file_path,filename,id,last_modified,sha256,size,type}]` | 100% | Binary/media attachments associated with the document. | `[{"id": "3772fb53-757e-3af2-b36d-778f80a1e641…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47291", "CVE-2026-49160"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CVE-2026-49160 \u4e0e CVE-2026-47291\uff1aHT…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.0, "uncertanity": 1.0, …` |
| `exploitProbabilityScoring` | `object{error,files_scanned,group_scores,probability,scan_at,total_score,url,version}` | 100% | Model-based exploit-probability scoring. | `{"url": "https://gitee.com/jinghunsanzu/CVE-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://gitee.com/jinghunsanzu/CVE-2026-4916…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"22E955DB-9127-5532-BFEB-AC714FDCA474"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:11:09"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T16:23:41"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T16:23:41"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"\u5929\u5802\u96be\u53d7\u7684\u5730\u72f1"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:11:09.912000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Exploit for Uncontrolled Resource Consumptio…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitee"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gitee/22E955DB-9127-5532…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |

