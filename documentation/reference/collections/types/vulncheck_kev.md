# `vulncheck_kev`  ·  ~5k documents

Vulncheck_kev aggregates security advisories and CVEs from various vendors, focusing on known exploited vulnerabilities across multiple products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `_product` | `str` | 100% | Affected product name (source-internal key). | `"Landry Office Automation (OA)"` |
| `_vendor` | `str` | 100% | Affected product's vendor (source-internal key). | `"Shenzhen Landray Software Co., Ltd."` |
| `_vulncheck_reported_exploitation` | `list[object{date_added,url}]` | 100% | VulnCheck-reported exploitation evidence. | `[{"url": "https://www.cve.org/CVERecord?id=CV…` |
| `_vulncheck_xdb` | `list[?], list[object{clone_ssh_url,date_added,exploit_type,xdb_id,xdb_url}]` | 100% | VulnCheck exploit/DB cross-references. | `[{"xdb_id": "c8884e9be221", "xdb_url": "https…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{VulnCheckCpeConfiguration,_index}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": false, "VulnCheckCpeConfiguration"…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-58352"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvssScore` | `float` | 100% | Flat numeric CVSS base score, when only a scalar is provided. | `8.7` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Landray OA contains an unauthenticated HQL i…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-58352", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://console.vulncheck.com/cve/CVE-2024-5…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNCHECK-KEV:CVE-2024-58352"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-03T05:11:39"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://console.vulncheck.com/cve/CVE-2024-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"VulnCheck"` |
| `source` | `str` | 100% | Source name/identifier for the record. | `"disclosure@vulncheck.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T05:11:39.451000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"VulnCheck KEV: CVE-2024-58352"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulncheck_kev"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulncheck_kev/VULNCHECK-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `true` |

