# `vulncheck_kev`  ·  ~5k documents

Vulncheck_kev aggregates security advisories and CVEs from various vendors, focusing on known exploited vulnerabilities across multiple products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-58352"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "disclosure@vulncheck.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Landray OA contains an unauthenticated HQL i…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-58352", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://console.vulncheck.com/cve/CVE-2024-5…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNCHECK-KEV:CVE-2024-58352"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-03T05:11:39"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://console.vulncheck.com/cve/CVE-2024-…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"VulnCheck"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T05:11:39.451000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"VulnCheck KEV: CVE-2024-58352"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulncheck_kev"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vulncheck_kev/VULNCHECK-…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `true` |

### Collection fields

Specific to the `vulncheck_kev` collection.

| field | type | description | example |
|---|---|---|---|
| `_product` | `str` | Affected product name (source-internal key). | `"Landry Office Automation (OA)"` |
| `_vendor` | `str` | Affected product's vendor (source-internal key). | `"Shenzhen Landray Software Co., Ltd."` |
| `_vulncheck_reported_exploitation` | `list[object{date_added,url}]` | VulnCheck-reported exploitation evidence. | `[{"url": "https://www.cve.org/CVERecord?id=CV…` |
| `_vulncheck_xdb` | `list[object{clone_ssh_url,date_added,exploit_type,xdb_id,xdb_url}]` | VulnCheck exploit/DB cross-references. | `[{"xdb_id": "c8884e9be221", "xdb_url": "https…` |
| `cpeConfigurations` | `object{VulnCheckCpeConfiguration,_index}` | CPE applicability configurations (NVD-style match tree). | `{"_index": false, "VulnCheckCpeConfiguration"…` |
| `cvssScore` | `float` | Flat numeric CVSS base score, when only a scalar is provided. | `8.7` |
| `source` | `str` | Source name/identifier for the record. | `"disclosure@vulncheck.com"` |

