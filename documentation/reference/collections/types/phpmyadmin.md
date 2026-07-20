# `phpmyadmin`  ·  ~230 documents

phpMyAdmin collection includes security advisories and CVEs related to vulnerabilities in the phpMyAdmin web-based database management tool.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "5.2.2", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 90% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2024-2961"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.3, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 70% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 90% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## PMASA-2025-3\n\n**Announcement-ID:** PMAS…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-2961", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.phpmyadmin.net/security/PMASA-20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PHPMYADMIN:PMASA-2025-3"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-22T18:09:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | 90% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-01-21T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-01-21T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"phpMyAdmin"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-01-20T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"glibc/iconv Vulnerability (CVE-2024-2961)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"phpmyadmin"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/phpmyadmin/PHPMYADMIN:PM…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `65` |

