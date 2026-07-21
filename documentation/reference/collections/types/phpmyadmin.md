# `phpmyadmin`  ·  ~230 documents

phpMyAdmin collection includes security advisories and CVEs related to vulnerabilities in the phpMyAdmin web-based database management tool.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PHPMYADMIN:PMASA-2025-3"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-22T18:09:04"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-01-21T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-01-21T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-01-20T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"glibc/iconv Vulnerability (CVE-2024-2961)"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"phpmyadmin"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/phpmyadmin/PHPMYADMIN:PM…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `65` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.3, "vector": "C…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"phpMyAdmin"` |

### Collection fields

Specific to the `phpmyadmin` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "5.2.2", "operator": "le", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-2961"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## PMASA-2025-3\n\n**Announcement-ID:** PMAS…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-2961", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.phpmyadmin.net/security/PMASA-20…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |

