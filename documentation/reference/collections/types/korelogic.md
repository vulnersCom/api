# `korelogic`  ·  ~100 documents

KoreLogic provides security advisories and vulnerability data focused on various software products and services, including CVEs and exploit information.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-15464"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cybersecurity@se.com",…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"1. Vulnerability Details\n\n     Affected Ve…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-15464", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://korelogic.com/Resources/Advisories/K…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KL-001-2026-001"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-22T17:27:57"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-01-08T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-01-08T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Felix Segoviano of"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-08T21:27:06.491000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"yintibao Fun Print Mobile Unauthorized Acces…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"korelogic"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/korelogic/KL-001-2026-001"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `39` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "6.05.15", "operator": "eq", "na…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `korelogic` collection.

_None in the sample._

