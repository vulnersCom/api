# `trellix`  ·  ~610 documents

Trellix provides security advisories and CVEs related to its cybersecurity products and services, focusing on vendor-specific vulnerabilities.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TRELLIX:AC25BB751DE50B70ACF0B27808C9D8D4"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-20T00:00:00"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-04-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-04-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-20T15:40:35.743000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"PureRAT: A Multi-Stage, Fileless RAT Utilizi…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"trellix"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/trellix/TRELLIX:AC25BB75…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 0.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Trellix"` |

### Collection fields

Specific to the `trellix` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-20045"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@eset.com", "v…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# PureRAT: A Multi-Stage, Fileless RAT Utili…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-10561", "date": "2026-04-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.trellix.com/content/mainsite/en-…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

