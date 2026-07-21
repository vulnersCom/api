# `bdu_fstec`  ·  ~91k documents

BDU FSTEC provides advisories from the Russian Federal Service for Technical and Export Control, focusing on vulnerabilities in software and hardware products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BDU:2025-09829"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T23:50:31"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-26T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T23:50:31"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T12:57:04.861000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"The vulnerability of the pg_dump utility in …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"bdu_fstec"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/bdu_fstec/BDU:2025-09829"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `34` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "2.0", "score": 10.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"FSTEC of Russia \u2014 Information Security …` |

### Collection fields

Specific to the `bdu_fstec` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,platform,type,vendor,version,versionRaw}]` | Affected software products (name/version/operator). | `[{"vendor": "\u041e\u041e\u041e \u00ab\u0420\…` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-8714"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "vendor", "version": "2…` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "vendor", "version": "3…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The vulnerability of the pg_dump utility in …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-8714", "date": "2026-07-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://bdu.fstec.ru/vul/2025-09829"` |
| `metrics` | `object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "vendor", "ve…` |
| `references` | `list[str]` | External reference URLs. | `["http://repo.red-soft.ru/redos/7.3c/x86_64/u…` |

