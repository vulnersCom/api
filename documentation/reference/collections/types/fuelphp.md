# `fuelphp`  ·  ~9 documents

FuelPHP vulnerabilities from the FuelPHP security advisory database, covering vulnerabilities in the FuelPHP framework, including CVEs and advisories.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SEC-CORE-009"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T16:02:42"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2018-05-07T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2018-05-07T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-05-06T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Unzip vulnerable to slip-zip attack"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fuelphp"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/fuelphp/SEC-CORE-009"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `40` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Github user cs-sonar"` |

### Collection fields

Specific to the `fuelphp` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.8.0", "operator": "le", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2014-1999"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"When extracting a ZIP file using the Unzip c…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-1999", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://fuelphp.com/security-advisories"` |
| `metrics` | `object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/fuel/core/commit/95945e1…` |

