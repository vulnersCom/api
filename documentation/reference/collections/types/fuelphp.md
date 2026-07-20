# `fuelphp`  ·  ~9 documents

FuelPHP vulnerabilities from the FuelPHP security advisory database, covering vulnerabilities in the FuelPHP framework, including CVEs and advisories.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.8.0", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 11% | Related CVE identifiers referenced by this document. | `["CVE-2014-1999"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 11% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"When extracting a ZIP file using the Unzip c…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 11% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-1999", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://fuelphp.com/security-advisories"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SEC-CORE-009"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T16:02:42"` |
| `metrics` | `object{nvd}` | 11% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2018-05-07T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2018-05-07T00:00:00"` |
| `references` | `list[str]` | 78% | External reference URLs. | `["https://github.com/fuel/core/commit/95945e1…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Github user cs-sonar"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-05-06T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unzip vulnerable to slip-zip attack"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fuelphp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fuelphp/SEC-CORE-009"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

