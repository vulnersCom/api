# `laminas`  ·  ~5 documents

Laminas vulnerability collection includes advisories and CVEs related to the Laminas PHP framework, focusing on security issues affecting its components.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2.18.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 60% | Related CVE identifiers referenced by this document. | `["CVE-2023-29530"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 40% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 60% | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The package laminas/laminas-diactoros (Diact…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 60% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-29530", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://getlaminas.org/security/advisory/LP-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"LP-2023-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T10:06:10"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | 60% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-04-17T17:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-04-17T17:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/laminas/laminas-diactoro…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Laminas Project Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-04-17T14:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"HTTP Multiline Header Termination Vulnerabil…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"laminas"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/laminas/LP-2023-01"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `50` |

