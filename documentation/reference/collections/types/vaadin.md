# `vaadin`  ·  ~37 documents

Vaadin collection includes security advisories and CVEs related to the Vaadin framework, focusing on vulnerabilities affecting web applications built with it.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-7860"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 5.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@vaadin.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A security vulnerability in the Vaadin Maven…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-7860", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://vaadin.com/security/cve-2026-7860"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VAADIN:CVE-2026-7860"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-22T15:09:59"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@vaadin…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-19T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-19T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/vaadin/flow/pull/23057"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Vaadin"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-19T15:09:58.826000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Possible information disclosure of environme…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vaadin"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vaadin/VAADIN:CVE-2026-7…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `21` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "23.6.10", "operator": "lt", "na…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `severity` | `str` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"LOW"` |

### Collection fields

Specific to the `vaadin` collection.

| field | type | description | example |
|---|---|---|---|
| `vendorCvss` | `object{score,severity}` | Vendor-assigned CVSS score block. | `{"severity": "LOW", "score": "1."}` |

