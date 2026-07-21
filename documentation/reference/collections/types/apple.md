# `apple`  ·  ~1.6k documents

Apple's vulnerability database includes advisories and CVEs related to security issues in Apple products and operating systems.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APPLE:F97D495326D54F7A07934F752B13A609"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T16:20:44"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-29T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T00:20:19.875000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"About the security content of iOS 26.5.2 and…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"apple"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/apple/APPLE:F97D495326D5…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `13` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Apple"` |

### Collection fields

Specific to the `apple` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "26.5.2", "operator": "lt", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-39868", "CVE-2026-43699", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "product-security", "v…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve-coordination@googl…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# About the security content of iOS 26.5.2 a…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39868", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.apple.com/en-us/127594"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "product-securi…` |
| `references` | `list[str]` | External reference URLs. | `["https://support.apple.com/en-us/HT201222"]` |

