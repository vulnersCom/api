# `apple`  ·  ~1.6k documents

Apple's vulnerability database includes advisories and CVEs related to security issues in Apple products and operating systems.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "26.5.2", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2026-39868", "CVE-2026-43699", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 90% | CVSS v3.x score block. | `{"cvssV31": {"source": "product-security", "v…` |
| `cvss4` | `object{cvssV4}` | 20% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve-coordination@googl…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# About the security content of iOS 26.5.2 a…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39868", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.apple.com/en-us/127594"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APPLE:F97D495326D54F7A07934F752B13A609"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T16:20:44"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 90% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "product-securi…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-29T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://support.apple.com/en-us/HT201222"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Apple"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T00:20:19.875000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"About the security content of iOS 26.5.2 and…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"apple"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/apple/APPLE:F97D495326D5…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

