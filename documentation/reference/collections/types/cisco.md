# `cisco`  ·  ~5.2k documents

Cisco's vulnerability database provides advisories and CVEs related to security issues in Cisco products and software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-SA-ISE-TRAVERSAL-XNT7WB2Y"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T19:36:58"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T16:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:36:59.945000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Cisco Identity Services Engine Path Traversa…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisco"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cisco/CISCO-SA-ISE-TRAVE…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 5.5, "vector": "CVSS:3.1/AV:N/AC:L/…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Cisco"` |

### Collection fields

Specific to the `cisco` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-20146"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@cisco.com", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A vulnerability in Cisco Identity Services E…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-20146", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/cont…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@cisco.co…` |
| `references` | `list[str]` | External reference URLs. | `["https://sec.cloudapps.cisco.com/security/ce…` |
| `vendorCvss` | `object{score,severity}` | Vendor-assigned CVSS score block. | `{"score": "5.5", "severity": "medium"}` |

