# `cisco`  ·  ~5.2k documents

Cisco's vulnerability database provides advisories and CVEs related to security issues in Cisco products and software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-20150", "CVE-2026-20153", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@cisco.com", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"As part of Cisco's ongoing commitment to pro…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-20150", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/cont…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-SA-HARDENING-ROOMOS-AQNMBEQ"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T19:36:58"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@cisco.co…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T16:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://sec.cloudapps.cisco.com/security/ce…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Cisco"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:37:00.431000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Cisco RoomOS Security Hardening Release: Jul…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisco"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cisco/CISCO-SA-HARDENING…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `56` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `cisco` collection.

| field | type | description | example |
|---|---|---|---|
| `vendorCvss` | `object{score,severity}` | Vendor-assigned CVSS score block. | `{"score": "8.8", "severity": "high"}` |

