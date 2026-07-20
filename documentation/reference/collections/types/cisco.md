# `cisco`  ·  ~5.2k documents

Cisco's vulnerability database provides advisories and CVEs related to security issues in Cisco products and software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}` | 55% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-20150", "CVE-2026-20153", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/…` |
| `cvss3` | `object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@cisco.com", "ve…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"As part of Cisco's ongoing commitment to pro…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-20150", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/cont…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-SA-HARDENING-ROOMOS-AQNMBEQ"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T19:36:58"` |
| `metrics` | `object{adp,cna}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@cisco.co…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T16:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T16:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://sec.cloudapps.cisco.com/security/ce…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cisco"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:37:00.431000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Cisco RoomOS Security Hardening Release: Jul…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisco"` |
| `vendorCvss` | `object{score,severity}` | 90% | Vendor-assigned CVSS score block. | `{"score": "8.8", "severity": "high"}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cisco/CISCO-SA-HARDENING…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `56` |

