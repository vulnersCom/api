# `erpscan`  ·  ~290 documents

ERPSCAN provides security advisories and CVEs specifically focused on vulnerabilities in ERP systems and related applications.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ERPSCAN-18-006"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-09-15T10:41:38"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2017-09-11T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2017-09-11T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-09-10T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"SAP Redwood BPA Message Service crypto secre…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"erpscan"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/erpscan/ERPSCAN-18-006"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `518` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": -0.0, "vector": "NONE"}, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ERPScan"` |

### Collection fields

Specific to the `erpscan` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2018-2636"]` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"accessComp…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "HIGH", "atta…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Application:** SAP Redwood BPA  \n**Vendor…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-2636", "date": "2026-06-30…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://erpscan.io/advisories/erpscan-18-006…` |

