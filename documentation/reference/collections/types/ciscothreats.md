# `ciscothreats`  ·  ~14k documents

Cisco Threats collection provides advisories and CVEs related to vulnerabilities in Cisco products and services.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Medium\n\nAlert ID: \n\n58703\n\nFirst Publi…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/view…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-THREAT-58703"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-15T17:08:31"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2018-08-15T15:55:56"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2018-08-15T15:55:56"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Cisco"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-08-15T12:55:56Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Threat Outbreak Alert RuleID33317: Email Mes…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ciscothreats"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ciscothreats/CISCO-THREA…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `542` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `ciscothreats` collection.

| field | type | description | example |
|---|---|---|---|
| `ciscoThreat` | `object{files,md5,messageBody,size,subject}` | Cisco Talos threat details (files, hashes, subject). | `{"md5": "c130666367eb5724a23d046a7963df5e", "…` |

