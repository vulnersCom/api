# `ciscothreats`  ·  ~14k documents

Cisco Threats collection provides advisories and CVEs related to vulnerabilities in Cisco products and services.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-THREAT-58703"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-15T17:08:31"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2018-08-15T15:55:56"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2018-08-15T15:55:56"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-08-15T12:55:56Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Threat Outbreak Alert RuleID33317: Email Mes…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ciscothreats"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ciscothreats/CISCO-THREA…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `542` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Cisco"` |

### Collection fields

Specific to the `ciscothreats` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `ciscoThreat` | `object{files,md5,messageBody,size,subject}` | Cisco Talos threat details (files, hashes, subject). | `{"md5": "c130666367eb5724a23d046a7963df5e", "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Medium\n\nAlert ID: \n\n58703\n\nFirst Publi…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/view…` |

