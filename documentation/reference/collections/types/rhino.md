# `rhino`  ·  ~83 documents

Rhino is a vulnerability collection from the Rhino Security Labs, focusing on advisories and CVEs related to various software products and services.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHINO:20781BBEA88200A8CED8AE3D3EBEFE46"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-08-27T17:11:36"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-08-27T17:03:12"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-08-27T17:03:12"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-08-27T17:11:36.722000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Referral Beware, Your Rewards are Mine (Part…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rhino"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rhino/RHINO:20781BBEA882…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 1.9, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://rhinosecuritylabs.com/research/refer…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Whit Taylor"` |

### Collection fields

Specific to the `rhino` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-26147"]` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The post Referral Beware, Your Rewards are M…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-55963", "date": "2026-06-2…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |

