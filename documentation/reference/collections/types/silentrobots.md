# `silentrobots`  ·  ~22 documents

Silent Robots provides vulnerability data sourced from various vendors, focusing on advisories and CVEs related to web applications and services.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SILENTROBOTS:0DC5D72435E65CEB453D75B8B0F45904"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-08-07T08:03:43"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2019-02-06T17:58:21"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2019-02-06T17:58:21"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-02-06T14:58:21Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"SSRF Protocol Smuggling in Plaintext Credent…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"silentrobots"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/silentrobots/SILENTROBOT…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `69` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.3, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.silentrobots.com/blog/2019/02/06…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Silent Robot Systems blog"` |

### Collection fields

Specific to the `silentrobots` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2016-4264"]` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"accessComp…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"SSRF protocol smuggling involves an attacker…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2016-4264", "date": "2026-06-16…` |

