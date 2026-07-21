# `websecuritylog`  ·  ~9 documents

WebSecurityLog provides security advisories and CVEs focused on web applications and services, sourced from various vendors and platforms.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WEBSECURITYLOG:0015FD108480E9500D1618ED9FD20…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T15:59:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2016-11-23T16:01:02"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2016-11-23T12:01:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2016-11-23T09:01:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Yahoo Web Security Bug Bounty :  Phpmyadmin …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"websecuritylog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/websecuritylog/WEBSECURI…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `33` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.8, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://www.websecuritylog.com/2016/11/yahoo-…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Anonymous (noreply@blogger.com)"` |

### Collection fields

Specific to the `websecuritylog` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2014-0130"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Yahoo Web Security Bug Bounty :   Phpmyadm…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-0130", "date": "2026-06-16…` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |

