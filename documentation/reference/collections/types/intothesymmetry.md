# `intothesymmetry`  ·  ~42 documents

IntotheSymmetry provides advisories and CVEs focused on vulnerabilities in various software products and systems, sourced from multiple vendors.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"INTOTHESYMMETRY:E90923CAE21ADFC423A96B462BCB…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T09:59:28"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-01-09T10:32:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-01-07T15:08:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-01-07T12:08:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"The Curious Case of WebCrypto Diffie-Hellman…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"intothesymmetry"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/intothesymmetry/INTOTHES…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `278` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 3.7, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.1, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://blog.intothesymmetry.com/2020/01/the-…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ll (noreply@blogger.com)"` |

### Collection fields

Specific to the `intothesymmetry` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2016-0701"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "nvd", "version": "3.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**tl;dr** Mozilla Firefox prior to version 7…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2016-0701", "date": "2026-06-16…` |
| `metrics` | `object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |

