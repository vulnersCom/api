# `thehackerblog`  ·  ~31 documents

The Hacker Blog provides security advisories, CVEs, and exploits focused on various vendors and products, sourced from community contributions.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THEHACKERBLOG:1F455E324E949389BD5A301D6CC18F69"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T15:27:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-02-11T08:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-02-11T08:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-11T05:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"\"Zero-Days\" Without Incident - Compromisin…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thehackerblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/thehackerblog/THEHACKERB…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `35` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.1, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"/zero-days-without-incident-compromising-ang…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Matthew Bryant (mandatory) (mandatory(cat)gm…` |

### Collection fields

Specific to the `thehackerblog` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2018-11101"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "nvd", "version": "3.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**NOTE:** _If you\u2019re just looking for t…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-11101", "date": "2026-06-1…` |
| `metrics` | `object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |

