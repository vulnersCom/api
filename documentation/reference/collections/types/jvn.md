# `jvn`  ·  ~5.6k documents

The JVN collection provides advisories and CVEs related to vulnerabilities in various software products and operating systems sourced from Japan's security community.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: jvn`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"jvn"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JVNDB-2026-024104"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T01:37:02"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T03:28:23"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T03:28:23"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T01:37:02.979000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security information for Hitachi Disk Array …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jvn"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/jvn/JVNDB-2026-024104"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `jvn`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-54518", "CVE-2026-21530", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# Overview\n\nCVE-2025-54518 \| AMD: CVE-2025…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 0.9, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://jvndb.jvn.jp/en/contents/2026/JVNDB-…` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,nvd}, object{adp,cna,vendor}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `references` | `list[str]` | External reference URLs. | `["https://www.hitachi.com/products/it/storage…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Japan Vulnerability Notes"` |

### Collection fields

Specific to the `jvn` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@amd.com", "versi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44024", "date": "2026-07-1…` |

