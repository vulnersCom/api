# `ncsc`  ·  ~4.2k documents

The NCSC collection includes UK government advisories and alerts on cybersecurity vulnerabilities across various vendors and products, featuring CVEs and mitigation guidance.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: ncsc`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"ncsc"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NCSC-2026-0250"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:38:05"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T11:01:56"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T11:01:56"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:38:05.958000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"WordPress vulnerabilities can be addressed t…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ncsc"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ncsc/NCSC-2026-0250"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Present in every sampled `ncsc`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"There are two vulnerabilities present in Wor…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.4, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://advisories.ncsc.nl/2026/ncsc-2026-02…` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,nvd}, object{adp,cna,vendor}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"NCSC"` |

### Collection fields

Specific to the `ncsc` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "ncsc", "version": "4.0…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `references` | `list[str]` | External reference URLs. | `["https://slcyber.io/research-center/wp2shell…` |

