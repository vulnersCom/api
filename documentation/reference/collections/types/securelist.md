# `securelist`  ·  ~1k documents

Securelist provides vendor-specific security advisories, CVEs, and threat intelligence reports focusing on malware and cyber threats.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURELIST:B789138E8D4DB2F0D45B23C33091F8F8"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:36:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T13:05:56"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T13:05:56"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T15:36:50.995000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"HelloNet campaign \u2014 new malicious modul…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"securelist"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/securelist/SECURELIST:B7…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `27` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 1.2, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://securelist.com/tr/hellonet-vipnet/12…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Konstantin Isakov, Georgy Kucherin, Anton Ka…` |

### Collection fields

Specific to the `securelist` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-2658"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt-cna@flexerasoftw…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![](https://media.kasperskycontenthub.com/wp…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-27925", "date": "2026-07-1…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "psirt-cna@flexe…` |

