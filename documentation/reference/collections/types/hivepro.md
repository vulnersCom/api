# `hivepro`  ·  ~1.6k documents

HivePro provides a comprehensive database of vulnerability advisories, CVEs, and threat intelligence focused on various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HIVEPRO:592FA80144C11B4FE007F3315B105DE5"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-02T12:05:55"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-02T10:06:20"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-02T10:06:20"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-02T12:05:55.160000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Zafran vs Hive Pro: CTEM Platform Comparison"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hivepro"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hivepro/HIVEPRO:592FA801…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `16` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Amit Mishra"` |

### Collection fields

Specific to the `hivepro` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-45185"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Persistent exposure backlogs do not shrink w…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-45185", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://hivepro.com/blog/zafran-vs-hive-pro-…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |

