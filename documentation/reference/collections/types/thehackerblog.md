# `thehackerblog`  ·  ~31 documents

The Hacker Blog provides security advisories, CVEs, and exploits focused on various vendors and products, sourced from community contributions.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 5% | Related CVE identifiers referenced by this document. | `["CVE-2018-11101"]` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3}` | 5% | CVSS v3.x score block. | `{"cvssV3": {"source": "nvd", "version": "3.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**NOTE:** _If you\u2019re just looking for t…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 5% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-11101", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"/zero-days-without-incident-compromising-ang…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THEHACKERBLOG:1F455E324E949389BD5A301D6CC18F69"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T15:27:50"` |
| `metrics` | `object{nvd}` | 5% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-11T08:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-11T08:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Matthew Bryant (mandatory) (mandatory(cat)gm…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-11T05:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\"Zero-Days\" Without Incident - Compromisin…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thehackerblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/thehackerblog/THEHACKERB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `35` |

