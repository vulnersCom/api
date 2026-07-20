# `talosblog`  ·  ~2k documents

Talos Blog provides security advisories and insights from Cisco Talos, focusing on vulnerabilities across various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 20% | Related CVE identifiers referenced by this document. | `["CVE-2026-42982", "CVE-2026-48561", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 20% | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![Begun, the Patch Wars have](https://storag…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42982", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.talosintelligence.com/begun-the…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TALOSBLOG:44007DB019F02AD1D5DB6CF9A85D8C92"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 20% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:00:50"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T18:00:50"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Joe Marshall"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:36:50.995000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Begun, the Patch Wars have"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"talosblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/talosblog/TALOSBLOG:4400…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

