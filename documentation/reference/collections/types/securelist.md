# `securelist`  ·  ~1k documents

Securelist provides vendor-specific security advisories, CVEs, and threat intelligence reports focusing on malware and cyber threats.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 20% | Related CVE identifiers referenced by this document. | `["CVE-2024-2658"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 10% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 15% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt-cna@flexerasoftw…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://media.kasperskycontenthub.com/wp…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 1.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 15% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-27925", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://securelist.com/tr/hellonet-vipnet/12…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURELIST:B789138E8D4DB2F0D45B23C33091F8F8"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 20% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "psirt-cna@flexe…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T13:05:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T13:05:56"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Konstantin Isakov, Georgy Kucherin, Anton Ka…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T15:36:50.995000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"HelloNet campaign \u2014 new malicious modul…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"securelist"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/securelist/SECURELIST:B7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `25` |

