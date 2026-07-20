# `kitploit`  ·  ~6k documents

Kitploit is a security database focused on exploits and tools, primarily for penetration testing and ethical hacking, sourced from various contributors.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: tools`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"tools"` |
| `cvelist` | `list[str]` | 15% | Related CVE identifiers referenced by this document. | `["CVE-2017-12542", "CVE-2017-5689"]` |
| `cvss` | `object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 10.0, "vector": "…` |
| `cvss3` | `object{cvssV3}` | 15% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.0", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 0.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 15% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2017-12542", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.kitploit.com/2025/05/shodan-dorks…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KITPLOIT:4163374071362481988"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-05-11T14:31:07"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}` | 15% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"version": "2.0", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-05-11T12:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-05-11T12:30:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/nullfuzz-pentest/shodan-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"KitPloit"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-05-11T14:31:08.318000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Shodan-Dorks - Dorks for Shodan; a powerful …` |
| `toolHref` | `str` | 100% | Link to the associated tool/exploit. | `"https://github.com/nullfuzz-pentest/shodan-d…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kitploit"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/kitploit/KITPLOIT:416337…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `785` |

