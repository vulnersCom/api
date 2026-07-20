# `rhino`  ·  ~83 documents

Rhino is a vulnerability collection from the Rhino Security Labs, focusing on advisories and CVEs related to various software products and services.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 45% | Related CVE identifiers referenced by this document. | `["CVE-2025-26147"]` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 40% | CVSS v3.x score block. | `{"cvssV31": {"source": "cve", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The post Referral Beware, Your Rewards are M…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 40% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-55963", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://rhinosecuritylabs.com/research/refer…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHINO:20781BBEA88200A8CED8AE3D3EBEFE46"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-08-27T17:11:36"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}` | 40% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-08-27T17:03:12"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-08-27T17:03:12"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Whit Taylor"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-08-27T17:11:36.722000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Referral Beware, Your Rewards are Mine (Part…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rhino"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rhino/RHINO:20781BBEA882…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

