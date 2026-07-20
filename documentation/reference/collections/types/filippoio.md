# `filippoio`  ·  ~110 documents

Filippo.io provides security advisories and CVEs focused on vulnerabilities in various software products and libraries, primarily for developers.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 10% | Related CVE identifiers referenced by this document. | `["CVE-2026-26958"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A requirement for staying sane while working…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-26958", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://words.filippo.io/vuln-reports/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FILIPPOIO:7E5AA1729D42CFF70B3B99F0B9C1A508"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T11:36:50"` |
| `metrics` | `object{adp,cna}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security-adviso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-23T13:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-23T13:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Filippo Valsorda <feed@filippo.io>"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-23T15:36:50.439000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Vulnerability Reports Are Not Special Anymore"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"filippoio"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/filippoio/FILIPPOIO:7E5A…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

