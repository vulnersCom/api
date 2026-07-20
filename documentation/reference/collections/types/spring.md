# `spring`  ·  ~930 documents

Spring collection includes vulnerability advisories and CVEs related to the Spring framework and its ecosystem, sourced from various security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 5% | Affected software products (name/version/operator). | `[{"version": "4.0.1", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 5% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 20% | Related CVE identifiers referenced by this document. | `["CVE-2026-47835"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 20% | CVSS v3.x score block. | `{"cvssV31": {"source": "security@vmware.com",…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"I\u2019m joined, I think, for the second tim…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 20% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47835", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://spring.io/blog/2026/07/16/a-bootiful…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SPRING:5F62B7C8F014C10E2FD7C3B2BB3BC743"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:37:30"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 20% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"joshlong"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:37:30.020000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"A Bootiful Podcast: Russ Miles on Safer, Mor…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"spring"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/spring/SPRING:5F62B7C8F0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

