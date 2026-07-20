# `hashicorp`  ·  ~190 documents

HashiCorp's vulnerability collection includes security advisories and CVEs related to its products and services, focusing on cloud infrastructure and automation tools.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2.0.4", "operator": "lt", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-14896"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.2, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "security@hashicorp.co…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Summary\nHashiCorp Nomad and Nomad Enterpris…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 60% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14896", "date": "2026-07-1…` |
| `hashicorpBulletinId` | `str` | 100% | HashiCorp advisory identifier. | `"HCSEC-2026-22"` |
| `hashicorpProducts` | `list[str]` | 85% | Affected HashiCorp products. | `["Nomad", "Nomad Enterprise"]` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://discuss.hashicorp.com/t/hcsec-2026-2…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HASHICORP:HCSEC-2026-22"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T13:24:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@hashi…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T20:18:59"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T20:18:59"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"HashiCorp Security Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T00:30:59.870000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Nomad vulnerable to cross-namespace host vol…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hashicorp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hashicorp/HASHICORP:HCSE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

