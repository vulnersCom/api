# `elastic`  ·  ~250 documents

Elastic's vulnerability collection includes advisories and CVEs related to Elastic products, focusing on security issues and patches for their software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49091"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.0, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "elastic", "version": …` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Improper Output Neutralization for Logs in…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49091", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://discuss.elastic.co/t/kibana-7-17-15-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ELASTIC:387449"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-01T19:40:18"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "elastic", "…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-01T14:05:44"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-01T14:05:44"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ElasticCo"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-01T15:39:08.447000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Kibana 7.17.15, 8.11.1 Security Update (ESA-…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"elastic"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/elastic/ELASTIC:387449"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

