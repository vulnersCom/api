# `elastic`  ·  ~250 documents

Elastic's vulnerability collection includes advisories and CVEs related to Elastic products, focusing on security issues and patches for their software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-49091"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.0, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "elastic", "version": …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Improper Output Neutralization for Logs in…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49091", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://discuss.elastic.co/t/kibana-7-17-15-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ELASTIC:387449"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-01T19:40:18"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "elastic", "…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-01T14:05:44"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-01T14:05:44"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ElasticCo"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-01T15:39:08.447000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Kibana 7.17.15, 8.11.1 Security Update (ESA-…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"elastic"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/elastic/ELASTIC:387449"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `elastic` collection.

_None in the sample._

