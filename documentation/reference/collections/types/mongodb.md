# `mongodb`  ·  ~150 documents

MongoDB vulnerability collection includes advisories and CVEs related to MongoDB database software, focusing on security issues and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "8.3.3", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11933"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 100% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@mongodb.com", "ver…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A use-after-free vulnerability exists in Mon…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11933", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.mongodb.com/alerts#security"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MONGODB:CVE-2026-11933"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-23T07:36:56"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-12T01:58:46"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-12T01:57:32"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://jira.mongodb.org/browse/SERVER-1281…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"MongoDB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-12T02:27:59.008000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Post-authentication use-after-free in server…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mongodb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mongodb/MONGODB:CVE-2026…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

