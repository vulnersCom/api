# `postgresql`  ·  ~150 documents

PostgreSQL vulnerabilities database provides advisories and CVEs specific to PostgreSQL database server security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "14.23", "operator": "lt", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-6477"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### PostgreSQL libpq lo_* functions let serv…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6477", "date": "2026-07-01…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.postgresql.org/support/security/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"POSTGRESQL:CVE-2026-6477"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T06:10:24"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-14T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.postgresql.org/about/news/postg…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"PostgreSQL Global Development Group"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-14T15:28:02.274000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Vulnerability in client (CVE-2026-6477)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"postgresql"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/postgresql/POSTGRESQL:CV…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `34` |

