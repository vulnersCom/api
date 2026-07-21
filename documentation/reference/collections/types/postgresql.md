# `postgresql`  ·  ~150 documents

PostgreSQL vulnerabilities database provides advisories and CVEs specific to PostgreSQL database server security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-6477"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### PostgreSQL libpq lo_* functions let serv…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6477", "date": "2026-07-01…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.postgresql.org/support/security/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"POSTGRESQL:CVE-2026-6477"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T06:10:24"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-14T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.postgresql.org/about/news/postg…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"PostgreSQL Global Development Group"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-14T15:28:02.274000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Vulnerability in client (CVE-2026-6477)"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"postgresql"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/postgresql/POSTGRESQL:CV…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `34` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "14.23", "operator": "lt", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `postgresql` collection.

_None in the sample._

