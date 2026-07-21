# `postgresql`  ·  ~150 documents

PostgreSQL vulnerabilities database provides advisories and CVEs specific to PostgreSQL database server security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"POSTGRESQL:CVE-2026-6474"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T17:37:03"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-14T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-14T15:28:02.944000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Vulnerability in core server (CVE-2026-6474)"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"postgresql"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/postgresql/POSTGRESQL:CV…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `29` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"PostgreSQL Global Development Group"` |

### Collection fields

Specific to the `postgresql` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "16.14", "operator": "lt", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-6474"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### PostgreSQL timeofday() can disclose port…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6474", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.postgresql.org/support/security/…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://www.postgresql.org/about/news/postg…` |

