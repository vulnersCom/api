# `httpd`  ·  ~270 documents

Apache HTTP Server vulnerabilities from the Apache Software Foundation, including advisories, CVEs, and security patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T07:36:58"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-06-08T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-06-08T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-06-07T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Apache Httpd < 2.4.54 : Denial of service in…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"httpd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/httpd/HTTPD:C1F57FDC580B…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `167` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.6, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Apache Team Foundation"` |

### Collection fields

Specific to the `httpd` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "2.4.53", "operator": "eq", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-29404"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"In Apache HTTP Server 2.4.53 and earlier, a …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-29404", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://httpd.apache.org/security_report.html"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |

