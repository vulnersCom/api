# `ibm`  ·  ~36k documents

IBM's vulnerability collection includes advisories and CVEs specific to IBM products and software, sourced from IBM's security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"168D73892C71241D65957598EBDE23D9D54A12B23391…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T03:38:46"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T03:21:39"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T03:21:39"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T03:38:46.527000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security Bulletin: TS4500 CLI tool addresses…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ibm"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ibm/168D73892C71241D6595…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"IBM"` |

### Collection fields

Specific to the `ibm` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "1.12.0.2", "operator": "eq", "n…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-16107"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@apache.org", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Summary\n\nThe TS4500 CLI tool used an in…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-69419", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.ibm.com/support/pages/node/7280583"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

