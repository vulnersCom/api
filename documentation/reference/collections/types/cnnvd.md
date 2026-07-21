# `cnnvd`  ·  ~200k documents

CNNVD is a Chinese national vulnerability database that provides advisories and CVEs for various software products and systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: cnnvd`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cnnvd"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-6250"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The TP-Link Tapo C110 is an indoor network c…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6250", "date": "2026-06-18…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cnnvd.org.cn/home/globalSearch?k…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CNNVD-202606-2882"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T03:50:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-11T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-6…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"China National Vulnerability Database of Inf…` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-16T03:12:23.618000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"TP-Link Tapo C110 \u683c\u5f0f\u5316\u5b57\u…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cnnvd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cnnvd/CNNVD-202606-2882"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `23` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `cnnvd` collection.

_None in the sample._

