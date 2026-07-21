# `hp`  ·  ~620 documents

HP's vulnerability collection provides advisories and CVEs related to HP products and software, focusing on security issues and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HPSBHF04134"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:52:04"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-13T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:52:05.023000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"InsydeH20 Tools - Buffer Overflow"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hp"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hp/HPSBHF04134"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"HP Product Security Response Team"` |

### Collection fields

Specific to the `hp` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "F.17", "operator": "lt", "name"…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-12050", "CVE-2025-12051", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "hp-security-alert@hp.c…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Insyde has informed HP of potential vulnerab…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5923", "date": "2026-07-10…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.hp.com/us-en/document/ish_15…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |

