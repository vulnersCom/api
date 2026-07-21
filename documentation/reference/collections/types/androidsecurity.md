# `androidsecurity`  ·  ~400 documents

Android Security collection includes advisories and CVEs related to vulnerabilities in the Android OS and its ecosystem from Google's security updates.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANDROID:PIXEL-2026-07-01"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:38:11"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-07T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-07T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-07T19:38:28.554000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Pixel Update Bulletin\u2014July 2026Stay org…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"androidsecurity"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/androidsecurity/ANDROID:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `29` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Android Open Source Project"` |

### Collection fields

Specific to the `androidsecurity` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-59609", "CVE-2026-0125", "CVE-2026…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@android.com",…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The Pixel Update Bulletin contains details o…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-59609", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://source.android.com/docs/security/bul…` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "dsap-vuln-mana…` |

