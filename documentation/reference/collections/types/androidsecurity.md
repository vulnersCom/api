# `androidsecurity`  ·  ~400 documents

Android Security collection includes advisories and CVEs related to vulnerabilities in the Android OS and its ecosystem from Google's security updates.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-25836", "CVE-2022-25837", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@android.com",…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The Pixel Update Bulletin contains details o…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-25836", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://source.android.com/docs/security/bul…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANDROID:PIXEL-2026-07-01"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:38:11"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-07T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-07T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Android Open Source Project"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-07T19:38:28.554000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Pixel Update Bulletin\u2014July 2026Stay org…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"androidsecurity"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/androidsecurity/ANDROID:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `29` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `androidsecurity` collection.

_None in the sample._

