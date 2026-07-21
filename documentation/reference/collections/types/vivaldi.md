# `vivaldi`  ·  ~66 documents

Vivaldi collection includes security advisories and CVEs related to the Vivaldi web browser, focusing on vulnerabilities affecting its functionality and security.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-5281"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "chrome-cve-admin", "v…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Head to the Google Play Store and download t…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5281", "date": "2026-06-24…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://vivaldi.com/blog/android/minor-updat…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VIVALDI-929252"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-18T07:06:49"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-04-01T16:50:22"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-04-01T16:50:20"` |
| `references` | `list[str]` | External reference URLs. | `["https://vivaldi.com/blog/android/minor-upda…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"https://vivaldi.com"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-18T07:06:49.627000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Minor update for Vivaldi Android Browser 7.9"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vivaldi"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vivaldi/VIVALDI-929252"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `vivaldi` collection.

_None in the sample._

