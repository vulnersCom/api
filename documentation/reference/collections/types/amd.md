# `amd`  ·  ~190 documents

AMD's vulnerability collection includes advisories and CVEs related to AMD hardware and software products, focusing on security issues affecting their technology.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-40677"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.7, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "arm-security", "versi…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@amd.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## CVE Details\n\nRefer to Glossary for expl…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-40677", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.amd.com/en/resources/product-sec…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AMD-SB-9027"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-12T18:52:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "psirt@amd.com",…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-09T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-09T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"amd.com"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-10T00:55:26.325000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"AMD Auto Updater Vulnerability"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"amd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/amd/AMD-SB-9027"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `amd` collection.

_None in the sample._

