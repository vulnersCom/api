# `pypa`  ·  ~7k documents

The PyPA collection contains Python Package Authority advisories and CVEs related to Python packages and their vulnerabilities.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-59203"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "pypa", "version": "3.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "pypa", "version": "4.0…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Pillow is a Python imaging library. From 12.…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-59203", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/pypa/advisory-database/bl…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PYPA:PYSEC-2026-3452"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T19:59:09"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "pypa", "ver…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T18:13:37"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T16:17:02"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/python-pillow/Pillow/rel…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Python Packaging Advisory"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:59:09.660000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"PYSEC-2026-3452"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pypa"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/pypa/PYPA:PYSEC-2026-3452"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "12.3.0", "operator": "lt", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `pypa` collection.

_None in the sample._

