# `anthropic`  ·  ~27 documents

Anthropic collection includes security advisories and CVEs related to vulnerabilities in Anthropic's AI products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-5448"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "facts@wolfssl.com", "v…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"##  heap-buffer-overflow medium\n\nCVE-2026-…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5448", "date": "2026-06-24…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://red.anthropic.com/2026/cvd/findings/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANT-2026-6615Y595"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-28T13:56:41"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-20T01:20:34"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Anthropic"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-28T07:21:58.118000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"ANT-2026-6615Y595 \u00b7 wolfSSL \u00b7 Heap…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"anthropic"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/anthropic/ANT-2026-6615Y…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `22` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `anthropic` collection.

_None in the sample._

