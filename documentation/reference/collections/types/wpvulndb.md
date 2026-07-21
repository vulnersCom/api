# `wpvulndb`  ·  ~15k documents

Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-7544"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security@wordfence.co…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Description The Mux Video Uploader plugin fo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10024", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://wpscan.com/vulnerability/8e31419b-83…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WPVDB-ID:8E31419B-834D-42ED-B57F-202B1837CEE3"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T20:27:00"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@wordf…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-11T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-10T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.wordfence.com/threat-intel/vuln…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"wpvulndb"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T20:27:00.971000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Mux Video Uploader < 1.1.5 - Authenticated (…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wpvulndb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wpvulndb/WPVDB-ID:8E3141…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `wpvulndb` collection.

| field | type | description | example |
|---|---|---|---|
| `exploit` | `str` | Exploit availability/details (source-specific). | `"https://example.com/wp-content/plugins/8-deg…` |
| `generation` | `int` | Internal generation/version counter of the record. | `0` |

