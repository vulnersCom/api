# `paloalto`  ·  ~510 documents

Palo Alto Networks collection includes advisories and CVEs related to their security products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-0119"]` |
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"version": "4.0", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A command injection vulnerability\u00a0in th…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.0, "uncertanity": 1.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-0119", "date": "2026-07-14…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://securityadvisories.paloaltonetworks.…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PA-CVE-2025-0119"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-24T14:48:48"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-04-09T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-04-09T16:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.paloaltonetworks.com/CVE-2…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Palo Alto Networks Product Security Incident…` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-09T16:36:16Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Cortex XDR Broker VM: Authenticated Command …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"paloalto"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/paloalto/PA-CVE-2025-0119"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `28` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `paloalto` collection.

_None in the sample._

