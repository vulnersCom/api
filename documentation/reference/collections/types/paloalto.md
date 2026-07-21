# `paloalto`  ·  ~510 documents

Palo Alto Networks collection includes advisories and CVEs related to their security products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PA-CVE-2025-0124"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-15T04:35:52"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-04-09T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-04-09T16:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-09T16:36:16Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"PAN-OS: Authenticated File Deletion Vulnerab…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"paloalto"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/paloalto/PA-CVE-2025-0124"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `47` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 2.1, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 1.4, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Palo Alto Networks Product Security Incident…` |

### Collection fields

Specific to the `paloalto` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-0124"]` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"version": "4.0", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An authenticated file deletion vulnerability…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-0124", "date": "2026-07-14…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://securityadvisories.paloaltonetworks.…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |
| `references` | `list[str]` | External reference URLs. | `["https://security.paloaltonetworks.com/CVE-2…` |

