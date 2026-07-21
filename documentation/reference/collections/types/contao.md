# `contao`  ·  ~29 documents

Contao vulnerability collection provides advisories and CVEs specific to the Contao CMS, sourced from security bulletins and community reports.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CONTAO:REMOTE-COMMAND-EXECUTION-THROUGH-FILE…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-01-16T15:11:19"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-09-17T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-09-17T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-09-16T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Remote command execution through file uploads"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"contao"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/contao/CONTAO:REMOTE-COM…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `75` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.8, "uncertanity": 0.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Contao org"` |

### Collection fields

Specific to the `contao` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "4.0", "operator": "eq", "name":…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-45398"]` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Date** : 2024-09-17  \n**CVE ID** : CVE-20…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-45398", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://contao.org/en/security-advisories/re…` |
| `metrics` | `object{adp,cna,nvd}, object{cna,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |

