# `circl`  ·  ~180k documents

CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-13142"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "emo@eclipse.org", "ve…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "emo@eclipse.org", "ver…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"creation_timestamp\| type\| source  \n---\|---\|…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-13142 creatio…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://cve.circl.lu/api/sighting"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CIRCL:CVE-2026-13142"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:40:09"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "emo@eclipse.or…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:30:26"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T07:30:26"` |
| `references` | `list[str]` | External reference URLs. | `["https://bsky.app/profile/offseq.bsky.social…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Circl"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:40:09.421000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-13142"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"circl"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/circl/CIRCL:CVE-2026-13142"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `false` |

### Collection fields

Specific to the `circl` collection.

| field | type | description | example |
|---|---|---|---|
| `items` | `list[object{content,creation_timestamp,source,type,uuid,vulnerability_lookup_origin}]` | Sub-items/entries contained in the document. | `[{"uuid": "59c11fe5-d383-4045-b69a-ff0824fdb5…` |

