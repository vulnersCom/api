# `openwrt`  ·  ~33 documents

OpenWrt vulnerability collection includes advisories and CVEs related to OpenWrt firmware, focusing on security issues affecting routers and embedded devices.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENWRT-SA-2024-12-06"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-04T15:56:07"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-12-07T07:31:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-12-06T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-04T15:56:07Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Security Advisory 2024-12-06-1 - OpenWrt Att…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openwrt"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/openwrt/OPENWRT-SA-2024-…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `50` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"** DESCRIPTION ** \nDue to the combination o…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{aggregatedScoring,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.3, "uncertanity": 2.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OpenWrt Project"` |

### Collection fields

Specific to the `openwrt` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2024-54143"]` |
| `cvss3` | `object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"version": "4.0", "vectorString":…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-54143", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://openwrt.org/advisory/2024-12-06"` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |

