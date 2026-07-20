# `openwrt`  ·  ~33 documents

OpenWrt vulnerability collection includes advisories and CVEs related to OpenWrt firmware, focusing on security issues affecting routers and embedded devices.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2024-54143"]` |
| `cvss` | `object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `cvss3` | `object{cvssV3}` | 75% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"version": "4.0", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"** DESCRIPTION ** \nDue to the combination o…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{aggregatedScoring,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.3, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 80% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-54143", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://openwrt.org/advisory/2024-12-06"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENWRT-SA-2024-12-06"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-04T15:56:07"` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{cna,nvd}, object{nvd}` | 80% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-12-07T07:31:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-12-06T00:00:00"` |
| `references` | `list[str]` | 15% | External reference URLs. | `["https://lxr.openwrt.org/ident?i=blobmsg_for…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenWrt Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-04T15:56:07Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Advisory 2024-12-06-1 - OpenWrt Att…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openwrt"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openwrt/OPENWRT-SA-2024-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `50` |

