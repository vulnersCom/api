# `circl`  ·  ~180k documents

CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2026-13142"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 45% | CVSS v3.x score block. | `{"cvssV31": {"source": "emo@eclipse.org", "ve…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "emo@eclipse.org", "ver…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"creation_timestamp\| type\| source  \n---\|---\|…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "CVE-2026-13142 creatio…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://cve.circl.lu/api/sighting"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CIRCL:CVE-2026-13142"` |
| `items` | `list[object{content,creation_timestamp,source,type,uuid,vulnerability_lookup_origin}]` | 100% | Sub-items/entries contained in the document. | `[{"uuid": "59c11fe5-d383-4045-b69a-ff0824fdb5…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:40:09"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 60% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "emo@eclipse.or…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:30:26"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:30:26"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bsky.app/profile/offseq.bsky.social…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Circl"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:40:09.421000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-13142"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"circl"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/circl/CIRCL:CVE-2026-13142"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `false` |

