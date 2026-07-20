# `circl`  ·  ~180k documents

CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-7708"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"creation_timestamp\| type\| source  \n---\|---\|…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.8, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://cve.circl.lu/api/sighting"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CIRCL:CVE-2024-7708"` |
| `items` | `list[object{content,creation_timestamp,source,type,uuid,vulnerability_lookup_origin}]` | 100% | Sub-items/entries contained in the document. | `[{"uuid": "47fce2b0-b875-4aa1-badb-22d5b07806…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:37:45"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "emo@eclipse.or…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:47:11"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:47:11"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bsky.app/profile/khesefxyz.bsky.soc…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Circl"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:37:45.115000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2024-7708"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"circl"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/circl/CIRCL:CVE-2024-7708"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `false` |

