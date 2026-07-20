# `ptsecurity`  ·  ~190k documents

PTSecurity provides security advisories and CVEs focused on vulnerabilities affecting various software products and systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-13142"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 10% | CVSS v3.x score block. | `{"cvssV31": {"source": "dbugs", "version": "3…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The Social Login, Passkeys, Magic Link & Ema…` |
| `enchantments` | `object{dependencies,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "WordPress plugin befor…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://dbugs.ptsecurity.com/vulnerability/P…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PT-2026-61531"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:38:03"` |
| `metrics` | `object{cna,vendor}` | 10% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "dbugs", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://wpscan.com/vulnerability/a34d9be7-c…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Positive Technologies"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:38:03.653000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PT-2026-61531"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ptsecurity"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ptsecurity/PT-2026-61531"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

