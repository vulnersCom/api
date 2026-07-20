# `binamuse`  ·  ~15 documents

Binamuse is a vulnerability collection from the Binamuse database focusing on advisories and CVEs related to various software products and systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2014-4481"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 6.8, "vector": "AV…` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](http://1.bp.blogspot.com/-BEbEha_KlFc/VB…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-4481", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://blog.binamuse.com/2015/01/coregraphic…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BINAMUSE:F61C45CDC72EEDA3B26D9A56201D5E74"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:33:18"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2015-01-28T00:40:23"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2015-01-28T00:39:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"feliam (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-01-27T21:39:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CoreGraphics CCITT Memory Corruption - CVE-2…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"binamuse"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/binamuse/BINAMUSE:F61C45…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `661` |

