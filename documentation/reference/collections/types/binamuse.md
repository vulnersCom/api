# `binamuse`  ·  ~15 documents

Binamuse is a vulnerability collection from the Binamuse database focusing on advisories and CVEs related to various software products and systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BINAMUSE:F61C45CDC72EEDA3B26D9A56201D5E74"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:33:18"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2015-01-28T00:40:23"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2015-01-28T00:39:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-01-27T21:39:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"CoreGraphics CCITT Memory Corruption - CVE-2…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"binamuse"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/binamuse/BINAMUSE:F61C45…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `661` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 6.8, "vector": "AV:N/AC:M/Au:N/C:P/…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"feliam (noreply@blogger.com)"` |

### Collection fields

Specific to the `binamuse` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2014-4481"]` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"accessComp…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"![](http://1.bp.blogspot.com/-BEbEha_KlFc/VB…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-4481", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://blog.binamuse.com/2015/01/coregraphic…` |

