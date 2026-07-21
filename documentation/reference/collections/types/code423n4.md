# `code423n4`  ·  ~10k documents

Code423n4 is a vulnerability database focused on security advisories and reports for smart contracts and blockchain projects.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: crypto`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"crypto"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CODE423N4:2024-01-CANTO-FINDINGS-ISSUES-12"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-02-07T20:21:07"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2024-02-05T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2024-01-28T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-01-27T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"secRewardsPerShare Insufficient precision"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"code423n4"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/code423n4/CODE423N4:2024…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `30` |

### Family fields

Present in every sampled `crypto`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"[Lines of code](https://github.com/code-423n…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/code-423n4/2024-01-canto-…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Code4rena"` |
| `vendor_severity` | `str` | Vendor's own qualitative severity rating. | `"2 (Med Risk)"` |

### Collection fields

Specific to the `code423n4` collection, beyond the common and family sets.

_None in the sample._

