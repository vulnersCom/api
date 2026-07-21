# `anandpraka`  ·  ~6 documents

AnandPraka provides security advisories and CVEs focused on vulnerabilities in various software products and operating systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANANDPRAKA:E923C02933F806CD63FC04F38A23CAA2"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-07-29T13:18:31"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2017-05-28T14:38:32"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2017-05-28T14:38:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-05-28T11:38:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"How I took control of your Twitter account (…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"anandpraka"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/anandpraka/ANANDPRAKA:E9…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `161` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://www.anandpraka.sh/2017/05/how-i-took-…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Anand Prakash (noreply@blogger.com)"` |

### Collection fields

Specific to the `anandpraka` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Summary:\n\nThis blog post is about an I…` |

