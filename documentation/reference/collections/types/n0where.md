# `n0where`  ·  ~1.1k documents

n0where is a vulnerability database focusing on advisories and CVEs related to various software products and operating systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: tools`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"tools"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"N0WHERE:173110"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-03-06T07:51:59"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2019-03-06T03:58:08"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2019-03-06T03:58:08"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-03-06T00:58:08Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"NSA Software Reverse Engineering Framework: …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"n0where"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/n0where/N0WHERE:173110"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `234` |

### Family fields

Present in every sampled `tools`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Ghidra is a software reverse engineering (SR…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": -0.0, "vector": "NONE"}, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://n0where.net/nsa-software-reverse-eng…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"N0where"` |
| `toolHref` | `str` | Link to the associated tool/exploit. | `"https://ghidra-sre.org/"` |

### Collection fields

Specific to the `n0where` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `references` | `list[str]` | External reference URLs. | `["https://github.com/GoVanguard/legion/"]` |

