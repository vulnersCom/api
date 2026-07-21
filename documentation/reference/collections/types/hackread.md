# `hackread`  ·  ~7.5k documents

HackRead provides cybersecurity news and insights, focusing on vulnerabilities, exploits, and advisories related to various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HACKREAD:5A61871594EEF4A5E33B01D4616C238F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T21:36:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T21:06:48"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T21:06:48"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T21:36:51.221000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Hugging Face Says Autonomous AI Agent System…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackread"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hackread/HACKREAD:5A6187…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://hackread.com/hugging-face-ai-agent-b…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Waqas"` |

### Collection fields

Specific to the `hackread` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An AI-led cyberattack breached limited Huggi…` |

