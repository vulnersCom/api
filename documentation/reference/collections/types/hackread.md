# `hackread`  ·  ~7.5k documents

HackRead provides cybersecurity news and insights, focusing on vulnerabilities, exploits, and advisories related to various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An email that appears to contain a shipping …` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://hackread.com/ttf-trap-phishing-fake-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HACKREAD:AF31C6761373B8B4F878D3C67311F51B"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T15:36:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T13:51:42"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T13:51:42"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Waqas"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T15:36:50.664000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"\u201cTTF Trap\u201d Phishing Emails Use Fak…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackread"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hackread/HACKREAD:AF31C6…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `hackread` collection.

_None in the sample._

