# `hackread`  ·  ~7.5k documents

HackRead provides cybersecurity news and insights, focusing on vulnerabilities, exploits, and advisories related to various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An email that appears to contain a shipping …` |
| `enchantments` | `object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://hackread.com/ttf-trap-phishing-fake-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HACKREAD:AF31C6761373B8B4F878D3C67311F51B"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T15:36:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T13:51:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T13:51:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Waqas"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T15:36:50.664000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\u201cTTF Trap\u201d Phishing Emails Use Fak…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackread"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hackread/HACKREAD:AF31C6…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

