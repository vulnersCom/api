# `xssed`  ·  ~31k documents

XSSed is a vulnerability database focused on cross-site scripting (XSS) vulnerabilities, providing advisories and exploit details for various web applications.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Security researcher 0x73F, has submitted on …` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.xssed.com/mirror/81499/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"XSSED:81499"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2016-03-20T00:54:31"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2015-03-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2015-12-03T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["http://lavillette.com"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"0x73F"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-12-02T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unfixed XSS vulnerability at lavillette.com"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"xssed"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/xssed/XSSED:81499"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `64` |

