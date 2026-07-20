# `euvd`  ·  ~420k documents

The EUVDB (European Vulnerability Database) provides advisories and CVEs focused on vulnerabilities across various vendors and products in the EU.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: euvd`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"euvd"` |
| `cnaAffected` | `list[object{enisaIdProduct,enisaIdVendor}]` | 100% | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"enisaIdVendor": [{"id": "2c1872ad-cf0a-3f1…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-16235"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://euvd.enisa.europa.eu/vulnerability/E…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"EUVD-2026-45895"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:03:48"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:02:11"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:02:11"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://metacpan.org/release/DRSTEVE/Crypt-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"EUVD"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:03:48.354000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"EUVD-2026-45895"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"euvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/euvd/EUVD-2026-45895"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

