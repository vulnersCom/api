# `euvd`  ·  ~420k documents

The EUVDB (European Vulnerability Database) provides advisories and CVEs focused on vulnerabilities across various vendors and products in the EU.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: euvd`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"euvd"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-16235"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://euvd.enisa.europa.eu/vulnerability/E…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"EUVD-2026-45895"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:03:48"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:02:11"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T07:02:11"` |
| `references` | `list[str]` | External reference URLs. | `["https://metacpan.org/release/DRSTEVE/Crypt-…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"EUVD"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:03:48.354000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"EUVD-2026-45895"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"euvd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/euvd/EUVD-2026-45895"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `euvd` collection.

| field | type | description | example |
|---|---|---|---|
| `cnaAffected` | `list[object{enisaIdProduct,enisaIdVendor}]` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"enisaIdVendor": [{"id": "2c1872ad-cf0a-3f1…` |

