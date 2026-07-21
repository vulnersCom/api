# `euvd`  ·  ~420k documents

The EUVDB (European Vulnerability Database) provides advisories and CVEs focused on vulnerabilities across various vendors and products in the EU.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: euvd`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"euvd"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"EUVD-2026-46144"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:03:48"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T03:32:09"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T03:32:09"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T04:03:48.194000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"EUVD-2026-46144"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"euvd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/euvd/EUVD-2026-46144"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `euvd`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cnaAffected` | `list[object{enisaIdProduct,enisaIdVendor}]` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"enisaIdVendor": [{"id": "b6cdc6e0-a160-34d…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63729"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The SyncTeX parser (synctex_parser.c) shippe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 1.2, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://euvd.enisa.europa.eu/vulnerability/E…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/TeX-Live/texlive-source/…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"EUVD"` |

### Collection fields

Specific to the `euvd` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "disclosure@vulncheck.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "euvd", "version": "4.0…` |
| `metrics` | `object{cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "euvd", "vers…` |

