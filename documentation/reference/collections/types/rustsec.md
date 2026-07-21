# `rustsec`  ·  ~1.1k documents

RustSec is a vulnerability database focused on Rust programming language packages, providing advisories and CVEs related to security issues in Rust crates.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63430"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Crate libcrux-aesgcm was renamed to libcr…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://rustsec.org/advisories/RUSTSEC-2026-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RUSTSEC-2026-0210"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:46:23"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T11:34:24"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T12:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"rustsec"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T11:46:32.330000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"libcrux-aesgcm Renamed to libcrux-aes"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rustsec"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rustsec/RUSTSEC-2026-0210"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "0.0.8", "name…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `rustsec` collection.

_None in the sample._

