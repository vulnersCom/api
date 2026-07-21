# `Bulletin` — base fields

Fields the server sends in **every** document, across all collections. Every family and collection model inherits them. Nested value objects — `Cvss` (with `Cvss2`/`Cvss3`/`Cvss4` by version), `Timestamps`, `Enchantments`, `EpssScore` — are shared value objects reused across families.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str | None` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str] | None` | Related CVE identifiers referenced by this document. | `["CVE-2019-12169"]` |
| `cvss` | `Cvss | None` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `Cvss | None` | CVSS v2 score block. | `{"severity": "MEDIUM", "acInsufInfo": false, …` |
| `cvss3` | `Cvss | None` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `cvss4` | `Cvss | None` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str | None` | Full text or summary of the vulnerability/advisory. | `"PHP-Fusion version 9.03.60 suffers from a PH…` |
| `enchantments` | `Enchantments | None` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "vector": "NONE"}, "…` |
| `epss` | `list[EpssScore] | None` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-12169", "date": "2026-06-1…` |
| `href` | `str | None` | Canonical URL of the document at its original source. | `"https://0daydb.com/php-fusion-9-03-60-php-ob…` |
| `id` | `str | None` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"0DAYDB:B906BFDBDE502CE63C0691A9F1882E35"` |
| `immutableFields` | `Any` | Fields the source marks as immutable. |  |
| `lastseen` | `str | None` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-07-02T19:14:05"` |
| `metrics` | `Any` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str | None` | Last modification timestamp at the source (ISO-8601). | `"2020-07-02T15:46:53"` |
| `published` | `str | None` | Original publication timestamp (ISO-8601). | `"2020-07-02T15:46:51"` |
| `references` | `list[str] | None` | External reference URLs. | `["https://wordpress.org/news/2024/06/wordpres…` |
| `reporter` | `str | None` | Person or organization credited with reporting/authoring it. | `"0daydb.com"` |
| `sourceAvailable` | `bool | None` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `Timestamps | None` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-07-02T12:46:51Z", "updated"…` |
| `title` | `str | None` | Human-readable title of the document. | `"PHP-Fusion 9.03.60 - PHP Object Injection"` |
| `type` | `str | None` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"0daydb"` |
| `vendorId` | `str | None` | Vendor's own identifier for the advisory, when provided. | `"GITHUBEXPL:DANIELISSAQ-EXPLOITATION-BASICS"` |
| `vhref` | `str | None` | URL of the document on vulners.com. | `"https://vulners.com/0daydb/0DAYDB:B906BFDBDE…` |
| `viewCount` | `int | None` | How many times the document has been viewed on Vulners. | `142` |

