# `mageia`  ·  ~6k documents

Mageia security advisories provide information on vulnerabilities affecting Mageia Linux, including CVEs and patches for various software packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MGASA-2026-0277"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T19:52:58"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T19:06:32"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T19:06:32"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T19:52:58.982000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Updated xmlstarlet package fixes a security …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mageia"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mageia/MGASA-2026-0277"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The updated package fixes a security vulnera…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Gentoo Foundation"` |

### Collection fields

Specific to the `mageia` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,version}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "xmlstarlet", "v…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Mageia", "OSVersion": "9", "arch": "…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-11822", "CVE-2026-11824"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "disclosure@vulncheck.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://advisories.mageia.org/MGASA-2026-027…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |
| `references` | `list[str]` | External reference URLs. | `["https://bugs.mageia.org/show_bug.cgi?id=356…` |

