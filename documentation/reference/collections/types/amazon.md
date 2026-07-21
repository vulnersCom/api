# `amazon`  ·  ~8.9k documents

Amazon's vulnerability collection includes security advisories and CVEs related to AWS services and products, focusing on cloud security issues.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALAS2023-2026-1990"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T01:16:40"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T01:16:41.008000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Important: openvpn"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"amazon"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/amazon/ALAS2023-2026-1990"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 5.9, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Issue Overview:**  \n\n\nAn attacker contr…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Amazon"` |

### Collection fields

Specific to the `amazon` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "id=\"new_packag…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Amazon Linux", "OSVersion": "any", "…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-11771", "CVE-2026-12996", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@openvpn.net",…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://alas.aws.amazon.com/AL2023/ALAS2023-…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

