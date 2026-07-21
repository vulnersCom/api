# `openvas`  ·  ~180k documents

OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENVAS:1361412562310156935"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-12T00:00:54"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-08T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-07T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-08T11:44:04.946000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Endian Firewall Detection Consolidation"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openvas"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/openvas/OPENVAS:13614125…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `32` |

### Family fields

Present in every sampled `scanner`-family document (typed by [`ScannerBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Consolidation of Endian Firewall detections."` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://plugins.openvas.org/nasl.php?oid=1361…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Copyright (C) 2026 Greenbone AG"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"# SPDX-FileCopyrightText: 2026 Greenbone AG\…` |

### Collection fields

Specific to the `openvas` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-5107"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@vuldb.com", "versi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5107", "date": "2026-06-16…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `naslFamily` | `str` | Nessus NASL plugin family. | `"Product detection"` |
| `pluginID` | `str` | Scanner plugin identifier (e.g. Nessus plugin id). | `"1361412562310156935"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.endian.com/en/community/"]` |

