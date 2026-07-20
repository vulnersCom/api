# `openvas`  ·  ~180k documents

OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2026-1519"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 95% | CVSS v3.x score block. | `{"cvssV31": {"source": "security-officer", "v…` |
| `cvss4` | `object{cvssV4}` | 25% | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Consolidation of Endian Firewall detections."` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-1519", "date": "2026-07-01…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://plugins.openvas.org/nasl.php?oid=1361…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENVAS:1361412562310156935"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-12T00:00:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 95% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-offic…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-08T00:00:00"` |
| `naslFamily` | `str` | 100% | Nessus NASL plugin family. | `"Product detection"` |
| `pluginID` | `str` | 100% | Scanner plugin identifier (e.g. Nessus plugin id). | `"1361412562310156935"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-07T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.endian.com/en/community/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Copyright (C) 2026 Greenbone AG"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"# SPDX-FileCopyrightText: 2026 Greenbone AG\…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-08T11:44:04.946000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Endian Firewall Detection Consolidation"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openvas"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openvas/OPENVAS:13614125…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `32` |

