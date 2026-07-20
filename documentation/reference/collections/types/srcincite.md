# `srcincite`  ·  ~290 documents

SrcIncite provides vulnerability advisories and CVEs focused on various software products and services, sourced from multiple security vendors.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 80% | Related CVE identifiers referenced by this document. | `["CVE-2026-25200"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 80% | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@samsung.com", "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Vulnerability Details:**\n\nThis vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 80% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-25200", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://srcincite.io/advisories/src-2025-0007/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SRC-2025-0007"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-29T04:06:29"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | 80% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@samsung.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-28T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-09-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Steven Seeley of Source Incite"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 50% | Raw, unparsed source body as delivered by the origin. | `"#!/usr/bin/env python3\n\"\"\"\nSamsung Magi…` |
| `sourceHref` | `str` | 70% | URL of the raw source object, when it differs from href. | `"https://srcincite.io/pocs/src-2025-0006.py.txt"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-29T04:06:29.886000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SRC-2025-0007 : Samsung MagicINFO 9 Server M…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"srcincite"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/srcincite/SRC-2025-0007"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `136` |

