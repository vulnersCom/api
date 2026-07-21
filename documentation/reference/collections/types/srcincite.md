# `srcincite`  ·  ~290 documents

SrcIncite provides vulnerability advisories and CVEs focused on various software products and services, sourced from multiple security vendors.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SRC-2025-0007"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-29T04:06:29"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-01-28T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-09-09T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-29T04:06:29.886000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"SRC-2025-0007 : Samsung MagicINFO 9 Server M…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"srcincite"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/srcincite/SRC-2025-0007"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `137` |

### Family fields

Present in every sampled `exploit`-family document (typed by [`ExploitBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |

### Collection fields

Specific to the `srcincite` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-25202"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@samsung.com", "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Vulnerability Details:**\n\nThis vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-25202", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://srcincite.io/advisories/src-2025-0007/"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@samsung.…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Steven Seeley of Source Incite"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"#!/usr/bin/env python3\n\"\"\"\nSamsung Magi…` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://srcincite.io/pocs/src-2025-0006.py.txt"` |

