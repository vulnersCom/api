# `hackerone`  ·  ~15k documents

HackerOne collection includes vulnerability reports and advisories from various vendors, focusing on security issues discovered through bug bounty programs.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"H1:3833577"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T12:36:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T12:31:07"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-30T07:12:59"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T12:36:54.023000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"curl: heap-use-after-free in curl_easy_clean…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackerone"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/hackerone/H1:3833577"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `49` |

### Family fields

Present in every sampled `bugbounty`-family document (typed by [`BugBountyBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Summary:\n\nCurl_close() (lib/url.c:21…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://hackerone.com/reports/3833577"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"carehi1324"` |

### Collection fields

Specific to the `hackerone` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `bounty` | `float` | Bounty amount/details paid for the report. | `0.0` |
| `bountyState` | `str` | State of the bounty (awarded, pending, …). | `"not-applicable"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-27782", "CVE-2023-27538"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "support", "version": …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-9080", "date": "2026-07-10…` |
| `h1reporter` | `object{__typename,id,name,username}` | HackerOne reporter profile. | `{"id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvNDUwNDg0M…` |
| `h1team` | `object{handle,medium_profile_picture,name,url}` | HackerOne team/program the report belongs to. | `{"url": "https://hackerone.com/curl", "handle…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |

