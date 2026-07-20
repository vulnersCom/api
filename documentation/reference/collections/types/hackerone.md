# `hackerone`  ·  ~15k documents

HackerOne collection includes vulnerability reports and advisories from various vendors, focusing on security issues discovered through bug bounty programs.

**Family model:** [`BugBountyBulletin`](../../data-models.md) — `bulletinFamily: bugbounty`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bounty` | `float` | 100% | Bounty amount/details paid for the report. | `0.0` |
| `bountyState` | `str` | 100% | State of the bounty (awarded, pending, …). | `"not-applicable"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-27782", "CVE-2023-27538"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Summary:\n\nCurl_close() (lib/url.c:21…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-9080", "date": "2026-07-10…` |
| `h1reporter` | `object{__typename,id,name,username}` | 100% | HackerOne reporter profile. | `{"id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvNDUwNDg0M…` |
| `h1team` | `object{handle,medium_profile_picture,name,url}` | 100% | HackerOne team/program the report belongs to. | `{"url": "https://hackerone.com/curl", "handle…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://hackerone.com/reports/3833577"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"H1:3833577"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T12:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T12:31:07"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-30T07:12:59"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"carehi1324"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T12:36:54.023000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"curl: heap-use-after-free in curl_easy_clean…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackerone"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hackerone/H1:3833577"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `48` |

