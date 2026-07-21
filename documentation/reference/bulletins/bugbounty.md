# `bugbounty` family

**Model:** `BugbountyBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: bugbounty`. 4 collections.

## Family fields

Present in every `bugbounty` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

## Collections

### `hackerone` · ~15k documents → `HackeroneBulletin`

HackerOne collection includes vulnerability reports and advisories from various vendors, focusing on security issues discovered through bug bounty programs.

| field | type | description | example |
|---|---|---|---|
| `bounty` | `float | None` | Bounty amount/details paid for the report. | `0.0` |
| `bountyState` | `str | None` | State of the bounty (awarded, pending, …). | `"not-applicable"` |
| `h1reporter` | `Any` | HackerOne reporter profile. | `{"id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvNDUwNDg0M…` |
| `h1team` | `Any` | HackerOne team/program the report belongs to. | `{"url": "https://hackerone.com/curl", "handle…` |

### `huntr` · ~4.1k documents → `HuntrBulletin`

Huntr is a vulnerability database that aggregates security advisories, CVEs, and exploits primarily focused on open-source software projects.

| field | type | description | example |
|---|---|---|---|
| `cwe_id` | `str | None` | Single associated CWE identifier. | `"d32d"` |
| `language` | `str | None` | Language of the report. | `"Python"` |
| `patch_commit_sha` | `str | None` | Commit SHA of the fixing patch. | `"f9b1eb510478570609ef451984a255775aa4b937"` |
| `repository` | `str | None` | Source code repository associated with the report. | `"https://github.com/mlflow/mlflow"` |
| `status` | `str | None` | Workflow status of the record. | `"valid"` |

### `openbugbounty` · ~1.3M documents → `OpenbugbountyBulletin`

OpenBugBounty is a community-driven platform that catalogs security advisories and vulnerabilities reported by researchers across various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `openbugbounty` | `Any` | Open Bug Bounty metadata (mirror, patch status). | `{"patchStatus": "On Hold", "mirror": ""}` |

### `xssed` · ~31k documents → `XssedBulletin`

XSSed is a vulnerability database focused on cross-site scripting (XSS) vulnerabilities, providing advisories and exploit details for various web applications.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

