# `tools` family

**Model:** `ToolsBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: tools`. 2 collections.

## Family fields

Present in every `tools` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `toolHref` | `str | None` | Link to the associated tool/exploit. | `"https://github.com/nullfuzz-pentest/shodan-d…` |

## Collections

### `kitploit` · ~6k documents → `KitploitBulletin`

Kitploit is a security database focused on exploits and tools, primarily for penetration testing and ethical hacking, sourced from various contributors.

_No fields beyond the layers above._

### `n0where` · ~1.1k documents → `N0whereBulletin`

n0where is a vulnerability database focusing on advisories and CVEs related to various software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

