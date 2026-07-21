# `jvn` family

**Model:** `JvnBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: jvn`.

## Family fields

Present in every `jvn` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

## Collections

### `jvn` · ~5.6k documents → `JvnCollectionBulletin`

The JVN collection provides advisories and CVEs related to vulnerabilities in various software products and operating systems sourced from Japan's security community.

_No fields beyond the layers above._

