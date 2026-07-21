# `cnnvd` family

**Model:** `CnnvdBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: cnnvd`.

## Family fields

Present in every `cnnvd` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

## Collections

### `cnnvd` · ~200k documents → `CnnvdCollectionBulletin`

CNNVD is a Chinese national vulnerability database that provides advisories and CVEs for various software products and systems.

_No fields beyond the layers above._

