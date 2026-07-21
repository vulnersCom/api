# `ncsc` family

**Model:** `NcscBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: ncsc`.

## Family fields

Present in every `ncsc` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

## Collections

### `ncsc` · ~4.2k documents → `NcscCollectionBulletin`

The NCSC collection includes UK government advisories and alerts on cybersecurity vulnerabilities across various vendors and products, featuring CVEs and mitigation guidance.

_No fields beyond the layers above._

