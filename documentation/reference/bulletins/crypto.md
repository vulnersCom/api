# `crypto` family

**Model:** `CryptoBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: crypto`.

## Family fields

Present in every `crypto` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `vendor_severity` | `str | None` | Vendor's own qualitative severity rating. | `"2 (Med Risk)"` |

## Collections

### `code423n4` · ~10k documents → `Code423n4Bulletin`

Code423n4 is a vulnerability database focused on security advisories and reports for smart contracts and blockchain projects.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

