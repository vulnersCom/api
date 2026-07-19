# BC oracle — normalization allowances (A21)

The backward-compatibility oracle compares the v4 shims against the real
`vulners==3.2.0` baseline **byte-for-byte**. A small, explicit list of volatile
tokens is normalized before comparison — everything else must match exactly.
New entries are added only with review.

## Surface (`surface.json`)

| Token | Normalized to | Why |
|---|---|---|
| `version` | `{VERSION}` | The package version legitimately differs (3.2.0 → 4.0.0). Every other public symbol, signature and default must be identical. |

Private modules (any dotted component starting with `_`, e.g. `vulners._version`
or the v4 core `vulners._base_client`) are excluded from the surface entirely —
they are not part of the compatibility contract.

## Wire (`golden/wire.json`)

| Token | Normalized to | Why |
|---|---|---|
| `User-Agent` version | `{VERSION}` | The UA string embeds the package version (`Vulners Python API 3.2.0`). |
| multipart boundary (`sbom_audit`) | `{BOUNDARY}` | httpx generates a fresh random boundary per request; it appears in both the `Content-Type` header and the body. `Content-Length` is unaffected (fixed-width hex), so it is still compared. |

Everything else — HTTP method, path (including the trailing slash on v3 routes),
query-string key order, JSON body key order (v3 uses insertion order + orjson,
deterministic), header set, and the `apiKey`-in-query quirk of
`webhook.read` — is compared byte-for-byte with no allowance.
