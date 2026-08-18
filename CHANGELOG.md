# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release dates below are the dates of the version-bump commits; historical
releases were published without git tags, so this history was reconstructed from
the commit log. Only the v3 series is covered in detail.

## [Unreleased]

## [4.2.0] - 2026-08-18

Support for the Vulners v4 audit API updates.

### Added

- `audit.kb_audit(os_name, kb_list, *, os_version=..., fields=...)` now targets the new
  `/api/v4/audit/kb` endpoint and returns one finding per missing update: a result with
  `items` (each carrying the fixing package `fixedPackage` and the update `advisories`, which
  list the KBs they `supersedes`) plus `totalPackages`. The deprecated v3 endpoint (flat
  `kbLatest`/`kbMissed`/`cvelist`) is preserved as `audit.kb_audit_v3(os, kb_list)`.
- `audit.smart(..., fields=[...])` — project which fields each vulnerability carries (e.g.
  `metrics`, `exploitation`, `cvelist`, `cvelistMetrics`, `epss`); an unknown field is rejected
  by the server with `400`. Each result now also includes `fixedVersion`.
- `audit.software(..., cvelist_metrics=True)` and `audit.host(..., cvelist_metrics=True)` —
  enrich each finding with per-CVE `cvelist`/`cvelistMetrics`. Results carry the resolving
  `fixed_version`, and the applied projection is echoed in the `X-Vulners-Applied-Options`
  response header.
- `audit.linux_audit(..., fields=[...])` and `audit.library_audit(..., fields=[...])` — apply
  advisory enrichment options (`metrics`, `cvelistMetrics`); the result reports the
  `appliedOptions` that took effect and any `warnings` for unsupported ones.
- `audit.sbom_audit(..., cvelist_metrics=True)` — sent as a query option (the request body
  carries the uploaded file); the result carries `appliedOptions` and `warnings`.

### Changed

- **Breaking:** `audit.kb_audit` moved from the v3 endpoint to `/api/v4/audit/kb`. Its request
  now uses `os_name` (not `os`) and its response shape changed from a flat CVE list to
  per-update advisories (see Added). Callers that need the old flat shape should use the new
  `audit.kb_audit_v3`.

## [4.1.0] - 2026-08-17

### Added

- `archive.download_getsploit(path, *, connections=8, timeout=...)` — download the
  getsploit exploit database archive to disk over multiple parallel HTTP range
  connections, saturating the link while using constant memory, with an automatic
  fallback to a single stream when the storage does not offer ranges. The write is
  atomic and the raw archive (a single-member zip containing `getsploit.db`) is what
  lands on disk. The SDK-owned client transfers the ranges over a dedicated HTTP/1.1
  connection pool so each connection opens a real socket (HTTP/2 would multiplex them
  onto one, throttling throughput); with your own `http_client`, set `http2=False` for
  the same benefit. Legacy v3 endpoint.

### Changed

- `archive.download_collection(...)` now downloads over multiple parallel range
  connections (new `connections=8` argument) instead of a single stream, sharing the
  same engine as `download_getsploit`. It falls back to a single stream when the
  storage does not offer ranges; the output (the raw compressed archive) and the
  atomic-write behavior are unchanged.

### Documentation

- Every public client, resource and model method now carries a complete reference
  docstring (arguments, return values and errors), rendered on the documentation site
  at https://vulnersCom.github.io/api/ and in `api.md`.

## [4.0.1] - 2026-08-14

Maintenance release. The public API is unchanged from 4.0.0.

### Changed

- Raised the minimum supported versions of the runtime dependencies to the
  currently tested lines: pydantic >=2.13, typing-extensions >=4.16,
  typing-inspection >=0.4.4, h2 >=4.4, stream-unzip >=0.0.101, brotli >=1.2,
  zstandard >=0.25, isal >=1.8, ijson >=3.5. Upper bounds are unchanged. Installs
  pinned below these versions now resolve up to the new minimums.
- Reordered `None` to the end of type-union annotations (ruff 0.16 RUF036); no
  runtime effect.

### Internal

- Refreshed the development lockfile to the latest dependency versions, made the
  MCP test suite reproducible against the lockfile, bumped the pinned GitHub
  Actions (the Pages actions now run on Node 24), and enabled documentation
  auto-deploy to GitHub Pages.

## [4.0.0] - 2026-07-24

A ground-up modernization that keeps 100% backward compatibility with the v3 API.

### Added

- New sync and async clients, `Vulners` and `AsyncVulners`, with resource
  namespaces (`search`, `documents`, `audit`, `archive`, `misc`, `report`, `stix`,
  `subscriptions`, `subscriptions_email`, `webhooks`, `vscanner`), importable as
  `from vulners import Vulners, AsyncVulners`.
- Typed response models (bulletin family hierarchy), `SearchPage` pagination
  with auto-iteration bounded by the 10 000-document search window, and lazy
  streaming of the gzip/zip-compressed JSON-array archive downloads.
- A structured exception hierarchy (`VulnersError` → `APIError` → …) and
  `with_raw_response` / `with_streaming_response` accessors.
- `audit.smart()` — the Smart Audit endpoint (`POST /api/v4/audit/smart`).
- Subscription and webhook methods accept an optional `api_key` argument naming
  the *owner* of the subscription (sent in the body as `apiKey`), defaulting to
  the client's own key so existing calls stay byte-identical on the wire. A
  privileged key sent in the `X-Api-Key` header can pass a different owner key to
  manage that key's subscriptions — on the modern `webhooks` and
  `subscriptions_email` resources and on the legacy `WebhookApi` /
  `SubscriptionApi` compatibility layer.
- **HTTP/2 on by default.** `h2` is now a core dependency, so the SDK-owned
  transport negotiates HTTP/2 out of the box, multiplexing concurrent API calls
  over one connection. A new `http2` constructor argument (`Vulners` /
  `AsyncVulners`, default `True`) lets you force HTTP/1.1 with `http2=False` —
  preferable for a huge single-stream archive download, where HTTP/1.1 avoids
  h2's flow-control window overhead. Ignored when a custom `http_client` is
  supplied (set HTTP/2 on that client instead).
- **Faster, more modern transport by default, no build step.** A plain
  `pip install vulners` now bundles response compression (`brotli` + `zstandard`,
  so the client advertises `Accept-Encoding: gzip, deflate, br, zstd` and httpx
  decompresses transparently), ISA-L-accelerated gzip inflate (`isal`) on the
  archive hot path, multi-member gzip decoding (no longer truncated at the first
  member), and multi-member zip streaming (`stream-unzip`) — all as core
  dependencies with prebuilt wheels for CPython 3.10–3.14. The former `http2`,
  `stream-zip` extras are removed (their contents are now core); `mcp` and `otel`
  remain the only extras.
- Proxy configuration via the `proxy=` argument (a URL or `httpx.Proxy`), plus
  automatic support for the `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` environment
  variables (honouring `NO_PROXY`) when `trust_env` is set.
- License change to **MIT** for 4.0.0.

### Compatibility

- The entire v3 API (`VulnersApi`, `VScannerApi`, `vulners.base.*`,
  `vulners.vulners.*`, all import paths) is preserved unchanged. Existing code
  keeps working; new code should prefer the v4 clients.

## [3.2.0] - 2026-07-19

This is a bug-fix release that keeps the observable behavior of successful calls
unchanged; the changes below repair broken paths (crashes, hangs, resource
leaks, "garbage returned as success") and add small additive surfaces.

### Added

- Optional `max_response_bytes` constructor argument (default `None` = no limit,
  behavior unchanged). When set, both the raw response body and the output of
  gzip/zip decompression are bounded by it and a `VulnersApiError` is raised on
  overflow, so a decompression bomb or an unbounded response from a compromised
  upstream cannot exhaust memory. Left unset, large archive downloads (which can
  reach several gigabytes) keep working exactly as before.
- `vulners.__version__` is now re-exported from the package root.
- `__all__` on the package root pins the public surface to `VulnersApi`,
  `VScannerApi` and `VulnersApiError`.
- PEP 561 `py.typed` marker so type checkers read the inline annotations; note
  that strict-mode consumers may now surface real type errors that were
  previously hidden.
- `typing-extensions (>=4.12)` and `typing-inspection (>=0.4)` are declared as
  direct dependencies instead of being relied on transitively through pydantic.
- `VulnersApiError.retry_after` is populated from a `Retry-After` response header
  when present; the two-argument constructor stays valid.
- `VulnersApiError` now parses the server's problem description into `.message`
  and `.error_code` (and keeps the full redacted payload on `.data`) across the
  v3 (`error`/`errorCode`), v4 (`errors`/`detail`) and plain-text error shapes,
  without echoing the request `input` a validation item carries. `str(err)`
  shows the human-readable message.
- `VulnersDeprecationWarning` category and PEP 702-style `__deprecated__` runtime
  markers on deprecated methods.
- `VulnersApi` / `VScannerApi` now support `close()` and the context-manager
  protocol (`with VulnersApi(key) as api: ...`), which release the underlying
  httpx connection pool; the transport wrapper delegates `close()` to the inner
  transport so the pool is actually torn down.
- Package metadata now declares an SPDX `GPL-3.0-only` license and Homepage,
  Repository, Documentation and Changelog project URLs.

### Changed

- `import vulners` no longer flips the process-global `DeprecationWarning`
  filter. The SDK's own notices are shown via a filter scoped to
  `VulnersDeprecationWarning`, so a host application's `-W` / `PYTHONWARNINGS`
  policy for other libraries is preserved.
- Rate-limit buckets are now per-instance rather than shared at class level, so
  separate instances / API keys no longer couple their limits; N instances with
  the same key may now issue up to N times the request rate (the server remains
  authoritative through its rate-limit header).
- POST/PUT/PATCH request bodies are serialized with orjson; the bytes on the
  wire are unchanged.
- Package description no longer claims a non-existent command-line utility, and a
  stray "Version Control" classifier was removed.
- The ruff `target-version` is pinned to `py310` to match the declared python
  floor, so lint rules no longer allow 3.11-3.13-only syntax.
- Example scripts under `samples/` are task-oriented, live-tested scenarios that
  read the API key from the `VULNERS_API_KEY` environment variable, and each
  shows the direct `api_key="YOUR_API_KEY_HERE"` form as a comment alternative.
- VScanner object-model list wrappers are parametrized over their element type
  and the delegate methods carry return types. Annotation-only, no runtime
  change.
- `SubscriptionV4Api.update()` now documents that it is a full-replace operation:
  optional arguments left out are sent with SDK defaults and overwrite the
  subscription's current values (the server does not support a partial PUT).
  A true partial update belongs to the v4 client API.

### Security

- `VulnersApiError` now masks API-key material before it is stringified: a
  value under an `apiKey` / `X-Api-Key` field, or a server echo of the request
  that carried the key, is replaced with `[REDACTED]` in `str()` / `repr()`, so
  it can no longer leak into logs, APM or a crash reporter. An ordinary error
  payload carries no key, so its representation is unchanged.
- The `X-Api-Key` header is registered with httpx's sensitive-header set, so it
  renders as `[secure]` in `repr(headers)` and DEBUG/event-hook logs instead of
  showing the key in clear text. The on-wire header and every value accessor are
  unchanged.
- The `X-Api-Key` header is now stripped from any redirect hop that leaves the
  configured `server_url` origin. `follow_redirects=True` is unchanged, but an
  open redirect to a third-party host no longer receives the API key (httpx
  only strips `Authorization`); a plain http->https upgrade of the same host
  keeps the key.
- The API key is now also scrubbed from the request body and query on a
  cross-origin redirect, not just the header. An `add_api_key` endpoint injects
  the key into the JSON/form body (or the GET query), which a 307/308 preserves
  across the hop; the credential is now removed from the outgoing cross-origin
  request. Same-origin requests are untouched and stay byte-identical.
- A cross-origin redirect whose target is a private or internal IP literal
  (`127.0.0.0/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, `169.254.0.0/16`
  link-local incl. the cloud metadata endpoint, `0.0.0.0`, and other
  reserved/multicast ranges) is now refused instead of followed, so a
  server- or MITM-controlled `Location` cannot turn the client into an SSRF
  probe. `follow_redirects=True` is unchanged and any public host (e.g. a
  `storage.googleapis.com` archive redirect) still works; an on-prem private-IP
  `server_url` is same-origin and unaffected.
- `VScannerApi.get_image_binary` now rejects a server `image_uri` whose
  normalized path escapes `/vscanner/screen/`, closing a path-traversal that
  could retarget the authenticated GET at another endpoint on the same host;
  the request bytes for a legitimate uri are unchanged.
- The `image_uri` decode-to-fixed-point loop in `VScannerApi.get_image_binary`
  is now capped at a fixed number of passes, so a server-supplied uri with
  deeply nested percent-encoding can no longer force an O(n^2) amount of
  decoding work. A legitimate uri settles in one or two passes and is
  unaffected.
- An opt-in `max_response_bytes` limit (see Added) closes a decompression-bomb
  and an unbounded-response-buffering vector as a defense-in-depth knob; it is
  off by default so byte-for-byte behavior is unchanged.
- CI now pins the third-party GitHub Actions (`actions/checkout`,
  `actions/setup-python`) to full commit SHAs instead of mutable major tags, so
  a moved tag on a compromised upstream cannot inject code into the runner.
- File uploads (e.g. `audit.sbom_audit`) now validate the opened file
  descriptor with `fstat` and reject a non-regular target (device / FIFO /
  directory), closing the TOCTOU window between the pydantic `FilePath` check
  and the actual `open()`. A regular file (including a symlink to one) is
  uploaded exactly as before.
- The API key is no longer duplicated into the query string of the
  `SubscriptionApi.list` and `WebhookApi.list` GET requests, where it could leak
  into access logs, proxies and APM; these endpoints authenticate header-only
  via `X-Api-Key` (CWE-598). `WebhookApi.read` still sends the key in the query
  because the server requires it there.

### Fixed

- `search_bulletins` (and `search_exploits`) with `offset >= 10000` now raises a
  clear `ValueError` (the backend caps the search window at 10000 documents),
  instead of a confusing pydantic `ValidationError` about a `size` field the
  caller never passed. Use the archive API to retrieve more.
- The audit / subscription bulletin-field enums gained server-confirmed values
  (`cvss`, `bulletinFamily`, `lastseen`) and now accept any string via a
  `| str` union, so a legal server field name (e.g. `cvss3`) no longer trips a
  client-side `ValidationError`; known values are byte-identical on the wire.
- The `retry_count` constructor argument is now documented honestly: it only
  retries connection failures (ConnectError / ConnectTimeout), not HTTP error
  responses (429, 5xx) or read timeouts, and it is not applied at all when a
  proxy is configured on httpx 0.28.
- `SubscriptionV4Api.get` now sends the `subscription_id` query parameter the
  server requires instead of `id` (which returned 400, leaving the method dead).
  It accepts either `id` or `subscription_id` for convenience — `get("...")`,
  `get(id=...)` and `get(subscription_id=...)` are equivalent.
- `import vulners` no longer raises `PackageNotFoundError` when the distribution
  metadata is absent (checkout / PYTHONPATH / vendored / frozen); the version
  falls back to `"unknown"`.
- HTTP >= 400 responses that carry a `{"data": ...}` body are no longer returned
  as a successful result; they raise `VulnersApiError` (whose `.message` /
  `.error_code` expose the server's problem description).
- Response handling dispatches on the media-type only, tolerating a
  charset/parameter suffix, a missing `content-type` header and case
  differences, and it checks the status for every content-type.
- HTML/plain gateway error pages (502/503/504) are wrapped in `VulnersApiError`
  instead of leaking a raw `orjson.JSONDecodeError`.
- Empty (EOCD-only) ZIP archives raise the existing `RuntimeError` instead of an
  `IndexError`, and the extracted file object is closed.
- Upload file handles are closed on every path, including errors during a partial
  open or the request itself.
- Path-parameter values are percent-quoted when substituted into the URL so a
  stray `/` (or `?` / `#`) can no longer retarget the request; canonical UUID
  values are unchanged on the wire.
- `RateLimitBucket` no longer hangs forever on a server limit below 60 req/min,
  and zero / negative / non-finite rate headers are ignored instead of crashing
  or freezing the bucket.
- `RateLimitBucket` uses a monotonic clock and is synchronized with a lock (slept
  outside the lock), so a backward clock step or concurrent access can no longer
  freeze it or over-issue tokens.
- `inspect.signature` of a bound endpoint method keeps its first wire parameter
  instead of dropping it as `self`.
- `typing.get_type_hints()` on generated endpoint methods no longer raises
  `NameError`; generated code is compiled with an explicit future flag.
- Endpoint generation no longer depends on `sys._getframe`, so import works on
  interpreters without it.
- `FieldInfo` is selected from `Annotated` metadata without blind indexing,
  fixing import-time crashes on otherwise-valid annotations.
- Deprecation warnings are attributed to the caller's call site via
  `stacklevel`, and a deprecated shim delegating to a deprecated endpoint now
  warns exactly once.

## [3.1.11] - 2026-06-12

### Added

- `audit.cve_batch_audit` API for batch CVE auditing.

## [3.1.10] - 2026-05-18

### Added

- `audit.library` API.

## [3.1.9] - 2026-04-25

### Added

- `audit.cve_audit` API.

### Removed

- `MiscApi.get_ai_score` and the `VulnersApi.get_ai_score` flat alias were
  removed (breaking change).

## [3.1.8] - 2026-03-17

Maintenance release.

## [3.1.7] - 2026-02-26

### Added

- Optional `size` parameter for `search_cpe`.

## [3.1.6] - 2026-02-07

### Added

- `audit.sbom_audit` API.

## [3.1.5] - 2026-01-13

### Changed

- Updated the default request timeout.

## [3.1.4] - 2025-12-28

### Added

- STIX endpoint (`VulnersApi.stix`).

## [3.1.3] - 2025-12-10

### Added

- `references` argument for `get_multiple_bulletins`.

## [3.1.2] - 2025-11-11

### Fixed

- Linux audit request handling.

## [3.1.1] - 2025-09-12

Maintenance release.

## [3.1.0] - 2025-08-10

### Added

- `audit.linux_audit` API.

### Deprecated

- `os_audit` in favor of `audit.linux_audit`.

## [3.0.0] - 2025-05-11

### Changed

- Initial v3 release: the client was rewritten around a declarative endpoint
  generator with pydantic request models, httpx transport and per-endpoint rate
  limiting. Legacy flat methods are retained as deprecated shims.
