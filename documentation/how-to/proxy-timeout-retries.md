# How to configure proxies, timeouts and retries

The client exposes network policy through constructor arguments and, for full control, a
caller-supplied `httpx` client.

## Timeouts

Pass `timeout` as seconds (applied to connect/read/write/pool) or an `httpx.Timeout` for
per-phase control:

```python
import httpx
from vulners import Vulners

# a single overall budget
v = Vulners(timeout=30.0)

# per-phase
v = Vulners(timeout=httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=10.0))
```

Bulk `archive` downloads use a longer read budget automatically, independent of this setting.

## Retries

`max_retries` bounds automatic retries of transient failures (connection errors, `429` and
`5xx`), with backoff that honors a `Retry-After` header:

```python
v = Vulners(max_retries=5)     # default is 2
```

## Override per call site without a new pool

`with_options` returns a lightweight copy that **shares the same connection pool** but
overrides selected settings — handy for one slow endpoint:

```python
with Vulners() as v:
    patient = v.with_options(timeout=300.0, max_retries=0)
    patient.archive.fetch_collection("cve")
    # `v` still uses its original timeout/retries
```

## Corporate proxy (and any other httpx setting)

For a proxy, custom TLS, HTTP/2 or a mounted transport, build your own `httpx.Client` and
inject it. You own its lifecycle — the SDK will not close a client you passed in:

```python
import httpx
from vulners import Vulners

http_client = httpx.Client(
    proxy="http://proxy.corp.example:8080",
    verify="/etc/ssl/corp-ca.pem",
    http2=True,                          # h2 is a core dependency (no extra needed)
)

with httpx.Client() as _:                # illustrative
    pass

v = Vulners(http_client=http_client)
try:
    v.search.query("type:cve", limit=5)
finally:
    v.close()          # closes the SDK wrapper
    http_client.close()  # you close the client you created
```

For async, inject an `httpx.AsyncClient` into `AsyncVulners(http_client=...)`.

## Cap response size

`max_response_bytes` bounds how many (decompressed) bytes the client will read from a
response — a guard against decompression bombs on untrusted archives:

```python
v = Vulners(max_response_bytes=500 * 1024**2)   # 500 MiB
```
