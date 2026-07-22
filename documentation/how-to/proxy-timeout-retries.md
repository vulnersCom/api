# How to configure proxies, timeouts and retries

The client exposes network policy through constructor arguments and, for full control, a
caller-supplied `httpx` client.

## Timeouts

Pass `timeout` as seconds (applied to connect/read/write/pool) or an `httpx.Timeout` for
per-phase control:

=== "Sync"

    ```python
    import httpx
    from vulners import Vulners

    # a single overall budget
    v = Vulners(timeout=30.0)

    # per-phase
    v = Vulners(timeout=httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=10.0))
    ```

=== "Async"

    ```python
    import httpx
    from vulners import AsyncVulners

    # a single overall budget
    v = AsyncVulners(timeout=30.0)

    # per-phase
    v = AsyncVulners(timeout=httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=10.0))
    ```

Bulk `archive` downloads use a longer read budget automatically, independent of this setting.

## Retries

`max_retries` bounds automatic retries of transient failures (connection errors, `429` and
`5xx`), with backoff that honors a `Retry-After` header:

=== "Sync"

    ```python
    v = Vulners(max_retries=5)     # default is 2
    ```

=== "Async"

    ```python
    v = AsyncVulners(max_retries=5)     # default is 2
    ```

## Override per call site without a new pool

`with_options` returns a lightweight copy that **shares the same connection pool** but
overrides selected settings — handy for one slow endpoint:

=== "Sync"

    ```python
    with Vulners() as v:
        patient = v.with_options(timeout=300.0, max_retries=0)
        patient.archive.fetch_collection("cve")
        # `v` still uses its original timeout/retries
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        patient = v.with_options(timeout=300.0, max_retries=0)
        await patient.archive.fetch_collection("cve")
        # `v` still uses its original timeout/retries
    ```

## Proxies

Route SDK traffic through a proxy with the `proxy=` argument — a URL string, or an
`httpx.Proxy` for an authenticated proxy:

=== "Sync"

    ```python
    import httpx
    from vulners import Vulners

    v = Vulners(proxy="http://proxy.corp.example:8080")

    # authenticated proxy
    v = Vulners(proxy=httpx.Proxy("http://proxy.corp.example:8080", auth=("user", "pass")))
    ```

=== "Async"

    ```python
    import httpx
    from vulners import AsyncVulners

    v = AsyncVulners(proxy="http://proxy.corp.example:8080")
    v = AsyncVulners(proxy=httpx.Proxy("http://proxy.corp.example:8080", auth=("user", "pass")))
    ```

### From the environment

With no explicit `proxy=` and `trust_env=True` (the default), the client honors the standard
proxy environment variables — `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` — with `NO_PROXY`
exemptions:

```bash
export HTTPS_PROXY="http://proxy.corp.example:8080"
export NO_PROXY="localhost,127.0.0.1,.internal.example"
```

Pass an explicit `proxy=` to override them, or `trust_env=False` to ignore the environment.

### A proxy together with custom TLS or transport

For a proxy *plus* custom TLS, HTTP/2 tuning or a mounted transport, build your own `httpx`
client and inject it. You own its lifecycle — the SDK will not close a client you passed in
(and `proxy=`/`verify=` cannot be combined with `http_client=`):

=== "Sync"

    ```python
    import httpx
    from vulners import Vulners

    http_client = httpx.Client(
        proxy="http://proxy.corp.example:8080",
        verify="/etc/ssl/corp-ca.pem",
        http2=True,                          # h2 is a core dependency (no extra needed)
    )

    v = Vulners(http_client=http_client)
    try:
        v.search.query("type:cve", limit=5)
    finally:
        v.close()            # closes the SDK wrapper
        http_client.close()  # you close the client you created
    ```

=== "Async"

    ```python
    import httpx
    from vulners import AsyncVulners

    http_client = httpx.AsyncClient(
        proxy="http://proxy.corp.example:8080",
        verify="/etc/ssl/corp-ca.pem",
        http2=True,                          # h2 is a core dependency (no extra needed)
    )

    v = AsyncVulners(http_client=http_client)
    try:
        await v.search.query("type:cve", limit=5)
    finally:
        await v.aclose()            # closes the SDK wrapper
        await http_client.aclose()  # you close the client you created
    ```

## Cap response size

`max_response_bytes` bounds how many (decompressed) bytes the client will read from a
response — a guard against decompression bombs on untrusted archives:

=== "Sync"

    ```python
    v = Vulners(max_response_bytes=500 * 1024**2)   # 500 MiB
    ```

=== "Async"

    ```python
    v = AsyncVulners(max_response_bytes=500 * 1024**2)   # 500 MiB
    ```
