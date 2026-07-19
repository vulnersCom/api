<div align="center">

# 🛡️ Vulners Python SDK

### The official Python client for [Vulners](https://vulners.com) — the vulnerability intelligence graph to build on

Query CVEs, exploits and advisories enriched with CVSS, EPSS and exploitation status; assess your
software, hosts and SBOMs for the vulnerabilities that affect them; and stream the whole graph for
your own pipelines — all from a few lines of Python.

[![PyPI version](https://img.shields.io/pypi/v/vulners?color=blue&label=pypi)](https://pypi.org/project/vulners/)
[![Python versions](https://img.shields.io/pypi/pyversions/vulners)](https://pypi.org/project/vulners/)
[![Downloads](https://img.shields.io/pypi/dm/vulners?color=blue)](https://pypi.org/project/vulners/)
[![CI](https://github.com/vulnersCom/api/actions/workflows/ci.yml/badge.svg)](https://github.com/vulnersCom/api/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/pypi/l/vulners)](https://www.gnu.org/licenses/gpl-3.0)
[![Typed](https://img.shields.io/badge/typing-PEP%20561-brightgreen)](https://peps.python.org/pep-0561/)

[**Documentation**](https://docs.vulners.com/docs/) ·
[**API Reference**](https://docs.vulners.com/docs/api/) ·
[**Get an API key**](https://docs.vulners.com/docs/quickstart/authentication/) ·
[**Vulners.com**](https://vulners.com)

</div>

---

## Why Vulners?

[Vulners](https://vulners.com) aggregates **230+ sources** — CVEs, exploits, vendor advisories,
CISA KEV, EPSS and AI risk scores — into one queryable vulnerability-intelligence graph, so you can
prioritize what to fix **beyond raw CVSS**. It is API-first and needs no agents or network access:
send asset data in standard formats, get back risk-prioritized intelligence.

This SDK is the fastest way to build on that graph from Python:

- 🔎 **Intelligence** — search and enrich CVEs, bulletins and advisories with CVSS, EPSS, KEV and exploitation context
- 🧨 **Exploits** — track active exploitation and pull proof-of-concept code for a product or CVE
- 🖥️ **Assessment** — find the vulnerabilities affecting your software, Linux/Windows hosts, KBs, libraries and SBOMs
- 🗄️ **Datasets** — stream the full graph (and hourly updates) into your own pipelines and mirrors
- 🔔 **Alerts** — subscribe to new vulnerabilities matching a query and get notified via webhook
- 🤖 **AI-ready** — ground AI agents and copilots on live vulnerability facts, with fully typed responses

Powering vulnerability scanners, CI/CD security gates, remediation-prioritization and
threat-intelligence pipelines, SBOM analyzers, MSSP platforms and AI security agents — with
production-grade rate limiting and typed responses out of the box.

---

## Installation

```bash
pip install -U vulners
```

Requires **Python 3.10+**. The only runtime dependencies are
[`httpx`](https://www.python-httpx.org/), [`pydantic`](https://docs.pydantic.dev/), and
[`orjson`](https://github.com/ijl/orjson).

---

## Quickstart

```python
import vulners

# Get a free API key at https://vulners.com
api = vulners.VulnersApi(api_key="YOUR_API_KEY_HERE")

# Look up a CVE
log4shell = api.search.get_bulletin("CVE-2021-44228")
print(log4shell["id"], "—", log4shell["title"])

# Search the database with Lucene syntax
critical = api.search.search_bulletins("type:cve AND cvss.score:[9 TO 10]", limit=10)
for bulletin in critical:
    print(bulletin["id"], bulletin["title"])
```

> **Tip:** keep your key out of source code — read it from the environment instead:
> ```python
> import os
> api = vulners.VulnersApi(api_key=os.environ["VULNERS_API_KEY"])
> ```

---

## Usage examples

Every snippet below is a runnable, real script under [`samples/`](samples/).

### Search with Lucene syntax

```python
for doc in api.search.search_bulletins("Fortinet AND RCE order:published", limit=5):
    print(doc["id"], "-", doc["title"])
```

### Find public exploits for a CVE

```python
for exploit in api.search.search_exploits("CVE-2023-20198", limit=10):
    print(exploit["id"], exploit["href"])
```

### Audit installed software for known CVEs

```python
# Mix product/version dicts and raw CPE 2.3 strings.
for item in api.audit.software([{"product": "openssl", "version": "1.0.1"},
                                "cpe:2.3:a:apache:log4j:2.14.1"]):
    print(item["matched_criteria"], "->", len(item["vulnerabilities"]), "vulnerabilities")
# cpe:2.3:a:apache:log4j:2.14.1:... -> 12 vulnerabilities
```

### Audit a Linux host by installed packages

```python
# dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'  (or rpm -qa ...)
report = api.audit.linux_audit(os_name="debian", os_version="10",
                               packages=["openssl 1.1.1d-0+deb10u3 amd64"])
for issue in report["result"]["issues"]:
    print(issue["package"])
```

### Handle errors and clean up

```python
try:
    with vulners.VulnersApi(api_key="YOUR_API_KEY_HERE") as api:   # releases the pool on exit
        cve = api.search.get_bulletin("CVE-2021-44228")
        print(cve["cvss"]["score"], cve["cvss"]["severity"])       # 10.0 CRITICAL
except vulners.VulnersApiError as err:
    print(err.http_status, err.error_code, err.message)            # the server's problem description
```

More recipes — software/Linux/SBOM audits, CPE search, exploits — live in
[`samples/`](samples/) and the [official API reference](https://docs.vulners.com/docs/api/).

---

## Getting an API key

1. Create a free account at **[vulners.com](https://vulners.com)**.
2. Follow the [authentication guide](https://docs.vulners.com/docs/quickstart/authentication/#how-to-obtain-api-key)
   to generate a key.
3. Pass it to `VulnersApi(api_key=...)`, or export `VULNERS_API_KEY` and read it from the
   environment.

Never commit your API key. The SDK sends it only in the `X-Api-Key` header, strips it on
cross-origin redirects, and keeps it out of exception messages and object reprs.

---

## What's new in 3.2.0

This release keeps the observable behavior of successful calls **100% backward compatible**
while repairing broken paths and hardening the client:

- 🐍 **PEP 561 typed** — ships `py.typed`, so editors and type checkers see the full API.
- 🔁 **Reliable rate limiting** — the token bucket no longer stalls on low or malformed
  server limits and is now thread-safe and per-instance.
- 🧯 **Honest error handling** — HTTP errors and malformed bodies raise `VulnersApiError`
  instead of being silently returned as data.
- 🔐 **Security hardening** — the API key is masked in reprs and errors, stripped on
  cross-origin and internal-address redirects, and an opt-in `max_response_bytes` guard
  bounds decompression of untrusted archives.
- 🧹 **Context-manager support**, accurate deprecation warnings, and `vulners.__version__`.

See the [CHANGELOG](CHANGELOG.md) for the full list.

---

## Documentation

| Resource | Link |
|---|---|
| 📖 Full documentation | https://docs.vulners.com/docs/ |
| 🔌 API reference | https://docs.vulners.com/docs/api/ |
| 🧪 Interactive API (Swagger) | https://docs.vulners.com/docs/api/swagger/ |
| 🔑 Authentication / API keys | https://docs.vulners.com/docs/quickstart/authentication/ |
| 🧬 Data model | https://docs.vulners.com/docs/ |
| 💡 Examples | [`samples/`](samples/) |

---

## Compatibility

- **Python:** 3.10, 3.11, 3.12, 3.13, 3.14
- **Platforms:** Linux, macOS, Windows
- **Vulners API:** v3 and v4 endpoints

---

## Contributing

Issues and pull requests are welcome! Please open an issue to discuss substantial changes
first. Run the test suite with:

```bash
poetry install
poetry run pytest
```

---

## Security

Found a security issue in the SDK? Please report it responsibly — see
[SECURITY.md](SECURITY.md) if present, or contact the Vulners team via
[vulners.com](https://vulners.com). Do not open a public issue for vulnerabilities.

---

## License

Distributed under the **GNU GPL v3.0**. See [LICENSE](LICENSE).

---

<div align="center">

**Built by the [Vulners](https://vulners.com) team.**
If this SDK helps secure your stack, please ⭐ the repo — it helps others find it.

<sub>Keywords: vulnerability intelligence · CVE · exploit intelligence · CVSS · EPSS · CISA KEV ·
risk prioritization · security advisories · SBOM · vulnerability assessment · vulnerability scanner ·
threat intelligence · vulnerability database · AI security agents · MCP · MSSP · DevSecOps ·
Python security · infosec</sub>

</div>
