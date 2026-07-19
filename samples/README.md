# Examples

Runnable example scripts. Each reads the API key from the `VULNERS_API_KEY`
environment variable — get a free key at [vulners.com](https://vulners.com).

```bash
export VULNERS_API_KEY="your-key"
python samples/v4/search.py
```

Two parallel sets solve the **same tasks** so you can see the migration at a
glance:

| Task | v4 (recommended) | v3 (legacy) |
|---|---|---|
| Search + enrich a CVE | [`v4/search.py`](v4/search.py) | [`legacy/search.py`](legacy/search.py) |
| Find exploits for a CVE | [`v4/exploits.py`](v4/exploits.py) | [`legacy/exploits.py`](legacy/exploits.py) |
| Audit installed software | [`v4/software_scanner.py`](v4/software_scanner.py) | [`legacy/software_scanner.py`](legacy/software_scanner.py) |
| Audit a Linux host | [`v4/linux_audit.py`](v4/linux_audit.py) | [`legacy/linux_audit.py`](legacy/linux_audit.py) |
| Autocomplete + CPE search | [`v4/cpe_search.py`](v4/cpe_search.py) | [`legacy/cpe_search.py`](legacy/cpe_search.py) |
| Async search | [`v4/async_search.py`](v4/async_search.py) | — |

## v4 vs v3 at a glance

```python
# v4 (recommended): a typed client, context-managed, with response models.
from vulners import Vulners
with Vulners(api_key=key) as v:
    cve = v.search.get_bulletin("CVE-2021-44228")
    print(cve.id, cve.cvss.score)          # attribute access on a typed model

# v3 (legacy): still fully supported, unchanged.
import vulners
api = vulners.VulnersApi(api_key=key)
cve = api.search.get_bulletin("CVE-2021-44228")
print(cve["id"], cve["cvss"]["score"])     # dict access
```

The v3 API keeps working exactly as before — migrate at your own pace. See the
[migration guide](../documentation/explanation/migration.md).
