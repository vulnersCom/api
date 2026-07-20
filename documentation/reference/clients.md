# Clients

The two entry points to the v4 API. Both take the same arguments and expose the same resource
namespaces (`search`, `documents`, `audit`, `archive`, `misc`, `report`, `stix`,
`subscriptions`, `subscriptions_email`, `webhooks`, `vscanner`); the only difference is that
`AsyncVulners` methods are coroutines.

```python
from vulners import Vulners, AsyncVulners
```

## Vulners

::: vulners.Vulners
    options:
      show_root_heading: true
      heading_level: 3

## AsyncVulners

::: vulners.AsyncVulners
    options:
      show_root_heading: true
      heading_level: 3
