"""Assessment helpers: autocomplete a query and resolve software to a CPE.

Docs: https://docs.vulners.com/docs/
"""

import os

import vulners

# Direct: VulnersApi(api_key="YOUR_API_KEY_HERE"), or from the environment:
api = vulners.VulnersApi(api_key=os.environ["VULNERS_API_KEY"])

print("Suggestions:", api.misc.query_autocomplete("heartbleed")[:5])
print("CPEs:", api.misc.search_cpe("http_server", vendor="apache", size=5))
