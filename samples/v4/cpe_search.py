"""Assessment helpers: autocomplete a query and resolve software to a CPE (v4 API).

Docs: https://docs.vulners.com/docs/
"""

import os

from vulners import Vulners

# Direct: Vulners(api_key="YOUR_API_KEY_HERE"), or from the environment:
with Vulners(api_key=os.environ["VULNERS_API_KEY"]) as v:
    print("Suggestions:", v.misc.query_autocomplete("heartbleed")[:5])
    print("CPEs:", v.misc.search_cpe("http_server", vendor="apache", size=5))
