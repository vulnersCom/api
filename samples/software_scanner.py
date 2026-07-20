"""Assessment: find the vulnerabilities affecting your installed software.

Docs: https://docs.vulners.com/docs/
"""

import os

import vulners

# Direct: VulnersApi(api_key="YOUR_API_KEY_HERE"), or from the environment:
api = vulners.VulnersApi(api_key=os.environ["VULNERS_API_KEY"])

# Pass product/version dicts and/or raw CPE 2.3 strings.
for item in api.audit.software(
    [{"product": "openssl", "version": "1.0.1"}, "cpe:2.3:a:apache:log4j:2.14.1"]
):
    print(item["matched_criteria"], "->", len(item["vulnerabilities"]), "vulnerabilities")
