"""Vulnerability intelligence: search the graph and enrich a CVE.

Docs: https://docs.vulners.com/docs/
"""

import os

import vulners

# Direct: VulnersApi(api_key="YOUR_API_KEY_HERE"), or from the environment:
api = vulners.VulnersApi(api_key=os.environ["VULNERS_API_KEY"])

# Newest Fortinet RCEs (Lucene syntax), then full details for one CVE.
for doc in api.search.search_bulletins(
    "Fortinet AND RCE order:published", limit=5, fields=["id", "title", "published"]
):
    print(doc["id"], "-", doc["title"][:60])

cve = api.search.get_bulletin("CVE-2021-44228")
print(cve["id"], cve["cvss"]["score"], cve["cvss"]["severity"])
