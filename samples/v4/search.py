"""Vulnerability intelligence: search the graph and enrich a CVE (v4 API).

Docs: https://docs.vulners.com/docs/
"""

import os

from vulners import Vulners

# Direct: Vulners(api_key="YOUR_API_KEY_HERE"), or from the environment:
with Vulners(api_key=os.environ["VULNERS_API_KEY"]) as v:
    # Newest Fortinet RCEs (Lucene syntax). The page auto-paginates as you iterate;
    # each item is a typed Bulletin model.
    for doc in v.search.query(
        "Fortinet AND RCE order:published", limit=5, fields=["id", "title", "published"]
    ):
        print(doc.id, "-", (doc.title or "")[:60])

    # Full details for one CVE as a typed model.
    cve = v.search.get_bulletin("CVE-2021-44228")
    if cve is not None and cve.cvss is not None:
        print(cve.id, cve.cvss.score, cve.cvss.vector)
