"""Assessment: find the vulnerabilities affecting a Linux host's packages (v4 API).

Docs: https://docs.vulners.com/docs/
Collect packages with:  dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'
                        (or  rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n')
"""

import os

from vulners import Vulners

# Direct: Vulners(api_key="YOUR_API_KEY_HERE"), or from the environment:
with Vulners(api_key=os.environ["VULNERS_API_KEY"]) as v:
    report = v.audit.linux_audit(
        os_name="debian", os_version="10", packages=["openssl 1.1.1d-0+deb10u3 amd64"]
    )
    for issue in report["issues"]:
        print(issue["package"])
