#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners software vulnerabilities search example
# ==============

import vulners

vulners_api = vulners.Vulners(api_key="YOUR_API_KEY_HERE")

# Plain text software + version example for Apache Httpd 1.3
sw_results = vulners_api.softwareVulnerabilities("httpd", "1.3")
sw_exploit_list = sw_results.get('exploit')
sw_vulnerabilities_list = [sw_results.get(key) for key in sw_results if key not in ['info', 'blog', 'bugbounty']]
print(sw_vulnerabilities_list)

# CPE vulnerability search example
cpe_results = vulners_api.cpeVulnerabilities("cpe:/a:cybozu:garoon:4.2.1")
cpe_exploit_list = cpe_results.get('exploit')
cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
print(cpe_results.keys())