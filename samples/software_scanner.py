# Vulners software vulnerabilities search example

import os

import vulners

vulners_api = vulners.VulnersApi(api_key=os.environ["KEY"])

rules = vulners_api.misc.get_web_application_rules()
print(rules)

# Plain text software + version example for Apache Httpd 1.3
sw_results = vulners_api.audit.software([{"product": "nginx", "version": "1.4"}])
print(sw_results)


sw_results = vulners_api.audit.software(["cpe:2.3:a:adobe:acrobat_reader:20"])
print(sw_results)
