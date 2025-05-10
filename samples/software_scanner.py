# Vulners software vulnerabilities search example

import os

import vulners

vulners_api = vulners.VulnersApi(api_key=os.environ["KEY"])

rules = vulners_api.get_web_application_rules()
print(rules)

# Plain text software + version example for Apache Httpd 1.3
sw_results = vulners_api.audit_software([{"product": "nginx", "version": "1.4"}])
print(sw_results)


sw_results = vulners_api.audit_software(["cpe:2.3:a:adobe:acrobat_reader:20"])
print(sw_results)
