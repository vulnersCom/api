# [Vulners](https://vulners.com) API v3 Python wrapper
Vulners Python API wrapper

```
# mkdir vulnersapi
# cd vulnersapi
# git clone https://github.com/vulnersCom/api
# pip install -U -e api
```

# Examples

Search api usage
```
import vulners

vulnersApi = vulners.Vulners()
heartbleed_related = vulnersApi.search("heartbleed", limit=10)
CVE_2017_14174 = vulnersApi.document("CVE-2017-14174")
```

Software vulnerabilities audit 
```
import vulners

vulnersApi = vulners.Vulners()

# Plain text software + version example for Apache Httpd 1.5
sw_results = vulnersApi.softwareVulnerabilities("httpd", "1.5")
sw_exploit_list = sw_results.get('exploit')
sw_vulnerabilities_list = [sw_results.get(key) for key in sw_results if key not in ['info', 'blog', 'bugbounty']]

# CPE vulnerability search example
cpe_results = vulnersApi.cpeVulnerabilities("cpe:/a:cybozu:garoon:4.2.1")
cpe_exploit_list = cpe_results.get('exploit')
cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
print(cpe_results.keys())
```
