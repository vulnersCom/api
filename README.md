# [Vulners API v3](https://vulners.com) Python wrapper


# Description
Python 2/3 library for the [Vulners Database](https://vulners.com).
It provides *search, data retrieval, archive and vulnerability scanning* API's for the integration purposes.
With this library you can create powerful security tools and get access to the world largest security database.

## Python version
Library was tested on a *python2* and *python3*.

## How to install

Package is available with [PyPI](https://pypi.python.org/pypi) 

You can use pip for the installation

```bash
pip install -U vulners
```

# Functions and methods

All the callable methods are using [Vulners REST API](https://vulners.com/docs).

### Search in database
```python
import vulners

vulners_api = vulners.Vulners()
heartbleed_related = vulners_api.search("heartbleed", limit=10)
```
### Get information about document by identificator
```python
import vulners

vulners_api = vulners.Vulners()
CVE_2017_14174 = vulners_api.document("CVE-2017-14174")
```
### Search for the public available exploits
```python
import vulners

vulners_api = vulners.Vulners()
wordpress_exploits = vulners_api.searchExploit("wordpress 4.7.0")
```
### Get vulnerabilities and exploits by software name and version
```python
import vulners

vulners_api = vulners.Vulners()

results = vulners_api.softwareVulnerabilities("httpd", "1.5")
exploit_list = results.get('exploit')
vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
```
### Get vulnerabilities by CPE product and version string
```python
import vulners

vulners_api = vulners.Vulners()

cpe_results = vulners_api.cpeVulnerabilities("cpe:/a:cybozu:garoon:4.2.1")
cpe_exploit_list = cpe_results.get('exploit')
cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
```
### Get references for the vulnerability
```python
import vulners

vulners_api = vulners.Vulners()
references = vulners_api.references("CVE-2014-0160")
```
### Score any vulnerability description using [Vulners AI](https://lab.wallarm.com/new-from-wallarm-research-first-ai-based-tool-to-predict-vulnerability-risk-2d0a7e9b3474)
```python
import vulners

vulners_api = vulners.Vulners()
text_ai_score = vulners_api.aiScore("My cool vulnerability description")
```
### Download whole database collection and work with data locally
```python
import vulners

vulners_api = vulners.Vulners()
all_cve = vulners_api.archive("cve")
```
