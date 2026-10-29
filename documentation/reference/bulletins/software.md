# `software` family

**Model:** `SoftwareBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: software`.

## Family fields

Present in every `software` document, beyond the [common base](base.md).

_No fields beyond the layers above._

## Collections

### `acronis` · ~260 documents → `AcronisBulletin`

Acronis vulnerability collection includes advisories and CVEs related to Acronis software products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "42569", "operator": "lt", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `adobe` · ~820 documents → `AdobeBulletin`

Adobe's vulnerability collection includes advisories and CVEs related to Adobe products, addressing security issues across various software and platforms.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "6.10", "operator": "le", "name"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `android` · ~610 documents → `AndroidBulletin`

Android vulnerabilities collection from various sources, covering advisories and CVEs related to Android OS and applications.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "lt", "version": "7.0", "name":…` |
| `aiDescription` | `Any` | AI-generated summary of the vulnerability. |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `androidsecurity` · ~410 documents → `AndroidsecurityBulletin`

Android Security collection includes advisories and CVEs related to vulnerabilities in the Android OS and its ecosystem from Google's security updates.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `anthropic` · ~240 documents → `AnthropicBulletin`

Anthropic collection includes security advisories and CVEs related to vulnerabilities in Anthropic's AI products and services.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `appercut` · ~22 documents → `AppercutBulletin`

Appercut provides security advisories and CVEs related to vulnerabilities in various software applications and platforms.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "3.4.1", "name…` |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). | `{"reportPages": [{"vulnerabilities": [{"apper…` |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `apple` · ~1.6k documents → `AppleBulletin`

Apple's vulnerability database includes advisories and CVEs related to security issues in Apple products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "27.2", "operator": "lt", "name"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `arista` · ~200 documents → `AristaBulletin`

Arista's vulnerability collection includes advisories and CVEs related to their networking products and software, sourced from Arista Networks.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "4.36.3", "operator": "eq", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `atlassian` · ~4.9k documents → `AtlassianBulletin`

Atlassian's vulnerability collection includes security advisories and CVEs for its software products, focusing on vendor-specific vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `brave` · ~62 documents → `BraveBulletin`

Brave collection includes vulnerability advisories and CVEs specific to the Brave browser, sourced from security bulletins and vendor updates.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.98.62", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `broadcom` · ~1k documents → `BroadcomBulletin`

Broadcom vulnerability collection includes advisories and CVEs for Broadcom products and services, focusing on security issues and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `cakephp` · ~23 documents → `CakephpBulletin`

CakePHP vulnerabilities from the CVE database, covering security advisories and exploits related to the CakePHP framework.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `checkpoint_security` · ~210 documents → `CheckpointSecurityBulletin`

Checkpoint Security provides advisories and CVEs related to vulnerabilities in Check Point products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `chrome` · ~520 documents → `ChromeBulletin`

Google Chrome vulnerability collection includes advisories and CVEs related to security issues in the Chrome browser and its components.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "156.0.8078.73", "operator": "lt…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `cisco` · ~5.3k documents → `CiscoBulletin`

Cisco's vulnerability database provides advisories and CVEs related to security issues in Cisco products and software.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"score": "8.6", "severity": "high"}` |

### `citrix` · ~5.3k documents → `CitrixBulletin`

Citrix vulnerability collection includes advisories and CVEs related to Citrix products and services, sourced from Citrix's official security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "14.1-73.41", "operator": "lt", …` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `clickhouse` · ~49 documents → `ClickhouseBulletin`

ClickHouse vulnerability collection includes advisories and CVEs specific to ClickHouse database software, sourced from various security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "v25.1.5.5", "operator": "lt", "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `cloudfoundry` · ~1.1k documents → `CloudfoundryBulletin`

Cloud Foundry vulnerability data from various vendors, focusing on cloud platform advisories and CVEs related to Cloud Foundry components.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

### `contao` · ~50 documents → `ContaoBulletin`

Contao vulnerability collection provides advisories and CVEs specific to the Contao CMS, sourced from security bulletins and community reports.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "5.0", "operator": "eq", "name":…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `curl` · ~240 documents → `CurlBulletin`

This collection from the curl project includes advisories and CVEs related to vulnerabilities in the curl command-line tool and library across various platforms.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "8.14.3", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `curlAffects` | `str | None` | Affected curl versions (curl advisories). | `"both"` |
| `curlSeverity` | `str | None` | curl project's severity rating. | `"High"` |
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-416"]` |

### `drupal` · ~2.2k documents → `DrupalBulletin`

Drupal security advisories from the Drupal security team, including CVEs and patches for vulnerabilities in Drupal CMS and its modules.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `elastic` · ~380 documents → `ElasticBulletin`

Elastic's vulnerability collection includes advisories and CVEs related to Elastic products, focusing on security issues and patches for their software.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `f5` · ~6.9k documents → `F5Bulletin`

F5 collection includes security advisories and CVEs related to F5 Networks products and services, focusing on vulnerabilities and exploits.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "8.4.2", "operator": "eq", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `related` | `list[str] | None` | Ids of related Vulners documents. | `["https://my.f5.com/manage/s/article/K4194260…` |

### `fortinet` · ~900 documents → `FortinetBulletin`

Fortinet collection includes security advisories and CVEs related to Fortinet products and services, focusing on vulnerabilities and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `friendsofphp` · ~1.8k documents → `FriendsofphpBulletin`

FriendsOfPHP is a community-driven collection of security advisories for PHP projects, including CVEs and vulnerability details.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "13.4.4", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `fuelphp` · ~9 documents → `FuelphpBulletin`

FuelPHP vulnerabilities from the FuelPHP security advisory database, covering vulnerabilities in the FuelPHP framework, including CVEs and advisories.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.8.0", "operator": "le", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `github` · ~160k documents → `GithubBulletin`

GitHub collection includes vulnerability advisories and CVEs related to open-source projects hosted on GitHub, focusing on various software products and libraries.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `Any` | Affected libraries/packages (name, purl, version range). | `[{"registry": "npm", "name": "dsh-redteam-mod…` |
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "0.15.2", "operator": "eq", "eco…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-506"]` |
| `malware` | `bool | None` | Whether the advisory reports a malicious package itself (GitHub's 'Malware in …' entries) rather than a vulnerability in a legitimate one. | `true` |
| `purls` | `list[str] | None` | Affected packages as Package-URL (purl) strings. | `["pkg:npm/dsh-redteam-mode@0.15.2"]` |
| `withdrawn` | `Any` | Withdrawal date if the advisory was retracted. |  |

### `gitlab` · ~1.6k documents → `GitlabBulletin`

GitLab's vulnerability database provides advisories and CVEs related to security issues in GitLab products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "0.4.112", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cweIds` | `list[str] | None` | Associated CWE weakness identifiers (alternate key). | `["CWE-345", "CWE-937", "CWE-940", "CWE-1035"]` |
| `solution` | `str | None` | Recommended remediation/fix, as text. | `"Upgrade to version 0.4.112 or above."` |
| `vendorCvss2` | `Any` | Vendor-assigned CVSS v2. |  |
| `vendorCvss3` | `str | None` | Vendor-assigned CVSS v3. | `"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"` |

### `grafana` · ~130 documents → `GrafanaBulletin`

Grafana collection includes security advisories and CVEs related to Grafana software, focusing on vulnerabilities affecting the Grafana product.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N…` |

### `hackapp` · ~24k documents → `HackappBulletin`

HackApp is a vulnerability database focused on mobile applications, providing advisories, CVEs, and exploit information relevant to app security.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "Varies with d…` |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. | `{"apk": "COM.COINBASE.ANDROID.APK", "bugs": […` |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `hashicorp` · ~210 documents → `HashicorpBulletin`

HashiCorp's vulnerability collection includes security advisories and CVEs related to its products and services, focusing on cloud infrastructure and automation tools.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2.0.4", "operator": "le", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `hashicorpBulletinId` | `str | None` | HashiCorp advisory identifier. | `"HCSEC-2026-50"` |
| `hashicorpProducts` | `list[str] | None` | Affected HashiCorp products. | `["consul-k8s"]` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. |  |

### `hp` · ~650 documents → `HpBulletin`

HP's vulnerability collection provides advisories and CVEs related to HP products and software, focusing on security issues and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.87.4769.0", "operator": "lt",…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `hpe` · ~1.2k documents → `HpeBulletin`

HPE collection includes security advisories and CVEs related to Hewlett Packard Enterprise products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/…` |

### `htbridge` · ~560 documents → `HtbridgeBulletin`

HTBridge provides security advisories and vulnerability assessments focused on web applications and related technologies.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "3.9.2", "operator": "le", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `httpd` · ~270 documents → `HttpdBulletin`

Apache HTTP Server vulnerabilities from the Apache Software Foundation, including advisories, CVEs, and security patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2.4.53", "operator": "eq", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `huawei` · ~1k documents → `HuaweiBulletin`

Huawei's collection includes security advisories and CVEs related to Huawei products and software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "EnzoH-W5611T", "operator": "eq"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": false, "vulnersCpeConfiguration": …` |

### `ibm` · ~39k documents → `IbmBulletin`

IBM's vulnerability collection includes advisories and CVEs specific to IBM products and software, sourced from IBM's security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "3.7.0", "operator": "eq", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `ivanti` · ~300 documents → `IvantiBulletin`

Ivanti's vulnerability collection includes security advisories and CVEs related to Ivanti products and services, focusing on vendor-specific vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `jenkins` · ~1.6k documents → `JenkinsBulletin`

Jenkins vulnerability collection includes advisories and CVEs related to Jenkins software, focusing on security issues affecting the Jenkins automation server.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2.580.2", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `jenkinsAdvisoryId` | `str | None` | Jenkins advisory identifier. | `"2026-10-28"` |
| `jenkinsCore` | `Any` | Affected Jenkins core version. | `{"lts": {"previous": "2.580.1", "fixed": "2.5…` |
| `jenkinsKind` | `str | None` | Jenkins advisory kind (core/plugin). | `"core"` |
| `jenkinsPlugins` | `Any` | Affected Jenkins plugins (name, fixed/previous versions). |  |
| `jenkinsReporter` | `str | None` | Reporter credited by the Jenkins advisory. | `"Anthropic OSS program"` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"severity": "High", "vector": "CVSS:3.1/AV:N…` |

### `jetbrains` · ~12 documents → `JetbrainsBulletin`

JetBrains collection includes security advisories and CVEs related to JetBrains products, focusing on vulnerabilities in their development tools and IDEs.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2021.1.13890", "operator": "lt"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `joomla` · ~760 documents → `JoomlaBulletin`

Joomla collection includes security advisories, CVEs, and patches specific to vulnerabilities in the Joomla CMS platform.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "5.4.8", "operator": "lt", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `korelogic` · ~100 documents → `KorelogicBulletin`

KoreLogic provides security advisories and vulnerability data focused on various software products and services, including CVEs and exploit information.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "6.05.15", "operator": "eq", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `kubernetes` · ~94 documents → `KubernetesBulletin`

Kubernetes collection includes security advisories, CVEs, and patches specific to Kubernetes and its components from various vendors.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.34.12", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `kubernetesIssueNumber` | `int | None` | Kubernetes issue number for the advisory. | `142098` |
| `kubernetesStatus` | `str | None` | Status of the Kubernetes advisory. | `"fixed"` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/…` |

### `laminas` · ~5 documents → `LaminasBulletin`

Laminas vulnerability collection includes advisories and CVEs related to the Laminas PHP framework, focusing on security issues affecting its components.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2.18.0", "operator": "le", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `mend` · ~170k documents → `MendBulletin`

Mend provides security advisories and CVEs focused on open-source vulnerabilities across various software products and dependencies.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list | None` | Affected libraries/packages (name, purl, version range). | `[{"registry": "golang", "name": "github.com/i…` |
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-95"]` |

### `modx` · ~22 documents → `ModxBulletin`

MODX vulnerability collection includes advisories and CVEs related to the MODX CMS, focusing on security issues affecting its core and plugins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "2.6.4", "name…` |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `mongodb` · ~340 documents → `MongodbBulletin`

MongoDB vulnerability collection includes advisories and CVEs related to MongoDB database software, focusing on security issues and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2.14.0", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `mozilla` · ~1.6k documents → `MozillaBulletin`

Mozilla collection includes security advisories and CVEs related to Mozilla products, primarily focusing on vulnerabilities in Firefox and other Mozilla software.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "115.44", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `msvr` · ~46 documents → `MsvrBulletin`

MSVR is a Microsoft vulnerability database focusing on vendor-specific advisories and CVEs related to Microsoft products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "le", "version": "3.1.00495", "…` |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `nextcloud` · ~400 documents → `NextcloudBulletin`

Nextcloud vulnerability collection includes advisories and CVEs related to Nextcloud software, focusing on security issues for the Nextcloud platform.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "9.0.0", "operator": "lt", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `nginx` · ~68 documents → `NginxBulletin`

Nginx vulnerability collection includes advisories and CVEs related to the Nginx web server, focusing on security issues affecting its software.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.31.6", "operator": "le", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `nodejs` · ~1.6k documents → `NodejsBulletin`

Node.js vulnerability collection from various sources, focusing on advisories and CVEs related to Node.js applications and libraries.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "lt", "version": "0.8.4", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `nodejsblog` · ~80 documents → `NodejsblogBulletin`

Node.js Blog: A collection from various sources focusing on Node.js vulnerabilities, including advisories, CVEs, and security best practices.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `nvidia` · ~280 documents → `NvidiaBulletin`

NVIDIA collection includes security advisories and CVEs related to NVIDIA products and drivers, focusing on vulnerabilities affecting their software and hardware.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "616.56", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `openssl` · ~300 documents → `OpensslBulletin`

OpenSSL collection includes advisories, CVEs, and security updates specifically related to the OpenSSL cryptographic library.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "4.0.3", "operator": "lt", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `opera` · ~390 documents → `OperaBulletin`

Opera collection includes vulnerability advisories and CVEs related to the Opera web browser, focusing on browser security issues and exploits.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `oracle` · ~100 documents → `OracleBulletin`

Oracle's vulnerability database provides advisories and CVEs related to Oracle products and systems, focusing on security issues and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "24.2.0", "operator": "le", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### `ossf` · ~240k documents → `OssfBulletin`

OSSF provides security advisories and CVEs focused on open-source software vulnerabilities, sourced from various community contributions and reports.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

### `ossfuzz` · ~18k documents → `OssfuzzBulletin`

OSFuzz is a vulnerability collection from the Open Source Security Foundation focusing on security issues in open-source software, including advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `ossfuzz` | `Any` | OSS-Fuzz crash details (crash type, project, issue). | `{"issue": 577758652, "status": "Verified", "p…` |

### `owncloud` · ~310 documents → `OwncloudBulletin`

OwnCloud collection includes security advisories and CVEs related to the OwnCloud file sharing platform, focusing on vulnerabilities affecting its software.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "10.15.0", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `paloalto` · ~740 documents → `PaloaltoBulletin`

Palo Alto Networks collection includes advisories and CVEs related to their security products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### `patchstack` · ~53k documents → `PatchstackBulletin`

Patchstack provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "3.2.7", "operator": "le", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `classification` | `str | None` | Source-specific classification/category of the issue. | `"Cross Site Scripting (XSS)"` |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `isExploited` | `bool | None` | Whether the vulnerability is known to be exploited. | `false` |
| `owasp` | `str | None` | Related OWASP category. | `"A7: Cross-Site Scripting (XSS)"` |
| `vendor_cvss` | `Any` | Vendor-assigned CVSS (raw object). |  |

### `phpmyadmin` · ~230 documents → `PhpmyadminBulletin`

phpMyAdmin collection includes security advisories and CVEs related to vulnerabilities in the phpMyAdmin web-based database management tool.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "5.2.2", "operator": "le", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `postgresql` · ~180 documents → `PostgresqlBulletin`

PostgreSQL vulnerabilities database provides advisories and CVEs specific to PostgreSQL database server security issues.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "17.11", "operator": "lt", "name…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `pypa` · ~8k documents → `PypaBulletin`

The PyPA collection contains Python Package Authority advisories and CVEs related to Python packages and their vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.2.1.0", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `rubygems` · ~1.3k documents → `RubygemsBulletin`

RubyGems collection includes vulnerability advisories and CVEs specifically for Ruby libraries and gems, sourced from the Ruby community.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "2.14.1", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `rustsec` · ~1.4k documents → `RustsecBulletin`

RustSec is a vulnerability database focused on Rust programming language packages, providing advisories and CVEs related to security issues in Rust crates.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "ge", "version": "0.12.0", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `securityvulns` · ~47k documents → `SecurityvulnsBulletin`

A collection of security vulnerabilities sourced from various vendors, covering advisories and CVEs across multiple products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "eq", "version": "2.18", "name"…` |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `sick` · ~74 documents → `SickBulletin`

The "sick" collection includes advisories and CVEs from various vendors, focusing on vulnerabilities in software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `aiDescription` | `Any` | AI-generated summary of the vulnerability. |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `sonicwall` · ~210 documents → `SonicwallBulletin`

SonicWall collection includes advisories and CVEs related to SonicWall products and services, sourced from their security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `aiDescription` | `Any` | AI-generated summary of the vulnerability. |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-863", "CWE-78"]` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. |  |

### `sqlite` · ~53 documents → `SqliteBulletin`

SQLite vulnerabilities collection includes advisories and CVEs related to SQLite database software, focusing on security issues affecting its functionality.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "3.53.2", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `symantec` · ~6.9k documents → `SymantecBulletin`

Symantec's collection includes security advisories and CVEs related to its software products and services, focusing on vulnerabilities and exploits.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "4", "operator": "eq", "name": "…` |

### `symfony` · ~76 documents → `SymfonyBulletin`

Symfony collection includes vulnerability advisories and CVEs related to the Symfony framework, focusing on PHP applications and components.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `tibco` · ~220 documents → `TibcoBulletin`

TIBCO collection includes security advisories and CVEs related to TIBCO software products, focusing on vulnerabilities affecting their applications and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "4.", "operator": "eq", "name": …` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `tomcat` · ~360 documents → `TomcatBulletin`

This collection includes advisories and CVEs related to Apache Tomcat vulnerabilities, sourced from official Apache security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"operator": "ge", "version": "10.1.0-M1", "…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `typo3` · ~470 documents → `Typo3Bulletin`

TYPO3 vulnerability collection from various sources, covering advisories and CVEs specific to the TYPO3 CMS platform.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "v11", "operator": "eq", "name":…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `vaadin` · ~53 documents → `VaadinBulletin`

Vaadin collection includes security advisories and CVEs related to the Vaadin framework, focusing on vulnerabilities affecting web applications built with it.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "14.14.8", "operator": "lt", "na…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `severity` | `str | None` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"HIGH"` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"severity": "HIGH", "score": "8."}` |

### `veeam` · ~1.8k documents → `VeeamBulletin`

Veeam collection includes advisories and CVEs related to Veeam software products, focusing on vulnerabilities affecting backup and recovery solutions.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "13.1", "operator": "eq", "name"…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `veracode` · ~39k documents → `VeracodeBulletin`

Veracode provides security advisories and vulnerability data focused on application security for various software products and vendors.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "1.1.10.8", "operator": "le", "n…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `vivaldi` · ~70 documents → `VivaldiBulletin`

Vivaldi collection includes security advisories and CVEs related to the Vivaldi web browser, focusing on vulnerabilities affecting its functionality and security.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `vmware` · ~550 documents → `VmwareBulletin`

VMware collection includes security advisories and CVEs related to VMware products and services, sourced from VMware's official security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "26H1u1", "operator": "lt", "nam…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"severity": "Critical", "CVSSv3": "7.5-9.8"}` |

### `wpvulndb` · ~15k documents → `WpvulndbBulletin`

Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `exploit` | `str | None` | Exploit availability/details (source-specific). | `"The PoC will be displayed on November 09, 20…` |
| `generation` | `int | None` | Internal generation/version counter of the record. | `0` |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |

### `xen` · ~510 documents → `XenBulletin`

Xen collection includes security advisories and CVEs related to the Xen hypervisor, covering vulnerabilities affecting virtualization environments.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "4.5", "operator": "eq", "name":…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### `yubico` · ~23 documents → `YubicoBulletin`

Yubico collection includes advisories and CVEs related to Yubico's authentication products and services, sourced from their official security bulletins.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

