# `blog` family

**Model:** `BlogBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: blog`. 35 collections.

## Family fields

Present in every `blog` document, beyond the [common base](base.md).

_No fields beyond the layers above._

## Collections

### `akamaiblog` · ~2.4k documents → `AkamaiblogBulletin`

Akamai Blog provides security advisories and insights related to Akamai's products and services, focusing on web security and performance.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `anandpraka` · ~6 documents → `AnandprakaBulletin`

AnandPraka provides security advisories and CVEs focused on vulnerabilities in various software products and operating systems.

_No fields beyond the layers above._

### `avleonov` · ~390 documents → `AvleonovBulletin`

AVLeonov provides advisories and CVEs related to vulnerabilities in various software products, sourced from multiple vendors and security bulletins.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `carbonblack` · ~850 documents → `CarbonblackBulletin`

Carbon Black's collection includes vendor-specific advisories, CVEs, and threat intelligence related to endpoint security products.

_No fields beyond the layers above._

### `coalfire` · ~600 documents → `CoalfireBulletin`

Coalfire provides security advisories and vulnerability reports focused on various vendors and products, primarily for compliance and risk management.

_No fields beyond the layers above._

### `d0znpp` · ~140 documents → `D0znppBulletin`

The d0znpp collection provides vendor-specific advisories and CVEs related to vulnerabilities in various software products from the d0znpp database.

| field | type | description | example |
|---|---|---|---|
| `aiDescription` | `Any` | AI-generated summary of the vulnerability. |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `filippoio` · ~110 documents → `FilippoioBulletin`

Filippo.io provides security advisories and CVEs focused on vulnerabilities in various software products and libraries, primarily for developers.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `hackread` · ~7.5k documents → `HackreadBulletin`

HackRead provides cybersecurity news and insights, focusing on vulnerabilities, exploits, and advisories related to various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `impervablog` · ~1k documents → `ImpervablogBulletin`

Imperva Blog provides insights and advisories on web application security, focusing on vulnerabilities and exploits related to Imperva products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `intothesymmetry` · ~42 documents → `IntothesymmetryBulletin`

IntotheSymmetry provides advisories and CVEs focused on vulnerabilities in various software products and systems, sourced from multiple vendors.

_No fields beyond the layers above._

### `jakearchibald` · ~120 documents → `JakearchibaldBulletin`

Jake Archibald's collection features security advisories and CVEs primarily focused on web technologies and browser vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `krebs` · ~1.1k documents → `KrebsBulletin`

Krebs on Security provides in-depth articles and analysis on cybersecurity threats, breaches, and vulnerabilities, focusing on various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `malwarebytes` · ~4.7k documents → `MalwarebytesBulletin`

Malwarebytes collection includes advisories and threat intelligence related to malware and security vulnerabilities affecting various software and systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `mmpc` · ~730 documents → `MmpcBulletin`

MMPC is a Microsoft Malware Protection Center collection focusing on Microsoft products, providing advisories, CVEs, and malware threat intelligence.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `msrc` · ~1.4k documents → `MsrcBulletin`

The MSRC collection includes Microsoft Security Response Center advisories and CVEs, focusing on vulnerabilities in Microsoft products and services.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

### `mssecure` · ~1.6k documents → `MssecureBulletin`

Microsoft Security Update Guide collection featuring advisories and CVEs for Microsoft products and services across various platforms.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `pentestit` · ~150 documents → `PentestitBulletin`

PentestIT provides vulnerability advisories and CVEs focused on various software products and services, primarily for penetration testing professionals.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `pentestlab` · ~120 documents → `PentestlabBulletin`

PentestLab is a vulnerability database focused on penetration testing resources, including advisories, CVEs, and exploit techniques for various products.

_No fields beyond the layers above._

### `pentestnepal` · ~9 documents → `PentestnepalBulletin`

PentestNepal provides security advisories and vulnerability reports focused on various software products and services relevant to Nepal's cybersecurity landscape.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `pentestpartners` · ~510 documents → `PentestpartnersBulletin`

Pentest Partners provides security advisories and vulnerability reports focused on various vendors and products, including CVEs and exploit techniques.

_No fields beyond the layers above._

### `qualysblog` · ~1.1k documents → `QualysblogBulletin`

Qualys Blog provides vendor-specific security advisories and insights, focusing on vulnerabilities, CVEs, and best practices for various products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `rapid7community` · ~140 documents → `Rapid7communityBulletin`

Rapid7 Community provides vulnerability advisories and CVEs focused on various software products and platforms, sourced from community contributions.

_No fields beyond the layers above._

### `rhino` · ~83 documents → `RhinoBulletin`

Rhino is a vulnerability collection from the Rhino Security Labs, focusing on advisories and CVEs related to various software products and services.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `ripstech` · ~100 documents → `RipstechBulletin`

Ripstech provides vulnerability data focused on web application security, including advisories and CVEs related to various vendors and products.

_No fields beyond the layers above._

### `schneier` · ~3k documents → `SchneierBulletin`

Schneier's collection provides security advisories and analyses focused on various vulnerabilities across software and systems, sourced from Bruce Schneier's insights.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `securelist` · ~1k documents → `SecurelistBulletin`

Securelist provides vendor-specific security advisories, CVEs, and threat intelligence reports focusing on malware and cyber threats.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `silentrobots` · ~22 documents → `SilentrobotsBulletin`

Silent Robots provides vulnerability data sourced from various vendors, focusing on advisories and CVEs related to web applications and services.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `sonarsource` · ~38 documents → `SonarsourceBulletin`

SonarSource provides security advisories and vulnerability data for various programming languages and frameworks, focusing on code quality and security issues.

_No fields beyond the layers above._

### `talosblog` · ~2k documents → `TalosblogBulletin`

Talos Blog provides security advisories and insights from Cisco Talos, focusing on vulnerabilities across various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `taosecurity` · ~110 documents → `TaosecurityBulletin`

TaoSecurity provides advisories and CVEs focused on security vulnerabilities in various software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `thehackerblog` · ~31 documents → `ThehackerblogBulletin`

The Hacker Blog provides security advisories, CVEs, and exploits focused on various vendors and products, sourced from community contributions.

_No fields beyond the layers above._

### `trendmicroblog` · ~2.3k documents → `TrendmicroblogBulletin`

Trend Micro Blog provides vendor-specific advisories and insights on security threats, vulnerabilities, and product updates related to Trend Micro software.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `wallarmlab` · ~550 documents → `WallarmlabBulletin`

Wallarm Lab provides security advisories and CVEs focused on web application vulnerabilities across various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `websecuritylog` · ~9 documents → `WebsecuritylogBulletin`

WebSecurityLog provides security advisories and CVEs focused on web applications and services, sourced from various vendors and platforms.

_No fields beyond the layers above._

### `wired` · ~3.4k documents → `WiredBulletin`

Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

