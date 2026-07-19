# How to audit a host

The `audit` resource assesses inventories against Vulners intelligence. Pick the method that
matches what you can collect from the host.

## Audit a Linux host by installed packages

Collect the installed packages in the distro's native format and pass them to
`audit.linux_audit`:

```python
from vulners import Vulners

# dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'   (Debian/Ubuntu)
# rpm -qa                                                        (RHEL/Alma/Rocky)
# apk info -v                                                    (Alpine)
packages = [
    "openssl 1.1.1d-0+deb10u3 amd64",
    "bash 5.0-4 amd64",
]

with Vulners() as v:
    report = v.audit.linux_audit(
        os_name="debian",
        os_version="10",
        packages=packages,
    )
    print(report)
```

`linux_audit` accepts up to 2500 packages and several toggles — `os_arch`,
`include_unofficial`, `include_candidates`, `include_any_version`, `cvelist_metrics` — see
the [reference](../reference/resources.md#vulners._resources._sync.audit.Audit).

## Audit a host by CPE

If you have CPE identifiers for the host's software (and optionally its OS, application and
hardware), use `audit.host`:

```python
with Vulners() as v:
    report = v.audit.host(
        ["cpe:2.3:a:openssl:openssl:1.0.1"],
        operating_system="cpe:2.3:o:canonical:ubuntu_linux:22.04",
        match="partial",           # or "full"
    )
```

For a flat software list with no OS/hardware context, use `audit.software` instead.

## Audit a Windows host by installed KBs

```python
with Vulners() as v:
    report = v.audit.win_audit(
        os="Windows Server 2012 R2",
        os_version="10.0.19045",
        kb_list=["KB2918614", "KB2918616"],
        software=[{"software": "Google Chrome", "version": "120.0.6099.130"}],
    )
```

If you only have the KB list, `audit.kb_audit(os=..., kb_list=[...])` is enough.

## Audit an SBOM

Have an SPDX or CycloneDX file? Upload it directly:

```python
with Vulners() as v:
    report = v.audit.sbom_audit("sbom.cdx.json")
```

## Audit free-form software names

When you only have imprecise product strings (no CPE), `audit.smart` resolves each string to
a CPE/PURL heuristically and returns the affecting vulnerabilities:

```python
with Vulners() as v:
    results = v.audit.smart(["Apache HTTP Server 2.4.49", "nginx 1.18.0"])
```

!!! warning "Billing"
    `smart` is a preview endpoint and is **billed per submitted string** (1–500 entries, each
    ≤ 512 characters). Keep the batch to what you need.
